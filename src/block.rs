use ethers::{
    providers::{Http, Middleware, Provider},
    types::{Block, Transaction, H256, U256},
};
use std::{
    cmp::Ordering,
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

/// A pending block which manages ordering of pending txs
#[derive(Debug, Default, Clone)]
pub struct PendingBlock {
    /// Vec of transactions with their first-seen timestamp for a O(1) indexing and ordering. They are always ordered.
    // TODO replace with a linked list to build an ordered hash table
    transactions_vec: Vec<(Transaction, Instant)>,
    /// Map of transactions for an efficient O(1) lookup by hash
    transactions_map: HashMap<H256, usize>,
}

impl PendingBlock {
    /// Try to check if a transaction is really pending or not
    pub async fn check_finalized(http_provider: &Arc<Provider<Http>>, hash: H256) -> bool {
        http_provider
            .get_transaction_receipt(hash)
            .await
            .is_ok_and(|receipt| receipt.is_some())
    }

    pub fn transactions(&self) -> Vec<&Transaction> {
        self.transactions_vec.iter().map(|(tx, _)| tx).collect()
    }

    pub fn get_index(&self, index: usize) -> Option<&Transaction> {
        self.transactions_vec.get(index).map(|(tx, _)| tx)
    }

    pub fn get_hash(&self, hash: &H256) -> Option<&Transaction> {
        let index = self.transactions_map.get(hash)?;
        // this guarantees that the invariant: all the indexes are defined in the struct holds
        Some(self.get_index(*index).unwrap())
    }

    pub fn len(&self) -> usize {
        self.transactions_vec.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insertion_index(&self, tx: &Transaction) -> usize {
        let gas_price = tx.gas_price.unwrap();
        match self
            .transactions_vec
            .binary_search_by(|vec_tx| vec_tx.0.gas_price.unwrap().cmp(&gas_price))
        {
            Ok(mut i) => {
                // found 1 or more elements with this same gas price, find the rightmost index
                loop {
                    if let Some(idx_tx) = self.get_index(i + 1) {
                        match idx_tx.gas_price.unwrap().cmp(&gas_price) {
                            Ordering::Equal => i += 1,
                            Ordering::Greater => break i + 1,
                            Ordering::Less => panic!("invariant of ordering broken"),
                        }
                    } else {
                        // we reached the right-end so break here
                        break i + 1;
                    }
                }
            }
            Err(i) => {
                // not found in the vec, so we can safely insert here
                i
            }
        }
    }

    // TODO support replacement transactions
    /// Insert a new tx in the block and return the index where it was inserted
    pub fn add_tx(
        &mut self,
        mut tx: Transaction,
        block: Option<&Block<H256>>,
    ) -> eyre::Result<usize> {
        log::debug!("add full tx {:?}", &tx);

        if tx.block_hash.is_some() || tx.block_number.is_some() || tx.transaction_index.is_some() {
            eyre::bail!("transaction is not pending");
        }

        if let Some(block) = block {
            let gas_price = tx.gas_price.unwrap_or_default();
            if gas_price < block.base_fee_per_gas.expect("missing base fee") {
                let next_base_fee = Self::calculate_next_block_base_fee(block);
                // if max_fee < next_base_fee {
                if gas_price < next_base_fee {
                    eyre::bail!(
                        "not adding underpriced transaction with {} gas price",
                        gas_price
                    );
                }
            }
        }

        if self.transactions_map.contains_key(&tx.hash) {
            eyre::bail!("trying to add a transaction twice");
        }

        // TODO adapt to EIP-1559, this only works for legacy transactions
        tx.gas_price = Some(tx.gas_price.unwrap_or_default());
        let index = self.insertion_index(&tx);

        log::debug!("add tx {:?}", &tx.hash);

        self.transactions_map.insert(tx.hash, index);

        self.transactions_vec.insert(index, (tx, Instant::now()));
        if self.transactions_vec.len() > index {
            self.adjust_map_index(index + 1, true);
        }

        Ok(index)
    }

    /// Calculate the next block base fee
    /// based on math provided here: https://ethereum.stackexchange.com/questions/107173/how-is-the-base-fee-per-gas-computed-for-a-new-block
    /// based on https://github.com/mouseless-eth/rusty-sando/blob/eebeb43ba8f912c754cde2259fd87cfa505723b0/bot/crates/strategy/src/types.rs#L157
    /// very based
    pub fn calculate_next_block_base_fee(block: &Block<H256>) -> U256 {
        // Get the block base fee per gas
        let current_base_fee_per_gas = block.base_fee_per_gas.expect("base fee per gas not found");
        let current_gas_used = block.gas_used;
        let current_gas_target = block.gas_limit / 2;

        match current_gas_used.cmp(&current_gas_used) {
            Ordering::Equal => current_base_fee_per_gas,
            Ordering::Greater => {
                let gas_used_delta = current_gas_used - current_gas_target;
                let base_fee_per_gas_delta =
                    current_base_fee_per_gas * gas_used_delta / current_gas_target / 8;
                current_base_fee_per_gas + base_fee_per_gas_delta
            }
            Ordering::Less => {
                let gas_used_delta = current_gas_target - current_gas_used;
                let base_fee_per_gas_delta =
                    current_base_fee_per_gas * gas_used_delta / current_gas_target / 8;
                current_base_fee_per_gas - base_fee_per_gas_delta
            }
        }
    }

    fn adjust_map_index(&mut self, from: usize, add: bool) {
        if !self.transactions_vec.is_empty() {
            // adjust the index of all moved transactions in the map too
            for i in from..self.transactions_vec.len() {
                let tx = &self.transactions_vec[i].0;
                if add {
                    *self.transactions_map.get_mut(&tx.hash).unwrap() += 1;
                } else {
                    *self.transactions_map.get_mut(&tx.hash).unwrap() -= 1;
                }
            }
        }
    }

    /// Remove a transaction by hash and return the index where it was stored in the vec
    pub fn remove_tx(&mut self, hash: &H256) -> Result<usize, &str> {
        if !self.transactions_map.contains_key(hash) {
            return Err("trying to remove an nonexistent transaction");
        }

        log::debug!("rem tx {:?}", hash);

        let index = self
            .transactions_map
            .remove(hash)
            .expect("transaction not present in the map");
        // TODO doing the vec remove and map index adjustment at once is more efficient
        self.transactions_vec.remove(index);
        // the hash at this position is now missing so we substract all next indexes by 1
        self.adjust_map_index(index, false);

        Ok(index)
    }

    pub fn prune_transactions(&mut self, max_duration: Duration) {
        let mut to_remove = Vec::new();
        for (tx, inst) in self.transactions_vec.iter() {
            if inst.elapsed() > max_duration {
                to_remove.push(tx.hash);
            }
        }

        if !to_remove.is_empty() {
            for hash in to_remove.iter() {
                let _ = self.remove_tx(hash);
            }

            log::debug!("pruned {} transactions from the mempool", to_remove.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{block::PendingBlock, instantiate, stream::PendingStream};
    use ethers::{
        middleware::Middleware,
        providers::{Http, Provider, Ws},
        types::{BigEndianHash, Transaction, H256, U256},
    };
    use futures::stream::StreamExt;
    use std::{sync::Arc, time::Duration};
    use tokio::{
        sync::Mutex,
        time::{self},
    };

    fn num_to_hash(num: usize) -> H256 {
        let as_u256: U256 = num.into();
        H256::from_uint(&as_u256)
    }

    fn check_invariants(pending_block: &PendingBlock) {
        if pending_block.transactions_vec.len() != pending_block.transactions_map.len() {
            panic!(
                "vec {} != map {}",
                pending_block.transactions_vec.len(),
                pending_block.transactions_map.len()
            );
        }

        for (tx, _) in pending_block.transactions_vec.iter() {
            if !pending_block.transactions_map.contains_key(&tx.hash) {
                panic!("missing tx {:?}", tx.hash);
            }
        }

        for (hash, i) in pending_block.transactions_map.iter() {
            if &pending_block.transactions_vec.get(*i).unwrap().0.hash != hash {
                panic!("wrong insertion for tx {:?}", hash);
            }
        }

        assert!(
            pending_block
                .transactions_vec
                .windows(2)
                .all(|w| w[0].0.gas_price <= w[1].0.gas_price),
            "transactions are not ordered correctly"
        )
    }

    #[test]
    fn insert_remove_mempool1() {
        let mut block = PendingBlock::default();
        let tx = Transaction {
            gas_price: Some(0.into()),
            hash: num_to_hash(0),
            ..Default::default()
        };
        assert_eq!(block.insertion_index(&tx), 0);

        assert_eq!(block.add_tx(tx.clone(), None).unwrap(), 0);
        check_invariants(&block);

        let mut tx2 = tx.clone();
        tx2.hash = num_to_hash(1);
        assert_eq!(block.insertion_index(&tx2), 1);
        assert_eq!(block.add_tx(tx2.clone(), None).unwrap(), 1);
        check_invariants(&block);

        assert_eq!(block.remove_tx(&tx2.clone().hash).unwrap(), 1);
        check_invariants(&block);
        assert_eq!(block.remove_tx(&tx.clone().hash).unwrap(), 0);
        check_invariants(&block);
    }

    #[test]
    fn insert_remove_mempool2() {
        let mut block = PendingBlock::default();
        let tx = Transaction {
            gas_price: Some(0.into()),
            hash: num_to_hash(0),
            ..Default::default()
        };
        assert_eq!(block.insertion_index(&tx), 0);

        assert_eq!(block.add_tx(tx.clone(), None).unwrap(), 0);
        check_invariants(&block);

        let mut tx2 = tx.clone();
        tx2.hash = num_to_hash(1);
        assert_eq!(block.insertion_index(&tx2), 1);
        assert_eq!(block.add_tx(tx2.clone(), None).unwrap(), 1);
        check_invariants(&block);

        assert_eq!(block.remove_tx(&tx.clone().hash).unwrap(), 0);
        check_invariants(&block);
        assert_eq!(block.remove_tx(&tx2.clone().hash).unwrap(), 0);
        check_invariants(&block);
    }

    #[tokio::test]
    async fn mempool_coverage() {
        let http_url = "https://binance.llamarpc.com";
        let ws_url = "wss://bsc-rpc.publicnode.com";

        let http_provider = Arc::new(Provider::<Http>::try_from(http_url).unwrap());
        let ws_provider = Arc::new(Provider::<Ws>::connect(ws_url).await.unwrap());

        let pending_block = Arc::new(Mutex::new(PendingBlock::default()));

        let mut in_pool = 0;
        let mut total = 0;

        let pending_block2 = pending_block.clone();
        let http_provider2 = http_provider.clone();
        let pending = tokio::spawn(async move {
            let providers = instantiate(vec![ws_url, "wss://bsc-ws-node.nariox.org"]).await;
            let mut stream = PendingStream::new(&providers).await;

            while let Some(maybe_tx) = stream.next().await {
                if let Some(tx) = maybe_tx {
                    if !PendingBlock::check_finalized(&http_provider2, tx.hash).await {
                        if let Err(err) = pending_block2.lock().await.add_tx(tx, None) {
                            log::debug!("err from add_tx {:?}", err);
                        }
                    }
                }
            }
        });

        let pending_block2 = pending_block.clone();
        let http_provider2 = http_provider.clone();
        let finalized = tokio::spawn(async move {
            let mut block_stream = ws_provider
                .subscribe_blocks()
                .await
                .expect("subscription failed");

            while let Some(block) = block_stream.next().await {
                let tx_hashes = if block.transactions.is_empty() {
                    loop {
                        match http_provider2
                            .get_block(block.number.expect("missing block number"))
                            .await
                        {
                            Ok(Some(block)) => break block.transactions,
                            _rest => {
                                // dbg!(&rest);
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                continue;
                            }
                        }
                    }
                } else {
                    block.transactions
                };

                {
                    let pending_block = pending_block2.lock().await;
                    for hash in tx_hashes {
                        if pending_block.transactions_map.contains_key(&hash) {
                            in_pool += 1;
                        }

                        total += 1;
                    }
                }

                let per = if total == 0 {
                    0.
                } else {
                    (in_pool as f32 * 100.0) / total as f32
                };

                println!("coverage {in_pool}/{total} {per}%");
            }
        });

        let pending_block2 = pending_block.clone();
        let http_provider2 = http_provider.clone();
        let pruning = tokio::spawn(async move {
            let mut receipt_interval = time::interval(Duration::from_secs(20));
            let mut pruning_interval = time::interval(Duration::from_secs(10));

            loop {
                tokio::select! {
                    _ = receipt_interval.tick() => {
                        let mut block = pending_block2.lock().await;
                        let hashes: Vec<_> = block.transactions().into_iter().map(|tx| tx.hash).collect();
                        // TODO this could be parallelized
                        for hash in hashes {
                            if PendingBlock::check_finalized(&http_provider2, hash).await {
                                let _ = block.remove_tx(&hash);
                            }
                        }
                    }
                    _ = pruning_interval.tick() => {
                        let mut block = pending_block2.lock().await;
                        block.prune_transactions(Duration::from_secs(20));
                    }
                }
            }
        });

        let _ = tokio::join!(pending, finalized, pruning);
    }
}
