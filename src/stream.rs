use ethers::{
    providers::{Middleware, Provider, SubscriptionStream, Ws},
    types::{Transaction, H256},
};
use futures::{
    stream::{select_all, SelectAll},
    Stream,
};
use std::{
    collections::HashSet,
    pin::Pin,
    task::{Context, Poll},
};

pub(crate) type JoinStream<'a> =
    Pin<Box<SelectAll<Pin<Box<SubscriptionStream<'a, Ws, Transaction>>>>>>;

pub struct PendingStream<'a> {
    stream: JoinStream<'a>,
    /// The already seen transaction hashes
    seen: HashSet<H256>,
}

impl<'a> PendingStream<'a> {
    pub async fn new(providers: &'a [Provider<Ws>]) -> Self {
        let mut streams = Vec::new();
        for provider in providers.iter() {
            let sub = provider.subscribe_full_pending_txs().await.unwrap();
            streams.push(Box::pin(sub));
        }

        Self {
            stream: Box::pin(select_all(streams)),
            seen: Default::default(),
        }
    }
}

impl Stream for PendingStream<'_> {
    type Item = Option<Transaction>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut_self = self.get_mut();

        match mut_self.stream.as_mut().poll_next(cx) {
            Poll::Ready(maybe_tx) => {
                if let Some(tx) = maybe_tx {
                    if mut_self.seen.contains(&tx.hash) {
                        // already seen tx, don't yield
                        Poll::Ready(Some(None))
                    } else {
                        // new tx
                        mut_self.seen.insert(tx.hash);
                        Poll::Ready(Some(Some(tx)))
                    }
                } else {
                    // we never want this to return Poll::Ready(None) because it's a never ending stream
                    // if any of the socket has terminated, we should keep up with others
                    log::debug!("a stream has terminated");
                    Poll::Ready(Some(None))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
