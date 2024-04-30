// a module that mutualizes multiple mempools into one stream

use ethers::providers::{Provider, Ws};
use std::time::Duration;
use tokio::task::JoinSet;

pub mod block;
pub mod stream;

/// Instantiate many sockets in parallel
pub async fn instantiate(urls: Vec<&'static str>) -> Vec<Provider<Ws>> {
    if urls.is_empty() {
        panic!("please pass at least one url");
    }

    let mut sockets = Vec::new();
    let mut set = JoinSet::new();
    for url in urls.iter() {
        #[allow(suspicious_double_ref_op)]
        let url2 = url.clone();
        set.spawn(async move {
            match tokio::time::timeout(Duration::from_secs(5), async {
                Provider::<Ws>::connect(url2).await
            })
            .await
            {
                Ok(maybe_socket) => match maybe_socket {
                    Ok(socket) => Ok(socket),
                    Err(err) => Err(format!("not pushing socket: {err} {url2}")),
                },
                Err(err) => Err(format!("timeout: {err} {url2}")),
            }
        });
    }

    while let Some(res) = set.join_next().await {
        match res {
            Ok(maybe_socket) => match maybe_socket {
                Ok(socket) => {
                    sockets.push(socket);
                }
                Err(err) => {
                    log::error!("{:?}", err);
                }
            },
            Err(err) => {
                log::error!("{:?}", err);
            }
        }
    }

    sockets
}

#[cfg(test)]
mod tests {
    use super::{instantiate, stream::PendingStream};
    use futures::stream::StreamExt;
    use std::collections::HashSet;

    #[tokio::test]
    async fn redundancy() {
        let providers = instantiate(vec![
            "wss://bsc-rpc.publicnode.com",
            "wss://bsc-ws-node.nariox.org",
        ])
        .await;
        let mut stream = PendingStream::new(&providers).await;

        let mut seen_hashes = HashSet::new();

        while let Some(Some(tx)) = stream.next().await {
            if seen_hashes.contains(&tx.hash) {
                panic!("duplicate hash {:?}", tx.hash);
            } else if seen_hashes.len() > 20 {
                break;
            } else {
                seen_hashes.insert(tx.hash);
            }
        }
    }
}
