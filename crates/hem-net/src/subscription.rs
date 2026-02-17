use tokio::{sync::oneshot, task::JoinHandle};

use crate::error::{MeshError, Result};

#[derive(Debug)]
pub struct Subscription {
    stop_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<JoinHandle<()>>,
}

impl Subscription {
    pub(crate) fn new(stop_tx: oneshot::Sender<()>, join_handle: JoinHandle<()>) -> Self {
        Self {
            stop_tx: Some(stop_tx),
            join_handle: Some(join_handle),
        }
    }

    pub async fn unsubscribe(mut self) -> Result<()> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join_handle.take() {
            match handle.await {
                Ok(_) => {}
                Err(err) if err.is_cancelled() => {}
                Err(err) => {
                    return Err(MeshError::Shutdown(format!(
                        "subscription task failed: {err}"
                    )))
                }
            }
        }
        Ok(())
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join_handle.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsubscribe_stops_task() {
        let (stop_tx, stop_rx) = oneshot::channel();
        let join_handle = tokio::spawn(async move {
            let _ = stop_rx.await;
        });

        let subscription = Subscription::new(stop_tx, join_handle);
        subscription
            .unsubscribe()
            .await
            .expect("unsubscribe should succeed");
    }
}
