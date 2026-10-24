use crate::msg::Message;
use rat_types::ConnectionSource;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::interval;

pub async fn run_core_loop(
    mut source: impl ConnectionSource + Send + 'static,
    snapshot_tx: broadcast::Sender<Message>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let mut ticker = interval(Duration::from_millis(1500));

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                break;
            }
            _ = ticker.tick() => {
                if let Ok(connections) = source.sample() {
                    let msg = Message::Snapshot { connections };
                    let _ = snapshot_tx.send(msg);
                }
            }
        }
    }
}
