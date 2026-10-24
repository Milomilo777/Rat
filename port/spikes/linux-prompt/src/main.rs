use nfq::{Queue, Verdict, };
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting nfqueue spike...");

    let mut queue = match Queue::open() {
        Ok(q) => q,
        Err(e) => {
            eprintln!("Failed to open queue: {}", e);
            eprintln!("This environment likely lacks the required kernel modules (nfnetlink_queue, nf_tables) or permissions.");
            return Ok(());
        }
    };

    queue.bind(0)?;
    println!("Queue bound. Listening for packets...");

    // Basic run loop utilizing the `nfq` crate API correctly (it doesn't have run_with_timeout).
    // In a real environment, we'd use NlSocket/mio for async polling with timeout, but `nfq`'s `Queue` blocks.
    let mut count = 0;

    // We will just process one message for the spike.
    if let Ok(mut msg) = queue.recv() {
        count += 1;
        println!("Received packet {}", count);
        std::thread::sleep(Duration::from_secs(2));
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg)?;
    }

    Ok(())
}
