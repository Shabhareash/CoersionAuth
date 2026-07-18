use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};
use rdkafka::config::ClientConfig;
use rdkafka::producer::{BaseProducer, BaseRecord, Producer};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: kafka_producer <file-path> <topic> <multiplier> [broker]");
        std::process::exit(1);
    }
    let file_path = &args[1];
    let topic = &args[2];
    let multiplier: usize = args[3].parse().expect("Invalid multiplier");
    let broker = args.get(4).map(|s| s.as_str()).unwrap_or("localhost:9092");

    println!("Loading file '{}' into memory...", file_path);
    let file = File::open(file_path).expect("Failed to open file");
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let l = line.expect("Failed to read line");
        if !l.trim().is_empty() {
            lines.push(l);
        }
    }
    println!("Loaded {} lines.", lines.len());

    let producer: BaseProducer = ClientConfig::new()
        .set("bootstrap.servers", broker)
        .set("queue.buffering.max.messages", "2000000")
        .set("queue.buffering.max.kbytes", "1048576")
        .set("linger.ms", "20")
        .set("batch.num.messages", "20000")
        .set("compression.codec", "none")
        .set("acks", "1")
        .create()
        .expect("Failed to create producer");

    println!("Producing to topic '{}' with {}x multiplier (total {} events)...", 
        topic, multiplier, lines.len() * multiplier);

    let start = Instant::now();
    let mut total_sent = 0u64;
    let mut poll_counter = 0;

    for _ in 0..multiplier {
        for line in &lines {
            loop {
                let record = BaseRecord::<(), [u8]>::to(topic)
                    .payload(line.as_bytes())
                    .partition((total_sent % 3) as i32);
                match producer.send(record) {
                    Ok(_) => {
                        total_sent += 1;
                        break;
                    }
                    Err((_e, _)) => {
                        // Queue is full, poll to clear queue and retry
                        producer.poll(Duration::from_millis(1));
                    }
                }
            }

            poll_counter += 1;
            if poll_counter >= 5000 {
                producer.poll(Duration::from_millis(0));
                poll_counter = 0;
            }
        }
    }

    // Wait for all messages to be delivered
    println!("Flushing producer queue...");
    producer.flush(Duration::from_secs(30));

    let elapsed = start.elapsed();
    let eps = (total_sent as f64 / elapsed.as_secs_f64()) as u64;
    println!("✓ Produced {} events in {:.2?} (~{} EPS)", total_sent, elapsed, eps);
}
