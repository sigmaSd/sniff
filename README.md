# Sniff
https://github.com/imsnif/bandwhich sniffer/network librified

# Usage
```rust
fn sniff() {
    let mut threads = vec![];
    let networks = sniff::sniffer::get_networks(None).unwrap();
    networks
        .network_interfaces
        .into_iter()
        .zip(networks.network_frames.into_iter())
        .for_each(|(interface, frame)| {
            threads.push(std::thread::spawn(|| {
                let mut sniffer = sniff::sniffer::Sniffer::new(interface, frame, false);
                loop {
                    let segment = sniffer.next();
                    dbg!(segment);
                }
            }));
        });
    threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
}
```
