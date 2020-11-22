#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod lsof;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod lsof_utils;
#[cfg(target_os = "windows")]
mod windows;

pub mod connection;
pub mod sniffer;

#[test]
fn sniff() {
    let mut threads = vec![];
    let networks = sniffer::get_networks(None).unwrap();
    networks
        .network_interfaces
        .into_iter()
        .zip(networks.network_frames.into_iter())
        .for_each(|(interface, frame)| {
            threads.push(std::thread::spawn(|| {
                let mut sniffer = sniffer::Sniffer::new(interface, frame, false);
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
