#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod lsof;
#[cfg(target_os = "windows")]
mod windows;

pub mod connection;
pub mod sniffer;

#[test]
fn s() {
    let mut t = vec![];
    let i = sniffer::get_networks(None).unwrap();
    i.network_interfaces
        .into_iter()
        .zip(i.network_frames.into_iter())
        .for_each(|(ii, f)| {
            t.push(std::thread::spawn(|| {
                let mut ss = sniffer::Sniffer::new(ii, f, false);
                loop {
                    let a = ss.next();
                    dbg!(a);
                }
            }));
        });

    t.into_iter().for_each(|t| {
        t.join().unwrap();
    });
}
