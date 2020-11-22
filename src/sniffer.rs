use ::pnet::datalink::{DataLinkReceiver, NetworkInterface};
use ::pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use ::pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use ::pnet::packet::ipv6::Ipv6Packet;
use ::pnet::packet::tcp::TcpPacket;
use ::pnet::packet::udp::UdpPacket;
use ::pnet::packet::Packet;
use pnet::datalink;
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ipv4::Ipv4Packet;

use ::std::boxed::Box;
use ::std::io;
use ::std::net::{IpAddr, SocketAddr};
use ::std::thread::park_timeout;

use super::connection::LocalSocket;
use super::connection::{Connection, Protocol};

#[cfg(target_os = "linux")]
use super::linux::get_open_sockets;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use super::lsof::get_open_sockets;
#[cfg(target_os = "windows")]
use super::windows::get_open_sockets;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct OpenSockets {
    pub sockets_to_procs: std::collections::HashMap<LocalSocket, String>,
}

pub(crate) fn get_datalink_channel(
    interface: &NetworkInterface,
) -> Result<Box<dyn DataLinkReceiver>> {
    let mut config = pnet::datalink::Config::default();
    config.read_timeout = Some(std::time::Duration::new(1, 0));
    config.read_buffer_size = 65536;

    match pnet::datalink::channel(interface, config) {
        Ok(pnet::datalink::Channel::Ethernet(_tx, rx)) => Ok(rx),
        Ok(_) => Err(format!("{}: Unsupported interface type", interface.name).into()),
        Err(e) => Err(e.into()),
    }
}

const PACKET_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(10);
const CHANNEL_RESET_DELAY: std::time::Duration = std::time::Duration::from_millis(1000);

#[derive(Debug)]
pub struct Segment {
    pub interface_name: String,
    pub connection: Connection,
    pub direction: Direction,
    pub data_length: u128,
}

#[derive(PartialEq, Hash, Eq, Debug, Clone, PartialOrd)]
pub enum Direction {
    Download,
    Upload,
}

impl Direction {
    pub fn new(network_interface_ips: &[IpNetwork], source: IpAddr) -> Self {
        if network_interface_ips
            .iter()
            .any(|ip_network| ip_network.ip() == source)
        {
            Direction::Upload
        } else {
            Direction::Download
        }
    }
}

trait NextLevelProtocol {
    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol;
}

impl NextLevelProtocol for Ipv6Packet<'_> {
    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_header()
    }
}

macro_rules! extract_transport_protocol {
    (  $ip_packet: ident ) => {{
        match $ip_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let message = TcpPacket::new($ip_packet.payload())?;
                (
                    Protocol::Tcp,
                    message.get_source(),
                    message.get_destination(),
                    $ip_packet.payload().len() as u128,
                )
            }
            IpNextHeaderProtocols::Udp => {
                let datagram = UdpPacket::new($ip_packet.payload())?;
                (
                    Protocol::Udp,
                    datagram.get_source(),
                    datagram.get_destination(),
                    $ip_packet.payload().len() as u128,
                )
            }
            _ => return None,
        }
    }};
}

pub struct Sniffer {
    network_interface: NetworkInterface,
    network_frames: Box<dyn DataLinkReceiver>,
    dns_shown: bool,
}

impl Sniffer {
    pub fn new(
        network_interface: NetworkInterface,
        network_frames: Box<dyn DataLinkReceiver>,
        dns_shown: bool,
    ) -> Self {
        Sniffer {
            network_interface,
            network_frames,
            dns_shown,
        }
    }
    pub fn next(&mut self) -> Option<Segment> {
        let bytes = match self.network_frames.next() {
            Ok(bytes) => bytes,
            Err(err) => match err.kind() {
                std::io::ErrorKind::TimedOut => {
                    park_timeout(PACKET_WAIT_TIMEOUT);
                    return None;
                }
                _ => {
                    park_timeout(CHANNEL_RESET_DELAY);
                    self.reset_channel().ok();
                    return None;
                }
            },
        };
        // See https://github.com/libpnet/libpnet/blob/master/examples/packetdump.rs
        // VPN interfaces (such as utun0, utun1, etc) have POINT_TO_POINT bit set to 1
        let payload_offset = if (self.network_interface.is_loopback()
            || self.network_interface.is_point_to_point())
            && cfg!(target_os = "macos")
        {
            // The pnet code for BPF loopback adds a zero'd out Ethernet header
            14
        } else {
            0
        };
        let ip_packet = Ipv4Packet::new(&bytes[payload_offset..])?;
        let version = ip_packet.get_version();

        match version {
            4 => Self::handle_v4(ip_packet, &self.network_interface, self.dns_shown),
            6 => Self::handle_v6(
                Ipv6Packet::new(&bytes[payload_offset..])?,
                &self.network_interface,
            ),
            _ => {
                let pkg = EthernetPacket::new(bytes)?;
                match pkg.get_ethertype() {
                    EtherTypes::Ipv4 => Self::handle_v4(
                        Ipv4Packet::new(pkg.payload())?,
                        &self.network_interface,
                        self.dns_shown,
                    ),
                    EtherTypes::Ipv6 => {
                        Self::handle_v6(Ipv6Packet::new(pkg.payload())?, &self.network_interface)
                    }
                    _ => None,
                }
            }
        }
    }
    pub fn reset_channel(&mut self) -> Result<()> {
        self.network_frames = get_datalink_channel(&self.network_interface)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Interface not available"))?;
        Ok(())
    }
    fn handle_v6(ip_packet: Ipv6Packet, network_interface: &NetworkInterface) -> Option<Segment> {
        let (protocol, source_port, destination_port, data_length) =
            extract_transport_protocol!(ip_packet);

        let interface_name = network_interface.name.clone();
        let direction = Direction::new(&network_interface.ips, ip_packet.get_source().into());
        let from = SocketAddr::new(ip_packet.get_source().into(), source_port);
        let to = SocketAddr::new(ip_packet.get_destination().into(), destination_port);

        let connection = match direction {
            Direction::Download => Connection::new(from, to.ip(), destination_port, protocol),
            Direction::Upload => Connection::new(to, from.ip(), source_port, protocol),
        };
        Some(Segment {
            interface_name,
            connection,
            data_length,
            direction,
        })
    }
    fn handle_v4(
        ip_packet: Ipv4Packet,
        network_interface: &NetworkInterface,
        show_dns: bool,
    ) -> Option<Segment> {
        let (protocol, source_port, destination_port, data_length) =
            extract_transport_protocol!(ip_packet);

        let interface_name = network_interface.name.clone();
        let direction = Direction::new(&network_interface.ips, ip_packet.get_source().into());
        let from = SocketAddr::new(ip_packet.get_source().into(), source_port);
        let to = SocketAddr::new(ip_packet.get_destination().into(), destination_port);

        let connection = match direction {
            Direction::Download => Connection::new(from, to.ip(), destination_port, protocol),
            Direction::Upload => Connection::new(to, from.ip(), source_port, protocol),
        };

        if !show_dns && connection.remote_socket.port == 53 {
            return None;
        }
        Some(Segment {
            interface_name,
            connection,
            data_length,
            direction,
        })
    }
}

fn get_interface(interface_name: &str) -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
}

pub struct OsInputOutput {
    pub network_interfaces: Vec<NetworkInterface>,
    pub network_frames: Vec<Box<dyn DataLinkReceiver>>,
    pub get_open_sockets: fn() -> OpenSockets,
}

pub fn get_networks(interface_name: Option<String>) -> Result<OsInputOutput> {
    let network_interfaces = if let Some(name) = interface_name {
        match get_interface(&name) {
            Some(interface) => vec![interface],
            None => {
                return Err(format!("Cannot find interface {}", name).into());
                // the homebrew formula relies on this wording, please be careful when changing
            }
        }
    } else {
        datalink::interfaces()
    };

    #[cfg(any(target_os = "windows"))]
    let network_frames = network_interfaces
        .iter()
        .filter(|iface| !iface.ips.is_empty())
        .map(|iface| (iface, get_datalink_channel(iface)));
    #[cfg(not(target_os = "windows"))]
    let network_frames = network_interfaces
        .iter()
        .filter(|iface| iface.is_up() && !iface.ips.is_empty())
        .map(|iface| (iface, get_datalink_channel(iface)));

    let (available_network_frames, network_interfaces) = {
        let network_frames = network_frames.clone();
        let mut available_network_frames = Vec::new();
        let mut available_interfaces: Vec<NetworkInterface> = Vec::new();
        for (iface, rx) in network_frames.filter_map(|(iface, channel)| {
            if let Ok(rx) = channel {
                Some((iface, rx))
            } else {
                None
            }
        }) {
            available_interfaces.push(iface.clone());
            available_network_frames.push(rx);
        }
        (available_network_frames, available_interfaces)
    };

    if available_network_frames.is_empty() {
        return Err("Failed to find any network interface to listen on.".into());
    }

    Ok(OsInputOutput {
        network_interfaces,
        network_frames: available_network_frames,
        get_open_sockets,
    })
}
