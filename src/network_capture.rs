
use pcap::{Capture, Device};
use std::env;
use std::process;
use std::net::{Ipv4Addr, IpAddr};
use crate::rule_parser::SnortRule;
// use http::{Request, Response};
use ureq;
use hex;
use serde_json::json;

pub fn get_traffic(rule_list: &[SnortRule]) {
    // Get the network interface as a command-line argument
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <INTERFACE>", args[0]);
        process::exit(1);
    }

    let interface = &args[1];

    let device = Device::list()
        .unwrap_or_else(|err| {
            eprintln!("Error listing devices: {}", err);
            process::exit(1);
        })
        .into_iter()
        .find(|device| device.name == *interface)
        .unwrap_or_else(|| {
            eprintln!("Error: Device {} not found", interface);
            process::exit(1);
        });

    // Create a capture object for the specified interface
    let mut capture = Capture::from_device(device)
        .unwrap_or_else(|err| {
            eprintln!("Error creating capture for device {}: {}", interface, err);
            process::exit(1);
        })
        .promisc(true)
        .snaplen(2048)
        .open()
        .unwrap_or_else(|err| {
            eprintln!("Error opening capture: {}", err);
            process::exit(1);
        });

    // Process packets
    // this is where I need to do filtering shit
    loop {
        match capture.next() {
            Ok(packet) => {
                let data = packet.data;
                if let Some((src_ip, dst_ip, src_port, dst_port)) = parse_packet_headers(data) {
                    for rule in rule_list {
                        let src_ip_match = rule.src_ip == src_ip.to_string() || rule.src_ip == "any";
                        let src_port_match = rule.src_port == src_port.to_string() || rule.src_port == "any";
                        let dst_ip_match = rule.dst_ip == dst_ip.to_string() || rule.dst_ip == "any";
                        let dst_port_match = rule.dst_port == dst_port.to_string() || rule.dst_port == "any";

                        let content_match = if let Some(ref content) = rule.content {
                            if !content.is_empty() {
                                let content_bytes = content.as_bytes();
                                data.windows(content_bytes.len()).any(|window| window == content_bytes)
                            } else {
                                true
                            }
                        } else {
                            true
                        };
                    
                
                    if src_ip_match && src_port_match && dst_ip_match && dst_port_match && content_match {
                        println!("Source IP: {}, Source Port: {}", src_ip, src_port);
                        println!("Destination IP: {}, Destination Port: {}", dst_ip, dst_port);
                        if let Some(ref msg) = rule.msg {
                            println!("Rule matched! Message: {}", msg);
                        }
                        print_packet_data(data);
                        let url = "urlhere";
                        let data_hex = hex::encode(data);
                        let payload = json!({
                            "src_ip": src_ip.to_string(),
                            "src_port": src_port,
                            "dst_ip": dst_ip.to_string(),
                            "dst_port": dst_port,
                            "msg": rule.msg.clone().unwrap_or_default(),
                            "packet_data": data_hex
                        });

                        let resp = ureq::post(url)
                        .set("Content-Type", "application/json")
                        .send_string(&payload.to_string());
                        
                        if let Err(e) = resp {
                            eprintln!("Failed to send webhook: {}", e);
                        }
                        
                    }

                    }
                  
                }
            }
            Err(err) => {
                eprintln!("Error capturing packet: {}", err);
                break;
            }
        }
    }
}

// Parses packet headers to extract source and destination IPs and ports
fn parse_packet_headers(data: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
    let eth_header_len = 14;

    // Check if the packet is long enough to contain an Ethernet and IPv4 header
    if data.len() < eth_header_len + 20 {
        return None;
    }

    // Check if the packet is IPv4 (0x0800)
    if data[12] != 0x08 || data[13] != 0x00 {
        return None;
    }

    // Parse IPv4 header
    let src_ip = Ipv4Addr::new(data[eth_header_len + 12], data[eth_header_len + 13], data[eth_header_len + 14], data[eth_header_len + 15]);
    let dst_ip = Ipv4Addr::new(data[eth_header_len + 16], data[eth_header_len + 17], data[eth_header_len + 18], data[eth_header_len + 19]);
    let ip_header_len = (data[eth_header_len] & 0x0F) as usize * 4;
    let protocol = data[eth_header_len + 9];

    // Check if the packet is TCP (0x06) or UDP (0x11)
    if protocol != 0x06 && protocol != 0x11 {
        return None;
    }

     // Check if the packet is long enough to contain an IPv4 header and a TCP/UDP header
     if data.len() < eth_header_len + ip_header_len + 8 {
        return None;
    }

    // Parse TCP/UDP header
    let src_port = u16::from_be_bytes([data[eth_header_len + ip_header_len], data[eth_header_len + ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[eth_header_len + ip_header_len + 2], data[eth_header_len + ip_header_len + 3]]);

    Some((IpAddr::V4(src_ip), IpAddr::V4(dst_ip), src_port, dst_port))
}

fn print_packet_data(data: &[u8]) {
    const HEX_CHARS_PER_LINE: usize = 16;

    for (i, byte) in data.iter().enumerate() {
        if i % HEX_CHARS_PER_LINE == 0 {
            print!("{:04x}: ", i);
        }

        print!("{:02x} ", byte);

        if i % HEX_CHARS_PER_LINE == HEX_CHARS_PER_LINE - 1 || i == data.len() - 1 {
            let padding = 3 * (HEX_CHARS_PER_LINE - (i % HEX_CHARS_PER_LINE) - 1);
            print!("{:padding$}", "", padding = padding);

            let start = i / HEX_CHARS_PER_LINE * HEX_CHARS_PER_LINE;
            let end = std::cmp::min(start + HEX_CHARS_PER_LINE, data.len());

            for byte in &data[start..end] {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    print!("{}", *byte as char);
                } else {
                    print!(".");
                }
            }

            println!();
        }

    }
    println!("#####################################################################################");

}