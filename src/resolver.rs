use std::collections::HashMap;
use std::time::Instant;
use std::net::{UdpSocket, Ipv6Addr, IpAddr, TcpStream};
use std::io::{Result, Write, Read};

use crate::*;


pub struct DNSResolver {
    cache: HashMap<String, (String, Instant)>,
    dns_server: String,
    dns_mode: DnsMode,
}

impl DNSResolver {
    pub fn new(dns_server: Option<&String>, dns_mode: DnsMode) -> DNSResolver {
        if dns_server.is_none() || IpAddr::from_str(dns_server.unwrap()).is_err() {
            DNSResolver {
                cache: HashMap::<String, (String, Instant)>::new(),
                dns_server: "198.41.0.4".to_string(),
                dns_mode,
            }
        } else {
            DNSResolver {
                cache: HashMap::<String, (String, Instant)>::new(),
                dns_server: dns_server.unwrap().to_string(),
                dns_mode,
            }
        }
    }
    
    pub fn send_query(&mut self, ip_address: String, domain_name: String, record_type: u16) -> Result<DNSPacket> {
        let query = build_query(domain_name, record_type);
        let socket = match Ipv6Addr::from_str(&ip_address[0..ip_address.rfind(":").unwrap()]) {
            Ok(_) => UdpSocket::bind(":::1234").expect("Bind failed"),
            Err(_) => UdpSocket::bind("0.0.0.0:1234").expect("Bind failed")
        };
        socket
            .send_to(query.as_slice(), ip_address)
            .expect("Send failed");

        let mut buf = [0 as u8; 1024];
        socket.recv_from(&mut buf).expect("Receive failed");
        let mut reader = DecodeHelper {
            buffer: buf.to_vec(),
            pos: 0,
        };
        Ok(DNSPacket::parse(&mut reader))
    }

    pub fn send_query_tcp(&mut self, ip_address: String, domain_name: String, record_type: u16) -> Result<DNSPacket> {
        let query = build_query(domain_name, record_type);
        let mut stream = TcpStream::connect(ip_address)?;
        let n = stream.write(&query)?;
        if n < query.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Not written enough bytes"));
        }
        let mut buf = [0 as u8; 1024];
        stream.read(&mut buf)?;
        let mut reader = DecodeHelper {
            buffer: buf.to_vec(),
            pos: 0,
        };
        Ok(DNSPacket::parse(&mut reader))
    }

    pub fn send_query_tls(&mut self, ip_address: String, domain_name: String, record_type: u16) -> Result<DNSPacket> {
        unimplemented!()
    }

    pub fn send_query_quic(&mut self, ip_address: String, domain_name: String, record_type: u16) -> Result<DNSPacket> {
        unimplemented!()
    }

    pub fn resolve(&mut self, domain_name_: String, record_type: u16) -> String {
        let mut nameserver_ip = self.dns_server.clone() + ":53";
        let mut domain_name = domain_name_.clone();
        loop {
            println!("querying {nameserver_ip} for {domain_name}");
            let opt = self.cache.get(&domain_name);
            if opt.is_some() && opt.unwrap().1.elapsed().as_secs() < Duration::SECOND.as_secs() * 7200 {
                return opt.unwrap().0.clone();
            }
            let record: Option<String> = None;
            let resp = match self.dns_mode {
                DnsMode::UDP => {
                    self.send_query(nameserver_ip.clone(), domain_name.clone(), record_type).unwrap()
                },
                DnsMode::TCP => {
                    self.send_query_tcp(nameserver_ip.clone(), domain_name.clone(), record_type).unwrap()
                },
                DnsMode::TLS => {
                    self.send_query_tls(nameserver_ip.clone(), domain_name.clone(), record_type).unwrap()
                },
                DnsMode::QUIC => {
                    self.send_query_quic(nameserver_ip.clone(), domain_name.clone(), record_type).unwrap()
                }
            };
            if let Some(domain) = resp.get_cname() {
                domain_name = std::str::from_utf8(&domain).unwrap().to_owned();
            } else if let Some(ip) = resp.get_answer(record) {
                self.cache.insert(domain_name_.clone(), (ip_to_string(&ip), Instant::now()));
                return ip_to_string(&ip);
            } else if let Some(ns_ip) = resp.get_nameserver_ip() {
                nameserver_ip = ip_to_string(&ns_ip) + ":53";
            } else if let Some(ns_domain) = resp.get_nameserver() {
                nameserver_ip = 
                    self.resolve(
                        std::str::from_utf8(ns_domain.as_slice())
                            .unwrap()
                            .to_string(),
                        DnsType::TYPE_A as u16,
                    );
                println!("{nameserver_ip}")
            } else {
                panic!("Something went wrong");
            }
        }
    }
}


#[test]
fn test_send_query() {
    let mut resolver = DNSResolver::new(None, DnsMode::UDP);
    println!(
        "{:?}",
        resolver.send_query(
            "8.8.8.8:53".to_owned(),
            "www.example.com".to_owned(),
            DnsType::TYPE_A as u16
        )
        .unwrap()
    );
    println!(
        "{:?}",
        resolver.send_query(
            "8.8.8.8:53".to_owned(),
            "google.com".to_owned(),
            DnsType::TYPE_A as u16
        )
        .unwrap()
    );
    println!(
        "{:?}",
        resolver.send_query(
            "8.8.8.8:53".to_owned(),
            "www.facebook.com".to_owned(),
            DnsType::TYPE_A as u16
        )
        .unwrap()
    );
}

#[test]
fn test_resolve() {
    let mut resolver = DNSResolver::new(None, DnsMode::UDP);
    println!(
        "{:?}",
        resolver.resolve("google.com".to_owned(), DnsType::TYPE_A as u16)
    );
    println!(
        "{:?}",
        resolver.resolve("www.metafilter.com".to_owned(), DnsType::TYPE_A as u16)
    );
    // println!("{:?}", resolve("www.facebook.com".to_owned(), DnsType::TYPE_A as u16));
}
