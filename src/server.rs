use dashmap::DashMap;
use std::sync::Arc;
// use std::sync::mpsc;
use tokio::sync::mpsc;
use tokio::{net::UdpSocket, time::Instant};

use crate::*;

pub trait DNSServer {
    async fn start(&'static self);
}

#[derive(Clone)]
pub struct UDPServer {
    resolver: Arc<DNSResolver>,
    cache: DashMap<String, (String, Instant)>,
}

impl Default for UDPServer {
    fn default() -> Self {
        UDPServer {
            resolver: Arc::new(DNSResolver::new(
                Some(&"8.8.8.8".to_string()),
                None,
                DnsMode::UDP,
            )),
            cache: DashMap::new(),
        }
    }
}

impl DNSServer for UDPServer {
    async fn start(&'static self) {
        let socket = UdpSocket::bind("0.0.0.0:53").await.expect("Bind failed");
        let arcsock = Arc::new(socket);
        // let (tx, rx) = mpsc::channel::<tokio::task::JoinHandle<()>>();
        loop {
            let mut buf = [0 as u8; 1024];
            let narcsock = arcsock.clone();
            match narcsock.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    let _ = tokio::spawn(async move {
                        let mut reader = DecodeHelper {
                            buffer: buf.to_vec(),
                            pos: 0,
                        };
                        let question_packet = DNSPacket::parse(&mut reader, DnsMode::UDP);
                        let domain_name = std::str::from_utf8(&question_packet.questions[0].name)
                            .unwrap()
                            .to_string();
                        let opt = self.cache.get(&domain_name);
                        let ip = if opt.is_some()
                            && opt.as_ref().unwrap().1.elapsed().as_secs()
                                < Duration::SECOND.as_secs() * 7200
                        {
                            opt.unwrap().0.clone()
                        } else {
                            // TODO: change all the methods in DNSResolver as async
                            self.resolver
                                .resolve(domain_name.clone(), question_packet.questions[0].type_)
                        };
                        let record_type = if Ipv6Addr::from_str(&ip).is_ok() {
                            DnsType::TYPE_AAAA
                        } else {
                            DnsType::TYPE_A
                        };
                        let answer =
                            self.resolver
                                .build_answer(domain_name.clone(), record_type as u16, ip);
                        narcsock
                            .send_to(&answer, addr)
                            .await
                            .expect("Send answer back to client error");
                    }).await;
                    // tx.send(handle).await.expect("Send task to queue error!");
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                }
            }
        }
    }
}


#[derive(Clone)]
pub struct TCPServer {
    resolver: Arc<DNSResolver>,
    cache: DashMap<String, (String, Instant)>,
}

impl Default for TCPServer {
    fn default() -> Self {
        TCPServer {
            resolver: Arc::new(DNSResolver::new(
                Some(&"8.8.8.8".to_string()),
                None,
                DnsMode::TCP,
            )),
            cache: DashMap::new(),
        }
    }
}
