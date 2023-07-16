use std::io::{Read, Result, Write};
use std::net::{IpAddr, Ipv6Addr, TcpStream, UdpSocket};
use std::sync::Arc;

use h2::client;
use http::{Request, Version};
use tokio_rustls::TlsConnector;

use crate::*;

pub struct DNSResolver {
    dns_server: String,
    uri: Option<String>,
    dns_mode: DnsMode,
}

impl DNSResolver {
    pub fn new(
        dns_server: Option<&String>,
        uri: Option<&String>,
        dns_mode: DnsMode,
    ) -> DNSResolver {
        if dns_server.is_none() || IpAddr::from_str(dns_server.unwrap()).is_err() {
            DNSResolver {
                dns_server: "8.8.8.8".to_string(),
                dns_mode,
                uri: Some("https://dns.google/dns-query".to_string()),
            }
        } else {
            DNSResolver {
                dns_server: dns_server.unwrap().to_string(),
                dns_mode,
                uri: uri.cloned(),
            }
        }
    }

    pub fn set_mode(&mut self, mode: DnsMode) {
        self.dns_mode = mode;
    }

    pub fn build_query(&self, domain_name: String, record_type: u16) -> Vec<u8> {
        let name = encode_dns_name(domain_name);
        let id: u16 = random();
        let header = DNSHeader {
            // length: None,
            id,
            flags: RECURSION_DESIRED,
            num_questions: 1,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        };
        let question = DNSQuestion {
            name,
            type_: record_type,
            class: CLASS_IN,
        };
        [header.to_bytes(), question.to_bytes()].concat()
    }

    pub fn build_answer(&self, domain_name: String, record_type: u16, ip: String) -> Vec<u8> {
        let name = encode_dns_name(domain_name);
        let id: u16 = random();
        let header = DNSHeader {
            id,
            flags: RECURSION_DESIRED,
            num_questions: 1, // atm we only support this
            num_answers: 1,
            num_authorities: 0,
            num_additionals: 0,
        };
        // Currently we consult the root servers each time so we don't have authorities
        let question = DNSQuestion {
            name: name.clone(),
            type_: record_type,
            class: CLASS_IN,
        };
        let answer = DNSRecord {
            name,
            type_: record_type,
            class: CLASS_IN,
            ttl: 60, // 60 seconds
            data: string_to_be_ip(ip),
        };
        [header.to_bytes(), question.to_bytes(), answer.to_bytes()].concat()
    }

    pub fn send_query(
        &self,
        ip_address: String,
        domain_name: String,
        record_type: u16,
    ) -> Result<DNSPacket> {
        let query = self.build_query(domain_name, record_type);
        let socket = match Ipv6Addr::from_str(&ip_address) {
            Ok(_) => UdpSocket::bind(":::1234").expect("Bind failed"),
            Err(_) => UdpSocket::bind("0.0.0.0:1234").expect("Bind failed"),
        };
        socket
            .send_to(query.as_slice(), ip_address + ":53")
            .expect("Send failed");

        let mut buf = [0 as u8; 1024];
        socket.recv_from(&mut buf).expect("Receive failed");
        let mut reader = DecodeHelper {
            buffer: buf.to_vec(),
            pos: 0,
        };
        Ok(DNSPacket::parse(&mut reader, self.dns_mode))
    }

    pub fn send_query_tcp(
        &self,
        ip_address: String,
        domain_name: String,
        record_type: u16,
    ) -> Result<DNSPacket> {
        let query = self.build_query(domain_name, record_type);
        let mut stream = TcpStream::connect(ip_address + ":53")?;
        let n = stream.write(&u16::to_be_bytes(query.len() as u16))?;
        let n = stream.write(&query)?;
        if n < query.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Not written enough bytes",
            ));
        }
        let mut lenbuf = [0 as u8; 2];
        stream.read(&mut lenbuf)?;
        let length = u16::from_be_bytes(lenbuf);
        let mut buf = Vec::new();
        buf.resize(length.into(), 0);
        stream.read(&mut buf)?;
        let mut reader = DecodeHelper {
            buffer: buf.to_vec(),
            pos: 0,
        };
        Ok(DNSPacket::parse(&mut reader, self.dns_mode))
    }

    pub fn send_query_tls(
        &self,
        ip_address: String,
        domain_name: String,
        record_type: u16,
    ) -> Result<DNSPacket> {
        let query = self.build_query(domain_name, record_type);
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let mut conn = rustls::ClientConnection::new(
            Arc::new(config),
            ip_address.as_str().try_into().unwrap(),
        )
        .expect("TLS connect failed");
        let mut sock = TcpStream::connect(ip_address + ":853").expect("TCP connect failed");
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write(&u16::to_be_bytes(query.len() as u16));
        tls.write(&query).expect("TLS write buffer failed");
        let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
        // debug!("Ciphersuite: {:?}", ciphersuite);
        let mut lenbuf = [0 as u8; 2];
        tls.read(&mut lenbuf)?;
        let length = u16::from_be_bytes(lenbuf);
        let mut buf = Vec::new();
        buf.resize(length.into(), 0);
        tls.read(&mut buf)?;
        let mut reader = DecodeHelper {
            buffer: buf.to_vec(),
            pos: 0,
        };
        Ok(DNSPacket::parse(&mut reader, self.dns_mode))
    }

    pub fn send_query_quic(
        &self,
        ip_address: String,
        domain_name: String,
        record_type: u16,
    ) -> Result<DNSPacket> {
        unimplemented!()
    }

    pub fn send_query_https(
        &self,
        ip_address: String,
        uri: String,
        domain_name: String,
        record_type: u16,
    ) -> Result<DNSPacket> {
        let tls_client_config = std::sync::Arc::new({
            let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
            root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
                |ta| {
                    tokio_rustls::rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                },
            ));

            let mut c = tokio_rustls::rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            c.alpn_protocols.push("h2".as_bytes().to_owned());
            c
        });
        let query = self.build_query(domain_name, record_type);
        let request = Request::builder()
            .uri(uri.clone())
            .method("POST")
            .version(Version::HTTP_2)
            .header("content-type", "application/dns-message")
            .header("content-length", query.len())
            .header("accept", "application/dns-message")
            .body(())
            .expect("Build request failed");
        let mut buf = Vec::<u8>::new();
        let async_block = async {
            let tcp = tokio::net::TcpStream::connect(ip_address.clone() + ":443")
                .await
                .expect("TCP connection failed");
            let tls = TlsConnector::from(tls_client_config)
                .connect(ip_address.clone().as_str().try_into().unwrap(), tcp)
                .await
                .expect("Build tls connection failed");
            let (mut client, h2) = client::handshake(tls).await.expect("H2 handshake error");
            let (response, mut stream) = client
                .send_request(request, false)
                .expect("Build h2 connection failed");
            stream
                .send_data(query.into(), true)
                .expect("Failed to send data through h2 stream");
            tokio::spawn(async move {
                if let Err(e) = h2.await {
                    println!("GOT ERR={:?}", e);
                }
            });
            let mut body = response.await.expect("Wait for response error").into_body();

            while let Some(chunk) = body.data().await {
                buf.append(&mut chunk.expect("Read data from h2 stream error").into());
            }
        };

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async_block);

        let mut reader = DecodeHelper {
            buffer: buf,
            pos: 0,
        };

        Ok(DNSPacket::parse(&mut reader, self.dns_mode))
    }

    pub fn resolve(&self, domain_name_: String, record_type: u16) -> String {
        let mut nameserver_ip = self.dns_server.clone();
        let mut uri = if self.dns_mode == DnsMode::HTTPS {
            self.uri.clone().unwrap()
        } else {
            "".to_string()
        };
        let mut domain_name = domain_name_.clone();
        loop {
            println!("querying {nameserver_ip} for {domain_name}");
            let record: Option<String> = None;
            let resp = match self.dns_mode {
                DnsMode::UDP => self
                    .send_query(nameserver_ip.clone(), domain_name.clone(), record_type)
                    .unwrap(),
                DnsMode::TCP => self
                    .send_query_tcp(nameserver_ip.clone(), domain_name.clone(), record_type)
                    .unwrap(),
                DnsMode::TLS => self
                    .send_query_tls(nameserver_ip.clone(), domain_name.clone(), record_type)
                    .unwrap(),
                DnsMode::HTTPS => self
                    .send_query_https(
                        nameserver_ip.clone(),
                        uri.clone(),
                        domain_name.clone(),
                        record_type,
                    )
                    .unwrap(),
                DnsMode::QUIC => self
                    .send_query_quic(nameserver_ip.clone(), domain_name.clone(), record_type)
                    .unwrap(),
            };
            if let Some(domain) = resp.get_cname() {
                domain_name = std::str::from_utf8(&domain).unwrap().to_owned();
            } else if let Some(ip) = resp.get_answer(record) {
                /*  self.cache
                .insert(domain_name_.clone(), (ip_to_string(&ip), Instant::now())); */
                return ip_to_string(&ip);
            } else if let Some(ns_ip) = resp.get_nameserver_ip() {
                nameserver_ip = ip_to_string(&ns_ip);
            } else if let Some(ns_domain) = resp.get_nameserver() {
                nameserver_ip = self.resolve(
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
    let mut resolver = DNSResolver::new(None, None, DnsMode::UDP);
    println!(
        "{:?}",
        resolver
            .send_query(
                "8.8.8.8".to_owned(),
                "www.example.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query(
                "8.8.8.8".to_owned(),
                "google.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query(
                "8.8.8.8".to_owned(),
                "www.facebook.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query(
                "8.8.8.8".to_owned(),
                "www.example.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query(
                "8.8.8.8".to_owned(),
                "google.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query(
                "8.8.8.8".to_owned(),
                "www.facebook.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
}

#[test]
fn test_send_query_tcp() {
    let mut resolver = DNSResolver::new(None, None, DnsMode::TCP);
    println!(
        "{:?}",
        resolver
            .send_query_tcp(
                "8.8.8.8".to_owned(),
                "www.example.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_tcp(
                "8.8.8.8".to_owned(),
                "google.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_tcp(
                "8.8.8.8".to_owned(),
                "www.facebook.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_tcp(
                "8.8.8.8".to_owned(),
                "www.example.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_tcp(
                "8.8.8.8".to_owned(),
                "google.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_tcp(
                "8.8.8.8".to_owned(),
                "www.facebook.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
}

#[test]
fn test_send_query_tls() {
    let mut resolver = DNSResolver::new(None, None, DnsMode::TLS);
    println!(
        "{:?}",
        resolver
            .send_query_tls(
                "8.8.8.8".to_owned(),
                "www.example.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_tls(
                "8.8.8.8".to_owned(),
                "google.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_tls(
                "8.8.8.8".to_owned(),
                "www.facebook.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_tls(
                "8.8.8.8".to_owned(),
                "www.example.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_tls(
                "8.8.8.8".to_owned(),
                "google.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_tls(
                "8.8.8.8".to_owned(),
                "www.facebook.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
}

#[test]
fn test_send_query_https() {
    let mut resolver = DNSResolver::new(None, None, DnsMode::HTTPS);
    println!(
        "{:?}",
        resolver
            .send_query_https(
                "8.8.8.8".to_owned(),
                resolver.uri.clone().unwrap(),
                "www.example.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_https(
                "8.8.8.8".to_owned(),
                resolver.uri.clone().unwrap(),
                "google.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_https(
                "8.8.8.8".to_owned(),
                resolver.uri.clone().unwrap(),
                "www.facebook.com".to_owned(),
                DnsType::TYPE_A as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_https(
                "8.8.8.8".to_owned(),
                resolver.uri.clone().unwrap(),
                "www.example.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_https(
                "8.8.8.8".to_owned(),
                resolver.uri.clone().unwrap(),
                "google.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
    println!(
        "{:?}",
        resolver
            .send_query_https(
                "8.8.8.8".to_owned(),
                resolver.uri.clone().unwrap(),
                "www.facebook.com".to_owned(),
                DnsType::TYPE_AAAA as u16
            )
            .unwrap()
    );
}

#[test]
fn test_resolve() {
    let mut resolver = DNSResolver::new(None, None, DnsMode::UDP);
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

#[test]
fn test_resolve_tcp() {
    let mut resolver = DNSResolver::new(None, None, DnsMode::TCP);
    println!(
        "{:?}",
        resolver.resolve("google.com".to_owned(), DnsType::TYPE_A as u16)
    );
    println!(
        "{:?}",
        resolver.resolve("www.metafilter.com".to_owned(), DnsType::TYPE_A as u16)
    );
}

#[test]
fn test_resolve_tls() {
    let mut resolver = DNSResolver::new(None, None, DnsMode::TLS);
    println!(
        "{:?}",
        resolver.resolve("google.com".to_owned(), DnsType::TYPE_A as u16)
    );
    println!(
        "{:?}",
        resolver.resolve("www.metafilter.com".to_owned(), DnsType::TYPE_A as u16)
    );
}

#[test]
fn test_build_query() {
    let resolver = DNSResolver::new(None, None, DnsMode::UDP);
    let query = resolver.build_query("www.example.com".to_owned(), 1);
    let mut reader = DecodeHelper {
        buffer: query.clone(),
        pos: 0,
    };
    println!(
        "{:?}: {:?}",
        query,
        DNSPacket::parse(&mut reader, resolver.dns_mode)
    );
}

#[test]
fn test_build_query_tcp() {
    let resolver = DNSResolver::new(None, None, DnsMode::TCP);
    let query = resolver.build_query("www.example.com".to_owned(), 1);
    let mut reader = DecodeHelper {
        buffer: query.clone(),
        pos: 0,
    };
    println!("{:?}", query);
    println!(
        "{:?}: {:?}",
        query,
        DNSPacket::parse(&mut reader, resolver.dns_mode)
    );
}
