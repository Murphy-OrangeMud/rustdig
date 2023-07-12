#![feature(array_chunks)]

use core::{panic};
use std::{string, io::{Write, Read, Bytes, BufReader}, str::FromStr, net::UdpSocket};

use dns_weekend::{Serializer, Deserializer};
use rand::prelude::*;
use std::io::Result;

use std::net::{IpAddr, SocketAddr, TcpStream};

extern crate num;
#[macro_use]
extern crate num_derive;

#[derive(Serializer, Deserializer, Debug, PartialEq)]
struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

#[derive(Clone, Serializer, Debug, PartialEq)]
struct DNSQuestion {
    name: Vec<u8>,
    type_: u16,
    class: u16,
}

impl DNSQuestion {
    pub fn parse(reader: &mut DecodeHelper) -> DNSQuestion {
        let mut name = decode_name(reader);
        let type_ = u16::from_be_bytes(*reader.buffer[reader.pos..reader.pos + 2].array_chunks::<2>().next().unwrap());
        let class = u16::from_be_bytes(*reader.buffer[reader.pos + 2..reader.pos + 4].array_chunks::<2>().next().unwrap());
        reader.pos += 4 as usize;
        DNSQuestion{ name, type_, class, }
    }
}

#[derive(Debug, Serializer, PartialEq)]
struct DNSRecord {
    name: Vec<u8>,
    type_: u16,
    class: u16,
    ttl: u32,
    data: Vec<u8>,
}

impl DNSRecord {
    pub fn parse(reader: &mut DecodeHelper) -> DNSRecord {
        let mut name = decode_name(reader);
        let mut data: Vec<u8>;
        let type_ = u16::from_be_bytes(*reader.buffer[reader.pos..reader.pos + 2].array_chunks::<2>().next().unwrap());
        let class = u16::from_be_bytes(*reader.buffer[reader.pos + 2..reader.pos + 4].array_chunks::<2>().next().unwrap());
        let ttl = u32::from_be_bytes(*reader.buffer[reader.pos + 4..reader.pos + 8].array_chunks::<4>().next().unwrap());
        let data_len = u16::from_be_bytes(*reader.buffer[reader.pos + 8..reader.pos + 10].array_chunks::<2>().next().unwrap());
        reader.pos += 10;
        // encoded = encoded[10..encoded.len()].to_vec();
        match num::FromPrimitive::from_u16(type_) {
            Some(DnsType::TYPE_NS) => {
                data = decode_name(reader);
            }
            Some(DnsType::TYPE_A) => {
                data = reader.buffer[reader.pos..reader.pos + data_len as usize].to_vec();//.join(b"."); // IP addr
                reader.pos += data_len as usize;
            }
            Some(DnsType::TYPE_TXT) => {
                data = reader.buffer[reader.pos..reader.pos + data_len as usize].to_vec();
                reader.pos += data_len as usize;
            }
            _ => panic!("Wrong dns type: {type_}")
        }
        DNSRecord { name, type_, class, ttl, data }
    }
}

#[derive(Debug, PartialEq)]
struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>,
}

impl DNSPacket {
    pub fn parse(reader: &mut DecodeHelper) -> DNSPacket {
        let header: DNSHeader = DNSHeader::parse(reader);
        let mut questions = Vec::<DNSQuestion>::new();
        let mut answers = Vec::<DNSRecord>::new();
        let mut authorities = Vec::<DNSRecord>::new();
        let mut additionals = Vec::<DNSRecord>::new();
        for _ in 0..header.num_questions {
            let question = DNSQuestion::parse(reader);
            questions.push(question);
        }
        for _ in 0..header.num_answers {
            let answer = DNSRecord::parse(reader);
            answers.push(answer);
        }
        for _ in 0..header.num_authorities {
            let authority = DNSRecord::parse(reader);
            authorities.push(authority);
        }
        for _ in 0..header.num_additionals {
            let additional = DNSRecord::parse(reader);
            additionals.push(additional);
        }
        DNSPacket { header, questions, answers, authorities, additionals }
    }

    fn get_answer(&self) -> Option<Vec<u8>> {
        for answer in &self.answers {
            if answer.type_ == DnsType::TYPE_A as u16 {
                return Some(answer.data.clone())
            }
        }
        None
    }

    fn get_nameserver_ip(&self) -> Option<Vec<u8>> {
        for answer in &self.additionals {
            if answer.type_ == DnsType::TYPE_A as u16 {
                return Some(answer.data.clone())
            }
        }
        None
    }

    fn get_nameserver(&self) -> Option<Vec<u8>> {
        for answer in &self.authorities {
            if answer.type_ == DnsType::TYPE_NS as u16 {
                return Some(std::str::from_utf8(answer.data.as_slice()).unwrap().as_bytes().to_vec())
            }
        }
        None
    }
}

struct DecodeHelper {
    buffer: Vec<u8>,
    pos: usize,
}

fn decode_name(reader: &mut DecodeHelper) -> Vec<u8> {
    let mut parts = Vec::<String>::new();
    loop {
        let length = reader.buffer[reader.pos];
        reader.pos += 1 as usize;
        if length == 0 {
            break;
        }
        if length & 0b1100_0000 != 0 {
            parts.push(std::str::from_utf8(decode_compressed_name(length, reader).as_slice()).unwrap().to_string());
            break;
        } else {
            reader.pos += length as usize;
            parts.push(std::str::from_utf8(&reader.buffer[reader.pos - length as usize..reader.pos]).unwrap().to_string());
        }
    }
    parts.join(".").as_bytes().to_vec()
}

fn decode_compressed_name(length: u8, reader: &mut DecodeHelper) -> Vec<u8> {
    let pointer_bytes = [[length & 0b0011_1111], [reader.buffer[reader.pos]]].concat();
    reader.pos += 1;
    let pointer = u16::from_be_bytes(*pointer_bytes.array_chunks::<2>().next().unwrap());
    let current_pos = reader.pos;
    reader.pos = pointer as usize;
    let result = decode_name(reader);
    reader.pos = current_pos;
    result
}

fn encode_dns_name(domain_name: String) -> Vec<u8> {
    let mut encoded = Vec::new();
    for part in domain_name.split('.') {
        encoded = [encoded, (part.len() as u8).to_be_bytes().to_vec(), part.to_ascii_lowercase().as_bytes().to_owned()].concat()
    }
    [encoded, (0 as u8).to_be_bytes().to_vec()].concat()
}

const RECURSION_DESIRED: u16 = 1 << 8;
const CLASS_IN: u16 = 1;


#[derive(FromPrimitive)]
enum DnsType {
    TYPE_A = 1,
    TYPE_NS = 2,
    TYPE_TXT = 16,
}

fn build_query(domain_name: String, record_type: u16) -> Vec<u8> {
    let name = encode_dns_name(domain_name);
    let id: u16 = random();
    let header = DNSHeader {
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
    return [header.to_bytes(), question.to_bytes()].concat()
}

fn send_query(ip_address: String, domain_name: String, record_type: u16) -> Result<DNSPacket> {
    let query = build_query(domain_name, record_type);
    let socket = UdpSocket::bind("0.0.0.0:8964").expect("Bind failed"); // TODO: Why is 127.0.0.1 not working
    socket.send_to(query.as_slice(), ip_address).expect("Send failed");
    let mut buf = [0 as u8; 1024];
    socket.recv_from(&mut buf).expect("Receive failed");
    let mut reader = DecodeHelper {
        buffer: buf.to_vec(),
        pos: 0,
    };
    Ok(DNSPacket::parse(&mut reader))
}

fn resolve(domain_name: String, record_type: u16) -> Vec<u8> {
    let mut nameserver_ip = "198.41.0.4".to_string();
    loop {
        println!("querying {nameserver_ip} for {domain_name}");
        let resp = send_query(nameserver_ip.clone(), domain_name.clone(), record_type).unwrap();
        if let Some(ip) = resp.get_answer() {
            return ip
        } else if let Some(nsIP) = resp.get_nameserver_ip() {
            nameserver_ip = std::str::from_utf8(nsIP.as_slice()).unwrap().to_string();
        } else if let Some(ns_domain) = resp.get_nameserver() {
            nameserver_ip = std::str::from_utf8(resolve(std::str::from_utf8(ns_domain.as_slice()).unwrap().to_string(), DnsType::TYPE_A as u16).as_slice()).unwrap().to_string()
        } else {
            panic!("Something went wrong");
        }
    }
}

fn ip_to_string(ip: &Vec<u8>) -> String {
    let mut nip = String::new();
    for byte in ip {
        nip += &byte.to_string();
        nip += ".";
    }
    nip.strip_suffix(".").unwrap().to_string()
}

fn lookup_domain(domain_name: String) -> String {
    let packet = send_query("8.8.8.8:53".to_owned(), domain_name, DnsType::TYPE_A as u16).expect("Send query failed");
    ip_to_string(&packet.answers[0].data)
}

fn main() {
    println!("{:?}", build_query("google.com".to_owned(), DnsType::TYPE_A as u16));
}

#[test]
fn test_encode_dns_name() {
    println!("{:?}", ("google".as_bytes().len() as u8).to_be_bytes());
    println!("{:?}", encode_dns_name("google.com".to_owned()));
    assert_eq!(decode_name(&mut DecodeHelper{buffer:encode_dns_name("google.com".to_owned()), pos:0}), "google.com".as_bytes())
}

#[test]
fn test_parse_header() {
    let header = DNSHeader {
        id: 1,
        flags: RECURSION_DESIRED,
        num_questions: 1,
        num_answers: 0,
        num_authorities: 0,
        num_additionals: 0,
    };
    let mut reader = DecodeHelper {
        buffer: header.to_bytes(),
        pos: 0,
    };
    assert_eq!(DNSHeader::parse(&mut reader), header);
}

#[test]
fn test_parse_question() {
    let name = encode_dns_name("www.example.com".to_owned());
    let question = DNSQuestion {
        name,
        type_: DnsType::TYPE_A as u16,
        class: CLASS_IN,
    };
    let mut reader = DecodeHelper {
        buffer: question.to_bytes(),
        pos: 0,
    };
    println!("{:?}", DNSQuestion::parse(&mut reader));
}

#[test]
fn test_parse_record() {
    let name = encode_dns_name("www.example.com".to_owned());
    let record = DNSRecord {
        name,
        type_: DnsType::TYPE_A as u16,
        class: CLASS_IN,
        ttl: 1,
        data: Vec::<u8>::new(),
    };
    let mut reader = DecodeHelper {
        buffer: [record.to_bytes(), (0 as u32).to_be_bytes().to_vec()].concat(),
        pos: 0,
    };
    println!("{:?}", DNSRecord::parse(&mut reader));
}

#[test]
fn test_build_query() {
    let query = build_query("www.example.com".to_owned(), 1);
    let mut reader = DecodeHelper {
        buffer: query.clone(),
        pos: 0,
    };
    println!("{:?}: {:?}", query, DNSPacket::parse(&mut reader));
}

#[test]
fn test_part1() {
    let packet = send_query("8.8.8.8:53".to_owned(), "www.example.com".to_owned(), DnsType::TYPE_A as u16).unwrap();
    println!("{:?}", packet);
}

#[test]
fn test_lookup_domain() {
    println!("{:?}", lookup_domain("google.com".to_owned()));
}

