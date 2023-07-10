#![feature(array_chunks)]

use core::{panic};
use std::{string, io::{Write, Read, Bytes}, str::FromStr, net::UdpSocket};

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
    pub fn parse(mut encoded: Vec<u8>) -> (DNSQuestion, Vec<u8>) {
        let mut name: Vec<u8>;
        (name, encoded) = decode_name(encoded);
        let type_ = u16::from_be_bytes(*encoded[0..2].array_chunks::<2>().next().unwrap());
        let class = u16::from_be_bytes(*encoded[2..4].array_chunks::<2>().next().unwrap());
        (DNSQuestion{ name, type_, class, }, encoded[4..encoded.len()].to_vec())
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
    pub fn parse(mut encoded: Vec<u8>) -> (DNSRecord, Vec<u8>) {
        let mut name: Vec<u8>;
        (name, encoded) = decode_name(encoded);
        let mut data: Vec<u8>;
        let type_ = u16::from_be_bytes(*encoded[0..2].array_chunks::<2>().next().unwrap());
        let class = u16::from_be_bytes(*encoded[2..4].array_chunks::<2>().next().unwrap());
        let ttl = u32::from_be_bytes(*encoded[4..8].array_chunks::<4>().next().unwrap());
        let data_len = u16::from_be_bytes(*encoded[8..10].array_chunks::<2>().next().unwrap());
        // encoded = encoded[10..encoded.len()].to_vec();
        match num::FromPrimitive::from_u16(type_) {
            Some(DnsType::TYPE_NS) => {
                (data, _) = decode_name(encoded[10..encoded.len()].to_vec());
            }
            Some(DnsType::TYPE_A) => {
                data = encoded[10..10 + data_len as usize].to_vec()//.join(b"."); // IP addr
            }
            Some(DnsType::TYPE_TXT) => {
                data = encoded[10..10 + data_len as usize].to_vec()
            }
            _ => panic!("Wrong dns type: {type_}")
        }
        (DNSRecord { name, type_, class, ttl, data }, encoded[10..10 + data_len as usize].to_vec())
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
    pub fn parse(mut encoded: Vec<u8>) -> DNSPacket {
        let header: DNSHeader = DNSHeader::parse(encoded[0..12].to_vec());
        println!("{:?}", header);
        encoded = encoded[12..encoded.len()].to_vec();
        let mut questions = Vec::<DNSQuestion>::new();
        let mut answers = Vec::<DNSRecord>::new();
        let mut authorities = Vec::<DNSRecord>::new();
        let mut additionals = Vec::<DNSRecord>::new();
        for _ in 0..header.num_questions {
            let question: DNSQuestion;
            (question, encoded) = DNSQuestion::parse(encoded);
            println!("{:?}", question);
            questions.push(question);
        }
        for _ in 0..header.num_answers {
            let answer: DNSRecord;
            (answer, encoded) = DNSRecord::parse(encoded);
            answers.push(answer);
        }
        for _ in 0..header.num_authorities {
            let authority: DNSRecord;
            (authority, encoded) = DNSRecord::parse(encoded);
            authorities.push(authority);
        }
        for _ in 0..header.num_additionals {
            let additional: DNSRecord;
            (additional, encoded) = DNSRecord::parse(encoded);
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

fn decode_name(encoded: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut parts = Vec::<String>::new();
    let mut pos = 0;
    while pos < encoded.len() && encoded[pos] != (0 as u8) {
        if encoded[pos] & 192 != 0  {
            let pointer_bytes = [[encoded[pos] & 63], [encoded[pos + 1]]].concat();
            // let pointer = u16::from_be_bytes([[encoded[pos] & 63], [encoded[pos + 1]]].concat());

        } else {
            parts.push(std::str::from_utf8(&encoded[pos + 1..pos + 1 + encoded[pos] as usize]).unwrap().to_string());
            pos += (encoded[pos] + 1) as usize;
        }
    }
    (parts.join(".").as_bytes().to_vec(), encoded[pos + 1..encoded.len()].to_vec())
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
    println!("{:?}", buf);
    Ok(DNSPacket::parse(buf.to_vec()))
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

fn main() {
    println!("{:?}", build_query("google.com".to_owned(), DnsType::TYPE_A as u16));
}

#[test]
fn test_encode_dns_name() {
    println!("{:?}", ("google".as_bytes().len() as u8).to_be_bytes());
    println!("{:?}", encode_dns_name("google.com".to_owned()));
    assert_eq!(decode_name(encode_dns_name("google.com".to_owned())).0, "google.com".as_bytes())
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
    assert_eq!(DNSHeader::parse(header.to_bytes()), header);
}

#[test]
fn test_parse_question() {
    let name = encode_dns_name("www.example.com".to_owned());
    let question = DNSQuestion {
        name,
        type_: DnsType::TYPE_A as u16,
        class: CLASS_IN,
    };
    println!("{:?}", DNSQuestion::parse(question.to_bytes()).0);
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
    println!("{:?}", DNSRecord::parse([record.to_bytes(), (0 as u32).to_be_bytes().to_vec()].concat()).0);
}

#[test]
fn test_build_query() {
    let query = build_query("www.example.com".to_owned(), 1);
    println!("{:?}: {:?}", query.clone(), DNSPacket::parse(query));
}

#[test]
fn test_part1() {
    let packet = send_query("8.8.8.8:53".to_owned(), "www.example.com".to_owned(), DnsType::TYPE_A as u16).unwrap();
    println!("{:?}", packet);
}

