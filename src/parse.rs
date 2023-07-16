use crate::*;
use rsdig::{Deserializer, Serializer};

#[derive(Serializer, Deserializer, Debug, PartialEq)]
pub struct DNSHeader {
    // for tcp
    // pub length: Option<u16>,

    pub id: u16,
    pub flags: u16,
    pub num_questions: u16,
    pub num_answers: u16,
    pub num_authorities: u16,
    pub num_additionals: u16,
}

#[derive(Clone, Serializer, Debug, PartialEq)]
pub struct DNSQuestion {
    pub name: Vec<u8>,
    pub type_: u16,
    pub class: u16,
}

impl DNSQuestion {
    pub fn parse(reader: &mut DecodeHelper) -> DNSQuestion {
        let mut name = reader.decode_name();
        let type_ = u16::from_be_bytes(
            *reader.buffer[reader.pos..reader.pos + 2]
                .array_chunks::<2>()
                .next()
                .unwrap(),
        );
        let class = u16::from_be_bytes(
            *reader.buffer[reader.pos + 2..reader.pos + 4]
                .array_chunks::<2>()
                .next()
                .unwrap(),
        );
        reader.pos += 4 as usize;
        DNSQuestion { name, type_, class }
    }
}

#[derive(Debug, Serializer, PartialEq)]
pub struct DNSRecord {
    pub name: Vec<u8>,
    pub type_: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl DNSRecord {
    pub fn parse(reader: &mut DecodeHelper) -> DNSRecord {
        let mut name = reader.decode_name();
        let mut data: Vec<u8>;
        let type_ = u16::from_be_bytes(
            *reader.buffer[reader.pos..reader.pos + 2]
                .array_chunks::<2>()
                .next()
                .unwrap(),
        );
        let class = u16::from_be_bytes(
            *reader.buffer[reader.pos + 2..reader.pos + 4]
                .array_chunks::<2>()
                .next()
                .unwrap(),
        );
        let ttl = u32::from_be_bytes(
            *reader.buffer[reader.pos + 4..reader.pos + 8]
                .array_chunks::<4>()
                .next()
                .unwrap(),
        );
        let data_len = u16::from_be_bytes(
            *reader.buffer[reader.pos + 8..reader.pos + 10]
                .array_chunks::<2>()
                .next()
                .unwrap(),
        );
        reader.pos += 10;
        // encoded = encoded[10..encoded.len()].to_vec();
        match num::FromPrimitive::from_u16(type_) {
            Some(DnsType::TYPE_NS) => {
                data = reader.decode_name();
            }
            Some(DnsType::TYPE_A) => {
                data = reader.buffer[reader.pos..reader.pos + data_len as usize].to_vec(); //.join(b"."); // IP addr
                reader.pos += data_len as usize;
            }
            Some(DnsType::TYPE_TXT) => {
                data = reader.buffer[reader.pos..reader.pos + data_len as usize].to_vec();
                reader.pos += data_len as usize;
            }
            Some(DnsType::TYPE_AAAA) => {
                data = reader.buffer[reader.pos..reader.pos + data_len as usize].to_vec();
                reader.pos += data_len as usize;
            }
            Some(DnsType::TYPE_CNAME) => {
                data = reader.decode_name();
                // data = reader.buffer[reader.pos..reader.pos + data_len as usize].to_vec();
                // reader.pos += data_len as usize;
            }
            _ => panic!("Wrong dns type: {type_}"),
        }
        DNSRecord {
            name,
            type_,
            class,
            ttl,
            data,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>,
}

impl DNSPacket {
    pub fn parse(reader: &mut DecodeHelper, dns_mode: DnsMode) -> DNSPacket {
        let header: DNSHeader = DNSHeader::parse(reader, dns_mode);
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
        DNSPacket {
            header,
            questions,
            answers,
            authorities,
            additionals,
        }
    }

    pub fn get_answer(&self, name: Option<String>) -> Option<Vec<u8>> {
        for answer in &self.answers {
            if answer.type_ == DnsType::TYPE_A as u16 || answer.type_ == DnsType::TYPE_AAAA as u16 {
                return Some(answer.data.clone());
            }
        }
        None
    }

    pub fn get_nameserver_ip(&self) -> Option<Vec<u8>> {
        for answer in &self.additionals {
            if answer.type_ == DnsType::TYPE_A as u16 || answer.type_ == DnsType::TYPE_AAAA as u16 {
                return Some(answer.data.clone());
            }
        }
        None
    }

    pub fn get_nameserver(&self) -> Option<Vec<u8>> {
        for answer in &self.authorities {
            if answer.type_ == DnsType::TYPE_NS as u16 {
                return Some(
                    std::str::from_utf8(answer.data.as_slice())
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                );
            }
        }
        None
    }

    pub fn get_cname(&self) -> Option<Vec<u8>> {
        for answer in &self.answers {
            if answer.type_ == DnsType::TYPE_CNAME as u16 {
                return Some(answer.data.clone());
            }
        }
        None
    }
}

#[test]
fn test_parse_header() {
    let header = DNSHeader {
        //length: None,

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
    assert_eq!(DNSHeader::parse(&mut reader, DnsMode::UDP), header);
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

