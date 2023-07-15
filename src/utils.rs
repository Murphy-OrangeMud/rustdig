use crate::*;
pub struct DecodeHelper {
    pub buffer: Vec<u8>,
    pub pos: usize,
}

impl DecodeHelper {
    pub fn decode_name(&mut self) -> Vec<u8> {
        let mut parts = Vec::<String>::new();
        loop {
            let length = self.buffer[self.pos];
            self.pos += 1 as usize;
            if length == 0 {
                break;
            }
            if length & 0b1100_0000 != 0 {
                parts.push(
                    std::str::from_utf8(self.decode_compressed_name(length).as_slice())
                        .unwrap()
                        .to_string(),
                );
                break;
            } else {
                self.pos += length as usize;
                parts.push(
                    std::str::from_utf8(&self.buffer[self.pos - length as usize..self.pos])
                        .unwrap()
                        .to_string(),
                );
            }
        }
        parts.join(".").as_bytes().to_vec()
    }

    fn decode_compressed_name(&mut self, length: u8) -> Vec<u8> {
        let pointer_bytes = [[length & 0b0011_1111], [self.buffer[self.pos]]].concat();
        self.pos += 1;
        let pointer = u16::from_be_bytes(*pointer_bytes.array_chunks::<2>().next().unwrap());
        let current_pos = self.pos;
        self.pos = pointer as usize;
        let result = self.decode_name();
        self.pos = current_pos;
        result
    }
}

pub fn encode_dns_name(domain_name: String) -> Vec<u8> {
    let mut encoded = Vec::new();
    for part in domain_name.split('.') {
        encoded = [
            encoded,
            (part.len() as u8).to_be_bytes().to_vec(),
            part.to_ascii_lowercase().as_bytes().to_owned(),
        ]
        .concat()
    }
    [encoded, (0 as u8).to_be_bytes().to_vec()].concat()
}

pub fn ip_to_string(ip: &Vec<u8>) -> String {
    let mut nip = String::new();
    if ip.len() == 4 {
        for byte in ip {
            nip += &byte.to_string();
            nip += ".";
        }
        nip.strip_suffix(".").unwrap().to_string()
    } else {
        let mut bytes = ip.array_chunks::<2>();
        while let Some(slice) = bytes.next() {
            nip += &format!("{:x}", u16::from_be_bytes(*slice));
            nip += ":";
        }
        nip.strip_suffix(":").unwrap().to_string()
    }
}

pub fn build_query(domain_name: String, record_type: u16) -> Vec<u8> {
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
    return [header.to_bytes(), question.to_bytes()].concat();
}

pub fn lookup_domain(domain_name: String) -> String {
    // let packet = resolve(domain_name, DnsType::TYPE_A as u16);
    let packet = DNSResolver::new(None, DnsMode::UDP).send_query("8.8.8.8:53".to_owned(), domain_name, DnsType::TYPE_A as u16)
        .expect("Send query failed");
    ip_to_string(&packet.answers[0].data)
}

#[test]
fn test_encode_dns_name() {
    println!("{:?}", ("google".as_bytes().len() as u8).to_be_bytes());
    println!("{:?}", encode_dns_name("google.com".to_owned()));
    let mut reader = DecodeHelper {
        buffer: encode_dns_name("google.com".to_owned()),
        pos: 0
    };
    assert_eq!(
        reader.decode_name(),
        "google.com".as_bytes()
    )
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
fn test_lookup_domain() {
    println!("{:?}", lookup_domain("google.com".to_owned()));
    println!("{:?}", lookup_domain("example.com".to_owned()));
    println!("{:?}", lookup_domain("recurse.com".to_owned()));
    println!("{:?}", lookup_domain("metafilter.com".to_owned()));
    println!("{:?}", lookup_domain("www.metafilter.com".to_owned()));
    println!("{:?}", lookup_domain("www.facebook.com".to_owned()));
}
