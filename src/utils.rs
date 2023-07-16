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

pub fn lookup_domain(domain_name: String) -> String {
    // let packet = resolve(domain_name, DnsType::TYPE_A as u16);
    let packet = DNSResolver::new(None, DnsMode::UDP)
        .send_query("8.8.8.8".to_owned(), domain_name, DnsType::TYPE_A as u16)
        .expect("Send query failed");
    ip_to_string(&packet.answers[0].data)
}

#[test]
fn test_encode_dns_name() {
    println!("{:?}", ("google".as_bytes().len() as u8).to_be_bytes());
    println!("{:?}", encode_dns_name("google.com".to_owned()));
    let mut reader = DecodeHelper {
        buffer: encode_dns_name("google.com".to_owned()),
        pos: 0,
    };
    assert_eq!(reader.decode_name(), "google.com".as_bytes())
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
