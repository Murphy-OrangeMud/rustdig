#![feature(array_chunks)]
#![feature(duration_constants)]

use std::str::FromStr;

use rand::prelude::*;
use rsdig::{Deserializer, Serializer};
use std::collections::HashMap;
use std::io::Result;

use clap::{arg, Command, Arg, ArgAction};
use std::net::{IpAddr, Ipv6Addr, UdpSocket};
use std::process::exit;
use std::time::{Duration, Instant};

extern crate num;
#[macro_use]
extern crate num_derive;

pub mod parse;
pub mod resolver;
pub mod utils;

use crate::parse::*;
use crate::resolver::*;
use crate::utils::*;

const RECURSION_DESIRED: u16 = 1 << 8;
const CLASS_IN: u16 = 1;

#[derive(FromPrimitive)]
pub enum DnsType {
    TYPE_A = 1,
    TYPE_NS = 2,
    TYPE_CNAME = 5,
    TYPE_TXT = 16,
    TYPE_AAAA = 28,
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum DnsMode {
    UDP = 0,
    TCP = 1,
    TLS = 2,
    QUIC = 3,
}

fn main() {
    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .disable_help_subcommand(true)
        .args(
            [
                arg!(-n --domain_name <DOMAIN_NAME> "The domain name you want to lookup"),
                arg!(-s --server_ip <IPADDR> "The IP address and port you want to listen on"),
                arg!(-d --dns_server <DNS_SERVER> "The dns server to be sent query, default 198.41.0.4"),
                Arg::new("tcp").long("tcp").action(ArgAction::SetTrue),
                Arg::new("tls").long("tls").action(ArgAction::SetTrue),
                Arg::new("quic").long("quic").action(ArgAction::SetTrue),
                // arg!(-f --file_path <FILE_PATH> "The file path with dns server listed"),
            ]
        )
        .get_matches();

    let domain_name = matches.get_one::<String>("domain_name");
    let server_ip = matches.get_one::<String>("server_ip");
    let dns_server = matches.get_one::<String>("dns_server");
    let tcp_mode = matches.get_flag("tcp");
    let tls_mode = matches.get_flag("tls");
    let quic_mode = matches.get_flag("quic");

    let dns_mode: DnsMode = 
    if quic_mode {
        DnsMode::QUIC
    } else if tls_mode {
        DnsMode::TLS
    } else if tcp_mode {
        DnsMode::TCP
    } else {
        DnsMode::UDP
    };

    if domain_name.is_none() && server_ip.is_none() {
        eprintln!(
            "Error: you must specify one of domain_name (for dig) and server ip (for server mode)"
        );
        exit(1);
    } else if domain_name.is_some() {
        let mut resolver = DNSResolver::new(dns_server, dns_mode);
        println!(
            "{}",
            resolver.resolve(domain_name.unwrap().to_owned(), DnsType::TYPE_A as u16)
        );
        println!(
            "{}",
            resolver.resolve(domain_name.unwrap().to_owned(), DnsType::TYPE_AAAA as u16)
        );
    } else {
    }
}
