# Rust dig

A DNS query tool like dig inspired by [DNS-in-a-weekend](https://implement-dns.wizardzines.com/) written in Rust.

### Test
Because the implementation utilizes Rust macros, the tests should only be started manually. `cargo test` will fail.

### Start
Just type `cargo run` to start, add --name flag to specify the domain name you want to look up.

### Features
- [x] Utilizes Rust macro to generate parsing function
- [x] Support IPv6
- [x] Support CName records
- [x] DNS Cache
- [x] Support commandline use
- [ ] Support EDNS0
- [x] Support DNS over TCP
- [ ] Support DNS over TLS
- [ ] Support DNS over QUIC
- [ ] DNS Server
  - [ ] DNS over TCP
  - [ ] DNS over TLS
  - [ ] DNS over QUIC

