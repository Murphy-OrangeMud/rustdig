# Rust dig
---------------------

A toy DNS server inspired by [DNS-in-a-weekend](https://implement-dns.wizardzines.com/) written in Rust.

### Test
Because the implementation utilizes Rust macros, the tests should only be started manually. `cargo test` will fail.

### Start
Just type `cargo run` to start!

### Features
- [x] Utilizes Rust macro to generate parsing function
- [x] Support IPv6
- [x] Support CName records
- [x] DNS Cache
- [x] Support commandline use
- [ ] Support EDNS0
- [ ] Support DNS over TCP
- [ ] Support DNS over TLS
- [ ] Support DNS over QUIC

