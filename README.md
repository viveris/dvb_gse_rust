# dvb_gse_rust


## Name
GSE encapsulation/decapsulation crate in RUST

## Description
Crate in RUST for the encapsulation and decapsulation of GSE packets. 

## Usage
This crate is intended for the encapsulation and decapsulation of network layer data (IP for example) in the physical layer (DVB-S2 for example) using Generic Stream Encapsulation protocol.
The encap function allows to encapsulate a new payload in a packet. 
The decap function allows to obtain the payload from a packet.

## Content
This crate is composed of serval modules:
- `gse_encap` contains the structures and functions used for GSE encapsulation
- `gse_decap` contains the structures and functions used for GSE decapsulation
- `crc`, `gse_standard`, `pkt_type` contains the common functions and structures
- `utils` contains tool functions

Each of these modules is tested individually in their respective `tests.rs` file and functionally tested in `test_end_to_end.rs`.

## Example
See [lib.rs](src/lib.rs).

## Tests
Tests can be found in the [tests](tests) repository. Launch them using `cargo test`.

## Documentation
Documentation can be generated using `cargo doc`. You can access it by loading `/target/doc/index.html` in your browser.
