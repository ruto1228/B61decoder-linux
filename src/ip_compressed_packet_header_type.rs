#[derive(PartialEq, Debug)]
pub enum IpCompressedPacketHeaderType {
    PartialIPv4Header = 0x20,
    IPv4Header = 0x21,
    PartialIPv6Header = 0x60,
    NoCompressedHeader = 0x61,
}