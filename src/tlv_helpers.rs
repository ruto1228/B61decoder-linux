use crate::tlv_packet::TlvPacketType;

pub fn find_tlv_header(bytes: &[u8]) -> Option<usize> {
    for i in 0..bytes.len() - 1 {
        if bytes[i] == 0x7F && (bytes[i+1] == TlvPacketType::Undefined as u8 || bytes[i+1] == TlvPacketType::HeaderCompressed as u8 || bytes[i+1] == TlvPacketType::IPv4 as u8 || bytes[i+1] == TlvPacketType::IPv6 as u8 || bytes[i+1] == TlvPacketType::NullPacket as u8 || bytes[i+1] == TlvPacketType::TransmissionControlSignalPacket as u8)
        {
            return Some(i);
        }
    }
    None
}

pub fn is_valid_tlv_header(bytes: &[u8]) -> bool {
   bytes[0] == 0x7F
   && match bytes[1] {
       0x00 | 0x03 | 0x01 | 0x02 | 0xFF | 0xFE => true,
       _ => false,
       
   }
}