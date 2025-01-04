use crate::encryption_flag::EncryptionFlag;
use crate::ip_compressed_packet_header_type::IpCompressedPacketHeaderType;
use crate::mmtp_payload_type::MmtpPayloadType;
use crate::acas_card::DecryptedEcm;

use byteorder::{BigEndian, ReadBytesExt};
use aes::{Aes128, NewBlockCipher};
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use ctr::Ctr128BE;

type AesCtr128BE = Ctr128BE<Aes128>;

pub struct TlvPacket {
    data: Vec<u8>,
}

impl TlvPacket {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    
     pub fn get_ecm(&self) -> Option<Vec<u8>> {
        let ecm_header: [u8; 6] = [0x00, 0x00, 0x93, 0x2D, 0x1E, 0x01];
         if let Some(ecm_header_index) = self.data.windows(ecm_header.len()).position(|window| window == ecm_header)
        {
             return Some(self.data[ecm_header_index + 2..ecm_header_index+ 150].to_vec());
         }
        None
    }

      fn tlv_packet_type(&self) -> TlvPacketType {
          match self.data[1] {
            0x00 => TlvPacketType::Undefined,
            0x01 => TlvPacketType::IPv4,
            0x02 => TlvPacketType::IPv6,
            0x03 => TlvPacketType::HeaderCompressed,
            0xFE => TlvPacketType::TransmissionControlSignalPacket,
            0xFF => TlvPacketType::NullPacket,
            _=> TlvPacketType::Undefined
          }
    }
     fn mmtp_header_type(&self) -> u8
    {
      self.data[6]
     }

     fn get_mmtp_packet(&self) -> MmtpPacket
    {
       if self.mmtp_header_type() == IpCompressedPacketHeaderType::NoCompressedHeader as u8
       {
         let mmtp_data = &self.data[7..];

        return MmtpPacket { data: mmtp_data.to_vec() };
    }
       if self.mmtp_header_type() == IpCompressedPacketHeaderType::PartialIPv6Header as u8
    {
        let mmtp_data = &self.data[49..];

          return MmtpPacket { data: mmtp_data.to_vec()};
    }
        panic!("Unknown Mmtp Header type")
    }
    fn get_tlv_and_mmtp_header(&self) -> Vec<u8>{
        if self.mmtp_header_type() == IpCompressedPacketHeaderType::NoCompressedHeader as u8
        {
             return self.data[..7].to_vec();
        }
        if self.mmtp_header_type() == IpCompressedPacketHeaderType::PartialIPv6Header as u8
        {
           return self.data[..49].to_vec();
         }

        panic!("Unknown Mmtp Header type")
    }
     pub fn get_decrypted_tlv(&self, decrypted_ecm: Option<&DecryptedEcm>) -> Vec<u8>
     {
         if self.tlv_packet_type() != TlvPacketType::HeaderCompressed {
            return vec![];
        }
         let mmtp_packet = self.get_mmtp_packet();

       if mmtp_packet.get_encryption_flag() == EncryptionFlag::Unscrambled
       {
           return self.data.to_vec();
       }
        
       let decrypted_ecm_data = match decrypted_ecm
        {
           Some(d)=>d,
           None => return vec![],
        };
       if mmtp_packet.payload_type() != MmtpPayloadType::MPU{
          panic!("Non MPU packet found");
       }
      
       let tlv_and_mmtp_header = self.get_tlv_and_mmtp_header();
        let decrypted_mmts_packet = mmtp_packet.get_decrypted_mmts(decrypted_ecm_data);
         let mut decrypted_tlv = tlv_and_mmtp_header;
         decrypted_tlv.extend_from_slice(&decrypted_mmts_packet);
         
        return decrypted_tlv;
     }
}

struct MmtpPacket {
   data: Vec<u8>,
}
    
 impl MmtpPacket {
    fn get_encryption_flag(&self) -> EncryptionFlag
    {
        let has_extension_flag = (self.data[0] & 0b00000010) > 0;
         if !has_extension_flag
        {
           return EncryptionFlag::Unscrambled;
        }
        let header_extension_type = u16::from_be_bytes([self.data[16], self.data[17]]);
         if (header_extension_type & 0x7FFF) == 0x0001
        {
             let extension_length = u16::from_be_bytes([self.data[18],self.data[19]]);
             if  extension_length != 1
            {
             panic!("Extension of unknown length");
           }
             return match (self.data[20] & 0b00011000) >> 3 {
                0x00 => EncryptionFlag::Unscrambled,
                0x01 => EncryptionFlag::Reserved,
                0x02 => EncryptionFlag::Even,
                0x03 => EncryptionFlag::Odd,
                _=> EncryptionFlag::Unscrambled
             };
            }
        return EncryptionFlag::Unscrambled;
       }
       fn payload_type(&self) -> MmtpPayloadType
    {
        match (self.data[1] & 0b00111111)
          {
               0x00 => MmtpPayloadType::MPU,
               0x01 => MmtpPayloadType::GenericObject,
               0x02 => MmtpPayloadType::ControlMessage,
               0x03 => MmtpPayloadType::RepairSymbol,
               _ => panic!("Unknown Mmtp Payload type")
           }
    }
       fn get_decrypted_mmts(&self, decrypted_ecm: &DecryptedEcm)-> Vec<u8>
    {
        let has_packet_counter_flag = (self.data[0] & 0b00100000) > 0;
            if has_packet_counter_flag
            {
                panic!("Has packet counter flag");
            }
         let key = match self.get_encryption_flag()
        {
            EncryptionFlag::Odd => &decrypted_ecm.odd,
            EncryptionFlag::Even => &decrypted_ecm.even,
            _ => panic!("Encryption flag reserved"),
        };

       let scrambling_initial_counter_value = self.data[20] & 0b00000001;
        if scrambling_initial_counter_value > 0
        {
            panic!("SICV not implemented");
        }

         let message_authentication_control = (self.data[20] & 0b00000010) >> 1;
         if message_authentication_control > 0
         {
             panic!("MAC not implemented");
        }
         let packet_id: [u8; 2] = self.data[2..4].try_into().unwrap();
         let packet_sequence_number: [u8; 4] = self.data[8..12].try_into().unwrap();
         let iv: [u8; 16] = [
             packet_id[0],
             packet_id[1],
             packet_sequence_number[0],
             packet_sequence_number[1],
             packet_sequence_number[2],
             packet_sequence_number[3],
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
         ];

         let payload = if (self.data[0] & 0b00000010) > 0
         {
            let extension_length = u16::from_be_bytes([self.data[18],self.data[19]]);
             &self.data[20 + extension_length + 4..]
         }
        else
        {
           &self.data[12..]
         };
          let cipher = AesCtr128BE::new_from_slices(key, &iv).expect("Invalid key or IV");
         let mut decrypted_payload = payload[8..].to_vec();
          cipher.decrypt_blocks_mut(unsafe { std::slice::from_raw_parts_mut(decrypted_payload.as_mut_ptr() as *mut ctr::Block<Aes128>, decrypted_payload.len() / 16) });

          let mut decrypted_mmts = self.data[..20].to_vec();
          decrypted_mmts.push((self.data[20] & 0b11100011));

        if (self.data[0] & 0b00000010) > 0
         {
            decrypted_mmts.extend_from_slice(&self.data[21..(20 + u16::from_be_bytes([self.data[18],self.data[19]]) as usize)]);
        }
          decrypted_mmts.extend_from_slice(&decrypted_payload);
       return decrypted_mmts;
   }
 }