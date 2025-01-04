mod acas_card;
mod tlv_helpers;
mod tlv_packet;
mod encryption_flag;
mod ip_compressed_packet_header_type;
mod mmtp_payload_type;

use crate::acas_card::AcasCard;
use crate::tlv_helpers::find_tlv_header;
use crate::tlv_packet::TlvPacket;
use pcsc::*;

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: b61decoder <encryptedfile.mmts> <decryptedfile.mmts>");
        return Ok(());
    }

    let encrypted_file = &args[1];
    let decrypted_file = &args[2];

    let ctx = Context::establish(Scope::System)?;

    let readers = ctx.list_readers()?;
    if readers.is_empty() {
        eprintln!("No smartcard readers found.");
        return Ok(());
    }

    let iso_reader = ctx.connect(
        &readers[0],
        ShareMode::Shared,
        Protocols::ANY,
    )?;

    let acas_card = AcasCard::new(iso_reader);
    acas_card.init()?;

    let mut decrypted_ecm: Option<acas_card::DecryptedEcm> = None;
    let encrypted_data = std::fs::read(encrypted_file).expect("Unable to read file");
    let mut decrypted_data = Vec::new();

    let mut buffer = encrypted_data.as_slice();
    while !buffer.is_empty() {
        match find_tlv_header(buffer) {
            Some(tlv_header_index) => {
                let data_length = u16::from_be_bytes([buffer[tlv_header_index + 2], buffer[tlv_header_index + 3]]) as usize + 4;
                if data_length > buffer.len() - tlv_header_index {
                    break;
                }
                let tlv_packet = &buffer[tlv_header_index..tlv_header_index + data_length];
                buffer = &buffer[tlv_header_index + data_length..];

                let tlv = TlvPacket::new(tlv_packet.to_vec());
                let ecm = tlv.get_ecm();
                if let Some(ecm_bytes) = ecm {
                    decrypted_ecm = Some(acas_card.decrypt_ecm(&ecm_bytes)?);
                }
                let decrypted_tlv = tlv.get_decrypted_tlv(decrypted_ecm.as_ref());

                decrypted_data.extend_from_slice(&decrypted_tlv);
            },
            None => {
                break;
            }
        }
    }
    
    std::fs::write(decrypted_file, decrypted_data).expect("Unable to write file");
    Ok(())
}