use pcsc::*;
use std::str;
use sha2::{Sha256, Digest};
use hex;
use aes::{Aes128, NewBlockCipher};
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use ctr::Ctr128BE;

type AesCtr128BE = Ctr128BE<Aes128>;

const MASTER_KEY: [u8; 32] = [
    0x4F, 0x4C, 0x7C, 0xEB, 0x34, 0xFE, 0xB0, 0xA3,
    0x1E, 0x41, 0x19, 0x51, 0xE1, 0x35, 0x15, 0x12,
    0x87, 0xD3, 0x3D, 0x33, 0xD4, 0x9B, 0x4F, 0x52,
    0x05, 0x77, 0xF9, 0xEF, 0xE5, 0x56, 0x1F, 0x32,
];

pub struct AcasCard {
    reader: CardReader,
}

impl AcasCard {
    pub fn new(reader: CardReader) -> Self {
        Self { reader }
    }

    pub fn init(&self) -> Result<(), Error> {
        let apdu = [0x90, 0x30, 0x00, 0x01, 0x00];
        let response = self.reader.transmit(&apdu)?;

        if response.len() < 2 || response[response.len() - 2] != 0x90 || response[response.len() - 1] != 0x00
        {
            return Err(Error::InvalidCard);
        }

        Ok(())
    }

   fn get_a0_auth_kcl(&self) -> Result<[u8; 32], Error> {
        let mut rng = rand::thread_rng();
        let mut a0init = [0u8; 8];
        rand::Rng::fill(&mut rng, &mut a0init);

        let mut apdu = vec![0x90, 0xA0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x8A, 0xF7];
        apdu.extend_from_slice(&a0init);

       let response = self.reader.transmit(&apdu)?;

       if response.len() < 2 || response[response.len() - 2] != 0x90 || response[response.len() - 1] != 0x00
       {
            return Err(Error::InvalidCard);
       }


        let a0data = &response[..];
        let a0response = &a0data[6..14];
        let a0hash = &a0data[14..];

        let mut kcl_hasher = Sha256::new();
        kcl_hasher.update(&MASTER_KEY);
        kcl_hasher.update(&a0init);
        kcl_hasher.update(a0response);
        let kcl: [u8; 32] = kcl_hasher.finalize().into();


        let mut hash_hasher = Sha256::new();
        hash_hasher.update(&kcl);
        hash_hasher.update(&a0init);
        let hash = hash_hasher.finalize();

        if !hash.as_slice().eq(a0hash) {
            return Err(Error::InvalidCard);
        }
        Ok(kcl)
   }
    pub fn decrypt_ecm(&self, ecm: &[u8]) -> Result<DecryptedEcm, Error> {
        let kcl = self.get_a0_auth_kcl()?;

        let mut apdu = vec![0x90, 0x34, 0x00, 0x01];
        apdu.extend_from_slice(ecm);
        apdu.push(0x00);

       let response = self.reader.transmit(&apdu)?;

        if response.len() < 2 || response[response.len() - 2] != 0x90 || response[response.len() - 1] != 0x00 || ecm.len() != 148
        {
            return Err(Error::InvalidCard);
        }

        let ecm_data = &response[..];
        let ecm_response = &ecm_data[6..];

        let ecm_init = &ecm[4..27];

       let mut hash_hasher = Sha256::new();
       hash_hasher.update(kcl);
       hash_hasher.update(ecm_init);
       let mut hash = hash_hasher.finalize().to_vec();

        for i in 0..hash.len() {
            hash[i] ^= ecm_response[i];
        }
        
        let odd: [u8; 16] = hash[..16].try_into().unwrap();
        let even: [u8; 16] = hash[16..].try_into().unwrap();

        println!("ECM: Odd {} Even {}", hex::encode(odd), hex::encode(even));
        Ok(DecryptedEcm { odd, even })
    }
}

#[derive(Debug)]
pub struct DecryptedEcm {
    pub odd: [u8; 16],
    pub even: [u8; 16],
}