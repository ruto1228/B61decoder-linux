#[derive(PartialEq, Debug)]
pub enum EncryptionFlag {
    Unscrambled = 0x00,
    Reserved = 0x01,
    Even = 0x02,
    Odd = 0x03,
}