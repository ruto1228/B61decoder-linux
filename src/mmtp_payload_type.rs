#[derive(PartialEq, Debug)]
pub enum MmtpPayloadType {
    MPU = 0x00,
    GenericObject = 0x01,
    ControlMessage = 0x02,
    RepairSymbol = 0x03,
}