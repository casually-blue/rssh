use crate::encryption::Cipher;
use crate::mac::Mac;

pub struct Packet {
    payload: Vec<u8>,
    mac_type: Mac,
    encryption_cipher: Box<dyn Cipher>,
}

impl Packet {
    pub fn new(payload: Vec<u8>, mac_type: Mac, cipher: Box<dyn Cipher>) -> Self {
        Packet {
            payload,
            mac_type,
            encryption_cipher: cipher,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded_packet = vec![];

        encoded_packet.append(&mut (self.payload.len() as u32).to_le_bytes().to_vec());

        let padding_length = if 8 > self.encryption_cipher.get_block_size() {
            self.payload.len() % 8
        } else {
            self.payload.len() % self.encryption_cipher.get_block_size()
        };

        encoded_packet.push(padding_length as u8);

        for i in 0..padding_length {
            encoded_packet.push(i as u8);
        }

        encoded_packet
    }
}
