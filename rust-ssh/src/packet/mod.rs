use crate::mac::Mac;

pub struct Packet {
    payload: Vec<u8>,
    mac_type: Mac
}

impl Packet {
    pub fn new(payload: Vec<u8>, mac_type: Mac) -> Self {
        Packet { payload, mac_type }
    }

    pub fn encode(&self, cipher_block_size: usize) -> Vec<u8> {
        let mut encoded_packet = vec![];

        encoded_packet.append(&mut (self.payload.len() as u32).to_le_bytes().to_vec());

        let padding_length = if 8 > cipher_block_size {
            self.payload.len() % 8
        } else {
            self.payload.len() % cipher_block_size
        };

        encoded_packet.push(padding_length as u8);

        for i in 0..padding_length {
            encoded_packet.push(i as u8);
        }

        encoded_packet
    }
}
