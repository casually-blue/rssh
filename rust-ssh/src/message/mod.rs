pub mod disconnect;
pub mod message_type;

use result::Result;

use message_type::*;

pub trait Message {
    fn encode(&self) -> Vec<u8>;
    fn get_type(&self) -> MessageType;
    fn decode(data: Vec<u8>) -> Result<Self> where Self: Sized + Message;
}

pub struct NameList<T: std::fmt::Display> {
    this: Vec<T>,
}

impl<T: std::fmt::Display> NameList<T> {
    pub fn encode(&self) -> Vec<u8> {
        format!("{}", self).chars().map(|x| x as u8).collect()
    }
}

impl<T: std::fmt::Display> std::fmt::Display for NameList<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let inter: String = ",".to_string();
        let str_list = self.this.iter().map(|x| format!("{x}")).intersperse(inter);
        write!(f, "(")?;
        for item in str_list {
            write!(f, "{}", item)?
        }
        write!(f, ")")?;

        Ok(())
    }
}

pub enum SSHService {
    UserAuth,
    Connection,
    Named(String),
}

impl std::fmt::Display for SSHService {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::UserAuth => "ssh-userauth",
            Self::Connection => "ssh-connection",
            Self::Named(name) => name,
        })
    }
}

pub struct ServiceRequest {
    pub service: SSHService
}

impl Message for ServiceRequest {
    fn get_type(&self) -> MessageType {
        MessageType::ServiceRequest
    }

    fn decode(_data: Vec<u8>) -> Result<Self> {
        todo!()
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = vec![];

        encoded.push(self.get_type() as u8);

        let service = format!("{}", self.service);

        for byte in (service.len() as u32).to_be_bytes() {
            encoded.push(byte);
        }
        encoded.append(&mut service.chars().map(|x| x as u8).collect());

        encoded
    }
}

use std::fmt::{Display, Formatter};
enum KexAlgorithm {}

impl Display for KexAlgorithm {
    fn fmt(&self, _f: &mut Formatter) -> std::fmt::Result {
        Ok(())
    }
}

enum EncryptionAlgorithm {}

impl Display for EncryptionAlgorithm {
    fn fmt(&self, _f: &mut Formatter) -> std::fmt::Result {
        Ok(())
    }
}

enum MacAlgorithm {}
impl Display for MacAlgorithm{
    fn fmt(&self, _f: &mut Formatter) -> std::fmt::Result {
        Ok(())
    }
}

enum Language {}
impl Display for Language{
    fn fmt(&self, _f: &mut Formatter) -> std::fmt::Result {
        Ok(())
    }
}

enum CompressionAlgorithm {
    Zstd,
    None
}
impl Display for CompressionAlgorithm{
    fn fmt(&self, _f: &mut Formatter) -> std::fmt::Result {
        Ok(())
    }
}
struct KexInitMessage {
    cookie: [u8; 16],
    kex_algorithms: NameList<KexAlgorithm>,
    server_host_key_algorithms: NameList<KexAlgorithm>,

    encryption_algorithms_client_to_server: NameList<EncryptionAlgorithm>,
    encryption_algorithms_server_to_client: NameList<EncryptionAlgorithm>,

    mac_algorithms_client_to_server: NameList<MacAlgorithm>,
    mac_algorithms_server_to_client: NameList<MacAlgorithm>,

    compression_algorithms_client_to_server: NameList<CompressionAlgorithm>,
    compression_algorithms_server_to_client: NameList<CompressionAlgorithm>,

    languages_client_to_server: NameList<Language>,
    languages_server_to_client: NameList<Language>,

    first_kex_packet_follows: bool,

    #[allow(unused)]
    reserved: u32,
}

impl Message for KexInitMessage {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = vec![];

        encoded.push(self.get_type() as u8);

        for elem in self.cookie {
            encoded.push(elem);
        }

        encoded.append(&mut self.kex_algorithms.encode());
        encoded.append(&mut self.server_host_key_algorithms.encode());

        encoded.append(&mut self.encryption_algorithms_client_to_server.encode());
        encoded.append(&mut self.encryption_algorithms_server_to_client.encode());


        encoded.append(&mut self.mac_algorithms_client_to_server.encode());
        encoded.append(&mut self.mac_algorithms_server_to_client.encode());


        encoded.append(&mut self.compression_algorithms_client_to_server.encode());
        encoded.append(&mut self.compression_algorithms_server_to_client.encode());

        encoded.append(&mut self.languages_client_to_server.encode());
        encoded.append(&mut self.languages_server_to_client.encode());

        encoded.push(match self.first_kex_packet_follows {
            true => 1 as u8,
            false => 0 as u8,
        });

        for b in (0 as u32).to_be_bytes() {
            encoded.push(b as u8);
        }

        encoded
    }

    fn get_type(&self) -> MessageType {
        MessageType::KexInit
    }

    fn decode(data: Vec<u8>) -> Result<Self> {
        if data.len() < 17 {
            return Err("Packet to short".into())
        } else {
            todo!()
        }
    }
}
