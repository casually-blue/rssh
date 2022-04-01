use rust_ssh::{
    identification::{
        Identification,
        ssh_version::SSHVersion,
    },
    message::*,
    packet::Packet,
    encryption::*,
    mac::Mac,
};

fn main() {
    let ident = Identification::new(SSHVersion::Ver2, "rssh_testing".into(), None);

    let bytes: [u8; 16] = [0;16];

    let kex_message = KexInitMessage {
        cookie: bytes,
        kex_algorithms: vec![].into(),
        server_host_key_algorithms: vec![].into(),
        encryption_algorithms_client_to_server: vec![].into(),
        encryption_algorithms_server_to_client: vec![].into(),
        mac_algorithms_client_to_server: vec![].into(),
        mac_algorithms_server_to_client: vec![].into(),
        compression_algorithms_client_to_server: vec![].into(),
        compression_algorithms_server_to_client: vec![].into(),
        languages_client_to_server: vec![].into(),
        languages_server_to_client: vec![].into(),
        first_kex_packet_follows: false,
        reserved: 0,
    };

    let packet = Packet::new(
        kex_message.encode(),
        Mac::None,
        Box::new(CipherType::None));

    println!("{}", ident.try_encode_to_string().unwrap());

    let byte_string: String = packet.encode().iter().map(|x| *x as char).collect();

    print!("{}", byte_string);
}
