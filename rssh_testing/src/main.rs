use rust_ssh::{
    identification::{
        Identification,
        ssh_version::SSHVersion,
    },
    message::{
        message_type::*,
        ServiceRequest,
        SSHService,
        Message,
    },
    packet::*,
};

fn main() {
    let ident = Identification::new(SSHVersion::Ver2, "rssh_testing".into(), None);

    let sr = ServiceRequest { service: SSHService::Connection };

    println!("{}", ident.try_encode_to_string().unwrap());
    let str_encod: String = sr.encode().iter().map(|byte|*byte as char).collect();
    print!("{}", str_encod);

}
