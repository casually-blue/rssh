use rust_ssh::{
    identification::{
        Identification,
        ssh_version::SSHVersion,
    },
    packet::*,
};

fn main() {
    let ident = Identification::new(SSHVersion::Ver2, "rssh_testing".into(), None);

    println!("{}", ident.try_encode_to_string().unwrap());

}
