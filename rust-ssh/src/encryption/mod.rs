#[derive(Debug, PartialEq, Eq)]
pub enum Ciphers {
    ThreeDESCBC,
    BlowfishCBC,
    Twofish256CBC,

    TwofishCBC,

    Twofish192CBC,
    Twofish128CBC,
    AES256CBC,

    AES192CBC,
    AES128CBC,
    Serpent256CBC,

    Serpent192CBC,
    Serpent128CBC,

    ArcFour,
    IDEACBC,
    Cast128CBC,
    None
}
