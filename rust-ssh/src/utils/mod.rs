pub mod character_constants {
    pub const CR: &str = "\r";
    pub const LF: &str = "\n";
    pub const SP: &str = " ";

    pub enum ControlCharacter {
        C,
        D,
    }

    impl ControlCharacter {
        pub fn as_str(&self) -> &str {
            match self {
                Self::C => "^C",
                Self::D => "^D",
            }
        }
    }
}
