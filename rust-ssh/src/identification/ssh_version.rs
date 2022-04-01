/// IETF recognized ssh protocol version numbers.
#[derive(Eq, Debug, PartialEq)]
pub enum SSHVersion {
    /// The standard defined version, usually the one that should be used by any client or server
    Ver2,
    /// A version number defined for backwards compatibility with undocumented older versions of
    /// ssh in most cases it will act as ssh 2.0 with a few differences which are documented in the
    /// specification
    Ver1 { minor: usize },
}

impl std::fmt::Display for SSHVersion {
    /// Convert to a recognized string version of the version number
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Ver2 => write!(f, "2.0"),
            Self::Ver1 { minor } => write!(f, "1.{minor}"),
        }
    }
}
