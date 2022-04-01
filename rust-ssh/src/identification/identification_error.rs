#[derive(Debug, Eq, PartialEq)]
/// Possible errors in creating a SSH Protocol Identification string
pub enum IdentificationError {
    /// The maximum length of the identification string was exceeded
    ///
    /// length: The length of the string that resulted in the error
    /// value: the String value itself
    MaxLengthExceeded {
        length: usize,
        value: String,
    },
    ContainsNullCharacter {
        index: usize,
        value: String,
    },

    InvalidEnding {
        actual: String,
    },
    InvalidStringBeginning {
        actual: String,
    },
    InvalidProtocolVersion {
        actual: String,
    },

    UnsupportedProtocolVersion {
        ver: String,
    },

    ExpectedSpaceSeparator {
        actual: char,
        value: String,
    },

    MissingSoftwareVersion,
}

impl std::fmt::Display for IdentificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::MaxLengthExceeded {length, value} => write!(f, "Identification String must not exceed 256 characters (got {length}); Actual result string was {value}"),
            Self::ContainsNullCharacter {index, value} => write!(f, "Identification String must not contain the null character '\0', found at index {index} in \"{value}\""),

            Self::InvalidEnding { actual } => write!(f, "Expected string to end with a carriage return followed by a line feed \"\\r\\n\", found \"{actual}\""),
            Self::InvalidStringBeginning { actual } => write!(f, "Expected identification string to start with \"SSH-\", got {actual}"),
            Self::InvalidProtocolVersion { actual } => write!(f, "Expected a supported protocol version (2.0 or 1.99) got {actual}"),

            Self::UnsupportedProtocolVersion { ver } => write!(f, "Got an unsupported version of the ssh protocol: expected (2.0 or 1.99) got {ver}"),
            Self::MissingSoftwareVersion => write!(f, "No software version identifier in identification string"),
            Self::ExpectedSpaceSeparator { actual, value } => write!(f, "Expected a space character separating protocol version and comments, got {actual} in (\"{value}\")"),
        }
    }
}

impl std::error::Error for IdentificationError {}
