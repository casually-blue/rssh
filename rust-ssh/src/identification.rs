/// IETF recognized ssh protocol version numbers.
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

#[derive(Debug)]
/// Possible errors in creating a SSH Protocol Identification string
pub enum IdentificationError {
    /// The maximum length of the identification string was exceeded
    ///
    /// length: The length of the string that resulted in the error
    /// value: the String value itself
    MaxLengthExceeded { length: usize, value: String },
    ContainsNullCharacter { index: usize, value: String },

    InvalidEnding { actual: String },
    InvalidStringBeginning { actual: String },
    InvalidProtocolVersion { actual: String },

    UnsupportedProtocolVersion { ver: String },

    ExpectedSpaceSeparator { actual: char, value: String },

    MissingSoftwareVersion
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

/// The identification information for a ssh client or server as defined by IETF RFC 4253.
///
/// The most important function on this data structure is `try_encode_to_string` which will
/// attempt to create a identification string to be sent to the other partner in a connection.
pub struct Identification {
    protocol_version: SSHVersion,
    software_version: String,
    comments: Option<String>
}

impl Identification {
    /// Create a default identification structure using the standard ssh protocol version (2.0) as
    /// defined by RFC 4253.
    pub fn default_ident() -> Self {
        Identification {
            protocol_version: SSHVersion::Ver2,
            software_version: "rssh_0.1".into(),
            comments: None
        }
    }

    /// Generate a identification structure with the given information
    pub fn new(protocol_version: SSHVersion, software_version: String, comments: Option<String>) -> Self {
        Self {
            protocol_version,
            software_version,
            comments
        }
    }

    /// Attempt to create the Identification string that will be sent to the server/client;
    ///
    /// The function will return an error if the string including comments and the carriage return
    /// line feed combination would be more than `255` characters as this is the maximum length
    /// allowed by the spec
    pub fn try_encode_to_string(&self) -> Result<String, IdentificationError> {
        use crate::utils::character_constants::{CR,LF,SP};

        let ending = match self.protocol_version {
            SSHVersion::Ver2 => format!("{CR}{LF}"),
            SSHVersion::Ver1 { minor: 99 } => format!("{LF}"),
            SSHVersion::Ver1 { minor } => return Err(IdentificationError::UnsupportedProtocolVersion { ver: format!("1.{minor}") }),
        };

        let identification_string = format!("SSH-{}-{}{}{ending}",
                // Convert the protocol enum to a string value
                // TODO: Add a display implementation so we don't have to call this dumb function
                self.protocol_version,
                self.software_version,
                // We only need a space before the '\r\n' if we have comments so insert it here
                match &self.comments {
                    Some(comments) => format!("{SP}{comments}"),
                    None => format!("")
                });


        // length for validation
        let id_string_len = identification_string.len();

        // Validate the identification string and throw an apropriate error if any issues are found
        if id_string_len > 255 {
            Err(IdentificationError::MaxLengthExceeded { length: id_string_len, value: identification_string })
        } else if let Some(index) = identification_string.find('\0') {
            Err(IdentificationError::ContainsNullCharacter{ index, value: identification_string })
        } else {
            Ok(identification_string)
        }
    }

    /// Attempt to decode the protocol information from a string
    ///
    /// The function will attempt to parse the identifier string in a RFC 4253 compatible way and
    /// fall back to compatibility mode if that fails (e.g. allowing the identification string to
    /// end with a single line feed character rather than a carriage return+line feed combo
    pub fn decode_from_string(identification_string: String) -> Result<Self, IdentificationError> {
        use crate::utils::character_constants::{CR,LF};

        let id_string_len = identification_string.len();

        // Perform the some basic validation of the data in the identification string we were
        // passed
        if id_string_len > 255 {
            return Err(IdentificationError::MaxLengthExceeded { length: id_string_len, value: identification_string })
        } else if let Some(index) = identification_string.find('\0') {
            return Err(IdentificationError::ContainsNullCharacter{ index, value: identification_string })
        }

        // Verify that this is indeed intended to be a SSH Identification string and not another
        // line of data that the ssh protocol allows to be sent before the identifier.
        if !identification_string.starts_with("SSH-") {
            return Err(IdentificationError::InvalidStringBeginning { actual: identification_string[0..4].into() })
        }

        // Slice off the "SSH-" portion of the identifier string
        let string_protocol_version_start_slice = &identification_string[4..];

        // Check the beginning of the slice for either of our supported protocol versions, make
        // sure that they are followed by a '-' character so we don't accidentally parse something
        // like '2.01' as supported when only '2.0 is supported
        let (protocol_version, string_software_version_start_slice) = match string_protocol_version_start_slice.split("-").next() {
            Some(version) if version == "2.0" => (SSHVersion::Ver2, &string_protocol_version_start_slice[version.len()..]),
            Some(version) if version == "1.99" => (SSHVersion::Ver1 { minor: 99 }, &string_protocol_version_start_slice[version.len()..]),
            Some(ver) => return Err(IdentificationError::InvalidProtocolVersion { actual: ver.into() }),
            None => unreachable!()

        };

        // Perform validation of the identifier string ending based on protocol version
        let end_len = match protocol_version {
            SSHVersion::Ver2 => {
            // Verify that the identifier string has a correct ending
                if !identification_string.ends_with(&format!("{CR}{LF}")) {
                    let ending_start_index = identification_string.len() - 3;
                    return Err(IdentificationError::InvalidEnding { actual: identification_string[ending_start_index..].into() })
                }
                2
            },
            SSHVersion::Ver1 { minor: 99 } => {
                if !identification_string.ends_with(&format!("{LF}")) {
                    let ending_start_index = identification_string.len() - 2;
                    return Err(IdentificationError::InvalidEnding { actual: identification_string[ending_start_index..].into() })
                }
                1
            },

            SSHVersion::Ver1 { minor } => return Err(IdentificationError::UnsupportedProtocolVersion { ver: format!("1.{minor}") })
        };

        let (software_version, possible_comments_start_slice) = match string_software_version_start_slice.split("-").next() {
            Some(version) => {
                (version.into(), &string_software_version_start_slice[version.len()..])
            },
            None => {
                return Err(IdentificationError::MissingSoftwareVersion)
            }
        };

        match possible_comments_start_slice.chars().next()  {
            Some(c) if c == '\r' || c == '\n' => {
                Ok(Self::new(protocol_version, software_version, None))
            },
            Some(c) if c == ' ' => {
                let comments = possible_comments_start_slice[1..possible_comments_start_slice.len()-end_len].into();
                Ok(Self::new(protocol_version, software_version, Some(comments)))
            },
            Some(c) => Err(IdentificationError::ExpectedSpaceSeparator { actual: c, value: possible_comments_start_slice.into() }),
            None => unreachable!()
        }
    }
}
