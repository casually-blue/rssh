mod ssh_version;
mod identification_error;

use ssh_version::*;
use identification_error::*;

/// The identification information for a ssh client or server as defined by IETF RFC 4253.
///
/// The most important function on this data structure is `try_encode_to_string` which will
/// attempt to create a identification string to be sent to the other partner in a connection.
#[derive(Eq,PartialEq,Debug)]
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
        let rest = &identification_string[4..];

        // Check the beginning of the slice for either of our supported protocol versions, make
        // sure that they are followed by a '-' character so we don't accidentally parse something
        // like '2.01' as supported when only '2.0 is supported
        let (protocol_version, rest) = match rest.split("-").next() {
            Some(version) if version == "2.0" => (SSHVersion::Ver2, &rest[version.len()..]),
            Some(version) if version == "1.99" => (SSHVersion::Ver1 { minor: 99 }, &rest[version.len()..]),
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

        if !rest.starts_with('-') {
            return Err(IdentificationError::MissingSoftwareVersion);
        }
        let rest = &rest[1..];

        let (software_version, rest) = if rest.contains(' ') {
            match rest.split(" ").next() {
                Some(version) => {
                    // offset version length by one to get rid of the space character
                    // and strip the crlf from the string
                    (version, &rest[version.len()+1..rest.len()-end_len])
                },
                None => return Err(IdentificationError::MissingSoftwareVersion)
            }
        } else {
            // No comments string is present so we just strip the crlf from the end of the string
            (&rest[0..rest.len() - end_len], "")
        };

        let comments = match rest.len() {
            0 => None,
            _ => Some(rest.into()),
        };

        Ok(Identification::new(protocol_version, software_version.into(), comments))
    }
}

#[cfg(test)]
mod tests {
    use crate::identification::*;
    #[test]
    fn test_openssh_ubuntu_identification_string() {
        let ident = Identification::decode_from_string("SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5\r\n".into());

        assert_eq!(ident, Ok(Identification::new(SSHVersion::Ver2, "OpenSSH_7.6p1".into(), Some("Ubuntu-4ubuntu0.5".into()))));
    }

    #[test]
    fn test_ident_no_comment() {
        let ident = Identification::decode_from_string("SSH-2.0-rssh1.0\r\n".into());

        assert_eq!(ident, Ok(Identification::new(SSHVersion::Ver2, "rssh1.0".into(), None)));
    }
}
