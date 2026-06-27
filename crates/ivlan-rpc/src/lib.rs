use std::{
    collections::BTreeMap,
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct IpAddrs {
    pub v4: Ipv4Addr,
    pub v6: Ipv6Addr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteId(iroh::PublicKey);

impl From<RemoteId> for iroh::PublicKey {
    fn from(RemoteId(pk): RemoteId) -> Self {
        pk
    }
}

impl From<iroh::PublicKey> for RemoteId {
    fn from(pk: iroh::PublicKey) -> Self {
        RemoteId(pk)
    }
}

impl Display for RemoteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = base64::engine::general_purpose::URL_SAFE.encode(self.0.as_bytes());
        write!(f, "{s}")
    }
}

impl FromStr for RemoteId {
    type Err = RemoteIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base64::engine::general_purpose::URL_SAFE.decode(s)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            RemoteIdParseError::Key(n0_error::e!(iroh::KeyParsingError::InvalidLength))
        })?;
        let pk = iroh::PublicKey::from_bytes(&bytes)?;
        Ok(RemoteId(pk))
    }
}

impl Serialize for RemoteId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.0.as_bytes().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for RemoteId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let data: [u8; 32] = serde::Deserialize::deserialize(deserializer)?;
            iroh::PublicKey::try_from(data.as_ref())
                .map(RemoteId)
                .map_err(serde::de::Error::custom)
        }
    }
}

#[derive(Debug)]
pub enum RemoteIdParseError {
    Base64(base64::DecodeError),
    Key(iroh::KeyParsingError),
}

impl From<base64::DecodeError> for RemoteIdParseError {
    fn from(e: base64::DecodeError) -> Self {
        RemoteIdParseError::Base64(e)
    }
}

impl From<iroh::KeyParsingError> for RemoteIdParseError {
    fn from(e: iroh::KeyParsingError) -> Self {
        RemoteIdParseError::Key(e)
    }
}

impl Display for RemoteIdParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteIdParseError::Base64(e) => e.fmt(f),
            RemoteIdParseError::Key(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RemoteIdParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RemoteIdParseError::Base64(e) => e.source(),
            RemoteIdParseError::Key(e) => e.source(),
        }
    }

    fn description(&self) -> &str {
        #[allow(deprecated)]
        match self {
            RemoteIdParseError::Base64(e) => e.description(),
            RemoteIdParseError::Key(e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        #[allow(deprecated)]
        match self {
            RemoteIdParseError::Base64(e) => e.cause(),
            RemoteIdParseError::Key(e) => e.cause(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum Auth {
    None,
    Password(String),
}

#[tarpc::service]
pub trait IvLanService {
    async fn start(_sk: iroh::SecretKey) -> Result<(), String>;
    async fn connect(_id: RemoteId, _auth: Auth) -> Result<IpAddrs, String>;
    async fn lookup(_id: RemoteId) -> Result<IpAddrs, String>;
    async fn peers() -> BTreeMap<RemoteId, IpAddrs>;
}
