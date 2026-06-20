pub mod sk_serde {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use iroh_base::SecretKey;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a SecretKey as an ascii85-encoded string
    pub fn serialize<S>(key: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.to_bytes();
        let encoded = BASE64_STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    /// Deserialize an ascii85-encoded string back to a SecretKey
    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)?;
        let bytes = bytes
            .as_slice()
            .try_into()
            .map_err(serde::de::Error::custom)?;
        let sk = SecretKey::from_bytes(bytes);

        Ok(sk)
    }
}

pub mod pk_serde {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use iroh_base::PublicKey;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a SecretKey as an ascii85-encoded string
    pub fn serialize<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.as_bytes();
        let encoded = BASE64_STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    /// Deserialize an ascii85-encoded string back to a SecretKey
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)?;
        let bytes = bytes
            .as_slice()
            .try_into()
            .map_err(serde::de::Error::custom)?;
        let pk = PublicKey::from_bytes(bytes).map_err(serde::de::Error::custom)?;

        Ok(pk)
    }
}

pub fn pk_to_string(pk: &iroh_base::PublicKey) -> String {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Helper(#[serde(with = "crate::util::pk_serde")] iroh_base::PublicKey);

    let mut me_str = String::new();
    let vs = toml::ser::ValueSerializer::new(&mut me_str);
    Helper(*pk).serialize(vs).unwrap();

    me_str
}

pub fn pk_from_string(s: &str) -> iroh_base::PublicKey {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Helper(#[serde(with = "crate::util::pk_serde")] iroh_base::PublicKey);

    let norm = format!("\"{}\"", s.trim_matches('\"'));
    let de = toml::de::ValueDeserializer::parse(&norm).unwrap();
    Helper::deserialize(de).unwrap().0
}
