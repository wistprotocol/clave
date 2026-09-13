use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;

struct Unique;

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Unique)
    }
}

impl<'de> Visitor<'de> for Unique {
    type Value = Self;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with unique object member names")
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_str<E: Error>(self, _: &str) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_unit<E: Error>(self) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self, A::Error> {
        while seq.next_element::<Unique>()?.is_some() {}
        Ok(self)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self, A::Error> {
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(A::Error::custom("duplicate JSON member name"));
            }
            map.next_value::<Unique>()?;
        }
        Ok(self)
    }
}

pub fn validate(raw: &[u8]) -> Result<(), &'static str> {
    serde_json::from_slice::<Unique>(raw).map_err(|_| "WIST1-E05")?;
    Ok(())
}
