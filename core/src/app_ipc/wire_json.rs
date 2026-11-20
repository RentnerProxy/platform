use std::{collections::HashSet, fmt};

use rentnerproxy_app_contracts::MAX_JSON_DEPTH;
use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};

const MAX_MAGNITUDE: u64 = 9_007_199_254_740_991;

pub(crate) fn valid(body: &[u8]) -> bool {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    Check(0).deserialize(&mut deserializer).is_ok() && deserializer.end().is_ok()
}

#[derive(Clone, Copy)]
struct Check(usize);

impl<'de> DeserializeSeed<'de> for Check {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Check {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a v1 wire JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_bool<E: Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<(), E> {
        self.visit_u64(value.unsigned_abs())
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<(), E> {
        if value <= MAX_MAGNITUDE {
            Ok(())
        } else {
            Err(E::custom("JSON number out of range"))
        }
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<(), E> {
        if value.abs() <= MAX_MAGNITUDE as f64 {
            Ok(())
        } else {
            Err(E::custom("JSON number out of range"))
        }
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut array: A) -> Result<(), A::Error> {
        let child = self.child()?;
        while array.next_element_seed(child)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<(), A::Error> {
        let child = self.child()?;
        let mut keys = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(A::Error::custom("Duplicate JSON member"));
            }
            object.next_value_seed(child)?;
        }
        Ok(())
    }
}

impl Check {
    fn child<E: Error>(self) -> Result<Self, E> {
        if self.0 >= MAX_JSON_DEPTH {
            return Err(E::custom("JSON depth limit exceeded"));
        }
        Ok(Self(self.0 + 1))
    }
}
