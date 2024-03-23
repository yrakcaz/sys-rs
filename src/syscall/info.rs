use serde_derive::Deserialize;
use std::collections::HashMap;

use crate::diag::Result;

#[derive(Clone, Deserialize)]
pub enum Type {
    Int,
    Ptr,
    Str,
    Uint,
}

#[derive(Clone, Deserialize)]
pub struct Arg {
    pub name: String,
    pub arg_type: Type,
}

#[derive(Clone, Deserialize)]
pub struct Entry {
    pub name: String,
    pub ret_type: Type,
    pub args: Option<Vec<Arg>>,
}

pub struct Entries {
    map: HashMap<u64, Entry>,
}

impl Entries {
    /// # Errors
    ///
    /// Will return `Err` if failing to parse info.json.
    pub fn new() -> Result<Self> {
        let json = include_str!("info.json");
        let map = serde_json::from_str(json)?;
        Ok(Self { map })
    }

    #[must_use]
    pub fn get(&self, id: u64) -> Entry {
        self.map.get(&id).cloned().unwrap_or_else(|| Entry {
            name: "unknown".to_string(),
            ret_type: Type::Int,
            args: None,
        })
    }
}
