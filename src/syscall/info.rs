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
    name: String,
    arg_type: Type,
}

impl Arg {
    #[must_use]
    pub fn name(&self) -> &String {
        &self.name
    }

    #[must_use]
    pub fn arg_type(&self) -> &Type {
        &self.arg_type
    }
}

#[derive(Clone, Deserialize)]
pub struct Entry {
    name: String,
    ret_type: Type,
    args: Option<Vec<Arg>>,
}

impl Entry {
    #[must_use]
    pub fn name(&self) -> &String {
        &self.name
    }

    #[must_use]
    pub fn ret_type(&self) -> &Type {
        &self.ret_type
    }

    #[must_use]
    pub fn args(&self) -> &Option<Vec<Arg>> {
        &self.args
    }
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
