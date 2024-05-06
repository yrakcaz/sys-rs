use serde_derive::Deserialize;
use std::collections::HashMap;

use crate::diag::Result;

#[derive(Deserialize)]
pub enum Type {
    Int,
    Ptr,
    Str,
    Uint,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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

impl Default for Entry {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            ret_type: Type::Int,
            args: None,
        }
    }
}

pub struct Entries {
    map: HashMap<u64, Entry>,
    default: Entry,
}

impl Entries {
    /// # Errors
    ///
    /// Will return `Err` if failing to parse info.json.
    pub fn new() -> Result<Self> {
        let json = include_str!("info.json");
        let map = serde_json::from_str(json)?;
        Ok(Self {
            map,
            default: Entry::default(),
        })
    }

    #[must_use]
    pub fn get(&self, id: u64) -> &Entry {
        self.map.get(&id).unwrap_or(&self.default)
    }
}
