use libc::{gid_t, uid_t};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ffi::OsString};

#[derive(Serialize, Deserialize, Debug)]
pub struct Parameter {
    pub root_path: OsString,
    pub working_path: OsString,
    pub exe_path: OsString,
    pub args: Vec<String>,
    pub envs: HashMap<String, String>,
    pub uid: uid_t,
    pub gid: gid_t,
    pub time_limit: u32,
}
