extern crate libc;
mod cgroup;
mod process;
mod runner_def;

use process::Process;

pub struct Sandbox {}

impl Sandbox {
    pub fn run(&self) {}
}
