extern crate libc;
extern crate serde;
extern crate serde_json;
mod runner_def;

use libc::{c_int, c_ulong, c_void};
use runner_def::Parameter;
use std::{
    env,
    ffi::{CString, OsString},
    os::unix::ffi::OsStringExt,
    path::PathBuf,
    process, ptr,
};

const DEV_PATH: &str = "/dev";

fn mount(src: &str, target: PathBuf, fstype: &str, flags: c_ulong) -> c_int {
    let src = CString::new(src).unwrap();
    let target = CString::new(target.into_os_string().into_vec()).unwrap();
    let fstype = CString::new(fstype).unwrap();
    unsafe {
        libc::mount(
            src.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            ptr::null(),
        )
    }
}

extern "C" fn sigalrm_handler(_: c_int) {
    process::exit(1);
}

fn main() {
    let param: Parameter = serde_json::from_str(&env::args().nth(1).unwrap()).unwrap();
    let root_path = PathBuf::from(&param.root_path);
    if mount("", PathBuf::from("/"), "", libc::MS_REC | libc::MS_PRIVATE) != 0 {
        panic!();
    }
    if mount("", root_path.join("proc"), "proc", 0) != 0 {
        panic!();
    }
    if mount(DEV_PATH, root_path.join("dev"), "", libc::MS_BIND) != 0 {
        panic!();
    }
    let root_path_cstring = CString::new(param.root_path.into_vec()).unwrap();
    if unsafe { libc::chroot(root_path_cstring.as_ptr()) } != 0 {
        panic!();
    }
    if unsafe { libc::setgroups(0, ptr::null()) } != 0 {
        panic!();
    }
    if unsafe { libc::setresgid(param.gid, param.gid, param.gid) } != 0 {
        panic!();
    }
    if unsafe { libc::setresuid(param.uid, param.uid, param.uid) } != 0 {
        panic!();
    }
    unsafe {
        libc::signal(
            libc::SIGALRM,
            (sigalrm_handler as *mut c_void) as libc::sighandler_t,
        );
        libc::alarm((param.time_limit / 1000 + 1) * 10);
    }
    let status = process::Command::new(param.exe_path)
        .args(param.args)
        .envs(param.envs)
        .current_dir(param.working_path)
        .status()
        .unwrap();
    process::exit(status.code().unwrap());
}
