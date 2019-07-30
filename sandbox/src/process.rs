use super::{cgroup::CGroup, runner_def::Parameter as RunnerParameter};
use libc::{c_char, c_int, c_void, gid_t, uid_t};
use std::{
    collections::HashMap,
    env,
    ffi::CString,
    mem,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr,
};

const RUNNER_EXE_NAME: &str = "runner";
const WAIT_MARK: u8 = 23;

struct Config {
    root_path: PathBuf,
    working_path: PathBuf,
    exe_path: PathBuf,
    args: Vec<String>,
    envs: HashMap<String, String>,
    uid: uid_t,
    gid: gid_t,
    fd_map: HashMap<c_int, c_int>,
    time_limit: u32,
    memory_limit: usize,
}

struct Data {
    wait_fd: c_int,
    ready_fd: c_int,
    config: Config,
}

fn write_fd(fd: c_int, value: u8) -> Result<(), isize> {
    let write_len = unsafe {
        libc::write(
            fd,
            (&value as *const u8) as *const c_void,
            mem::size_of::<u8>(),
        )
    };
    if write_len == mem::size_of::<u8>() as isize {
        Ok(())
    } else {
        Err(write_len)
    }
}

fn read_fd(fd: c_int) -> Result<u8, isize> {
    let mut buf = 0u8;
    let read_len = unsafe {
        libc::read(
            fd,
            (&mut buf as *mut u8) as *mut c_void,
            mem::size_of::<u8>(),
        )
    };
    if read_len == mem::size_of::<u8>() as isize {
        Ok(buf)
    } else {
        Err(read_len)
    }
}

fn create_pipe() -> (c_int, c_int) {
    let mut pipes: [c_int; 2] = [0; 2];
    if unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        panic!("Failed to create the pipe.");
    }
    (pipes[0], pipes[1])
}

fn execute_runner(parameter: RunnerParameter) -> Result<(), ()> {
    let runner_path = env::current_exe().map_err(|_| ()).and_then(|mut path| {
        // Correct the path of test binary.
        #[cfg(test)]
        path.pop();

        path.set_file_name(RUNNER_EXE_NAME);
        CString::new(path.into_os_string().into_vec()).map_err(|_| ())
    })?;
    let paramter_json = serde_json::to_string(&parameter)
        .map_err(|_| ())
        .and_then(|json| CString::new(json).map_err(|_| ()))?;
    let args = [runner_path.as_ptr(), paramter_json.as_ptr(), ptr::null()];
    let envs: [*const c_char; 1] = [ptr::null()];
    unsafe {
        libc::execve(args[0], args.as_ptr(), envs.as_ptr());
    }
    Err(())
}

extern "C" fn process_entry(data: *mut c_void) -> c_int {
    let data = unsafe { Box::from_raw(data as *mut Data) };
    match write_fd(data.ready_fd, WAIT_MARK) {
        Ok(()) => (),
        Err(_) => return 1,
    }
    // Wait for the green light.
    match read_fd(data.wait_fd) {
        Ok(mark) if mark == WAIT_MARK => (),
        _ => return 1,
    }
    let config = data.config;
    let parameter = RunnerParameter {
        root_path: config.root_path.into_os_string(),
        working_path: config.working_path.into_os_string(),
        exe_path: config.exe_path.into_os_string(),
        args: config.args,
        envs: config.envs,
        uid: config.uid,
        gid: config.gid,
        time_limit: config.time_limit,
    };
    let _ = execute_runner(parameter);
    // Shouldn't reach here.
    1
}

pub struct Process {
    config: Config,
}

impl Process {
    pub fn new<R, W, E>(
        root_path: R,
        working_path: W,
        exe_path: E,
        args: &[String],
        envs: HashMap<String, String>,
        fd_map: HashMap<c_int, c_int>,
        uid: uid_t,
        gid: gid_t,
        time_limit: u32,
        memory_limit: usize,
    ) -> Self
    where
        R: AsRef<Path>,
        W: AsRef<Path>,
        E: AsRef<Path>,
    {
        let args = args.iter().map(|s| s.clone()).collect();
        Self {
            config: Config {
                root_path: root_path.as_ref().to_owned(),
                working_path: working_path.as_ref().to_owned(),
                exe_path: exe_path.as_ref().to_owned(),
                args,
                envs,
                fd_map,
                uid,
                gid,
                time_limit,
                memory_limit,
            },
        }
    }

    pub fn run(self) {
        let memory_limit = self.config.memory_limit;
        let (wait_read_fd, wait_write_fd) = create_pipe();
        let (ready_read_fd, ready_write_fd) = create_pipe();
        let data = Box::into_raw(Box::new(Data {
            wait_fd: wait_read_fd,
            ready_fd: ready_write_fd,
            config: self.config,
        }));
        let mut stack = vec![0u8; 4096 * 2];
        let stack_ptr = unsafe { stack.as_mut_ptr().add(stack.len()) };
        let pid = unsafe {
            libc::clone(
                process_entry,
                stack_ptr as *mut c_void,
                libc::CLONE_VM
                    | libc::CLONE_NEWIPC
                    | libc::CLONE_NEWNET
                    | libc::CLONE_NEWNS
                    | libc::CLONE_NEWPID
                    | libc::CLONE_NEWUTS
                    | libc::SIGCHLD,
                data as *mut c_void,
            )
        };
        if unsafe { libc::close(wait_read_fd) != 0 || libc::close(ready_write_fd) != 0 } {
            panic!("Failed to close the pipe.");
        }
        match read_fd(ready_read_fd) {
            Ok(mark) if mark == WAIT_MARK => (),
            _ => panic!("Failed to initialize the process."),
        }

        let cgroup = CGroup::new(pid as u64, memory_limit).unwrap();
        cgroup.add_pid(pid).unwrap();

        write_fd(wait_write_fd, WAIT_MARK).unwrap();
        match read_fd(ready_read_fd) {
            Err(len) if len == 0 => (),
            _ => panic!("Unexpected ready result."),
        }
        // Secure the lifetime of stack.
        drop(stack);

        let mut status: c_int = 0;
        let waited_pid = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited_pid != pid {
            panic!("Unexpected wait result.");
        }

        let memory_usage = cgroup.get_max_memory_usage().unwrap();
        println!("{} {}", status, memory_usage);
    }
}

#[cfg(test)]
mod tests {
    use super::Process;
    use std::collections::HashMap;

    #[test]
    fn it_works() {
        let process = Process::new(
            "/",
            "/",
            "/bin/cat",
            &["/proc/self/mountinfo".to_owned()],
            HashMap::new(),
            HashMap::new(),
            1000,
            1000,
            0,
            256 * 1024 * 1024,
        );
        process.run();
    }
}
