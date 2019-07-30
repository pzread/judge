use std::{
    fs,
    io::{BufRead, Error as IOError, Read, Write},
    path::{Path, PathBuf},
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP_MARK: &str = "judge";

fn write_config<P: AsRef<Path>, V: std::fmt::Display>(path: P, value: V) -> Result<(), IOError> {
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    write!(file, "{}", value)?;
    Ok(())
}

pub struct CGroup {
    id: u64,
    memory_path: PathBuf,
}

impl CGroup {
    pub fn new(id: u64, memory_limit: usize) -> Result<Self, ()> {
        let mark = &format!("{}_{}", CGROUP_MARK, id);
        let root_path = Path::new(CGROUP_ROOT);
        let memory_path = root_path.join("memory").join(mark);
        fs::create_dir(&memory_path).map_err(|_| ())?;

        write_config(memory_path.join("memory.soft_limit_in_bytes"), memory_limit)
            .map_err(|_| ())?;

        Ok(Self { id, memory_path })
    }

    pub fn add_pid(&self, pid: i32) -> Result<(), ()> {
        write_config(self.memory_path.join("cgroup.procs"), pid).map_err(|_| ())?;
        Ok(())
    }

    pub fn get_max_memory_usage(&self) -> Result<usize, ()> {
        let mut file =
            fs::File::open(self.memory_path.join("memory.max_usage_in_bytes")).map_err(|_| ())?;
        let mut line = String::new();
        file.read_to_string(&mut line).map_err(|_| ())?;
        Ok(line.trim().parse().unwrap())
    }
}

impl Drop for CGroup {
    fn drop(&mut self) {
        fs::remove_dir(&self.memory_path).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::CGroup;

    #[test]
    fn it_works() {
        let cgroup = CGroup::new(23, 1024).unwrap();
    }
}
