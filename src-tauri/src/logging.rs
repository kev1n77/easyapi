use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

use chrono::Local;
use tracing_subscriber::fmt::MakeWriter;

const LOG_DIRECTORY_NAME: &str = "logs";
const LOG_FILE_PREFIX: &str = "easyapi-";
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const MAX_ROTATED_FILES: usize = 2;
const MAX_STARTUP_LOGS: usize = 10;

struct RollingLogState {
    base_path: PathBuf,
    file: File,
    bytes: u64,
}

#[derive(Clone)]
struct RollingLogWriter {
    state: Arc<Mutex<RollingLogState>>,
}

struct RollingLogHandle {
    state: Arc<Mutex<RollingLogState>>,
}

impl RollingLogWriter {
    fn new(base_path: PathBuf) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&base_path)?;
        let bytes = file.metadata()?.len();
        Ok(Self {
            state: Arc::new(Mutex::new(RollingLogState {
                base_path,
                file,
                bytes,
            })),
        })
    }
}

impl<'a> MakeWriter<'a> for RollingLogWriter {
    type Writer = RollingLogHandle;

    fn make_writer(&'a self) -> Self::Writer {
        RollingLogHandle {
            state: self.state.clone(),
        }
    }
}

impl Write for RollingLogHandle {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("日志文件锁异常"))?;
        if state.bytes > 0 && state.bytes.saturating_add(bytes.len() as u64) > MAX_LOG_BYTES {
            rotate_locked(&mut state)?;
        }
        let written = state.file.write(bytes)?;
        state.bytes = state.bytes.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("日志文件锁异常"))?;
        state.file.flush()
    }
}

fn rotate_locked(state: &mut RollingLogState) -> io::Result<()> {
    state.file.flush()?;

    let oldest = rotated_path(&state.base_path, MAX_ROTATED_FILES);
    if oldest.exists() {
        fs::remove_file(oldest)?;
    }
    for index in (1..MAX_ROTATED_FILES).rev() {
        let source = rotated_path(&state.base_path, index);
        if source.exists() {
            fs::rename(source, rotated_path(&state.base_path, index + 1))?;
        }
    }
    if state.base_path.exists() {
        fs::rename(&state.base_path, rotated_path(&state.base_path, 1))?;
    }
    state.file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&state.base_path)?;
    state.bytes = 0;
    Ok(())
}

fn rotated_path(base_path: &Path, index: usize) -> PathBuf {
    PathBuf::from(format!("{}.{}", base_path.display(), index))
}

fn startup_log_path(log_dir: &Path) -> PathBuf {
    let now = Local::now();
    let timestamp = now.format("%Y%m%d-%H%M%S");
    let millis = now.timestamp_subsec_millis();
    log_dir.join(format!(
        "{LOG_FILE_PREFIX}{timestamp}-{millis:03}-{}.log",
        std::process::id()
    ))
}

fn is_startup_log(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(LOG_FILE_PREFIX) && name.ends_with(".log"))
}

fn remove_log_group(base_path: &Path) -> io::Result<()> {
    if base_path.exists() {
        fs::remove_file(base_path)?;
    }
    for index in 1..=MAX_ROTATED_FILES {
        let path = rotated_path(base_path, index);
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn cleanup_startup_logs(log_dir: &Path) -> io::Result<()> {
    let mut startup_logs = fs::read_dir(log_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| is_startup_log(path))
        .collect::<Vec<_>>();
    startup_logs.sort_by_key(|path| {
        fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });

    while startup_logs.len() >= MAX_STARTUP_LOGS {
        let oldest = startup_logs.remove(0);
        remove_log_group(&oldest)?;
    }
    Ok(())
}

pub fn init(app_data_dir: &Path) -> Result<PathBuf, String> {
    let log_dir = app_data_dir.join(LOG_DIRECTORY_NAME);
    fs::create_dir_all(&log_dir).map_err(|error| format!("无法创建日志目录: {error}"))?;
    cleanup_startup_logs(&log_dir).map_err(|error| format!("无法清理旧日志: {error}"))?;

    let base_path = startup_log_path(&log_dir);
    let writer = RollingLogWriter::new(base_path.clone())
        .map_err(|error| format!("无法打开日志文件: {error}"))?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "easyapi=info,tower_http=info".into()),
        )
        .with_target(false)
        .with_ansi(false)
        .compact()
        .with_writer(writer)
        .try_init()
        .map_err(|error| format!("无法初始化日志订阅器: {error}"))?;
    Ok(base_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_after_ten_megabytes_and_keeps_two_rotated_files() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("easyapi-test.log");
        let writer = RollingLogWriter::new(base.clone()).unwrap();
        let mut handle = writer.make_writer();
        let chunk = vec![b'x'; MAX_LOG_BYTES as usize];
        handle.write_all(&chunk).unwrap();
        handle.write_all(b"next").unwrap();
        handle.write_all(&chunk).unwrap();
        handle.write_all(b"last").unwrap();
        handle.flush().unwrap();

        assert!(base.exists());
        assert!(rotated_path(&base, 1).exists());
        assert!(rotated_path(&base, 2).exists());
        assert!(!rotated_path(&base, 3).exists());
    }

    #[test]
    fn startup_log_detection_excludes_rotated_files() {
        assert!(is_startup_log(Path::new("easyapi-20260905-120000-1.log")));
        assert!(!is_startup_log(Path::new(
            "easyapi-20260905-120000-1.log.1"
        )));
    }
}
