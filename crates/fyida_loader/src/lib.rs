use std::fmt;
use std::path::{Path, PathBuf};

use fyida_core::FileSelection;

#[derive(Debug)]
pub enum LoaderError {
    Metadata {
        path: PathBuf,
        source: std::io::Error,
    },
    NotAFile(PathBuf),
}

impl fmt::Display for LoaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata { path, source } => {
                write!(
                    formatter,
                    "无法读取文件元数据：{} ({source})",
                    path.display()
                )
            }
            Self::NotAFile(path) => write!(formatter, "选择的路径不是普通文件：{}", path.display()),
        }
    }
}

impl std::error::Error for LoaderError {}

pub fn load_file_metadata(path: impl AsRef<Path>) -> Result<FileSelection, LoaderError> {
    let path = path.as_ref().to_path_buf();
    let metadata = std::fs::metadata(&path).map_err(|source| LoaderError::Metadata {
        path: path.clone(),
        source,
    })?;

    if !metadata.is_file() {
        return Err(LoaderError::NotAFile(path));
    }

    Ok(FileSelection::new(path, metadata.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_is_not_accepted_as_file() {
        let error = load_file_metadata(".").expect_err("directories should be rejected");
        assert!(matches!(error, LoaderError::NotAFile(_)));
    }
}
