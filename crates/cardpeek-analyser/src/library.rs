//! Persistent user analyser library.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use thiserror::Error;

use crate::{AnalyserMetadata, DiscoveryError, discover, read_metadata};

include!(concat!(env!("OUT_DIR"), "/bundled_analysers.rs"));

/// A directory containing user-installed Lua analysers.
#[derive(Clone, Debug)]
pub struct AnalyserLibrary {
    root: PathBuf,
}

/// Analyser library configuration or filesystem failure.
#[derive(Debug, Error)]
pub enum LibraryError {
    /// No platform configuration directory is available.
    #[error("the platform configuration directory is unavailable")]
    ConfigurationUnavailable,
    /// An analyser library filesystem operation failed.
    #[error("analyser library I/O error for {path}: {source}")]
    Io {
        /// Affected path.
        path: PathBuf,
        /// Native I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Source metadata or the existing library is invalid.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    /// No Lua analysers were selected or discovered.
    #[error("no Lua analysers were selected or discovered")]
    EmptyImport,
    /// An import contains or conflicts with an analyser identifier.
    #[error("analyser {0} is already installed or occurs more than once in the import")]
    DuplicateAnalyser(String),
    /// An import would replace a library file.
    #[error("analyser destination already exists: {0}")]
    DestinationExists(PathBuf),
    /// The requested installed analyser does not exist.
    #[error("installed analyser {0} was not found")]
    UnknownAnalyser(String),
    /// An imported file does not have the Lua extension.
    #[error("analyser source must have the .lua extension: {0}")]
    NotLua(PathBuf),
    /// An imported file does not have a destination file name.
    #[error("analyser source has no file name: {0}")]
    InvalidSource(PathBuf),
}

impl AnalyserLibrary {
    /// Creates the analyser library in the platform user configuration directory.
    ///
    /// # Errors
    ///
    /// Returns an error when no configuration directory is available or it cannot be created.
    pub fn user() -> Result<Self, LibraryError> {
        let directories = ProjectDirs::from("", "", "cardpeek-ng")
            .ok_or(LibraryError::ConfigurationUnavailable)?;
        Self::at(directories.config_dir().join("analysers"))
    }

    /// Creates an analyser library at an explicit directory.
    ///
    /// A newly created library receives every bundled Lua analyser.
    /// Existing libraries are not modified, including when they are empty.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory or bundled analysers cannot be created.
    pub fn at(root: impl Into<PathBuf>) -> Result<Self, LibraryError> {
        let root = root.into();
        let create = !root.exists();
        fs::create_dir_all(&root).map_err(|source| LibraryError::Io {
            path: root.clone(),
            source,
        })?;
        if create {
            for (name, source) in BUNDLED_ANALYSERS {
                let destination = root.join(name);
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent).map_err(|source| LibraryError::Io {
                        path: parent.to_path_buf(),
                        source,
                    })?;
                }
                fs::write(&destination, source).map_err(|source| LibraryError::Io {
                    path: destination,
                    source,
                })?;
            }
        }
        Ok(Self { root })
    }

    /// Returns the library directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Lists installed analysers without executing them.
    ///
    /// # Errors
    ///
    /// Returns an error when a library file cannot be read or has invalid metadata.
    pub fn list(&self) -> Result<Vec<AnalyserMetadata>, LibraryError> {
        discover(&self.root).map_err(LibraryError::from)
    }

    /// Imports every valid Lua analyser from the source directory's `cards` subdirectory.
    ///
    /// # Errors
    ///
    /// Returns an error when discovery, validation, or copying fails.
    pub fn import_directory(&self, source: &Path) -> Result<Vec<AnalyserMetadata>, LibraryError> {
        let sources = discover(source)?;
        self.import_files(sources.iter().map(|analyser| analyser.path.as_path()))
    }

    /// Imports selected Lua files without executing them.
    ///
    /// All files and destination conflicts are checked before copying starts.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or copying fails.
    pub fn import_files<'a>(
        &self,
        sources: impl IntoIterator<Item = &'a Path>,
    ) -> Result<Vec<AnalyserMetadata>, LibraryError> {
        let mut paths = sources.into_iter().collect::<Vec<_>>();
        paths.sort();
        if paths.is_empty() {
            return Err(LibraryError::EmptyImport);
        }
        let mut imported = Vec::with_capacity(paths.len());
        let mut identifiers = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        for source in paths {
            if source
                .extension()
                .is_none_or(|extension| extension != "lua")
            {
                return Err(LibraryError::NotLua(source.to_path_buf()));
            }
            let metadata = read_metadata(source)?;
            if !identifiers.insert(metadata.id.clone()) {
                return Err(LibraryError::DuplicateAnalyser(metadata.id));
            }
            let file_name = source
                .file_name()
                .ok_or_else(|| LibraryError::InvalidSource(source.to_path_buf()))?;
            let destination = self.root.join("cards").join(file_name);
            if destination.exists() {
                return Err(LibraryError::DestinationExists(destination));
            }
            if !destinations.insert(destination.clone()) {
                return Err(LibraryError::DestinationExists(destination));
            }
            imported.push((metadata, source, destination));
        }
        for existing in self.list()? {
            if identifiers.contains(&existing.id) {
                return Err(LibraryError::DuplicateAnalyser(existing.id));
            }
        }
        let mut installed = Vec::with_capacity(imported.len());
        for (mut metadata, source, destination) in imported {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|source| LibraryError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            fs::copy(source, &destination).map_err(|source| LibraryError::Io {
                path: destination.clone(),
                source,
            })?;
            metadata.path = destination;
            installed.push(metadata);
        }
        Ok(installed)
    }

    /// Removes an installed analyser by its stable identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the analyser is absent or its file cannot be removed.
    pub fn remove(&self, analyser: &str) -> Result<AnalyserMetadata, LibraryError> {
        let metadata = self
            .list()?
            .into_iter()
            .find(|candidate| candidate.id == analyser)
            .ok_or_else(|| LibraryError::UnknownAnalyser(analyser.to_owned()))?;
        fs::remove_file(&metadata.path).map_err(|source| LibraryError::Io {
            path: metadata.path.clone(),
            source,
        })?;
        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_analyser(directory: &Path, name: &str, id: &str) {
        fs::create_dir_all(directory.join("cards")).unwrap();
        fs::write(
            directory.join("cards").join(name),
            format!(
                "-- @id {id}\n-- @title Test {id}\n-- @description Test analyser\n-- @version 1.0.0\n"
            ),
        )
        .unwrap();
    }

    fn empty_library() -> AnalyserLibrary {
        let directory = tempfile::tempdir().unwrap().keep();
        let library = AnalyserLibrary::at(directory.join("analysers")).unwrap();
        for analyser in library.list().unwrap() {
            library.remove(&analyser.id).unwrap();
        }
        library
    }

    #[test]
    fn creates_a_library_with_every_bundled_analyser_only_once() {
        let directories = tempfile::tempdir().unwrap();
        let root = directories.path().join("config/analysers");
        let library = AnalyserLibrary::at(&root).unwrap();
        let analyser_count = BUNDLED_ANALYSERS
            .iter()
            .filter(|(name, _)| {
                name.starts_with("cards/")
                    && !name["cards/".len()..].contains('/')
                    && std::path::Path::new(name)
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("lua"))
            })
            .count();
        assert_eq!(library.list().unwrap().len(), analyser_count);
        assert_ne!(analyser_count, 0);
        for (name, source) in BUNDLED_ANALYSERS {
            assert_eq!(fs::read_to_string(root.join(name)).unwrap(), *source);
        }
        for analyser in library.list().unwrap() {
            assert_eq!(
                analyser.path.file_stem().and_then(|name| name.to_str()),
                Some(analyser.id.as_str())
            );
            library.remove(&analyser.id).unwrap();
        }
        let reopened = AnalyserLibrary::at(&root).unwrap();
        assert_eq!(reopened.list().unwrap(), [] as [AnalyserMetadata; 0]);
    }

    #[test]
    fn creates_imports_lists_and_removes_a_library() {
        let directories = tempfile::tempdir().unwrap();
        let reopened = empty_library();
        let root = reopened.root();
        assert_eq!(reopened.list().unwrap(), [] as [AnalyserMetadata; 0]);
        let source = directories.path().join("source");
        fs::create_dir(&source).unwrap();
        write_analyser(&source, "one.lua", "one");
        write_analyser(&source, "two.lua", "two");
        fs::write(source.join("notes.txt"), "not an analyser").unwrap();
        let imported = reopened.import_directory(&source).unwrap();
        assert_eq!(imported.len(), 2);
        assert_eq!(reopened.list().unwrap().len(), 2);
        assert_eq!(reopened.remove("one").unwrap().id, "one");
        assert_eq!(reopened.list().unwrap()[0].id, "two");
        assert!(!root.join("cards/one.lua").exists());
    }

    #[test]
    fn rejects_duplicates_without_replacing_installed_files() {
        let directories = tempfile::tempdir().unwrap();
        let source = directories.path().join("source");
        fs::create_dir(&source).unwrap();
        write_analyser(&source, "replacement.lua", "one");
        let library = empty_library();
        write_analyser(library.root(), "one.lua", "one");
        let original = fs::read(library.root().join("cards/one.lua")).unwrap();
        assert!(matches!(
            library.import_directory(&source),
            Err(LibraryError::DuplicateAnalyser(id)) if id == "one"
        ));
        assert_eq!(
            fs::read(library.root().join("cards/one.lua")).unwrap(),
            original
        );
        assert!(!library.root().join("cards/replacement.lua").exists());
    }

    #[test]
    fn validates_every_selected_file_before_copying() {
        let directories = tempfile::tempdir().unwrap();
        let source = directories.path().join("source");
        fs::create_dir(&source).unwrap();
        write_analyser(&source, "valid.lua", "valid");
        let invalid = source.join("invalid.lua");
        fs::write(&invalid, "return {}\n").unwrap();
        let library = empty_library();
        assert!(
            library
                .import_files([source.join("valid.lua").as_path(), invalid.as_path()])
                .is_err()
        );
        assert_eq!(library.list().unwrap(), [] as [AnalyserMetadata; 0]);
    }
}
