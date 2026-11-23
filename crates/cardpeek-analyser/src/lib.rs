//! Analyser metadata, discovery, and execution contracts.

mod library;

pub use library::{AnalyserLibrary, LibraryError};

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cardpeek_core::{ApduResponse, Atr, CoreError, DocumentId, Protocol, ResetMode, RunId};
use cardpeek_transport::SessionCapabilities;
use thiserror::Error;

/// Static execution capabilities declared by an analyser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalyserCapabilities {
    /// Supports analyser-controlled live card collection.
    pub live_collection: bool,
    /// Supports pure offline decoding of capture bundles.
    pub offline_decoding: bool,
    /// Supports execution against recorded exchanges.
    pub replay: bool,
}

impl Default for AnalyserCapabilities {
    fn default() -> Self {
        Self {
            live_collection: true,
            offline_decoding: false,
            replay: true,
        }
    }
}

/// Static metadata read from an analyser comment header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalyserMetadata {
    /// Stable analyser identifier.
    pub id: String,
    /// Human-readable analyser name.
    pub title: String,
    /// Short analyser description.
    pub description: String,
    /// Analyser-provided version.
    pub version: String,
    /// Supported execution modes.
    pub capabilities: AnalyserCapabilities,
    /// Capture schema required by the decoder.
    pub capture_schema: Option<String>,
    /// Lua entry point.
    pub path: PathBuf,
}

impl AnalyserMetadata {
    /// Returns the directory used for analyser resources.
    #[must_use]
    pub fn resource_root(&self) -> &Path {
        self.path.parent().unwrap_or_else(|| Path::new("."))
    }
}

/// Parameters for one isolated analyser execution.
#[derive(Clone, Debug)]
pub struct ExecutionRequest {
    /// Analyser selected from static discovery.
    pub analyser: AnalyserMetadata,
    /// Stable run identifier.
    pub run_id: RunId,
    /// Stable result document identifier.
    pub document_id: DocumentId,
}

/// Analyser discovery or metadata error.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// A directory or analyser file could not be read.
    #[error("analyser I/O error for {path}: {source}")]
    Io {
        /// Affected path.
        path: PathBuf,
        /// Native I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Required metadata is absent or malformed.
    #[error("invalid analyser metadata in {path}: {message}")]
    Metadata {
        /// Analyser entry point.
        path: PathBuf,
        /// Validation detail.
        message: String,
    },
}

/// Discovers Lua analysers without executing them.
///
/// Only files directly inside `root` are examined. Metadata uses leading line
/// comments: `@id`, `@title`, `@description`, and `@version`.
///
/// # Errors
///
/// Returns an error when the directory or a Lua header cannot be read or validated.
pub fn discover(root: &Path) -> Result<Vec<AnalyserMetadata>, DiscoveryError> {
    let entries = fs::read_dir(root).map_err(|source| DiscoveryError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| DiscoveryError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.extension().is_some_and(|extension| extension == "lua") {
            paths.push(path);
        }
    }
    paths.sort();
    paths.iter().map(|path| read_metadata(path)).collect()
}

/// Parses one analyser header without executing Lua.
///
/// # Errors
///
/// Returns an error for unreadable, duplicate, missing, or empty metadata fields.
pub fn read_metadata(path: &Path) -> Result<AnalyserMetadata, DiscoveryError> {
    let source = fs::read_to_string(path).map_err(|source| DiscoveryError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_metadata(path, &source)
}

fn parse_metadata(path: &Path, source: &str) -> Result<AnalyserMetadata, DiscoveryError> {
    let mut fields = BTreeMap::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(comment) = line.strip_prefix("--") else {
            break;
        };
        let comment = comment.trim();
        let Some(directive) = comment.strip_prefix('@') else {
            continue;
        };
        let Some((name, value)) = directive.split_once(char::is_whitespace) else {
            return metadata_error(
                path,
                format!("metadata directive {directive:?} needs a value"),
            );
        };
        let name = name.trim();
        if !matches!(
            name,
            "id" | "title" | "description" | "version" | "capabilities" | "capture-schema"
        ) {
            continue;
        }
        let value = value.trim();
        if value.is_empty() {
            return metadata_error(path, format!("metadata field {name} is empty"));
        }
        if fields.insert(name.to_owned(), value.to_owned()).is_some() {
            return metadata_error(path, format!("metadata field {name} is duplicated"));
        }
    }
    let required = |name: &str| {
        fields
            .get(name)
            .cloned()
            .ok_or_else(|| DiscoveryError::Metadata {
                path: path.to_path_buf(),
                message: format!("required metadata field {name} is missing"),
            })
    };
    let mut capabilities = AnalyserCapabilities::default();
    if let Some(declared) = fields.get("capabilities") {
        capabilities = AnalyserCapabilities {
            live_collection: false,
            offline_decoding: false,
            replay: false,
        };
        for capability in declared.split(',').map(str::trim) {
            match capability {
                "live" => capabilities.live_collection = true,
                "decode" => capabilities.offline_decoding = true,
                "replay" => capabilities.replay = true,
                _ => {
                    return metadata_error(
                        path,
                        format!("unsupported analyser capability {capability}"),
                    );
                }
            }
        }
    }
    let capture_schema = fields.get("capture-schema").cloned();
    if capabilities.offline_decoding && capture_schema.is_none() {
        return metadata_error(path, "offline decoding requires @capture-schema".into());
    }
    Ok(AnalyserMetadata {
        id: required("id")?,
        title: required("title")?,
        description: required("description")?,
        version: required("version")?,
        capabilities,
        capture_schema,
        path: path.to_path_buf(),
    })
}

fn metadata_error<T>(path: &Path, message: String) -> Result<T, DiscoveryError> {
    Err(DiscoveryError::Metadata {
        path: path.to_path_buf(),
        message,
    })
}

/// Log severity emitted by an analyser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    /// Diagnostic detail.
    Debug,
    /// Normal information.
    Info,
    /// Recoverable problem.
    Warning,
    /// Operation failure.
    Error,
}

/// Interactive question supplied by an analyser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InteractionKind {
    /// A yes or no question.
    Question,
    /// A message with one acknowledgement action.
    Notice,
    /// Visible text input with an optional initial value.
    Text {
        /// Initial input value.
        default: Option<String>,
    },
    /// Secret text input.
    Secret,
    /// File selection.
    File {
        /// Whether the selected file must already exist.
        must_exist: bool,
    },
}

/// Response to an interactive analyser question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InteractionResponse {
    /// Answer to a yes or no question.
    Bool(bool),
    /// Acknowledgement of a notice.
    Acknowledged,
    /// Visible text input.
    Text(String),
    /// Secret text input.
    Secret(String),
    /// Selected file path.
    File(PathBuf),
}

/// Bounded event delivery supplied by the application.
pub trait EventSink {
    /// Emits one structured analyser log message.
    fn log(&self, level: LogLevel, message: &str);

    /// Requests a response without exposing secret values in event payloads.
    ///
    /// # Errors
    ///
    /// Returns cancellation, timeout, or unavailable-interaction errors.
    fn interact(
        &self,
        _kind: InteractionKind,
        _prompt: &str,
    ) -> Result<InteractionResponse, HostError> {
        Err(HostError::new("interaction is unavailable"))
    }
}

impl EventSink for () {
    fn log(&self, _level: LogLevel, _message: &str) {}
}

/// Structured native card-host failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct HostError {
    message: String,
    cancelled: bool,
}

impl HostError {
    /// Creates a native host error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cancelled: false,
        }
    }

    /// Creates a cooperative cancellation error.
    #[must_use]
    pub fn cancelled() -> Self {
        Self {
            message: "operation cancelled".into(),
            cancelled: true,
        }
    }

    /// Reports whether this error represents cancellation.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

impl From<CoreError> for HostError {
    fn from(error: CoreError) -> Self {
        Self::new(error.to_string())
    }
}

/// Blocking card operations owned by an analyser worker.
pub trait Cancellation: Clone + Send + Sync + 'static {
    /// Reports whether cooperative cancellation was requested.
    fn is_cancelled(&self) -> bool;
}

impl Cancellation for () {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Blocking card operations owned by an analyser worker.
pub trait CardHost {
    /// Cancellation state shared with the instruction hook.
    type Cancellation: Cancellation;

    /// Returns the negotiated protocol.
    fn protocol(&self) -> Protocol;

    /// Returns transport capabilities.
    fn capabilities(&self) -> SessionCapabilities;

    /// Returns the current Answer to Reset.
    ///
    /// # Errors
    ///
    /// Returns a structured native error.
    fn atr(&mut self) -> Result<Atr, HostError>;

    /// Resets the card and returns its new Answer to Reset.
    ///
    /// # Errors
    ///
    /// Returns a structured native error.
    fn reset(&mut self, mode: ResetMode) -> Result<Atr, HostError>;

    /// Transmits exact APDU bytes without implicit retries.
    ///
    /// # Errors
    ///
    /// Returns a structured native error.
    fn transmit(&mut self, command: &[u8]) -> Result<ApduResponse, HostError>;

    /// Returns the cancellation state for this run.
    fn cancellation(&self) -> &Self::Cancellation;

    /// Returns the source record for the current ATR when known.
    fn current_atr_record(&self) -> Option<cardpeek_core::TraceRecordId> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_stops_before_executable_source() {
        let metadata = parse_metadata(
            Path::new("atr.lua"),
            "-- @id atr\n-- @title ATR\n-- @description Native ATR\n-- @version 1.0.0\nerror('not executed')\n",
        )
        .unwrap();
        assert_eq!(metadata.id, "atr");
        assert_eq!(metadata.title, "ATR");
        assert_eq!(metadata.version, "1.0.0");
        assert_eq!(metadata.capabilities, AnalyserCapabilities::default());
        assert_eq!(metadata.capture_schema, None);
    }

    #[test]
    fn parses_and_validates_execution_capabilities() {
        let metadata = parse_metadata(
            Path::new("atr.lua"),
            "-- @id atr\n-- @title ATR\n-- @description Native ATR\n-- @version 1\n-- @capabilities live, decode, replay\n-- @capture-schema atr/v1\n",
        )
        .unwrap();
        assert!(metadata.capabilities.live_collection);
        assert!(metadata.capabilities.offline_decoding);
        assert!(metadata.capabilities.replay);
        assert_eq!(metadata.capture_schema.as_deref(), Some("atr/v1"));
        assert!(parse_metadata(
            Path::new("bad.lua"),
            "-- @id bad\n-- @title Bad\n-- @description Bad\n-- @version 1\n-- @capabilities decode\n",
        ).is_err());
    }

    #[test]
    fn missing_metadata_is_rejected() {
        assert!(parse_metadata(Path::new("bad.lua"), "-- @id bad\n").is_err());
    }
}
