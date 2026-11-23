use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use cardpeek_analyser::DiscoveryError;
use cardpeek_core::{
    ApduResponse, Atr, CoreError, DocumentId, Protocol, ReaderInfo, ResetMode, ResultDocument,
    RunId, TraceDocument, TraceRecordId, TransportKind,
};
use cardpeek_transport::SessionCapabilities;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::CancellationToken;

macro_rules! string_id {
    ($name:ident, $description:literal, $empty:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a nonempty identifier.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                let value = value.into();
                assert!(!value.is_empty(), $empty);
                Self(value)
            }

            /// Returns the identifier string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

string_id!(
    CommandId,
    "A unique application command identifier.",
    "command identifiers are nonempty"
);
string_id!(
    OperationId,
    "A unique application operation identifier.",
    "operation identifiers are nonempty"
);
string_id!(
    InteractionId,
    "A unique interaction request identifier.",
    "interaction identifiers are nonempty"
);

/// Application result type.
pub type Result<T> = std::result::Result<T, AppError>;

/// Structured application, transport, and export errors.
#[derive(Debug, Error)]
pub enum AppError {
    /// Cooperative cancellation was confirmed.
    #[error("operation cancelled")]
    Cancelled,
    /// The application no longer accepts commands.
    #[error("application is shut down")]
    Shutdown,
    /// A command identifier was submitted twice.
    #[error("duplicate command identifier {0}")]
    DuplicateCommand(CommandId),
    /// A session already owns the card worker.
    #[error("a card session is already active")]
    SessionAlreadyActive,
    /// The command needs an active session.
    #[error("no active card session")]
    NoActiveSession,
    /// Live collection needs a physically present card.
    #[error("live collection requires an active PCSC session with a physically present card")]
    CardNotPresent,
    /// A session operation or queue slot is unavailable.
    #[error("a session operation is already running")]
    OperationInProgress,
    /// The operation identifier is unknown.
    #[error("unknown operation {0}")]
    UnknownOperation(OperationId),
    /// The operation is already terminal.
    #[error("operation {0} has already finished")]
    OperationFinished(OperationId),
    /// The interaction is unknown or no longer pending.
    #[error("unknown or inactive interaction {0}")]
    UnknownInteraction(InteractionId),
    /// A pending interaction already has a response.
    #[error("interaction was already answered")]
    InteractionAlreadyAnswered,
    /// The response variant does not match the prompt.
    #[error("interaction response type does not match the request")]
    InteractionResponseType,
    /// No response arrived before the deadline.
    #[error("interaction timed out")]
    InteractionTimeout,
    /// No result document exists for the run.
    #[error("no result document for analyser run {0}")]
    MissingDocument(RunId),
    /// No disconnected session trace is available.
    #[error("trace is not available")]
    TraceUnavailable,
    /// Analyser metadata discovery failed.
    #[error(transparent)]
    AnalyserDiscovery(#[from] DiscoveryError),
    /// The selected analyser has not been discovered.
    #[error("unknown analyser {0}")]
    AnalyserNotFound(String),
    /// Lua analyser execution failed.
    #[error("analyser error: {0}")]
    Analyser(String),
    /// A native transport operation failed.
    #[error("transport error: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Core validation or serialisation failed.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// An export destination could not be written.
    #[error("export I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// An application worker panicked.
    #[error("application worker panicked")]
    WorkerPanicked,
}

/// Converts a native transport error without creating a synthetic status word.
pub fn transport_error(error: impl std::error::Error + Send + Sync + 'static) -> AppError {
    AppError::Transport(Box::new(error))
}

/// Reports whether an application error represents cooperative cancellation.
#[must_use]
pub fn is_cancellation(error: &AppError) -> bool {
    match error {
        AppError::Cancelled => true,
        AppError::Transport(source) => source
            .source()
            .and_then(|source| source.downcast_ref::<AppError>())
            .is_some_and(|error| matches!(error, AppError::Cancelled)),
        _ => false,
    }
}

/// Bounded command, event, worker, and interaction configuration.
#[derive(Clone, Copy, Debug)]
pub struct EngineConfig {
    /// Maximum queued application commands.
    pub command_capacity: usize,
    /// Maximum queued events for each subscriber.
    pub event_capacity: usize,
    /// Maximum queued card operations.
    pub worker_capacity: usize,
    /// Deadline for a pending interaction.
    pub interaction_timeout: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            command_capacity: 64,
            event_capacity: 256,
            worker_capacity: 32,
            interaction_timeout: Duration::from_secs(300),
        }
    }
}

/// Parameters for one reader connection.
#[derive(Clone, Debug)]
pub struct ConnectRequest {
    /// Reader name from discovery.
    pub reader: String,
    /// Reader transport implementation.
    pub transport: TransportKind,
    /// Optional native response buffer limit, including SW1 and SW2.
    pub response_limit: Option<usize>,
    /// Cooperative cancellation supplied to the backend.
    pub cancellation: CancellationToken,
}

impl ConnectRequest {
    /// Creates a connection request with default limits and cancellation state.
    #[must_use]
    pub fn new(reader: impl Into<String>, transport: TransportKind) -> Self {
        Self {
            reader: reader.into(),
            transport,
            response_limit: None,
            cancellation: CancellationToken::new(),
        }
    }
}

/// One explicit application command.
#[derive(Clone, Debug)]
pub struct Command {
    /// Unique command identifier.
    pub id: CommandId,
    /// Requested operation.
    pub kind: CommandKind,
}

impl Command {
    /// Creates a command with a caller-supplied identifier.
    #[must_use]
    pub fn new(id: impl Into<String>, kind: CommandKind) -> Self {
        Self {
            id: CommandId::new(id),
            kind,
        }
    }
}

/// Application command families.
#[derive(Clone, Debug)]
pub enum CommandKind {
    /// Enumerate available readers.
    EnumerateReaders,
    /// Connect and start a dedicated session worker.
    Connect(ConnectRequest),
    /// Disconnect the active session.
    Disconnect,
    /// Reset the active card.
    Reset(ResetMode),
    /// Reset the active card and start a fresh capture without disconnecting.
    NewSession,
    /// Transmit exact APDU bytes.
    Transmit(Vec<u8>),
    /// Discover analysers without executing scripts.
    DiscoverAnalysers(PathBuf),
    /// Start one analyser run with legacy behavior.
    RunAnalyser(RunAnalyserRequest),
    /// Collect and decode analyser values from the current physical card.
    CollectAnalyser(RunAnalyserRequest),
    /// Decode one retained capture bundle without card access.
    DecodeAnalyser(DecodeAnalyserRequest),
    /// Replay one selected trace segment without card access.
    ReplayAnalyser(ReplayAnalyserRequest),
    /// Request cancellation of one operation.
    Cancel(OperationId),
    /// Answer one pending interaction.
    AnswerInteraction(AnswerInteraction),
    /// Export an immutable result document.
    ExportDocument(ExportDocument),
    /// Export an immutable raw session trace.
    ExportTrace(ExportTrace),
    /// Stop accepting commands and clean up workers.
    Shutdown,
}

/// Correlates a response with one interaction request.
#[derive(Clone, Debug)]
pub struct RunAnalyserRequest {
    /// Discovered analyser identifier.
    pub analyser: String,
    /// Stable identifier for this run.
    pub run_id: RunId,
    /// Stable identifier for the fresh result document.
    pub document_id: DocumentId,
}

/// Pure offline analyser decoding parameters.
#[derive(Clone, Debug)]
pub struct DecodeAnalyserRequest {
    /// Discovered analyser identifier.
    pub analyser: String,
    /// Stable identifier for this run.
    pub run_id: RunId,
    /// Stable identifier for the fresh result document.
    pub document_id: DocumentId,
    /// Trace containing the selected capture bundle.
    pub trace: TraceDocument,
    /// Zero-based reset segment index.
    pub segment: usize,
}

/// Segment-scoped offline replay parameters.
#[derive(Clone, Debug)]
pub struct ReplayAnalyserRequest {
    /// Discovered analyser identifier.
    pub analyser: String,
    /// Stable identifier for this run.
    pub run_id: RunId,
    /// Stable identifier for the fresh result document.
    pub document_id: DocumentId,
    /// Source trace.
    pub trace: TraceDocument,
    /// Zero-based reset segment index.
    pub segment: usize,
}

/// Correlates a response with one interaction request.
#[derive(Clone, Debug)]
pub struct AnswerInteraction {
    /// Pending request identifier.
    pub request: InteractionId,
    /// Response value.
    pub response: InteractionResponse,
}

/// Native document export parameters.
#[derive(Clone, Debug)]
pub struct ExportDocument {
    /// Originating analyser run.
    pub run_id: RunId,
    /// Explicit destination path.
    pub destination: PathBuf,
}

/// Trace export privacy mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TraceExportMode {
    /// Preserve exact commands, responses, and ATR values for replay.
    #[default]
    Raw,
    /// Replace command data, response data, and ATR values with placeholders.
    Sanitised,
}

/// Trace export parameters.
#[derive(Clone, Debug)]
pub struct ExportTrace {
    /// Operation that established the session.
    pub session: OperationId,
    /// Privacy mode.
    pub mode: TraceExportMode,
    /// Explicit destination path.
    pub destination: PathBuf,
}

/// Application operation categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    /// Reader discovery.
    EnumerateReaders,
    /// Card connection.
    Connect,
    /// Card disconnection.
    Disconnect,
    /// Card reset.
    Reset,
    /// Reset and capture restart without disconnection.
    NewSession,
    /// APDU transmission.
    Transmit,
    /// Static analyser discovery.
    DiscoverAnalysers,
    /// Analyser execution.
    RunAnalyser,
    /// Live collection and decoding.
    CollectAnalyser,
    /// Offline capture decoding.
    DecodeAnalyser,
    /// Offline segment replay.
    ReplayAnalyser,
    /// Operation cancellation.
    Cancel,
    /// Interaction response.
    AnswerInteraction,
    /// Document export.
    ExportDocument,
    /// Trace export.
    ExportTrace,
    /// Application shutdown.
    Shutdown,
}

/// Operation lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationStatus {
    /// Accepted but not started.
    Pending,
    /// Running on its owner.
    Running,
    /// Cancellation requested but not confirmed.
    Cancelling,
    /// Completed successfully.
    Completed,
    /// Failed with a structured error.
    Failed,
    /// Cancellation confirmed.
    Cancelled,
}

impl OperationStatus {
    /// Reports whether no further lifecycle change is expected.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Snapshot of one operation.
#[derive(Clone, Debug)]
pub struct Operation {
    /// Operation identifier.
    pub id: OperationId,
    /// Originating command.
    pub command: CommandId,
    /// Operation category.
    pub kind: OperationKind,
    /// Current lifecycle state.
    pub status: OperationStatus,
    /// Analyser run, where applicable.
    pub run_id: Option<RunId>,
}

/// Snapshot of one owned session.
#[derive(Clone, Debug)]
pub struct SessionInfo {
    /// Operation that established the session.
    pub id: OperationId,
    /// Reader information.
    pub reader: ReaderInfo,
    /// Negotiated protocol.
    pub protocol: Protocol,
    /// Transport capabilities.
    pub capabilities: SessionCapabilities,
    /// Most recently observed ATR.
    pub atr: Atr,
    /// Connection state.
    pub state: SessionState,
}

/// Session lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Connection is in progress.
    Connecting,
    /// Session is ready for commands.
    Connected,
    /// A reset is in progress.
    Resetting,
    /// Disconnection is in progress.
    Disconnecting,
    /// Session is closed.
    Disconnected,
}

/// Structured analyser log severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

/// Determinate or indeterminate operation progress.
#[derive(Clone, Debug, PartialEq)]
pub enum Progress {
    /// Completion is not known.
    Indeterminate,
    /// Completed and total work units.
    Determinate {
        /// Completed work units.
        completed: u64,
        /// Total work units.
        total: u64,
    },
}

/// Interaction values supported by the first release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InteractionKind {
    /// Yes or no question.
    Question {
        /// Question text.
        prompt: String,
    },
    /// A message with one acknowledgement action.
    Notice {
        /// Message text.
        prompt: String,
    },
    /// Visible text input.
    TextInput {
        /// Input prompt.
        prompt: String,
        /// Initial value.
        default: Option<String>,
    },
    /// Secret input. Values are never included in events.
    SecretInput {
        /// Input prompt.
        prompt: String,
    },
    /// File selection.
    FileSelection {
        /// Selection prompt.
        prompt: String,
        /// Whether an existing file is required.
        must_exist: bool,
    },
}

/// One correlated interaction request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InteractionRequest {
    /// Unique request identifier.
    pub id: InteractionId,
    /// Prompt and response kind.
    pub kind: InteractionKind,
}

/// One interaction response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InteractionResponse {
    /// Answer to a yes or no question.
    Bool(bool),
    /// Visible text input.
    Text(String),
    /// Acknowledgement of a notice.
    Acknowledged,
    /// Secret text input.
    Secret(String),
    /// Selected file path.
    File(PathBuf),
}

impl InteractionResponse {
    pub(crate) fn matches(&self, request: &InteractionKind) -> bool {
        matches!(
            (self, request),
            (Self::Bool(_), InteractionKind::Question { .. })
                | (Self::Acknowledged, InteractionKind::Notice { .. })
                | (Self::Text(_), InteractionKind::TextInput { .. })
                | (Self::Secret(_), InteractionKind::SecretInput { .. })
                | (Self::File(_), InteractionKind::FileSelection { .. })
        )
    }
}

/// Immutable result document snapshot.
#[derive(Clone, Debug)]
pub struct DocumentSnapshot {
    /// Originating analyser run.
    pub run_id: RunId,
    /// Snapshot revision.
    pub revision: u64,
    /// Complete immutable document.
    pub document: Arc<ResultDocument>,
}

/// Counts of notifications removed under bounded-channel pressure.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DroppedEvents {
    /// Dropped analyser log messages.
    pub logs: u64,
    /// Coalesced or dropped document notifications.
    pub document_notifications: u64,
    /// Coalesced or dropped progress notifications.
    pub progress_notifications: u64,
}

/// One ordered application event.
#[derive(Clone, Debug)]
pub struct Event {
    /// Monotonic event sequence number.
    pub sequence: u64,
    /// Associated operation.
    pub operation: OperationId,
    /// Event payload.
    pub kind: EventKind,
    /// Drops since the preceding delivered event.
    pub dropped: Option<DroppedEvents>,
}

impl Event {
    pub(crate) fn new(operation: OperationId, kind: EventKind) -> Self {
        Self {
            sequence: 0,
            operation,
            kind,
            dropped: None,
        }
    }
}

/// Application event payloads.
#[derive(Clone, Debug)]
pub enum EventKind {
    /// Session lifecycle changed.
    SessionStateChanged {
        /// Session operation identifier.
        session: OperationId,
        /// New lifecycle state.
        state: SessionState,
        /// Associated reader.
        reader: ReaderInfo,
    },
    /// Card presence or connection details changed.
    CardStatusChanged {
        /// Session operation identifier.
        session: OperationId,
        /// Whether a card is present and connected.
        card_present: bool,
        /// Current negotiated protocol.
        protocol: Protocol,
        /// Current Answer to Reset.
        atr: Atr,
    },
    /// Exact APDU exchange completed.
    ApduExchanged {
        /// Session operation identifier.
        session: OperationId,
        /// Stable trace record identifier.
        record: TraceRecordId,
        /// Exact command bytes.
        command: Vec<u8>,
        /// Card response.
        response: ApduResponse,
    },
    /// Analyser emitted a structured log message.
    LogEmitted {
        /// Analyser run.
        run_id: RunId,
        /// Log severity.
        level: LogLevel,
        /// Log message.
        message: String,
    },
    /// A new immutable document revision is available.
    DocumentPublished {
        /// Analyser run.
        run_id: RunId,
        /// Published revision.
        revision: u64,
    },
    /// An interaction is waiting for its matching response.
    InteractionRequested {
        /// Owning operation.
        operation: OperationId,
        /// Request without any secret response data.
        request: InteractionRequest,
    },
    /// Operation progress changed.
    OperationProgress {
        /// Associated operation.
        operation: OperationId,
        /// New progress value.
        progress: Progress,
    },
    /// Operation completed successfully.
    OperationCompleted {
        /// Completed operation.
        operation: OperationId,
    },
    /// Operation failed.
    OperationFailed {
        /// Failed operation.
        operation: OperationId,
        /// Structured error rendered for frontends.
        error: String,
    },
    /// Cancellation reached its deterministic terminal state.
    OperationCancelled {
        /// Cancelled operation.
        operation: OperationId,
    },
}
