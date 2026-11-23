//! Command-line entry point for `Cardpeek` NG.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use cardpeek_analyser::AnalyserLibrary;
use cardpeek_app::{
    Application, CommandKind, ConnectRequest, EventKind, ExportTrace, OperationId, OperationStatus,
    PcscBackend, RunAnalyserRequest, SessionBackend, SubmitError, TraceExportMode, transport_error,
};
use cardpeek_core::{
    ApduResponse, Atr, ByteString, Protocol, ReaderInfo, ResetMode, TraceDocument, TransportKind,
};
use cardpeek_replay::{ReplayError, ReplaySession};
use cardpeek_transport::{CardSession, SessionCapabilities};
use clap::{Parser, Subcommand, ValueEnum};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(
    name = "cardpeek",
    version,
    about = "Inspect smart cards with Cardpeek-ng analysers"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum TraceMode {
    #[default]
    Raw,
    Sanitised,
}

impl From<TraceMode> for TraceExportMode {
    fn from(mode: TraceMode) -> Self {
        match mode {
            TraceMode::Raw => Self::Raw,
            TraceMode::Sanitised => Self::Sanitised,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage the user analyser library.
    #[command(subcommand)]
    Analysers(AnalyserCommand),
    /// Discover analysers without executing their scripts.
    Discover {
        /// Analyser library root. Defaults to the user library.
        analysers: Option<PathBuf>,
    },
    /// List native PC/SC readers and card-presence state.
    Readers,
    /// Transmit one exact APDU through a real PC/SC reader.
    Transmit {
        /// Exact reader name from the readers command.
        reader: String,
        /// Hexadecimal APDU command.
        command: String,
        /// Optional native JSON trace destination.
        #[arg(long)]
        trace_output: Option<PathBuf>,
        /// Privacy mode for the trace export.
        #[arg(long, value_enum, default_value_t)]
        trace_mode: TraceMode,
    },
    /// Run one analyser against a real PC/SC card.
    Run {
        /// Exact reader name from the readers command.
        reader: String,
        /// Analyser library root. Defaults to the user library.
        #[arg(long)]
        analysers: Option<PathBuf>,
        /// Analyser identifier from static discovery.
        analyser: String,
        /// Explicit native JSON document destination.
        #[arg(short, long)]
        output: PathBuf,
        /// Optional native JSON trace destination.
        #[arg(long)]
        trace_output: Option<PathBuf>,
        /// Privacy mode for the trace export.
        #[arg(long, value_enum, default_value_t)]
        trace_mode: TraceMode,
    },
    /// Run one analyser against a recorded exchange and export its document.
    Replay {
        /// Native JSON trace to replay.
        trace: PathBuf,
        /// Analyser library root. Defaults to the user library.
        #[arg(long)]
        analysers: Option<PathBuf>,
        /// Analyser identifier from static discovery.
        analyser: String,
        /// Explicit native JSON document destination.
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AnalyserCommand {
    /// List installed analysers and the library directory.
    List,
    /// Import every Lua analyser directly inside a directory.
    Import {
        /// Analyser library root with entry points in its cards directory.
        directory: PathBuf,
    },
    /// Remove an installed analyser by its stable identifier.
    Remove {
        /// Analyser identifier from the list command.
        analyser: String,
    },
}

#[derive(Debug, Error)]
enum CliError {
    #[error(transparent)]
    Application(#[from] cardpeek_app::AppError),
    #[error(transparent)]
    Submission(#[from] SubmitError),
    #[error(transparent)]
    Core(#[from] cardpeek_core::CoreError),
    #[error(transparent)]
    Replay(#[from] ReplayError),
    #[error(transparent)]
    Library(#[from] cardpeek_analyser::LibraryError),
    #[error("operation {0} did not reach a terminal state")]
    Timeout(OperationId),
    #[error("operation {operation} failed: {error}")]
    Operation {
        operation: OperationId,
        error: String,
    },
    #[error("analyser {0} was not discovered")]
    UnknownAnalyser(String),
}

type Result<T> = std::result::Result<T, CliError>;

fn main() -> ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cardpeek: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Arguments) -> Result<()> {
    match arguments.command {
        Command::Analysers(command) => manage_analysers(command),
        Command::Discover { analysers } => discover(&analyser_directory(analysers)?),
        Command::Readers => readers(),
        Command::Transmit {
            reader,
            command,
            trace_output,
            trace_mode,
        } => transmit(reader, &command, trace_output, trace_mode),
        Command::Run {
            reader,
            analysers,
            analyser,
            output,
            trace_output,
            trace_mode,
        } => run_pcsc(
            reader,
            analyser_directory(analysers)?,
            analyser,
            output,
            trace_output,
            trace_mode,
        ),
        Command::Replay {
            trace,
            analysers,
            analyser,
            output,
        } => replay(trace, analyser_directory(analysers)?, analyser, output),
    }
}

fn analyser_directory(explicit: Option<PathBuf>) -> Result<PathBuf> {
    explicit.map_or_else(
        || {
            AnalyserLibrary::user()
                .map(|library| library.root().to_path_buf())
                .map_err(CliError::from)
        },
        Ok,
    )
}

fn manage_analysers(command: AnalyserCommand) -> Result<()> {
    let library = AnalyserLibrary::user()?;
    println!("Library: {}", library.root().display());
    match command {
        AnalyserCommand::List => {
            print_analysers(&library.list()?);
            Ok(())
        }
        AnalyserCommand::Import { directory } => {
            let imported = library.import_directory(&directory)?;
            for analyser in imported {
                println!("Imported {}", analyser.id);
            }
            Ok(())
        }
        AnalyserCommand::Remove { analyser } => {
            let removed = library.remove(&analyser)?;
            println!("Removed {}", removed.id);
            Ok(())
        }
    }
}

fn discover(root: &Path) -> Result<()> {
    let analysers = cardpeek_app::discover(root).map_err(cardpeek_app::AppError::from)?;
    print_analysers(&analysers);
    Ok(())
}

fn print_analysers(analysers: &[cardpeek_analyser::AnalyserMetadata]) {
    let id_width = ["ID".len()]
        .into_iter()
        .chain(analysers.iter().map(|a| a.id.len()))
        .max()
        .unwrap_or(0);
    let version_width = ["VERSION".len()]
        .into_iter()
        .chain(analysers.iter().map(|a| a.version.len()))
        .max()
        .unwrap_or(0);
    let title_width = ["TITLE".len()]
        .into_iter()
        .chain(analysers.iter().map(|a| a.title.len()))
        .max()
        .unwrap_or(0);
    println!(
        "{:<id_width$}  {:<version_width$}  {:<title_width$}  DESCRIPTION",
        "ID", "VERSION", "TITLE"
    );
    for analyser in analysers {
        println!(
            "{:<id_width$}  {:<version_width$}  {:<title_width$}  {}",
            analyser.id, analyser.version, analyser.title, analyser.description,
        );
    }
}

fn readers() -> Result<()> {
    let application = Application::with_defaults(PcscBackend::establish()?);
    let events = application.subscribe();
    let operation = application.submit(CommandKind::EnumerateReaders)?;
    wait(&application, &events, &operation)?;
    println!("READER  CARD");
    for reader in application.readers() {
        let card = match reader.card_present {
            Some(true) => "present",
            Some(false) => "absent",
            None => "unknown",
        };
        println!("{}  {card}", reader.name);
    }
    application.shutdown()?;
    Ok(())
}

struct ReplayBackend {
    trace: TraceDocument,
}

struct ReplayAdapter {
    session: ReplaySession,
}

impl CardSession for ReplayAdapter {
    type Error = ReplayError;

    fn protocol(&self) -> Protocol {
        Protocol::T1
    }

    fn capabilities(&self) -> SessionCapabilities {
        SessionCapabilities {
            extended_apdus: true,
        }
    }

    fn atr(&self) -> std::result::Result<Atr, Self::Error> {
        self.session.atr().cloned()
    }

    fn reset(&mut self, mode: ResetMode) -> std::result::Result<Atr, Self::Error> {
        match mode {
            ResetMode::Cold => self.session.cold_reset().cloned(),
            ResetMode::Warm => self.session.warm_reset().cloned(),
        }
    }

    fn transmit(&mut self, command: &[u8]) -> std::result::Result<ApduResponse, Self::Error> {
        self.session.transmit(command)
    }

    fn disconnect(mut self) -> std::result::Result<(), Self::Error> {
        self.session.disconnect();
        Ok(())
    }
}

impl SessionBackend for ReplayBackend {
    type Session = ReplayAdapter;

    fn list_readers(&self) -> cardpeek_app::Result<Vec<ReaderInfo>> {
        Ok(vec![ReaderInfo {
            name: "Replay".into(),
            transport: TransportKind::Replay,
            card_present: Some(true),
        }])
    }

    fn connect(&self, _request: &ConnectRequest) -> cardpeek_app::Result<Self::Session> {
        let mut session = ReplaySession::new(self.trace.clone());
        session.connect().map_err(transport_error)?;
        Ok(ReplayAdapter { session })
    }
}

#[allow(clippy::too_many_arguments)]
fn run_pcsc(
    reader: String,
    analysers: PathBuf,
    analyser: String,
    output: PathBuf,
    trace_output: Option<PathBuf>,
    trace_mode: TraceMode,
) -> Result<()> {
    run_analyser(
        PcscBackend::establish()?,
        reader,
        TransportKind::Pcsc,
        analysers,
        analyser,
        output,
        trace_output,
        trace_mode,
        "pcsc",
    )
}

#[allow(clippy::too_many_arguments)]
fn run_analyser<B: SessionBackend>(
    backend: B,
    reader: String,
    transport: TransportKind,
    analysers: PathBuf,
    analyser: String,
    output: PathBuf,
    trace_output: Option<PathBuf>,
    trace_mode: TraceMode,
    fixture_id: &str,
) -> Result<()> {
    let application = Application::with_defaults(backend);
    let events = application.subscribe();
    let discovery = application.submit(CommandKind::DiscoverAnalysers(analysers))?;
    wait(&application, &events, &discovery)?;
    if !application
        .analysers()
        .iter()
        .any(|item| item.id == analyser)
    {
        return Err(CliError::UnknownAnalyser(analyser));
    }
    let session =
        application.submit(CommandKind::Connect(ConnectRequest::new(reader, transport)))?;
    wait(&application, &events, &session)?;
    let run_id = cardpeek_core::RunId::new(format!("run-{fixture_id}"))?;
    let run = application.submit(CommandKind::RunAnalyser(RunAnalyserRequest {
        analyser,
        run_id: run_id.clone(),
        document_id: cardpeek_core::DocumentId::new(format!("doc-{fixture_id}"))?,
    }))?;
    wait(&application, &events, &run)?;
    let document = application
        .document_snapshot(&run_id)
        .ok_or_else(|| cardpeek_app::AppError::MissingDocument(run_id.clone()))?;
    application.export_document_now(&cardpeek_app::ExportDocument {
        run_id,
        destination: output,
    })?;
    println!(
        "Exported {} nodes in revision {}",
        document.document.node_count(),
        document.revision
    );
    let disconnect = application.submit(CommandKind::Disconnect)?;
    wait(&application, &events, &disconnect)?;
    if let Some(destination) = trace_output {
        application.export_trace_now(&ExportTrace {
            session,
            mode: trace_mode.into(),
            destination: destination.clone(),
        })?;
        println!("Exported trace to {}", destination.display());
    }
    application.shutdown()?;
    Ok(())
}

fn replay(trace: PathBuf, analysers: PathBuf, analyser: String, output: PathBuf) -> Result<()> {
    let fixture_id = trace_file_stem(&trace);
    let trace = TraceDocument::load(trace)?;
    run_analyser(
        ReplayBackend { trace },
        "Replay".into(),
        TransportKind::Replay,
        analysers,
        analyser,
        output,
        None,
        TraceMode::Raw,
        &fixture_id,
    )
}

fn transmit(
    reader: String,
    command: &str,
    trace_output: Option<PathBuf>,
    trace_mode: TraceMode,
) -> Result<()> {
    let command = ByteString::from_hex(8, command)?
        .as_bytes()
        .unwrap_or_default()
        .to_vec();
    let application = Application::with_defaults(PcscBackend::establish()?);
    let events = application.subscribe();
    let session = application.submit(CommandKind::Connect(ConnectRequest::new(
        reader,
        TransportKind::Pcsc,
    )))?;
    wait(&application, &events, &session)?;
    let transmit = application.submit(CommandKind::Transmit(command))?;
    wait(&application, &events, &transmit)?;
    let disconnect = application.submit(CommandKind::Disconnect)?;
    wait(&application, &events, &disconnect)?;
    if let Some(destination) = trace_output {
        application.export_trace_now(&ExportTrace {
            session,
            mode: trace_mode.into(),
            destination: destination.clone(),
        })?;
        println!("Exported trace to {}", destination.display());
    }
    application.shutdown()?;
    Ok(())
}

fn trace_file_stem(trace: &std::path::Path) -> String {
    trace
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|stem| !stem.is_empty())
        .unwrap_or("replay")
        .to_owned()
}

fn wait<B: SessionBackend>(
    application: &Application<B>,
    events: &cardpeek_app::EventSubscription,
    operation: &OperationId,
) -> Result<()> {
    loop {
        let Some(event) = events.recv_timeout(Duration::from_secs(5)) else {
            return Err(CliError::Timeout(operation.clone()));
        };
        match event.kind {
            EventKind::LogEmitted { level, message, .. } => {
                eprintln!("{level:?}: {message}");
            }
            EventKind::ApduExchanged {
                command,
                response,
                record,
                ..
            } => {
                println!("{record} TX {}", hex(&command));
                println!(
                    "{record} RX {}{:04X}",
                    hex(&response.data),
                    response.status.value()
                );
            }
            EventKind::OperationCompleted { operation: id } if id == *operation => {
                if application
                    .operation(operation)
                    .is_some_and(|item| item.status == OperationStatus::Completed)
                {
                    return Ok(());
                }
            }
            EventKind::OperationFailed {
                operation: id,
                error,
            } if id == *operation => {
                return Err(CliError::Operation {
                    operation: id,
                    error,
                });
            }
            EventKind::OperationCancelled { operation: id } if id == *operation => {
                return Err(CliError::Operation {
                    operation: id,
                    error: "cancelled".into(),
                });
            }
            _ => {}
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    ByteString::from_bytes(bytes.to_vec()).to_hex()
}
