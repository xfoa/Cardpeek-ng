#![allow(missing_docs)]

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use cardpeek_analyser::AnalyserLibrary;
use cardpeek_app::{
    Application, CommandKind, ConnectRequest, DecodeAnalyserRequest, ExportDocument,
    ReplayAnalyserRequest, RunAnalyserRequest, SessionBackend,
};
use cardpeek_core::{ResetMode, TraceDocument, TransportKind};

use crate::state::{AnalysisOperation, DesktopState, ExportKind, ExportNotice};

pub enum UiMessage {
    Event(cardpeek_app::Event),
    Error(String),
    Export(Result<ExportNotice, String>),
    ExportDestination(PathBuf),
    InteractionFile(PathBuf),
    AnalyserChanged(Result<Vec<String>, String>),
    TraceSelected(Result<(PathBuf, TraceDocument), String>),
}

pub struct Controller<B: SessionBackend> {
    application: Arc<Application<B>>,
    analyser_library: AnalyserLibrary,
    messages: Receiver<UiMessage>,
    pending_message: RefCell<Option<UiMessage>>,
    last_reader_refresh: Cell<Option<Instant>>,
    sender: Sender<UiMessage>,
}

impl Controller<crate::DesktopBackend> {
    pub fn for_desktop(backend: crate::DesktopBackend, analyser_library: AnalyserLibrary) -> Self {
        Self::new(backend, analyser_library)
    }
}

impl<B: SessionBackend> PartialEq for Controller<B> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.application, &other.application)
    }
}

impl<B: SessionBackend> Controller<B> {
    pub fn new(backend: B, analyser_library: AnalyserLibrary) -> Self {
        let application = Arc::new(Application::with_defaults(backend));
        Self::from_application(application, analyser_library)
    }

    fn from_application(
        application: Arc<Application<B>>,
        analyser_library: AnalyserLibrary,
    ) -> Self {
        let subscription = application.subscribe();
        let (sender, messages) = mpsc::channel();
        let event_sender = sender.clone();
        spawn_task("cardpeek-desktop-events", move || {
            while let Some(event) = subscription.recv() {
                if event_sender.send(UiMessage::Event(event)).is_err() {
                    break;
                }
            }
        });
        let controller = Self {
            application,
            analyser_library,
            messages,
            pending_message: RefCell::new(None),
            last_reader_refresh: Cell::new(None),
            sender,
        };
        let _ = controller.submit(CommandKind::EnumerateReaders);
        controller.refresh_analysers();
        controller
    }

    pub fn refresh_readers(&self, state: &mut DesktopState) {
        if !state.pending.is_empty()
            || self
                .last_reader_refresh
                .get()
                .is_some_and(|last| last.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        self.last_reader_refresh.set(Some(Instant::now()));
        if let Some(operation) = self.submit(CommandKind::EnumerateReaders) {
            state
                .pending
                .insert(operation, cardpeek_app::OperationKind::EnumerateReaders);
        }
    }

    pub fn poll_pending(&self) -> bool {
        if self.pending_message.borrow().is_some() {
            return true;
        }
        match self.messages.try_recv() {
            Ok(message) => {
                self.pending_message.replace(Some(message));
                true
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => false,
        }
    }

    pub fn poll(&self, state: &mut DesktopState) {
        state.session = self.application.session();
        let pending = self.pending_message.take();
        for message in pending.into_iter().chain(self.messages.try_iter()) {
            match message {
                UiMessage::Event(event) => {
                    state.apply_event(event);
                    self.refresh_capture(state);
                }
                UiMessage::Error(error)
                | UiMessage::Export(Err(error))
                | UiMessage::AnalyserChanged(Err(error))
                | UiMessage::TraceSelected(Err(error)) => {
                    state.errors.push(error.clone());
                    state.notify_error(error);
                }
                UiMessage::Export(Ok(notice)) => state.export_finished(notice),
                UiMessage::ExportDestination(path) => {
                    state.export_destination = path.display().to_string();
                }
                UiMessage::InteractionFile(path) => {
                    state.interaction_file = Some(path);
                }
                UiMessage::AnalyserChanged(Ok(imported)) => {
                    state.notify(if imported.is_empty() {
                        "Analyser library updated.".into()
                    } else {
                        format!("Imported {}.", imported.join(", "))
                    });
                    self.refresh_analysers();
                }
                UiMessage::TraceSelected(Ok((path, trace))) => {
                    state.set_trace(trace);
                    state.trace_path = Some(path);
                    state.notify("Trace opened. The physical session is unchanged.");
                    state.screen = crate::state::Screen::Trace;
                }
            }
        }
        state.session = self.application.session();
        state.readers = self
            .application
            .readers()
            .into_iter()
            .filter(|reader| reader.transport == TransportKind::Pcsc)
            .collect();
        if state.analyser_directory.is_empty() {
            state.analyser_directory = self.analyser_library.root().display().to_string();
        }
        if state
            .selected_reader
            .as_ref()
            .is_none_or(|selected| !state.readers.iter().any(|reader| &reader.name == selected))
        {
            state.selected_reader = state.readers.first().map(|reader| reader.name.clone());
        }
        let analysers = self.application.analysers();
        if state.analysers != analysers {
            state.analysers = analysers;
        }
        if state.selected_analyser.as_ref().is_none_or(|selected| {
            !state
                .analysers
                .iter()
                .any(|analyser| &analyser.id == selected)
        }) {
            state.selected_analyser = state.analysers.first().map(|analyser| analyser.id.clone());
        }
        if state.session.is_none()
            && self.application.session().is_none()
            && state.pending.is_empty()
            && let Some(reader) = state.pending_connection.take()
        {
            self.connect(reader, state);
        }
        self.refresh_capture(state);
        if let Some(run_id) = state.run_id.clone()
            && let Some(document) = self.application.document_snapshot(&run_id)
        {
            state.publish_document(document);
        }
    }

    fn refresh_capture(&self, state: &mut DesktopState) {
        if let Some(session) = &state.session
            && let Some(trace) = self.application.trace_snapshot(&session.id)
        {
            state.set_capture_trace((*trace).clone());
        }
    }

    #[must_use]
    pub fn submit(&self, kind: CommandKind) -> Option<cardpeek_app::OperationId> {
        match self.application.submit(kind) {
            Ok(operation) => Some(operation),
            Err(error) => {
                self.send_error(format!("Cannot submit command: {error}"));
                None
            }
        }
    }

    pub fn connect(&self, reader: String, state: &mut DesktopState) {
        let Some(reader_info) = state
            .readers
            .iter()
            .find(|candidate| candidate.name == reader)
            .filter(|reader| reader.transport == TransportKind::Pcsc)
        else {
            state.notify_error("Select a physical PC/SC reader.");
            return;
        };
        let transport = reader_info.transport;
        if state.session.is_some()
            || self.application.session().is_some()
            || state.pending.values().any(|kind| {
                matches!(
                    kind,
                    cardpeek_app::OperationKind::Connect | cardpeek_app::OperationKind::Disconnect
                )
            })
        {
            state.pending_connection = Some(reader.clone());
            let different_session = state
                .session
                .as_ref()
                .is_some_and(|session| session.reader.name != reader);
            let disconnecting = state
                .pending
                .values()
                .any(|kind| matches!(kind, cardpeek_app::OperationKind::Disconnect));
            if state.session_connected() && different_session && !disconnecting {
                self.disconnect(state);
            }
            return;
        }
        state.session = None;
        state.capture_trace = None;
        state.session_exchanges.clear();
        let request = ConnectRequest::new(reader, transport);
        if let Some(operation) = self.submit(CommandKind::Connect(request)) {
            state
                .pending
                .insert(operation, cardpeek_app::OperationKind::Connect);
        }
    }

    pub fn disconnect(&self, state: &mut DesktopState) {
        if let Some(operation) = self.submit(CommandKind::Disconnect) {
            state
                .pending
                .insert(operation, cardpeek_app::OperationKind::Disconnect);
        }
    }

    pub fn new_session(&self, state: &mut DesktopState) {
        if !state.card_present() || state.run_running() || state.new_session_pending() {
            return;
        }
        if let Some(operation) = self.submit(CommandKind::NewSession) {
            state
                .pending
                .insert(operation.clone(), cardpeek_app::OperationKind::NewSession);
            state.new_session_operation = Some(operation);
            state.notify("Starting a new session.");
        }
    }

    pub fn reset(&self, state: &mut DesktopState) {
        if !state.card_present() {
            state.notify_error("A connected physical card is required.");
            return;
        }
        if let Some(operation) = self.submit(CommandKind::Reset(ResetMode::Warm)) {
            state
                .pending
                .insert(operation, cardpeek_app::OperationKind::Reset);
        }
    }

    pub fn transmit(&self, command: &str, state: &mut DesktopState) {
        if !state.card_present() {
            state.notify_error("Manual transmission requires a connected physical card.");
            return;
        }
        let parsed = cardpeek_core::ByteString::from_hex(8, command)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                bytes
                    .as_bytes()
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| "The command must contain complete bytes.".into())
            });
        match parsed {
            Ok(command) => {
                if let Some(operation) = self.submit(CommandKind::Transmit(command)) {
                    state
                        .pending
                        .insert(operation, cardpeek_app::OperationKind::Transmit);
                }
            }
            Err(error) => state.notify_error(format!("Invalid APDU: {error}")),
        }
    }

    pub fn select_trace_file(&self, path: PathBuf) {
        let sender = self.sender.clone();
        spawn_task("cardpeek-desktop-trace-loader", move || {
            let result = TraceDocument::load(&path)
                .map(|trace| (path, trace))
                .map_err(|error| error.to_string());
            let _ = sender.send(UiMessage::TraceSelected(result));
        });
    }

    pub fn select_segment(&self, segment: usize, state: &mut DesktopState) {
        if state
            .trace
            .as_ref()
            .is_some_and(|trace| trace.segment(segment).is_some())
        {
            state.selected_trace_segment = segment;
            state.select_analysis_input(crate::state::AnalysisInput::TraceSegment { segment });
        }
    }

    pub fn run(&self, analyser: String, state: &mut DesktopState) {
        let Some(operation_kind) = state.analysis_operation() else {
            if let Some(requirement) = state.analysis_requirement() {
                state.notify_error(requirement);
            }
            return;
        };
        if !state.can_run() {
            state.notify_error(
                state
                    .analysis_requirement()
                    .unwrap_or_else(|| "The current operation cannot start yet.".into()),
            );
            return;
        }
        let Some((run_id, document_id)) = state.next_run() else {
            return;
        };
        let common = RunAnalyserRequest {
            analyser,
            run_id,
            document_id,
        };
        let kind = match operation_kind {
            AnalysisOperation::Collect => CommandKind::CollectAnalyser(common),
            AnalysisOperation::Decode { segment } => {
                let Some(trace) = state.trace.clone() else {
                    return;
                };
                CommandKind::DecodeAnalyser(DecodeAnalyserRequest {
                    analyser: common.analyser,
                    run_id: common.run_id,
                    document_id: common.document_id,
                    trace,
                    segment,
                })
            }
            AnalysisOperation::Replay { segment } => {
                let Some(trace) = state.trace.clone() else {
                    return;
                };
                CommandKind::ReplayAnalyser(ReplayAnalyserRequest {
                    analyser: common.analyser,
                    run_id: common.run_id,
                    document_id: common.document_id,
                    trace,
                    segment,
                })
            }
        };
        let operation = self.application.submit(kind);
        match operation {
            Ok(operation) => {
                let pending_kind = match operation_kind {
                    AnalysisOperation::Collect => cardpeek_app::OperationKind::CollectAnalyser,
                    AnalysisOperation::Decode { .. } => cardpeek_app::OperationKind::DecodeAnalyser,
                    AnalysisOperation::Replay { .. } => cardpeek_app::OperationKind::ReplayAnalyser,
                };
                state.pending.insert(operation.clone(), pending_kind);
                state.run_operation = Some(operation);
            }
            Err(error) => {
                state.run_status = crate::state::RunStatus::Failed;
                self.send_error(format!("Cannot start analyser: {error}"));
            }
        }
    }

    pub fn cancel(&self, state: &DesktopState) {
        if let Some(operation) = &state.run_operation {
            let _ = self.submit(CommandKind::Cancel(operation.clone()));
        }
    }

    pub fn answer(&self, answer: cardpeek_app::AnswerInteraction, state: &mut DesktopState) {
        let _ = self.submit(CommandKind::AnswerInteraction(answer));
        state.interaction = None;
        state.interaction_operation = None;
    }

    pub fn select_analyser_files(&self, paths: Vec<PathBuf>) {
        let sender = self.sender.clone();
        let library = self.analyser_library.clone();
        spawn_task("cardpeek-desktop-analyser-import", move || {
            let result = library
                .import_files(paths.iter().map(PathBuf::as_path))
                .map(|imported| imported.into_iter().map(|analyser| analyser.id).collect())
                .map_err(|error| error.to_string());
            let _ = sender.send(UiMessage::AnalyserChanged(result));
        });
    }

    pub fn remove_analyser(&self, state: &mut DesktopState) {
        let Some(analyser) = state.selected_analyser.clone() else {
            state.notify_error("Select an analyser to remove.");
            return;
        };
        let sender = self.sender.clone();
        let library = self.analyser_library.clone();
        spawn_task("cardpeek-desktop-analyser-removal", move || {
            let result = library
                .remove(&analyser)
                .map(|removed| vec![format!("Removed {}", removed.id)])
                .map_err(|error| error.to_string());
            let _ = sender.send(UiMessage::AnalyserChanged(result));
        });
    }

    fn refresh_analysers(&self) {
        let _ = self.submit(CommandKind::DiscoverAnalysers(
            self.analyser_library.root().to_path_buf(),
        ));
    }

    pub fn export(&self, state: &mut DesktopState) {
        let destination = PathBuf::from(state.export_destination.trim());
        if destination.as_os_str().is_empty() {
            state.notify_error("Choose an export destination.");
            return;
        }
        let request = match state.export_kind {
            ExportKind::Document => state.document.as_ref().map(|document| {
                ExportRequest::Document(ExportDocument {
                    run_id: document.run_id.clone(),
                    destination: destination.clone(),
                })
            }),
            ExportKind::Trace => state.export_trace().map(ExportRequest::Trace),
        };
        let Some(request) = request else {
            state.notify_error("The selected export is not available.");
            return;
        };
        let application = self.application.clone();
        let sender = self.sender();
        let mode = state.trace_export_mode;
        state.show_export = false;
        spawn_task("cardpeek-desktop-export", move || {
            let path = destination.display().to_string();
            let result =
                match request {
                    ExportRequest::Document(export) => application
                        .export_document_now(&export)
                        .map(|()| ExportNotice::Document {
                            run_id: export.run_id,
                            path,
                        }),
                    ExportRequest::Trace(trace) => {
                        let trace = match mode {
                            cardpeek_app::TraceExportMode::Raw => trace,
                            cardpeek_app::TraceExportMode::Sanitised => trace.sanitised(),
                        };
                        trace
                            .save(&destination)
                            .map_err(cardpeek_app::AppError::from)
                            .map(|()| ExportNotice::Trace { path })
                    }
                }
                .map_err(|error| error.to_string());
            let _ = sender.send(UiMessage::Export(result));
        });
    }

    fn sender(&self) -> Sender<UiMessage> {
        self.sender.clone()
    }

    fn send_error(&self, message: String) {
        let _ = self.sender.send(UiMessage::Error(message));
    }
}

enum ExportRequest {
    Document(ExportDocument),
    Trace(TraceDocument),
}

fn spawn_task(name: &str, task: impl FnOnce() + Send + 'static) {
    if let Err(error) = thread::Builder::new().name(name.into()).spawn(task) {
        eprintln!("cardpeek-desktop: cannot create {name}: {error}");
    }
}
