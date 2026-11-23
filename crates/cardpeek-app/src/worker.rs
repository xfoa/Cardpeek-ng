use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use cardpeek_analyser::{
    AnalyserMetadata, Cancellation, CardHost, EventSink, ExecutionRequest, HostError,
};
use cardpeek_core::{
    ApduCommand, ApduResponse, Atr, Protocol, ReaderInfo, ResetMode, ResultDocument, RunId,
    TraceDocument, TraceRecordId,
};
use cardpeek_replay::ReplaySession;
use cardpeek_transport::{CardSession, CardStatus, SessionCapabilities};

use crate::state::SharedState;
use crate::sync::{CancellationToken, CommandQueue, EventQueue, lock_unpoisoned};
use crate::{
    AnalyserContext, AppError, CommandKind, ConnectRequest, Event, EventKind, InteractionKind,
    InteractionResponse, LogLevel, OperationId, OperationStatus, Result, SessionState,
    TraceExportMode, emit_to, is_cancellation, transport_error,
};

/// Factory for reader discovery and owned card sessions.
pub trait SessionBackend: Send + Sync + 'static {
    /// Blocking card session implementation.
    type Session: CardSession + Send + 'static;

    /// Lists currently available readers.
    ///
    /// # Errors
    ///
    /// Returns a native backend error when discovery fails.
    fn list_readers(&self) -> Result<Vec<ReaderInfo>>;

    /// Connects to one reader.
    ///
    /// # Errors
    ///
    /// Returns a native backend error when connection fails.
    fn connect(&self, request: &ConnectRequest) -> Result<Self::Session>;

    /// Returns a native interrupt callback for one cancellation token.
    ///
    /// Backends that cannot interrupt native waits can return `None`.
    fn cancellation_interrupt(
        &self,
        _token: &CancellationToken,
    ) -> Option<Box<dyn Fn() + Send + Sync>> {
        None
    }
}

/// Blocking operations issued by an analyser worker.
pub trait AnalyserHost {
    /// Returns the cancellation token for this operation.
    fn token(&self) -> &CancellationToken;

    /// Returns the source record for the current ATR when known.
    fn current_atr_record(&self) -> Option<cardpeek_core::TraceRecordId> {
        None
    }

    /// Returns the current Answer to Reset.
    ///
    /// # Errors
    ///
    /// Returns a structured transport error or cancellation error.
    fn atr(&self) -> Result<Atr>;

    /// Resets the active card.
    ///
    /// # Errors
    ///
    /// Returns a structured transport error or cancellation error.
    fn reset(&mut self, mode: ResetMode) -> Result<Atr>;

    /// Transmits exact APDU command bytes.
    ///
    /// # Errors
    ///
    /// Returns a structured transport error or cancellation error.
    fn transmit(&mut self, command: &[u8]) -> Result<ApduResponse>;
}

#[derive(Debug)]
pub(crate) struct WorkerCommand {
    pub(crate) operation: OperationId,
    pub(crate) kind: CommandKind,
    pub(crate) token: CancellationToken,
}

pub(crate) struct SessionRuntime<B: SessionBackend> {
    pub(crate) backend: Arc<B>,
    pub(crate) shared: SharedState,
    pub(crate) subscribers: Arc<std::sync::Mutex<Vec<Arc<EventQueue>>>>,
    pub(crate) session_traces: Arc<std::sync::Mutex<HashMap<OperationId, Arc<TraceDocument>>>>,
    pub(crate) sequence: Arc<std::sync::Mutex<u64>>,
    pub(crate) analysers: Arc<std::sync::Mutex<HashMap<String, AnalyserMetadata>>>,
    pub(crate) documents: Arc<std::sync::Mutex<HashMap<RunId, Arc<ResultDocument>>>>,
    pub(crate) interactions:
        Arc<std::sync::Mutex<HashMap<crate::InteractionId, Arc<crate::InteractionSlot>>>>,
    pub(crate) interaction_timeout: std::time::Duration,
}

impl<B: SessionBackend> SessionRuntime<B> {
    fn analyser_context(
        &self,
        operation: &OperationId,
        run_id: RunId,
        token: &CancellationToken,
    ) -> AnalyserContext {
        AnalyserContext::new(
            operation.clone(),
            run_id,
            token.clone(),
            self.subscribers.clone(),
            self.sequence.clone(),
            self.interactions.clone(),
            self.interaction_timeout,
        )
    }
}

pub(crate) struct OfflineContext {
    pub(crate) shared: SharedState,
    pub(crate) subscribers: Arc<std::sync::Mutex<Vec<Arc<EventQueue>>>>,
    pub(crate) documents: Arc<std::sync::Mutex<HashMap<RunId, Arc<ResultDocument>>>>,
    pub(crate) analysers: Arc<std::sync::Mutex<HashMap<String, AnalyserMetadata>>>,
    pub(crate) interactions:
        Arc<std::sync::Mutex<HashMap<crate::InteractionId, Arc<crate::InteractionSlot>>>>,
    pub(crate) sequence: Arc<std::sync::Mutex<u64>>,
    pub(crate) interaction_timeout: std::time::Duration,
}

impl<B: SessionBackend> SessionRuntime<B> {
    pub(crate) fn spawn_offline(
        context: OfflineContext,
        operation: OperationId,
        request: CommandKind,
        token: CancellationToken,
    ) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name(format!("cardpeek-offline-{}", operation.as_str()))
            .spawn(move || {
                OfflineRuntime { context }.run(&operation, request, &token);
            })
            .expect("offline worker thread can be created")
    }

    pub(crate) fn spawn(
        self,
        operation: OperationId,
        request: ConnectRequest,
        commands: Arc<CommandQueue<WorkerCommand>>,
    ) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name(format!("cardpeek-session-{}", operation.as_str()))
            .spawn(move || self.run(&operation, &request, &commands))
            .expect("session worker thread can be created")
    }

    fn run(
        self,
        operation: &OperationId,
        request: &ConnectRequest,
        commands: &CommandQueue<WorkerCommand>,
    ) {
        let mut reader = ReaderInfo {
            name: request.reader.clone(),
            transport: request.transport,
            card_present: None,
        };
        self.emit(Event::new(
            operation.clone(),
            EventKind::SessionStateChanged {
                session: operation.clone(),
                state: SessionState::Connecting,
                reader: reader.clone(),
            },
        ));
        let token = request.cancellation.clone();
        let session = token.check().and_then(|()| self.backend.connect(request));
        let mut session = match session {
            Ok(session) => session,
            Err(error) => {
                self.fail_pending(operation, &AppError::NoActiveSession);
                self.shared.clear_worker(operation);
                self.fail(operation, &error);
                return;
            }
        };
        let status = match session.status().map_err(transport_error) {
            Ok(status) => status,
            Err(error) => {
                self.fail_pending(operation, &AppError::NoActiveSession);
                self.shared.clear_worker(operation);
                self.fail(operation, &error);
                return;
            }
        };
        if let Err(error) = token.check() {
            self.shared.clear_worker(operation);
            self.fail(operation, &error);
            return;
        }
        reader.card_present = Some(status.card_present);
        let mut trace = TraceDocument::new();
        if status.card_present {
            trace.record_reset(ResetMode::Cold, status.atr.clone());
        }
        self.snapshot_trace(operation, &trace);
        self.shared.set_session(
            operation,
            reader.clone(),
            status.protocol,
            session.capabilities(),
            status.atr,
        );
        self.emit(Event::new(
            operation.clone(),
            EventKind::SessionStateChanged {
                session: operation.clone(),
                state: SessionState::Connected,
                reader: reader.clone(),
            },
        ));
        self.complete(operation);

        let disconnect_operation =
            self.process_commands(operation, &mut reader, &mut session, &mut trace, commands);
        commands.close();
        self.fail_pending(operation, &AppError::Shutdown);
        self.cleanup(operation, reader, session, trace, disconnect_operation);
    }

    fn process_commands<S: CardSession>(
        &self,
        operation: &OperationId,
        reader: &mut ReaderInfo,
        session: &mut S,
        trace: &mut TraceDocument,
        commands: &CommandQueue<WorkerCommand>,
    ) -> Option<OperationId> {
        while !commands.is_closed() {
            if let Err(error) = self.refresh_card_status(operation, reader, session, trace) {
                self.emit(Event::new(
                    operation.clone(),
                    EventKind::OperationFailed {
                        operation: operation.clone(),
                        error: error.to_string(),
                    },
                ));
                return None;
            }
            let Some(command) = commands.pop_timeout(std::time::Duration::from_millis(100)) else {
                continue;
            };
            let disconnect = matches!(command.kind, CommandKind::Disconnect);
            let disconnect_operation = disconnect.then(|| command.operation.clone());
            self.shared.begin(&command.operation);
            let mut host = SessionHost {
                session_id: operation.clone(),
                session,
                trace,
                token: &command.token,
                operation: &command.operation,
                runtime: self,
            };
            let result = match &command.kind {
                CommandKind::Disconnect => {
                    self.shared.session_state(SessionState::Disconnecting);
                    command.token.check()
                }
                CommandKind::Reset(mode) => host.reset(*mode).map(|_| ()),
                CommandKind::Transmit(bytes) => ApduCommand::parse(bytes)
                    .map_err(AppError::Core)
                    .and_then(|_| host.transmit(bytes).map(|_| ())),
                CommandKind::RunAnalyser(request) => {
                    self.run_analyser(&command, request, &mut host)
                }
                CommandKind::CollectAnalyser(request) => {
                    self.collect_analyser(operation, &command, request, &mut host)
                }
                _ => Err(AppError::OperationInProgress),
            };
            match result {
                Ok(()) if !disconnect => self.complete(&command.operation),
                Ok(()) => {}
                Err(error) => self.fail(&command.operation, &error),
            }
            if disconnect {
                return disconnect_operation;
            }
        }
        None
    }

    fn run_analyser<S: CardSession>(
        &self,
        command: &WorkerCommand,
        request: &crate::RunAnalyserRequest,
        host: &mut SessionHost<'_, S, B>,
    ) -> Result<()> {
        let Some(metadata) = lock_unpoisoned(&self.analysers)
            .get(&request.analyser)
            .cloned()
        else {
            return Err(AppError::AnalyserNotFound(request.analyser.clone()));
        };
        let execution = ExecutionRequest {
            analyser: metadata,
            run_id: request.run_id.clone(),
            document_id: request.document_id.clone(),
        };
        let context =
            self.analyser_context(&command.operation, request.run_id.clone(), &command.token);
        let session_info = self.shared.session().ok_or(AppError::NoActiveSession)?;
        let events = WorkerEvents {
            context,
            interactive: session_info.reader.transport != cardpeek_core::TransportKind::Replay,
        };
        let current_record = host.current_atr_record();
        let mut runtime_host = RuntimeCardHost {
            host,
            protocol: session_info.protocol,
            capabilities: session_info.capabilities,
            current_record,
        };
        let document = cardpeek_lua::execute(&execution, &mut runtime_host, &events)
            .map_err(|error| AppError::Analyser(error.to_string()))?;
        self.publish_document(&command.operation, &request.run_id, &document);
        Ok(())
    }

    fn collect_analyser<S: CardSession>(
        &self,
        operation: &OperationId,
        command: &WorkerCommand,
        request: &crate::RunAnalyserRequest,
        host: &mut SessionHost<'_, S, B>,
    ) -> Result<()> {
        let session_info = self.shared.session().ok_or(AppError::NoActiveSession)?;
        if session_info.reader.transport != cardpeek_core::TransportKind::Pcsc
            || session_info.reader.card_present != Some(true)
        {
            return Err(AppError::CardNotPresent);
        }
        let Some(metadata) = lock_unpoisoned(&self.analysers)
            .get(&request.analyser)
            .cloned()
        else {
            return Err(AppError::AnalyserNotFound(request.analyser.clone()));
        };
        if !metadata.capabilities.live_collection {
            return Err(AppError::Analyser(format!(
                "analyser {} does not support live collection",
                metadata.id
            )));
        }
        let decode_capture = metadata.capabilities.offline_decoding;
        let segment = host.trace.segments().len().saturating_sub(1);
        let execution = ExecutionRequest {
            analyser: metadata,
            run_id: request.run_id.clone(),
            document_id: request.document_id.clone(),
        };
        let context =
            self.analyser_context(&command.operation, request.run_id.clone(), &command.token);
        let events = WorkerEvents {
            context,
            interactive: true,
        };
        let current_record = host.current_atr_record();
        let mut runtime_host = RuntimeCardHost {
            host: &mut *host,
            protocol: session_info.protocol,
            capabilities: session_info.capabilities,
            current_record,
        };
        let document = if decode_capture {
            let result =
                cardpeek_lua::execute_with_capture(&execution, &mut runtime_host, &events, segment)
                    .map_err(|error| AppError::Analyser(error.to_string()))?;
            host.trace.captures.push(result.capture);
            host.trace.validate()?;
            self.snapshot_trace(operation, host.trace);
            result.document
        } else {
            cardpeek_lua::execute(&execution, &mut runtime_host, &events)
                .map_err(|error| AppError::Analyser(error.to_string()))?
        };
        self.publish_document(&command.operation, &request.run_id, &document);
        Ok(())
    }

    fn refresh_card_status<S: CardSession>(
        &self,
        operation: &OperationId,
        reader: &mut ReaderInfo,
        session: &mut S,
        trace: &mut TraceDocument,
    ) -> Result<()> {
        let status = session.status().map_err(transport_error)?;
        let changed = reader.card_present != Some(status.card_present)
            || self.shared.session().is_some_and(|current| {
                current.protocol != status.protocol || current.atr != status.atr
            });
        if !changed {
            return Ok(());
        }
        let inserted = reader.card_present == Some(false) && status.card_present;
        reader.card_present = Some(status.card_present);
        if inserted {
            trace.record_reset(ResetMode::Cold, status.atr.clone());
        }
        self.snapshot_trace(operation, trace);
        self.publish_card_status(operation, status);
        Ok(())
    }

    fn publish_card_status(&self, operation: &OperationId, status: CardStatus) {
        self.shared
            .update_card_status(status.card_present, status.protocol, status.atr.clone());
        self.emit(Event::new(
            operation.clone(),
            EventKind::CardStatusChanged {
                session: operation.clone(),
                card_present: status.card_present,
                protocol: status.protocol,
                atr: status.atr,
            },
        ));
    }

    fn cleanup<S: CardSession>(
        &self,
        operation: &OperationId,
        reader: ReaderInfo,
        session: S,
        trace: TraceDocument,
        disconnect_operation: Option<OperationId>,
    ) {
        let disconnect_result = session.disconnect().map_err(transport_error);
        lock_unpoisoned(&self.session_traces).insert(operation.clone(), Arc::new(trace));
        self.shared.clear_session();
        self.shared.clear_worker(operation);
        self.emit(Event::new(
            operation.clone(),
            EventKind::SessionStateChanged {
                session: operation.clone(),
                state: SessionState::Disconnected,
                reader,
            },
        ));
        if let Some(disconnect_operation) = disconnect_operation {
            match disconnect_result {
                Ok(()) => self.complete(&disconnect_operation),
                Err(error) => self.fail(&disconnect_operation, &error),
            }
        } else if let Err(error) = disconnect_result {
            self.emit(Event::new(
                operation.clone(),
                EventKind::OperationFailed {
                    operation: operation.clone(),
                    error: error.to_string(),
                },
            ));
        }
    }

    fn fail_pending(&self, session: &OperationId, error: &AppError) {
        for pending in self.shared.fail_worker_operations(session) {
            self.emit(Event::new(
                pending.clone(),
                EventKind::OperationFailed {
                    operation: pending,
                    error: error.to_string(),
                },
            ));
        }
    }

    fn complete(&self, operation: &OperationId) {
        if !self.shared.finish(operation, OperationStatus::Completed) {
            return;
        }
        self.emit(Event::new(
            operation.clone(),
            EventKind::OperationCompleted {
                operation: operation.clone(),
            },
        ));
    }

    fn fail(&self, operation: &OperationId, error: &AppError) {
        let cancelled = crate::is_cancellation(error)
            || self
                .shared
                .operation(operation)
                .is_some_and(|operation| operation.status == OperationStatus::Cancelling);
        if !self.shared.finish(
            operation,
            if cancelled {
                OperationStatus::Cancelled
            } else {
                OperationStatus::Failed
            },
        ) {
            return;
        }
        let kind = if cancelled {
            EventKind::OperationCancelled {
                operation: operation.clone(),
            }
        } else {
            EventKind::OperationFailed {
                operation: operation.clone(),
                error: error.to_string(),
            }
        };
        self.emit(Event::new(operation.clone(), kind));
    }

    fn snapshot_trace(&self, operation: &OperationId, trace: &TraceDocument) {
        lock_unpoisoned(&self.session_traces).insert(operation.clone(), Arc::new(trace.clone()));
    }

    pub(crate) fn publish_document(
        &self,
        operation: &OperationId,
        run_id: &RunId,
        document: &ResultDocument,
    ) {
        lock_unpoisoned(&self.documents).insert(run_id.clone(), Arc::new(document.clone()));
        self.emit(Event::new(
            operation.clone(),
            EventKind::DocumentPublished {
                run_id: run_id.clone(),
                revision: document.revision,
            },
        ));
    }

    fn emit(&self, event: Event) {
        emit_to(&self.subscribers, &self.sequence, event);
    }
}

impl Cancellation for CancellationToken {
    fn is_cancelled(&self) -> bool {
        CancellationToken::is_cancelled(self)
    }
}

struct RuntimeCardHost<'a, H: AnalyserHost> {
    host: &'a mut H,
    protocol: cardpeek_core::Protocol,
    capabilities: SessionCapabilities,
    current_record: Option<TraceRecordId>,
}

impl<H: AnalyserHost> CardHost for RuntimeCardHost<'_, H> {
    type Cancellation = CancellationToken;

    fn protocol(&self) -> cardpeek_core::Protocol {
        self.protocol
    }

    fn capabilities(&self) -> SessionCapabilities {
        self.capabilities
    }

    fn atr(&mut self) -> std::result::Result<Atr, HostError> {
        self.host.atr().map_err(|error| host_error(&error))
    }

    fn reset(&mut self, mode: ResetMode) -> std::result::Result<Atr, HostError> {
        let atr = self.host.reset(mode).map_err(|error| host_error(&error))?;
        self.current_record = self.host.current_atr_record();
        Ok(atr)
    }

    fn transmit(&mut self, command: &[u8]) -> std::result::Result<ApduResponse, HostError> {
        self.host
            .transmit(command)
            .map_err(|error| host_error(&error))
    }

    fn cancellation(&self) -> &Self::Cancellation {
        self.host.token()
    }

    fn current_atr_record(&self) -> Option<TraceRecordId> {
        self.current_record.clone()
    }
}

fn host_error(error: &AppError) -> HostError {
    if is_cancellation(error) {
        HostError::cancelled()
    } else {
        HostError::new(error.to_string())
    }
}

struct WorkerEvents {
    context: AnalyserContext,
    interactive: bool,
}

impl EventSink for WorkerEvents {
    fn log(&self, level: cardpeek_analyser::LogLevel, message: &str) {
        let level = match level {
            cardpeek_analyser::LogLevel::Debug => LogLevel::Debug,
            cardpeek_analyser::LogLevel::Info => LogLevel::Info,
            cardpeek_analyser::LogLevel::Warning => LogLevel::Warning,
            cardpeek_analyser::LogLevel::Error => LogLevel::Error,
        };
        self.context.log(level, message);
    }
    fn interact(
        &self,
        kind: cardpeek_analyser::InteractionKind,
        prompt: &str,
    ) -> std::result::Result<cardpeek_analyser::InteractionResponse, cardpeek_analyser::HostError>
    {
        if !self.interactive {
            return Err(cardpeek_analyser::HostError::new(
                "interaction is unavailable during replay",
            ));
        }
        let kind = match kind {
            cardpeek_analyser::InteractionKind::Question => InteractionKind::Question {
                prompt: prompt.into(),
            },
            cardpeek_analyser::InteractionKind::Notice => InteractionKind::Notice {
                prompt: prompt.into(),
            },
            cardpeek_analyser::InteractionKind::Text { default } => InteractionKind::TextInput {
                prompt: prompt.into(),
                default,
            },
            cardpeek_analyser::InteractionKind::Secret => InteractionKind::SecretInput {
                prompt: prompt.into(),
            },
            cardpeek_analyser::InteractionKind::File { must_exist } => {
                InteractionKind::FileSelection {
                    prompt: prompt.into(),
                    must_exist,
                }
            }
        };
        let response = self
            .context
            .interact(kind)
            .map_err(|error| cardpeek_analyser::HostError::new(error.to_string()))?;
        match response {
            InteractionResponse::Bool(value) => {
                Ok(cardpeek_analyser::InteractionResponse::Bool(value))
            }
            InteractionResponse::Acknowledged => {
                Ok(cardpeek_analyser::InteractionResponse::Acknowledged)
            }
            InteractionResponse::Text(value) => {
                Ok(cardpeek_analyser::InteractionResponse::Text(value))
            }
            InteractionResponse::Secret(value) => {
                Ok(cardpeek_analyser::InteractionResponse::Secret(value))
            }
            InteractionResponse::File(value) => {
                Ok(cardpeek_analyser::InteractionResponse::File(value))
            }
        }
    }
}

struct SessionHost<'a, S: CardSession, B: SessionBackend> {
    session_id: OperationId,
    session: &'a mut S,
    trace: &'a mut TraceDocument,
    token: &'a CancellationToken,
    operation: &'a OperationId,
    runtime: &'a SessionRuntime<B>,
}

impl<S: CardSession, B: SessionBackend> AnalyserHost for SessionHost<'_, S, B> {
    fn token(&self) -> &CancellationToken {
        self.token
    }

    fn current_atr_record(&self) -> Option<TraceRecordId> {
        self.trace
            .records
            .iter()
            .rev()
            .find_map(|record| match record {
                cardpeek_core::TraceRecord::Reset { id, .. } => Some(id.clone()),
                cardpeek_core::TraceRecord::Command { .. } => None,
            })
    }

    fn atr(&self) -> Result<Atr> {
        self.token.check()?;
        self.session.atr().map_err(transport_error)
    }

    fn reset(&mut self, mode: ResetMode) -> Result<Atr> {
        self.token.check()?;
        self.runtime.shared.session_state(SessionState::Resetting);
        let atr = self.session.reset(mode).map_err(transport_error)?;
        self.trace.record_reset(mode, atr.clone());
        self.runtime.snapshot_trace(&self.session_id, self.trace);
        self.runtime.shared.update_atr(atr.clone());
        self.runtime.shared.session_state(SessionState::Connected);
        self.token.check()?;
        Ok(atr)
    }

    fn transmit(&mut self, command: &[u8]) -> Result<ApduResponse> {
        self.token.check()?;
        let response = self.session.transmit(command).map_err(transport_error)?;
        let record =
            self.trace
                .record_command(command.to_vec(), response.data.clone(), response.status);
        self.runtime.snapshot_trace(&self.session_id, self.trace);
        self.runtime.emit(Event::new(
            self.operation.clone(),
            EventKind::ApduExchanged {
                session: self.session_id.clone(),
                record,
                command: command.to_vec(),
                response: response.clone(),
            },
        ));
        Ok(response)
    }
}

struct OfflineRuntime {
    context: OfflineContext,
}

impl OfflineRuntime {
    fn run(self, operation: &OperationId, request: CommandKind, token: &CancellationToken) {
        self.context.shared.begin(operation);
        let result = match request {
            CommandKind::DecodeAnalyser(request) => self.decode(operation, &request, token),
            CommandKind::ReplayAnalyser(request) => self.replay(operation, &request, token),
            _ => Err(AppError::OperationInProgress),
        };
        match result {
            Ok(()) => self.complete(operation),
            Err(error) => self.fail(operation, &error),
        }
    }

    fn decode(
        &self,
        operation: &OperationId,
        request: &crate::DecodeAnalyserRequest,
        token: &CancellationToken,
    ) -> Result<()> {
        token.check()?;
        request.trace.validate()?;
        let metadata = self.analyser(&request.analyser)?;
        let capture = request
            .trace
            .captures
            .iter()
            .find(|capture| {
                capture.analyser == request.analyser && capture.segment == request.segment
            })
            .ok_or_else(|| {
                AppError::Analyser(format!(
                    "missing capture bundle for analyser {} in segment {}",
                    request.analyser, request.segment
                ))
            })?
            .clone();
        let execution = ExecutionRequest {
            analyser: metadata,
            run_id: request.run_id.clone(),
            document_id: request.document_id.clone(),
        };
        let events = WorkerEvents {
            context: self.context(operation, request.run_id.clone(), token),
            interactive: false,
        };
        let document = cardpeek_lua::decode_capture(&execution, &capture, token, &events)
            .map_err(|error| AppError::Analyser(error.to_string()))?;
        self.publish(operation, &request.run_id, &document);
        Ok(())
    }

    fn replay(
        &self,
        operation: &OperationId,
        request: &crate::ReplayAnalyserRequest,
        token: &CancellationToken,
    ) -> Result<()> {
        token.check()?;
        request.trace.validate()?;
        let metadata = self.analyser(&request.analyser)?;
        if !metadata.capabilities.replay {
            return Err(AppError::Analyser(format!(
                "analyser {} does not support replay",
                metadata.id
            )));
        }
        let trace = request.trace.extract_segment(request.segment)?;
        let mut session = ReplaySession::for_segment(trace, 0).map_err(|error| {
            AppError::Analyser(format!(
                "analyser {} segment {} replay error: {error}",
                request.analyser, request.segment
            ))
        })?;
        session.connect().map_err(|error| {
            AppError::Analyser(format!(
                "analyser {} segment {} replay error: {error}",
                request.analyser, request.segment
            ))
        })?;
        let execution = ExecutionRequest {
            analyser: metadata,
            run_id: request.run_id.clone(),
            document_id: request.document_id.clone(),
        };
        let events = WorkerEvents {
            context: self.context(operation, request.run_id.clone(), token),
            interactive: false,
        };
        let mut host = OfflineHost {
            session,
            token: token.clone(),
            operation: operation.clone(),
            runtime: self,
            analyser: request.analyser.clone(),
            segment: request.segment,
        };
        let current_record = host.current_atr_record();
        let mut runtime_host = RuntimeCardHost {
            host: &mut host,
            protocol: Protocol::T1,
            capabilities: SessionCapabilities {
                extended_apdus: true,
            },
            current_record,
        };
        let document = cardpeek_lua::execute(&execution, &mut runtime_host, &events)
            .map_err(|error| AppError::Analyser(error.to_string()))?;
        self.publish(operation, &request.run_id, &document);
        Ok(())
    }

    fn analyser(&self, id: &str) -> Result<AnalyserMetadata> {
        lock_unpoisoned(&self.context.analysers)
            .get(id)
            .cloned()
            .ok_or_else(|| AppError::AnalyserNotFound(id.into()))
    }

    fn context(
        &self,
        operation: &OperationId,
        run_id: RunId,
        token: &CancellationToken,
    ) -> AnalyserContext {
        AnalyserContext::new(
            operation.clone(),
            run_id,
            token.clone(),
            self.context.subscribers.clone(),
            self.context.sequence.clone(),
            self.context.interactions.clone(),
            self.context.interaction_timeout,
        )
    }

    fn publish(&self, operation: &OperationId, run_id: &RunId, document: &ResultDocument) {
        lock_unpoisoned(&self.context.documents).insert(run_id.clone(), Arc::new(document.clone()));
        self.emit(Event::new(
            operation.clone(),
            EventKind::DocumentPublished {
                run_id: run_id.clone(),
                revision: document.revision,
            },
        ));
    }

    fn complete(&self, operation: &OperationId) {
        if self
            .context
            .shared
            .finish(operation, OperationStatus::Completed)
        {
            self.emit(Event::new(
                operation.clone(),
                EventKind::OperationCompleted {
                    operation: operation.clone(),
                },
            ));
        }
    }

    fn fail(&self, operation: &OperationId, error: &AppError) {
        let cancelled = is_cancellation(error)
            || self
                .context
                .shared
                .operation(operation)
                .is_some_and(|operation| operation.status == OperationStatus::Cancelling);
        let status = if cancelled {
            OperationStatus::Cancelled
        } else {
            OperationStatus::Failed
        };
        if self.context.shared.finish(operation, status) {
            let kind = if cancelled {
                EventKind::OperationCancelled {
                    operation: operation.clone(),
                }
            } else {
                EventKind::OperationFailed {
                    operation: operation.clone(),
                    error: error.to_string(),
                }
            };
            self.emit(Event::new(operation.clone(), kind));
        }
    }

    fn emit(&self, event: Event) {
        emit_to(&self.context.subscribers, &self.context.sequence, event);
    }
}

struct OfflineHost<'a> {
    session: ReplaySession,
    token: CancellationToken,
    operation: OperationId,
    runtime: &'a OfflineRuntime,
    analyser: String,
    segment: usize,
}

impl AnalyserHost for OfflineHost<'_> {
    fn token(&self) -> &CancellationToken {
        &self.token
    }

    fn current_atr_record(&self) -> Option<TraceRecordId> {
        self.session.current_reset_id().cloned()
    }

    fn atr(&self) -> Result<Atr> {
        self.token.check()?;
        self.session.atr().cloned().map_err(transport_error)
    }

    fn reset(&mut self, mode: ResetMode) -> Result<Atr> {
        self.token.check()?;
        match mode {
            ResetMode::Cold => self.session.cold_reset().cloned(),
            ResetMode::Warm => self.session.warm_reset().cloned(),
        }
        .map_err(transport_error)
    }

    fn transmit(&mut self, command: &[u8]) -> Result<ApduResponse> {
        self.token.check()?;
        let recorded = self
            .session
            .transmit_with_record(command)
            .map_err(|error| {
                AppError::Analyser(format!(
                    "analyser {} segment {} missing command {}: {error}",
                    self.analyser,
                    self.segment,
                    cardpeek_core::ByteString::from_bytes(command.to_vec()).to_hex()
                ))
            })?;
        self.runtime.emit(Event::new(
            self.operation.clone(),
            EventKind::ApduExchanged {
                session: self.operation.clone(),
                record: recorded.record,
                command: command.to_vec(),
                response: recorded.response.clone(),
            },
        ));
        Ok(recorded.response)
    }
}

pub(crate) fn export_document(document: &ResultDocument, path: PathBuf) -> Result<()> {
    let mut json = document.to_json()?;
    json.push('\n');
    std::fs::write(path, json).map_err(AppError::Io)
}

pub(crate) fn export_trace(
    trace: &TraceDocument,
    mode: TraceExportMode,
    path: PathBuf,
) -> Result<()> {
    let trace = match mode {
        TraceExportMode::Raw => trace.clone(),
        TraceExportMode::Sanitised => trace.sanitised(),
    };
    trace.save(path).map_err(AppError::Core)
}
