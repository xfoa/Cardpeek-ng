//! Commands, events, session workers, and application state.

mod backend;
mod interaction;
mod state;
mod sync;
mod types;
mod worker;

use std::collections::HashMap;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cardpeek_core::{ReaderInfo, ResultDocument, RunId, TraceDocument};

pub use backend::PcscBackend;
pub use cardpeek_analyser::{AnalyserMetadata, discover};
pub use interaction::AnalyserContext;
use state::SharedState;
pub use sync::{CancellationHandle, CancellationToken, SubmitError};
use sync::{CommandQueue, EventQueue, InteractionSlot, lock_unpoisoned};
pub use types::*;
pub use worker::{AnalyserHost, SessionBackend};
use worker::{OfflineContext, SessionRuntime, WorkerCommand};

/// Owns the command dispatcher and all active session workers.
pub struct Application<B: SessionBackend> {
    backend: Arc<B>,
    config: EngineConfig,
    shared: SharedState,
    analysers: Arc<std::sync::Mutex<HashMap<String, AnalyserMetadata>>>,
    commands: Arc<CommandQueue<Command>>,
    subscribers: Arc<std::sync::Mutex<Vec<Arc<EventQueue>>>>,
    interactions: Arc<std::sync::Mutex<HashMap<InteractionId, Arc<InteractionSlot>>>>,
    cancellations: Arc<std::sync::Mutex<HashMap<OperationId, CancellationHandle>>>,
    documents: Arc<std::sync::Mutex<HashMap<RunId, Arc<ResultDocument>>>>,
    session_traces: Arc<std::sync::Mutex<HashMap<OperationId, Arc<TraceDocument>>>>,
    sequence: Arc<std::sync::Mutex<u64>>,
    workers: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
    dispatcher: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl<B: SessionBackend> Application<B> {
    /// Creates an application with the supplied backend and queue limits.
    #[must_use]
    pub fn new(backend: B, config: EngineConfig) -> Self {
        Self::with_shared_backend(Arc::new(backend), config)
    }

    /// Creates an application with default queue and timeout limits.
    #[must_use]
    pub fn with_defaults(backend: B) -> Self {
        Self::new(backend, EngineConfig::default())
    }

    /// Creates an application from a shared backend.
    #[must_use]
    pub fn with_shared_backend(backend: Arc<B>, config: EngineConfig) -> Self {
        let application = Self {
            backend,
            config,
            shared: SharedState::new(),
            analysers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            commands: Arc::new(CommandQueue::new(config.command_capacity)),
            subscribers: Arc::new(std::sync::Mutex::new(Vec::new())),
            interactions: Arc::new(std::sync::Mutex::new(HashMap::new())),
            cancellations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            documents: Arc::new(std::sync::Mutex::new(HashMap::new())),
            session_traces: Arc::new(std::sync::Mutex::new(HashMap::new())),
            sequence: Arc::new(std::sync::Mutex::new(0)),
            workers: Arc::new(std::sync::Mutex::new(Vec::new())),
            dispatcher: std::sync::Mutex::new(None),
        };
        let dispatcher = application.spawn_dispatcher();
        *lock_unpoisoned(&application.dispatcher) = Some(dispatcher);
        application
    }

    /// Creates an independent bounded event subscription.
    #[must_use]
    pub fn subscribe(&self) -> EventSubscription {
        let queue = Arc::new(EventQueue::new(self.config.event_capacity));
        lock_unpoisoned(&self.subscribers).push(queue.clone());
        EventSubscription { queue }
    }

    /// Submits a command without waiting for queue space.
    ///
    /// # Errors
    ///
    /// Returns `Full` when the bounded queue is full or `Closed` after shutdown.
    pub fn try_submit(&self, command: Command) -> std::result::Result<(), SubmitError> {
        self.commands.push(command)
    }

    /// Allocates identifiers and submits a command.
    ///
    /// # Errors
    ///
    /// Returns `Full` when the bounded queue is full or `Closed` after shutdown.
    pub fn submit(&self, kind: CommandKind) -> std::result::Result<OperationId, SubmitError> {
        let (id, operation) = self.shared.allocate_ids();
        self.try_submit(Command { id, kind })?;
        Ok(operation)
    }

    /// Returns an immutable operation snapshot.
    #[must_use]
    pub fn operation(&self, id: &OperationId) -> Option<Operation> {
        self.shared.operation(id)
    }

    /// Returns all operation snapshots in identifier order.
    #[must_use]
    pub fn operations(&self) -> Vec<Operation> {
        self.shared.operations()
    }

    /// Returns the active session snapshot, if present.
    #[must_use]
    pub fn session(&self) -> Option<SessionInfo> {
        self.shared.session()
    }

    /// Returns the most recently discovered readers.
    #[must_use]
    pub fn readers(&self) -> Vec<ReaderInfo> {
        self.shared.readers()
    }

    /// Creates analyser services that share this application's event and interaction brokers.
    #[must_use]
    pub fn analyser_context(
        &self,
        operation: OperationId,
        run_id: RunId,
        token: CancellationToken,
    ) -> AnalyserContext {
        AnalyserContext::new(
            operation,
            run_id,
            token,
            self.subscribers.clone(),
            self.sequence.clone(),
            self.interactions.clone(),
            self.config.interaction_timeout,
        )
    }

    /// Returns analysers from the latest successful static discovery.
    #[must_use]
    pub fn analysers(&self) -> Vec<AnalyserMetadata> {
        let mut analysers: Vec<_> = lock_unpoisoned(&self.analysers).values().cloned().collect();
        analysers.sort_by(|left, right| left.id.cmp(&right.id));
        analysers
    }

    /// Returns the latest immutable document for an analyser run.
    #[must_use]
    pub fn document_snapshot(&self, run_id: &RunId) -> Option<DocumentSnapshot> {
        let document = lock_unpoisoned(&self.documents).get(run_id).cloned()?;
        Some(DocumentSnapshot {
            run_id: run_id.clone(),
            revision: document.revision,
            document,
        })
    }

    /// Returns an immutable trace after native session cleanup.
    #[must_use]
    pub fn trace_snapshot(&self, session: &OperationId) -> Option<Arc<TraceDocument>> {
        lock_unpoisoned(&self.session_traces).get(session).cloned()
    }

    /// Returns the latest trace for the active session.
    #[must_use]
    pub fn active_trace_snapshot(&self) -> Option<Arc<TraceDocument>> {
        self.shared
            .session()
            .and_then(|session| self.trace_snapshot(&session.id))
    }

    /// Writes a document to an explicit native JSON destination.
    ///
    /// # Errors
    ///
    /// Returns an error when the document is missing or cannot be saved.
    pub fn export_document_now(&self, export: &ExportDocument) -> Result<()> {
        let document = lock_unpoisoned(&self.documents)
            .get(&export.run_id)
            .cloned()
            .ok_or_else(|| AppError::MissingDocument(export.run_id.clone()))?;
        worker::export_document(&document, export.destination.clone())
    }

    /// Writes a completed trace to an explicit native JSON destination.
    ///
    /// # Errors
    ///
    /// Returns an error when the trace is unavailable or cannot be saved.
    pub fn export_trace_now(&self, export: &ExportTrace) -> Result<()> {
        let trace = self
            .trace_snapshot(&export.session)
            .ok_or(AppError::TraceUnavailable)?;
        worker::export_trace(&trace, export.mode, export.destination.clone())
    }

    /// Requests cooperative cancellation and native interruption where supported.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or terminal operation.
    pub fn cancel(&self, operation: &OperationId) -> Result<()> {
        self.shared.mark_cancelling(operation)?;
        let handle = lock_unpoisoned(&self.cancellations)
            .get(operation)
            .cloned()
            .ok_or_else(|| AppError::UnknownOperation(operation.clone()))?;
        handle.cancel();
        Ok(())
    }

    /// Answers one interaction with its required response type.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown, answered, or mismatched interaction.
    pub fn answer_interaction(&self, answer: AnswerInteraction) -> Result<()> {
        let slot = lock_unpoisoned(&self.interactions)
            .get(&answer.request)
            .cloned()
            .ok_or_else(|| AppError::UnknownInteraction(answer.request.clone()))?;
        slot.answer(answer.response)
    }

    /// Validates and publishes an immutable document revision.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an invalid document.
    pub fn publish_document(&self, run_id: RunId, document: ResultDocument) -> Result<()> {
        document.validate()?;
        let revision = document.revision;
        lock_unpoisoned(&self.documents).insert(run_id.clone(), Arc::new(document));
        let operation = self
            .operations()
            .into_iter()
            .find(|operation| operation.run_id.as_ref() == Some(&run_id))
            .map_or_else(
                || OperationId::new("document-publication"),
                |operation| operation.id,
            );
        self.emit(Event::new(
            operation,
            EventKind::DocumentPublished { run_id, revision },
        ));
        Ok(())
    }

    /// Emits an analyser log event.
    pub fn emit_log(&self, run_id: RunId, level: LogLevel, message: impl Into<String>) {
        let operation = self
            .operations()
            .into_iter()
            .find(|operation| operation.run_id.as_ref() == Some(&run_id))
            .map_or_else(
                || OperationId::new("analyser-log"),
                |operation| operation.id,
            );
        self.emit(Event::new(
            operation,
            EventKind::LogEmitted {
                run_id,
                level,
                message: message.into(),
            },
        ));
    }

    /// Stops the dispatcher, cancels work, and joins all workers.
    ///
    /// # Errors
    ///
    /// Returns an error when shutdown cannot be submitted or a worker panics.
    pub fn shutdown(&self) -> Result<()> {
        self.commands
            .push(Command::new("shutdown", CommandKind::Shutdown))
            .map_err(|_| AppError::Shutdown)?;
        self.join()
    }

    fn join(&self) -> Result<()> {
        self.close_subscriptions();
        if let Some(handle) = lock_unpoisoned(&self.dispatcher).take() {
            handle.join().map_err(|_| AppError::WorkerPanicked)?;
        }
        let workers = std::mem::take(&mut *lock_unpoisoned(&self.workers));
        let mut panicked = false;
        for worker in workers {
            panicked |= worker.join().is_err();
        }
        if panicked {
            Err(AppError::WorkerPanicked)
        } else {
            Ok(())
        }
    }

    fn spawn_dispatcher(&self) -> JoinHandle<()> {
        let commands = self.commands.clone();
        let dispatcher = Dispatcher {
            backend: self.backend.clone(),
            config: self.config,
            shared: self.shared.clone(),
            analysers: self.analysers.clone(),
            subscribers: self.subscribers.clone(),
            interactions: self.interactions.clone(),
            cancellations: self.cancellations.clone(),
            documents: self.documents.clone(),
            session_traces: self.session_traces.clone(),
            sequence: self.sequence.clone(),
            workers: self.workers.clone(),
        };
        thread::Builder::new()
            .name("cardpeek-application".into())
            .spawn(move || {
                while let Some(command) = commands.pop() {
                    let shutdown = matches!(command.kind, CommandKind::Shutdown);
                    dispatcher.dispatch(command);
                    if shutdown {
                        commands.close();
                        break;
                    }
                }
            })
            .expect("application dispatcher thread can be created")
    }

    fn emit(&self, event: Event) {
        emit_to(&self.subscribers, &self.sequence, event);
    }

    fn close_subscriptions(&self) {
        for subscriber in lock_unpoisoned(&self.subscribers).iter() {
            subscriber.close();
        }
    }
}

impl<B: SessionBackend> Drop for Application<B> {
    fn drop(&mut self) {
        self.close_subscriptions();
        self.commands.close();
        for handle in lock_unpoisoned(&self.cancellations).values() {
            handle.cancel();
        }
        self.shared.close();
        if let Some(handle) = lock_unpoisoned(&self.dispatcher).take() {
            let _ = handle.join();
        }
        for worker in std::mem::take(&mut *lock_unpoisoned(&self.workers)) {
            let _ = worker.join();
        }
    }
}

struct Dispatcher<B: SessionBackend> {
    backend: Arc<B>,
    config: EngineConfig,
    shared: SharedState,
    analysers: Arc<std::sync::Mutex<HashMap<String, AnalyserMetadata>>>,
    subscribers: Arc<std::sync::Mutex<Vec<Arc<EventQueue>>>>,
    interactions: Arc<std::sync::Mutex<HashMap<InteractionId, Arc<InteractionSlot>>>>,
    cancellations: Arc<std::sync::Mutex<HashMap<OperationId, CancellationHandle>>>,
    documents: Arc<std::sync::Mutex<HashMap<RunId, Arc<ResultDocument>>>>,
    session_traces: Arc<std::sync::Mutex<HashMap<OperationId, Arc<TraceDocument>>>>,
    sequence: Arc<std::sync::Mutex<u64>>,
    workers: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
}

impl<B: SessionBackend> Dispatcher<B> {
    fn dispatch(&self, command: Command) {
        let operation = state::operation_for(&command.id);
        if let Err(error) = self.shared.register(&command, &operation) {
            self.emit(Event::new(
                operation.clone(),
                EventKind::OperationFailed {
                    operation,
                    error: error.to_string(),
                },
            ));
            return;
        }
        let token = CancellationToken::new();
        lock_unpoisoned(&self.cancellations).insert(operation.clone(), token.handle());
        match command.kind {
            CommandKind::EnumerateReaders => self.enumerate(&operation, &token),
            CommandKind::Connect(mut request) => {
                let handle = self.backend.cancellation_interrupt(&token).map_or_else(
                    || CancellationHandle::new(token.clone()),
                    |interrupt| CancellationHandle::with_interrupt(token.clone(), interrupt),
                );
                lock_unpoisoned(&self.cancellations).insert(operation.clone(), handle);
                request.cancellation = token;
                self.connect(&operation, request);
            }
            CommandKind::Disconnect
            | CommandKind::Reset(_)
            | CommandKind::NewSession
            | CommandKind::Transmit(_)
            | CommandKind::RunAnalyser(_)
            | CommandKind::CollectAnalyser(_) => {
                let handle = self.backend.cancellation_interrupt(&token).map_or_else(
                    || CancellationHandle::new(token.clone()),
                    |interrupt| CancellationHandle::with_interrupt(token.clone(), interrupt),
                );
                lock_unpoisoned(&self.cancellations).insert(operation.clone(), handle);
                let worker_command = WorkerCommand {
                    operation: operation.clone(),
                    kind: command.kind,
                    token,
                };
                if let Err(error) = self.shared.forward(worker_command) {
                    self.fail(&operation, &error);
                }
            }
            CommandKind::DecodeAnalyser(_) | CommandKind::ReplayAnalyser(_) => {
                self.offline(&operation, command.kind, token);
            }
            CommandKind::DiscoverAnalysers(root) => self.discover_analysers(&operation, &root),
            CommandKind::Cancel(target) => {
                let result = self
                    .shared
                    .mark_cancelling(&target)
                    .and_then(|()| {
                        lock_unpoisoned(&self.cancellations)
                            .get(&target)
                            .cloned()
                            .ok_or_else(|| AppError::UnknownOperation(target.clone()))
                    })
                    .map(|handle| handle.cancel());
                self.finish_result(&operation, result);
            }
            CommandKind::AnswerInteraction(answer) => {
                let result = lock_unpoisoned(&self.interactions)
                    .get(&answer.request)
                    .cloned()
                    .ok_or_else(|| AppError::UnknownInteraction(answer.request.clone()))
                    .and_then(|slot| slot.answer(answer.response));
                self.finish_result(&operation, result);
            }
            CommandKind::ExportDocument(export) => {
                let result = lock_unpoisoned(&self.documents)
                    .get(&export.run_id)
                    .cloned()
                    .ok_or_else(|| AppError::MissingDocument(export.run_id.clone()))
                    .and_then(|document| worker::export_document(&document, export.destination));
                self.finish_result(&operation, result);
            }
            CommandKind::ExportTrace(export) => {
                let result = lock_unpoisoned(&self.session_traces)
                    .get(&export.session)
                    .cloned()
                    .ok_or(AppError::TraceUnavailable)
                    .and_then(|trace| {
                        worker::export_trace(&trace, export.mode, export.destination)
                    });
                self.finish_result(&operation, result);
            }
            CommandKind::Shutdown => {
                self.shared.close();
                for handle in lock_unpoisoned(&self.cancellations).values() {
                    handle.cancel();
                }
                self.complete(&operation);
            }
        }
    }

    fn offline(&self, operation: &OperationId, request: CommandKind, token: CancellationToken) {
        let context = OfflineContext {
            shared: self.shared.clone(),
            subscribers: self.subscribers.clone(),
            documents: self.documents.clone(),
            analysers: self.analysers.clone(),
            interactions: self.interactions.clone(),
            sequence: self.sequence.clone(),
            interaction_timeout: self.config.interaction_timeout,
        };
        let handle = SessionRuntime::<B>::spawn_offline(context, operation.clone(), request, token);
        lock_unpoisoned(&self.workers).push(handle);
    }

    fn discover_analysers(&self, operation: &OperationId, root: &std::path::Path) {
        self.shared.begin(operation);
        match cardpeek_analyser::discover(root) {
            Ok(discovered) => {
                let mut analysers = lock_unpoisoned(&self.analysers);
                analysers.clear();
                for metadata in discovered {
                    analysers.insert(metadata.id.clone(), metadata);
                }
                self.complete(operation);
            }
            Err(error) => self.fail(operation, &AppError::AnalyserDiscovery(error)),
        }
    }

    fn enumerate(&self, operation: &OperationId, token: &CancellationToken) {
        self.shared.begin(operation);
        let result = token.check().and_then(|()| self.backend.list_readers());
        match result {
            Ok(readers) => {
                self.shared.set_readers(readers);
                self.complete(operation);
            }
            Err(error) => self.fail(operation, &error),
        }
    }

    fn connect(&self, operation: &OperationId, request: ConnectRequest) {
        self.shared.begin(operation);
        let queue = Arc::new(CommandQueue::new(self.config.worker_capacity));
        self.shared.reserve_worker(operation, queue.clone());
        let runtime = SessionRuntime {
            backend: self.backend.clone(),
            shared: self.shared.clone(),
            subscribers: self.subscribers.clone(),
            session_traces: self.session_traces.clone(),
            sequence: self.sequence.clone(),
            analysers: self.analysers.clone(),
            documents: self.documents.clone(),
            interactions: self.interactions.clone(),
            interaction_timeout: self.config.interaction_timeout,
        };
        let handle = runtime.spawn(operation.clone(), request, queue);
        lock_unpoisoned(&self.workers).push(handle);
    }

    fn finish_result(&self, operation: &OperationId, result: Result<()>) {
        match result {
            Ok(()) => self.complete(operation),
            Err(error) => self.fail(operation, &error),
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
        let cancelled = matches!(error, AppError::Cancelled)
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

    fn emit(&self, event: Event) {
        emit_to(&self.subscribers, &self.sequence, event);
    }
}

pub(crate) fn emit_to(
    subscribers: &Arc<std::sync::Mutex<Vec<Arc<EventQueue>>>>,
    sequence: &Arc<std::sync::Mutex<u64>>,
    mut event: Event,
) {
    let mut next = lock_unpoisoned(sequence);
    *next += 1;
    event.sequence = *next;
    let mut subscribers = lock_unpoisoned(subscribers);
    subscribers.retain(|subscriber| !subscriber.is_closed());
    for subscriber in subscribers.iter() {
        subscriber.push(event.clone());
    }
}

/// A bounded receiver for ordered application events.
#[derive(Clone, Debug)]
pub struct EventSubscription {
    queue: Arc<EventQueue>,
}

impl EventSubscription {
    /// Waits for the next event.
    ///
    /// Returns `None` after the subscription closes and its queued events are drained.
    #[must_use]
    pub fn recv(&self) -> Option<Event> {
        self.queue.next()
    }

    /// Waits for the next event for at most the supplied duration.
    #[must_use]
    pub fn recv_timeout(&self, timeout: Duration) -> Option<Event> {
        self.queue.next_timeout(timeout)
    }
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        if Arc::strong_count(&self.queue) == 2 {
            self.queue.close();
        }
    }
}
