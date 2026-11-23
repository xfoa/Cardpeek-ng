//! Offline application engine integration tests.

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use cardpeek_app::{
    AnswerInteraction, AppError, Application, CancellationToken, CommandId, CommandKind,
    ConnectRequest, DecodeAnalyserRequest, EngineConfig, EventKind, ExportDocument, ExportTrace,
    InteractionId, InteractionKind, InteractionResponse, LogLevel, OperationId, OperationStatus,
    ReplayAnalyserRequest, RunAnalyserRequest, SessionBackend, TraceExportMode, transport_error,
};
use cardpeek_core::{
    ApduResponse, Atr, DocumentId, NodeId, ResetMode, ResultDocument, ResultNode, RunId,
    TraceDocument,
};
use cardpeek_replay::ReplaySession;
use cardpeek_transport::{CardSession, CardStatus, SessionCapabilities};

#[derive(Debug)]
struct ReplayAdapter {
    session: ReplaySession,
}

impl CardSession for ReplayAdapter {
    type Error = cardpeek_replay::ReplayError;

    fn protocol(&self) -> cardpeek_core::Protocol {
        cardpeek_core::Protocol::T1
    }

    fn capabilities(&self) -> SessionCapabilities {
        SessionCapabilities {
            extended_apdus: true,
        }
    }

    fn atr(&self) -> Result<Atr, Self::Error> {
        self.session.atr().cloned()
    }

    fn reset(&mut self, mode: ResetMode) -> Result<Atr, Self::Error> {
        match mode {
            ResetMode::Cold => self.session.cold_reset().cloned(),
            ResetMode::Warm => self.session.warm_reset().cloned(),
        }
    }

    fn transmit(&mut self, command: &[u8]) -> Result<ApduResponse, Self::Error> {
        self.session.transmit(command)
    }

    fn disconnect(mut self) -> Result<(), Self::Error> {
        self.session.disconnect();
        Ok(())
    }
}

#[derive(Debug)]
struct TestError;

impl fmt::Display for TestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cancelled")
    }
}

impl std::error::Error for TestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[derive(Debug)]
struct BlockingSession {
    wait: Arc<(Mutex<bool>, Condvar)>,
    started: Arc<(Mutex<bool>, Condvar)>,
    token: CancellationToken,
}

impl CardSession for BlockingSession {
    type Error = TestError;

    fn protocol(&self) -> cardpeek_core::Protocol {
        cardpeek_core::Protocol::T1
    }

    fn capabilities(&self) -> SessionCapabilities {
        SessionCapabilities {
            extended_apdus: true,
        }
    }

    fn atr(&self) -> Result<Atr, Self::Error> {
        Ok(Atr::new(vec![0x3b, 0]))
    }

    fn reset(&mut self, _mode: ResetMode) -> Result<Atr, Self::Error> {
        self.atr()
    }

    fn transmit(&mut self, _command: &[u8]) -> Result<ApduResponse, Self::Error> {
        let (started_lock, started_changed) = &*self.started;
        *started_lock.lock().unwrap() = true;
        started_changed.notify_all();
        let (lock, changed) = &*self.wait;
        let mut cancelled = lock.lock().unwrap();
        while !*cancelled && !self.token.is_cancelled() {
            cancelled = changed.wait(cancelled).unwrap();
        }
        Err(TestError)
    }

    fn disconnect(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct BlockingBackend {
    wait: Arc<(Mutex<bool>, Condvar)>,
    started: Arc<(Mutex<bool>, Condvar)>,
}

impl SessionBackend for BlockingBackend {
    type Session = BlockingSession;

    fn list_readers(&self) -> cardpeek_app::Result<Vec<cardpeek_core::ReaderInfo>> {
        Ok(Vec::new())
    }

    fn connect(&self, request: &ConnectRequest) -> cardpeek_app::Result<Self::Session> {
        Ok(BlockingSession {
            wait: self.wait.clone(),
            started: self.started.clone(),
            token: request.cancellation.clone(),
        })
    }

    fn cancellation_interrupt(
        &self,
        token: &CancellationToken,
    ) -> Option<Box<dyn Fn() + Send + Sync>> {
        let wait = self.wait.clone();
        let token = token.clone();
        Some(Box::new(move || {
            token.cancel();
            let (lock, changed) = &*wait;
            *lock.lock().unwrap() = true;
            changed.notify_all();
        }))
    }
}

struct DynamicSession {
    present: Arc<Mutex<bool>>,
    available: Arc<Mutex<bool>>,
}

impl CardSession for DynamicSession {
    type Error = TestError;

    fn protocol(&self) -> cardpeek_core::Protocol {
        cardpeek_core::Protocol::Other
    }

    fn capabilities(&self) -> SessionCapabilities {
        SessionCapabilities {
            extended_apdus: true,
        }
    }

    fn atr(&self) -> Result<Atr, Self::Error> {
        Ok(Atr::new(if *self.present.lock().unwrap() {
            vec![0x3b, 0]
        } else {
            Vec::new()
        }))
    }

    fn status(&mut self) -> Result<CardStatus, Self::Error> {
        if !*self.available.lock().unwrap() {
            return Err(TestError);
        }
        let card_present = *self.present.lock().unwrap();
        Ok(CardStatus {
            card_present,
            protocol: if card_present {
                cardpeek_core::Protocol::T1
            } else {
                cardpeek_core::Protocol::Other
            },
            atr: Atr::new(if card_present {
                vec![0x3b, 0]
            } else {
                Vec::new()
            }),
        })
    }

    fn reset(&mut self, _mode: ResetMode) -> Result<Atr, Self::Error> {
        self.atr()
    }

    fn transmit(&mut self, _command: &[u8]) -> Result<ApduResponse, Self::Error> {
        Err(TestError)
    }

    fn disconnect(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct DynamicBackend {
    present: Arc<Mutex<bool>>,
    available: Arc<Mutex<bool>>,
    access: Option<Arc<Mutex<usize>>>,
}

impl SessionBackend for DynamicBackend {
    type Session = DynamicSession;

    fn list_readers(&self) -> cardpeek_app::Result<Vec<cardpeek_core::ReaderInfo>> {
        Ok(Vec::new())
    }

    fn connect(&self, _request: &ConnectRequest) -> cardpeek_app::Result<Self::Session> {
        if let Some(access) = &self.access {
            *access.lock().unwrap() += 1;
        }
        Ok(DynamicSession {
            present: self.present.clone(),
            available: self.available.clone(),
        })
    }
}

struct Backend {
    trace: TraceDocument,
}

impl SessionBackend for Backend {
    type Session = ReplayAdapter;

    fn list_readers(&self) -> cardpeek_app::Result<Vec<cardpeek_core::ReaderInfo>> {
        Ok(vec![cardpeek_core::ReaderInfo {
            name: "Synthetic reader".into(),
            transport: cardpeek_core::TransportKind::Replay,
            card_present: Some(true),
        }])
    }

    fn connect(&self, _request: &ConnectRequest) -> cardpeek_app::Result<Self::Session> {
        let mut session = ReplaySession::new(self.trace.clone());
        session.connect().map_err(transport_error)?;
        Ok(ReplayAdapter { session })
    }
}

fn application(config: EngineConfig) -> Application<Backend> {
    let trace = TraceDocument::load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/traces/atr-synthetic-001.json"
    ))
    .unwrap();
    Application::new(Backend { trace }, config)
}

fn connect(app: &Application<Backend>) -> (OperationId, cardpeek_app::EventSubscription) {
    let events = app.subscribe();
    let session = app
        .submit(CommandKind::Connect(ConnectRequest::new(
            "Synthetic reader",
            cardpeek_core::TransportKind::Replay,
        )))
        .unwrap();
    wait_for_terminal(&events, &session);
    assert_eq!(
        app.operation(&session).unwrap().status,
        OperationStatus::Completed
    );
    (session, events)
}

fn wait_for_terminal(events: &cardpeek_app::EventSubscription, operation: &OperationId) {
    for _ in 0..512 {
        let event = events
            .recv_timeout(Duration::from_secs(2))
            .expect("terminal event");
        let terminal = match &event.kind {
            EventKind::OperationCompleted { operation: id }
            | EventKind::OperationFailed { operation: id, .. }
            | EventKind::OperationCancelled { operation: id } => Some(id),
            _ => None,
        };
        if terminal == Some(operation) {
            return;
        }
    }
    panic!("operation did not reach a terminal state");
}

fn next_request(events: &cardpeek_app::EventSubscription) -> cardpeek_app::InteractionRequest {
    loop {
        let event = events
            .recv_timeout(Duration::from_secs(2))
            .expect("interaction event");
        if let EventKind::InteractionRequested { request, .. } = event.kind {
            return request;
        }
    }
}

fn document(run_id: RunId) -> ResultDocument {
    let mut document = ResultDocument::new(DocumentId::new("app-doc").unwrap(), run_id);
    document.roots.push(ResultNode::new(
        NodeId::new("root").unwrap(),
        "card",
        "Card",
    ));
    document.publish();
    document
}

fn temporary_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cardpeek-{name}-{}-{:?}.json",
        std::process::id(),
        std::thread::current().id()
    ))
}

#[test]
fn concurrent_frontend_submissions_preserve_session_and_event_order() {
    let app = Arc::new(application(EngineConfig::default()));
    let (session, events) = connect(&app);
    let operations = Arc::new(Mutex::new(Vec::new()));
    let command = vec![0x00, 0xa4, 0x04, 0x00, 0x02, 0xa0, 0x00];
    let mut producers = Vec::new();
    for _ in 0..4 {
        let app = app.clone();
        let operations = operations.clone();
        let command = command.clone();
        producers.push(std::thread::spawn(move || {
            for _ in 0..4 {
                let operation = app.submit(CommandKind::Transmit(command.clone())).unwrap();
                operations.lock().unwrap().push(operation);
            }
        }));
    }
    for producer in producers {
        producer.join().unwrap();
    }
    let submitted = operations.lock().unwrap().clone();
    let mut pending: std::collections::HashSet<_> = submitted.iter().cloned().collect();
    let mut previous_sequence = 0;
    while !pending.is_empty() {
        let event = events
            .recv_timeout(Duration::from_secs(2))
            .expect("concurrent operation event");
        assert!(event.sequence > previous_sequence);
        previous_sequence = event.sequence;
        match event.kind {
            EventKind::OperationCompleted { operation }
            | EventKind::OperationFailed { operation, .. }
            | EventKind::OperationCancelled { operation } => {
                pending.remove(&operation);
            }
            _ => {}
        }
    }
    for operation in submitted {
        assert_eq!(
            app.operation(&operation).unwrap().status,
            OperationStatus::Completed
        );
    }
    assert_eq!(app.session().unwrap().id, session);
    let disconnect = app.submit(CommandKind::Disconnect).unwrap();
    wait_for_terminal(&events, &disconnect);
    assert!(app.session().is_none());
    assert_eq!(app.trace_snapshot(&session).unwrap().records.len(), 17);
    app.shutdown().unwrap();
}

#[test]
fn replay_session_serialises_commands_and_exports_trace() {
    let app = application(EngineConfig::default());
    let (session, events) = connect(&app);
    let command = vec![0x00, 0xa4, 0x04, 0x00, 0x02, 0xa0, 0x00];
    let operations: Vec<_> = (0..8)
        .map(|_| app.submit(CommandKind::Transmit(command.clone())).unwrap())
        .collect();
    for operation in &operations {
        wait_for_terminal(&events, operation);
        assert_eq!(
            app.operation(operation).unwrap().status,
            OperationStatus::Completed
        );
    }
    assert_eq!(app.session().unwrap().id, session);
    let active = app.trace_snapshot(&session).unwrap();
    assert_eq!(active.records.len(), 9);
    let disconnect = app.submit(CommandKind::Disconnect).unwrap();
    wait_for_terminal(&events, &disconnect);
    let trace = app.trace_snapshot(&session).unwrap();
    assert_eq!(trace.records.len(), 9);
    let destination = temporary_path("trace");
    app.export_trace_now(&ExportTrace {
        session: session.clone(),
        mode: TraceExportMode::Raw,
        destination: destination.clone(),
    })
    .unwrap();
    let exported = TraceDocument::load(&destination).unwrap();
    assert_eq!(exported, *trace);
    let _ = std::fs::remove_file(destination);
    app.shutdown().unwrap();
}

#[test]
fn duplicate_command_and_second_session_are_rejected() {
    let app = application(EngineConfig::default());
    let (_session, events) = connect(&app);
    let duplicate_id = CommandId::new("duplicate");
    app.try_submit(cardpeek_app::Command {
        id: duplicate_id.clone(),
        kind: CommandKind::EnumerateReaders,
    })
    .unwrap();
    let duplicate = cardpeek_app::OperationId::new("operation-for-duplicate");
    app.try_submit(cardpeek_app::Command {
        id: duplicate_id,
        kind: CommandKind::EnumerateReaders,
    })
    .unwrap();
    let mut saw_rejection = false;
    for _ in 0..8 {
        let event = events.recv_timeout(Duration::from_secs(2)).unwrap();
        if matches!(
            event.kind,
            EventKind::OperationFailed { ref error, .. }
                if error.contains("duplicate command identifier")
        ) {
            saw_rejection = true;
            break;
        }
    }
    assert!(saw_rejection);
    assert_eq!(
        app.operation(&duplicate).unwrap().status,
        OperationStatus::Completed
    );
    let second = app
        .submit(CommandKind::Connect(ConnectRequest::new(
            "Synthetic reader",
            cardpeek_core::TransportKind::Replay,
        )))
        .unwrap();
    wait_for_terminal(&events, &second);
    let disconnect = app.submit(CommandKind::Disconnect).unwrap();
    wait_for_terminal(&events, &disconnect);
    app.shutdown().unwrap();
}

#[test]
fn interaction_accepts_only_matching_type_and_id() {
    let app = application(EngineConfig::default());
    let (_session, events) = connect(&app);
    let context = app.analyser_context(
        OperationId::new("interaction-test"),
        RunId::new("interaction-run").unwrap(),
        CancellationToken::new(),
    );
    let worker = std::thread::spawn(move || {
        context.interact(InteractionKind::SecretInput {
            prompt: "PIN".into(),
        })
    });
    let request = next_request(&events);
    assert!(matches!(
        app.answer_interaction(AnswerInteraction {
            request: request.id.clone(),
            response: InteractionResponse::Text("not secret".into()),
        }),
        Err(AppError::InteractionResponseType)
    ));
    assert!(matches!(
        app.answer_interaction(AnswerInteraction {
            request: InteractionId::new("wrong-request"),
            response: InteractionResponse::Secret("1234".into()),
        }),
        Err(AppError::UnknownInteraction(_))
    ));
    app.answer_interaction(AnswerInteraction {
        request: request.id,
        response: InteractionResponse::Secret("1234".into()),
    })
    .unwrap();
    assert_eq!(
        worker.join().unwrap().unwrap(),
        InteractionResponse::Secret("1234".into())
    );
    let disconnect = app.submit(CommandKind::Disconnect).unwrap();
    wait_for_terminal(&events, &disconnect);
    app.shutdown().unwrap();
}

#[test]
fn notice_interaction_requires_an_acknowledgement() {
    let app = application(EngineConfig::default());
    let (_session, events) = connect(&app);
    let context = app.analyser_context(
        OperationId::new("notice"),
        RunId::new("run-notice").unwrap(),
        CancellationToken::new(),
    );
    let worker = std::thread::spawn(move || {
        context.interact(InteractionKind::Notice {
            prompt: "PIN verified".into(),
        })
    });
    let request = next_request(&events);
    assert!(matches!(request.kind, InteractionKind::Notice { .. }));
    assert!(
        app.answer_interaction(AnswerInteraction {
            request: request.id.clone(),
            response: InteractionResponse::Bool(true),
        })
        .is_err()
    );
    app.answer_interaction(AnswerInteraction {
        request: request.id,
        response: InteractionResponse::Acknowledged,
    })
    .unwrap();
    assert_eq!(
        worker.join().unwrap().unwrap(),
        InteractionResponse::Acknowledged
    );
    app.shutdown().unwrap();
}

#[test]
fn cancellation_wakes_an_interaction() {
    let app = application(EngineConfig::default());
    let (_session, events) = connect(&app);
    let context = app.analyser_context(
        OperationId::new("cancellation-test"),
        RunId::new("cancellation-run").unwrap(),
        CancellationToken::new(),
    );
    let token = context.cancellation_token().clone();
    let worker = std::thread::spawn(move || {
        context.interact(InteractionKind::Question {
            prompt: "Continue?".into(),
        })
    });
    let _request = next_request(&events);
    token.cancel();
    assert!(matches!(worker.join().unwrap(), Err(AppError::Cancelled)));
    let disconnect = app.submit(CommandKind::Disconnect).unwrap();
    wait_for_terminal(&events, &disconnect);
    app.shutdown().unwrap();
}

#[test]
fn bounded_event_queue_reports_dropped_logs_and_preserves_terminal_event() {
    let app = application(EngineConfig {
        event_capacity: 2,
        ..EngineConfig::default()
    });
    let events = app.subscribe();
    let run = RunId::new("bounded-run").unwrap();
    app.emit_log(run.clone(), LogLevel::Info, "one");
    app.emit_log(run.clone(), LogLevel::Info, "two");
    app.emit_log(run.clone(), LogLevel::Info, "three");
    app.publish_document(run.clone(), document(run.clone()))
        .unwrap();
    let first = events.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(first.dropped.unwrap().logs, 1);
    let operation = app.submit(CommandKind::EnumerateReaders).unwrap();
    wait_for_terminal(&events, &operation);
    assert_eq!(app.readers().len(), 1);
    app.shutdown().unwrap();
}

#[test]
fn document_snapshots_are_immutable_and_export_to_explicit_path() {
    let app = application(EngineConfig::default());
    let run = RunId::new("document-run").unwrap();
    app.publish_document(run.clone(), document(run.clone()))
        .unwrap();
    let snapshot = app.document_snapshot(&run).unwrap();
    let mut revised = document(run.clone());
    revised.publish();
    app.publish_document(run.clone(), revised).unwrap();
    assert_eq!(snapshot.revision, 1);
    assert_eq!(app.document_snapshot(&run).unwrap().revision, 2);
    let destination = temporary_path("document");
    app.export_document_now(&ExportDocument {
        run_id: run,
        destination: destination.clone(),
    })
    .unwrap();
    assert_eq!(
        ResultDocument::from_json(&std::fs::read_to_string(&destination).unwrap())
            .unwrap()
            .revision,
        2
    );
    let _ = std::fs::remove_file(destination);
    app.shutdown().unwrap();
}

#[test]
fn cancellation_interrupts_native_wait_and_cleans_up() {
    let started = Arc::new((Mutex::new(false), Condvar::new()));
    let backend = BlockingBackend {
        wait: Arc::new((Mutex::new(false), Condvar::new())),
        started: started.clone(),
    };
    let app = Application::with_defaults(backend);
    let events = app.subscribe();
    let session = app
        .submit(CommandKind::Connect(ConnectRequest::new(
            "Blocking reader",
            cardpeek_core::TransportKind::Pcsc,
        )))
        .unwrap();
    wait_for_terminal(&events, &session);
    let transmit = app
        .submit(CommandKind::Transmit(vec![0x00, 0xa4, 0x04, 0x00, 0x00]))
        .unwrap();
    let (started_lock, started_changed) = &*started;
    let mut is_started = started_lock.lock().unwrap();
    while !*is_started {
        is_started = started_changed.wait(is_started).unwrap();
    }
    drop(is_started);
    app.cancel(&transmit).unwrap();
    wait_for_terminal(&events, &transmit);
    assert_eq!(
        app.operation(&transmit).unwrap().status,
        OperationStatus::Cancelled
    );
    let disconnect = app.submit(CommandKind::Disconnect).unwrap();
    wait_for_terminal(&events, &disconnect);
    assert!(app.session().is_none());
    app.shutdown().unwrap();
}

#[test]
fn reader_session_tracks_card_insertion_and_removal() {
    let present = Arc::new(Mutex::new(false));
    let app = Application::with_defaults(DynamicBackend {
        present: present.clone(),
        available: Arc::new(Mutex::new(true)),
        access: None,
    });
    let events = app.subscribe();
    let session = app
        .submit(CommandKind::Connect(ConnectRequest::new(
            "Dynamic reader",
            cardpeek_core::TransportKind::Pcsc,
        )))
        .unwrap();
    wait_for_terminal(&events, &session);
    assert_eq!(app.session().unwrap().reader.card_present, Some(false));
    *present.lock().unwrap() = true;
    let event = events.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(
        event.kind,
        EventKind::CardStatusChanged {
            card_present: true,
            ..
        }
    ));
    assert_eq!(app.session().unwrap().reader.card_present, Some(true));
    *present.lock().unwrap() = false;
    let event = events.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(
        event.kind,
        EventKind::CardStatusChanged {
            card_present: false,
            ..
        }
    ));
    let disconnect = app.submit(CommandKind::Disconnect).unwrap();
    wait_for_terminal(&events, &disconnect);
    assert_eq!(app.trace_snapshot(&session).unwrap().records.len(), 1);
    app.shutdown().unwrap();
}

#[test]
fn reader_removal_error_disconnects_the_active_session() {
    let available = Arc::new(Mutex::new(true));
    let app = Application::with_defaults(DynamicBackend {
        present: Arc::new(Mutex::new(false)),
        available: available.clone(),
        access: None,
    });
    let events = app.subscribe();
    let session = app
        .submit(CommandKind::Connect(ConnectRequest::new(
            "Dynamic reader",
            cardpeek_core::TransportKind::Pcsc,
        )))
        .unwrap();
    wait_for_terminal(&events, &session);
    *available.lock().unwrap() = false;
    let event = events.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(event.kind, EventKind::OperationFailed { .. }));
    let event = events.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(
        event.kind,
        EventKind::SessionStateChanged {
            state: cardpeek_app::SessionState::Disconnected,
            ..
        }
    ));
    assert!(app.session().is_none());
    app.shutdown().unwrap();
}

#[test]
fn sanitised_trace_export_removes_card_values() {
    let app = application(EngineConfig::default());
    let (session, events) = connect(&app);
    let operation = app
        .submit(CommandKind::Transmit(vec![
            0x00, 0xa4, 0x04, 0x00, 0x02, 0xa0, 0x00,
        ]))
        .unwrap();
    wait_for_terminal(&events, &operation);
    let disconnect = app.submit(CommandKind::Disconnect).unwrap();
    wait_for_terminal(&events, &disconnect);
    let destination = temporary_path("sanitised-trace");
    app.export_trace_now(&ExportTrace {
        session,
        mode: TraceExportMode::Sanitised,
        destination: destination.clone(),
    })
    .unwrap();
    let trace = TraceDocument::load(&destination).unwrap();
    assert!(trace.records.iter().all(|record| match record {
        cardpeek_core::TraceRecord::Reset { atr, .. } => atr.as_bytes().is_empty(),
        cardpeek_core::TraceRecord::Command {
            command, response, ..
        } => {
            command.len() <= 4 && response.data.is_empty()
        }
    }));
    let _ = std::fs::remove_file(destination);
    app.shutdown().unwrap();
}

#[test]
fn unavailable_trace_is_a_structured_failure() {
    let app = application(EngineConfig::default());
    assert!(matches!(
        app.export_trace_now(&ExportTrace {
            session: OperationId::new("unknown"),
            mode: TraceExportMode::Raw,
            destination: PathBuf::from("unused"),
        }),
        Err(AppError::TraceUnavailable)
    ));
    app.shutdown().unwrap();
}

#[test]
fn invalid_apdu_is_a_structured_failure() {
    let app = application(EngineConfig::default());
    let (_session, events) = connect(&app);
    let operation = app.submit(CommandKind::Transmit(vec![0xff])).unwrap();
    wait_for_terminal(&events, &operation);
    assert_eq!(
        app.operation(&operation).unwrap().status,
        OperationStatus::Failed
    );
    let disconnect = app.submit(CommandKind::Disconnect).unwrap();
    wait_for_terminal(&events, &disconnect);
    app.shutdown().unwrap();
}

fn discover_atr<B: SessionBackend>(app: &Application<B>, events: &cardpeek_app::EventSubscription) {
    let operation = app
        .submit(CommandKind::DiscoverAnalysers(PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../analysers"
        ))))
        .unwrap();
    wait_for_terminal(events, &operation);
    assert_eq!(
        app.operation(&operation).unwrap().status,
        OperationStatus::Completed
    );
}

fn pin_verification_trace() -> TraceDocument {
    TraceDocument {
        schema_version: 1,
        captures: Vec::new(),
        records: vec![
            cardpeek_core::TraceRecord::Reset {
                id: cardpeek_core::TraceRecordId::new("reset").unwrap(),
                mode: ResetMode::Cold,
                atr: Atr::new(vec![0x3b, 0]),
            },
            command_record("mf-a0", &[0xa0, 0xa4, 0, 0, 2, 0x3f, 0, 0], &[], 0x9f0f),
            command_record(
                "mf-response",
                &[0xa0, 0xc0, 0, 0, 0x0f],
                &legacy_mf(),
                0x9000,
            ),
            command_record("dir", &[0xa0, 0xa4, 0, 0, 2, 0x2f, 0, 0], &[], 0x9404),
            command_record("languages", &[0xa0, 0xa4, 0, 0, 2, 0x2f, 5, 0], &[], 0x9404),
            command_record("arr", &[0xa0, 0xa4, 0, 0, 2, 0x2f, 6, 0], &[], 0x9404),
            command_record("iccid", &[0xa0, 0xa4, 0, 0, 2, 0x2f, 0xe2, 0], &[], 0x9f0f),
            command_record(
                "iccid-response",
                &[0xa0, 0xc0, 0, 0, 0x0f],
                &legacy_iccid(),
                0x9000,
            ),
            command_record("denied", &[0xa0, 0xb0, 0, 0, 10], &[], 0x9804),
            command_record(
                "verify",
                &[
                    0xa0, 0x20, 0, 1, 8, 0x31, 0x32, 0x33, 0x34, 0xff, 0xff, 0xff, 0xff,
                ],
                &[],
                0x9000,
            ),
            command_record(
                "retry",
                &[0xa0, 0xb0, 0, 0, 10],
                &[0x98, 0x53, 8, 0x26, 3, 0x29, 0x71, 0x70, 0x83, 0xf4],
                0x9000,
            ),
            command_record(
                "telecom",
                &[0xa0, 0xa4, 0, 0, 2, 0x7f, 0x10, 0],
                &[],
                0x9404,
            ),
            command_record("gsm", &[0xa0, 0xa4, 0, 0, 2, 0x7f, 0x20, 0], &[], 0x9404),
            command_record(
                "mf-restore",
                &[0xa0, 0xa4, 0, 0, 2, 0x3f, 0, 0],
                &[],
                0x9f0f,
            ),
            command_record(
                "mf-response-2",
                &[0xa0, 0xc0, 0, 0, 0x0f],
                &legacy_mf(),
                0x9000,
            ),
            command_record(
                "gsm-probe",
                &[0xa0, 0xa4, 0, 0, 2, 0x7f, 0x20, 0],
                &[],
                0x9404,
            ),
            command_record("mf-final", &[0xa0, 0xa4, 0, 0, 2, 0x3f, 0, 0], &[], 0x9f0f),
            command_record(
                "mf-response-3",
                &[0xa0, 0xc0, 0, 0, 0x0f],
                &legacy_mf(),
                0x9000,
            ),
            command_record(
                "usim",
                &[
                    0, 0xa4, 4, 0, 16, 0xa0, 0, 0, 0, 0x87, 0x10, 2, 0xff, 0xff, 0xff, 0xff, 0x89,
                    7, 9, 0, 0, 0,
                ],
                &[],
                0x6a82,
            ),
        ],
    }
}

fn node_contains(node: &ResultNode, text: &str) -> bool {
    node.alternative.as_deref() == Some(text)
        || node.children.iter().any(|child| node_contains(child, text))
}

#[test]
fn live_analyser_offers_one_pin_verification_and_retries_the_denied_read() {
    let app = Application::new(
        Backend {
            trace: pin_verification_trace(),
        },
        EngineConfig::default(),
    );
    app.submit(CommandKind::DiscoverAnalysers(PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../analysers"
    ))))
    .unwrap();
    let events = app.subscribe();
    let session = app
        .submit(CommandKind::Connect(ConnectRequest::new(
            "Synthetic reader",
            cardpeek_core::TransportKind::Pcsc,
        )))
        .unwrap();
    wait_for_terminal(&events, &session);
    let operation = app
        .submit(CommandKind::RunAnalyser(run_request("gsm-usim", "pin")))
        .unwrap();
    let question = next_request(&events);
    assert!(matches!(question.kind, InteractionKind::Question { .. }));
    app.submit(CommandKind::AnswerInteraction(AnswerInteraction {
        request: question.id,
        response: InteractionResponse::Bool(true),
    }))
    .unwrap();
    let secret = next_request(&events);
    assert!(matches!(secret.kind, InteractionKind::SecretInput { .. }));
    app.submit(CommandKind::AnswerInteraction(AnswerInteraction {
        request: secret.id,
        response: InteractionResponse::Secret("1234".into()),
    }))
    .unwrap();
    let success = next_request(&events);
    assert!(matches!(success.kind, InteractionKind::Notice { .. }));
    app.submit(CommandKind::AnswerInteraction(AnswerInteraction {
        request: success.id,
        response: InteractionResponse::Acknowledged,
    }))
    .unwrap();
    wait_for_terminal(&events, &operation);
    assert_eq!(
        app.operation(&operation).unwrap().status,
        OperationStatus::Completed
    );
    let document = app
        .document_snapshot(&RunId::new("run-pin").unwrap())
        .unwrap()
        .document;
    assert!(
        document
            .roots
            .iter()
            .any(|node| node_contains(node, "8935806230921707384"))
    );
    assert!(
        !document
            .roots
            .iter()
            .any(|node| node_contains(node, "1234"))
    );
    let trace = app.trace_snapshot(&session).unwrap();
    assert!(trace.records.iter().any(|record| matches!(record,
        cardpeek_core::TraceRecord::Command { command, .. } if command == &[0xa0, 0x20, 0, 1, 8, 0x31, 0x32, 0x33, 0x34, 0xff, 0xff, 0xff, 0xff])));
    app.shutdown().unwrap();
}

fn command_record(
    id: &str,
    command: &[u8],
    data: &[u8],
    status: u16,
) -> cardpeek_core::TraceRecord {
    cardpeek_core::TraceRecord::Command {
        id: cardpeek_core::TraceRecordId::new(id).unwrap(),
        command: command.to_vec(),
        response: ApduResponse::new(
            data.to_vec(),
            cardpeek_core::StatusWord::new(
                u8::try_from(status >> 8).unwrap(),
                u8::try_from(status & 0xff).unwrap(),
            ),
        ),
    }
}

fn legacy_mf() -> Vec<u8> {
    vec![
        0, 0, 0x57, 0x50, 0x3f, 0, 1, 0, 0xff, 0xff, 0xff, 1, 0x11, 0x33, 3, 0x0c, 0x0b, 0, 0x83,
        0x8a, 0x83, 0x8a, 0, 0x83, 0x8a, 0x85, 0x85, 0, 0, 0,
    ]
}

fn legacy_iccid() -> Vec<u8> {
    vec![0, 0, 0, 10, 0x2f, 0xe2, 4, 0, 0x0f, 0xff, 0x66, 1, 2, 0, 0]
}

fn run_request(analyser: &str, name: &str) -> RunAnalyserRequest {
    RunAnalyserRequest {
        analyser: analyser.into(),
        run_id: RunId::new(format!("run-{name}")).unwrap(),
        document_id: DocumentId::new(format!("doc-{name}")).unwrap(),
    }
}

#[test]
fn live_atr_collection_matches_offline_decode_without_backend_access() {
    let access = Arc::new(Mutex::new(0));
    let app = Application::with_defaults(DynamicBackend {
        present: Arc::new(Mutex::new(true)),
        available: Arc::new(Mutex::new(true)),
        access: Some(access.clone()),
    });
    let events = app.subscribe();
    discover_atr(&app, &events);
    let disconnected = app
        .submit(CommandKind::CollectAnalyser(run_request(
            "atr",
            "disconnected",
        )))
        .unwrap();
    wait_for_terminal(&events, &disconnected);
    let session = app
        .submit(CommandKind::Connect(ConnectRequest::new(
            "Dynamic reader",
            cardpeek_core::TransportKind::Pcsc,
        )))
        .unwrap();
    wait_for_terminal(&events, &session);
    let live_request = run_request("atr", "live");
    let live = app
        .submit(CommandKind::CollectAnalyser(live_request.clone()))
        .unwrap();
    wait_for_terminal(&events, &live);
    assert_eq!(
        app.operation(&live).unwrap().status,
        OperationStatus::Completed
    );
    let trace = app.active_trace_snapshot().unwrap().as_ref().clone();
    assert_eq!(trace.schema_version, 2);
    assert_eq!(trace.captures.len(), 1);
    assert_eq!(trace.captures[0].values[0].source.as_str(), "record-0001");
    let decode = app
        .submit(CommandKind::DecodeAnalyser(DecodeAnalyserRequest {
            analyser: "atr".into(),
            run_id: RunId::new("run-offline").unwrap(),
            document_id: DocumentId::new("doc-offline").unwrap(),
            trace: trace.clone(),
            segment: 0,
        }))
        .unwrap();
    wait_for_terminal(&events, &decode);
    assert_eq!(
        app.operation(&decode).unwrap().status,
        OperationStatus::Completed
    );
    assert_eq!(
        app.document_snapshot(&live_request.run_id)
            .unwrap()
            .document
            .roots,
        app.document_snapshot(&RunId::new("run-offline").unwrap())
            .unwrap()
            .document
            .roots
    );
    assert_eq!(*access.lock().unwrap(), 1);
    app.shutdown().unwrap();
}

#[test]
fn live_only_analyser_uses_legacy_collection_without_a_capture_bundle() {
    let trace = TraceDocument::load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/traces/gsm-usim-synthetic-001.json"
    ))
    .unwrap();
    let app = Application::with_defaults(Backend { trace });
    let events = app.subscribe();
    discover_atr(&app, &events);
    let session = app
        .submit(CommandKind::Connect(ConnectRequest::new(
            "Synthetic PC/SC reader",
            cardpeek_core::TransportKind::Pcsc,
        )))
        .unwrap();
    wait_for_terminal(&events, &session);
    let request = run_request("gsm-usim", "live-only");
    let operation = app
        .submit(CommandKind::CollectAnalyser(request.clone()))
        .unwrap();
    let question = next_request(&events);
    app.submit(CommandKind::AnswerInteraction(AnswerInteraction {
        request: question.id,
        response: InteractionResponse::Bool(false),
    }))
    .unwrap();
    wait_for_terminal(&events, &operation);
    assert_eq!(
        app.operation(&operation).unwrap().status,
        OperationStatus::Completed
    );
    assert!(app.document_snapshot(&request.run_id).is_some());
    assert_eq!(app.active_trace_snapshot().unwrap().captures.len(), 0);
    app.shutdown().unwrap();
}

#[test]
fn offline_decode_rejects_missing_and_incompatible_bundles() {
    let app = Application::with_defaults(DynamicBackend {
        present: Arc::new(Mutex::new(false)),
        available: Arc::new(Mutex::new(true)),
        access: None,
    });
    let events = app.subscribe();
    discover_atr(&app, &events);
    let mut trace = TraceDocument::new();
    let reset = trace.record_reset(ResetMode::Cold, Atr::new(vec![0x3b, 0]));
    let missing = app
        .submit(CommandKind::DecodeAnalyser(DecodeAnalyserRequest {
            analyser: "atr".into(),
            run_id: RunId::new("run-missing").unwrap(),
            document_id: DocumentId::new("doc-missing").unwrap(),
            trace: trace.clone(),
            segment: 0,
        }))
        .unwrap();
    wait_for_terminal(&events, &missing);
    assert_eq!(
        app.operation(&missing).unwrap().status,
        OperationStatus::Failed
    );
    trace.captures.push(cardpeek_core::CaptureBundle {
        analyser: "atr".into(),
        analyser_version: "old".into(),
        capture_schema: "atr/v1".into(),
        segment: 0,
        values: vec![cardpeek_core::CapturedValue {
            name: "atr".into(),
            bytes: cardpeek_core::ByteString::from_bytes(vec![0x3b, 0]),
            source: reset,
        }],
    });
    let incompatible = app
        .submit(CommandKind::DecodeAnalyser(DecodeAnalyserRequest {
            analyser: "atr".into(),
            run_id: RunId::new("run-incompatible").unwrap(),
            document_id: DocumentId::new("doc-incompatible").unwrap(),
            trace,
            segment: 0,
        }))
        .unwrap();
    wait_for_terminal(&events, &incompatible);
    assert_eq!(
        app.operation(&incompatible).unwrap().status,
        OperationStatus::Failed
    );
    app.shutdown().unwrap();
}

#[test]
fn offline_replay_is_segment_bounded_and_reports_missing_commands() {
    let access = Arc::new(Mutex::new(0));
    let app = Application::with_defaults(DynamicBackend {
        present: Arc::new(Mutex::new(false)),
        available: Arc::new(Mutex::new(true)),
        access: Some(access.clone()),
    });
    let events = app.subscribe();
    discover_atr(&app, &events);
    let mut trace = TraceDocument::new();
    trace.record_reset(ResetMode::Cold, Atr::new(vec![0x3b, 0]));
    trace.record_reset(ResetMode::Warm, Atr::new(vec![0x3b, 1]));
    let replay = app
        .submit(CommandKind::ReplayAnalyser(ReplayAnalyserRequest {
            analyser: "atr".into(),
            run_id: RunId::new("run-replay").unwrap(),
            document_id: DocumentId::new("doc-replay").unwrap(),
            trace,
            segment: 1,
        }))
        .unwrap();
    wait_for_terminal(&events, &replay);
    assert_eq!(
        app.operation(&replay).unwrap().status,
        OperationStatus::Completed
    );
    let value = app
        .document_snapshot(&RunId::new("run-replay").unwrap())
        .unwrap()
        .document
        .roots[0]
        .children[0]
        .clone();
    assert_eq!(value.provenance.unwrap().record.as_str(), "record-0002");
    assert_eq!(*access.lock().unwrap(), 0);
    app.shutdown().unwrap();
}

#[test]
fn offline_replay_missing_command_identifies_analyser_segment_and_command() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "cardpeek-replay-test-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("cards")).unwrap();
    std::fs::write(
        root.join("cards/missing.lua"),
        "-- @id missing\n-- @title Missing\n-- @description Missing command\n-- @version 1\nlocal cp = require('cardpeek')\nlocal response, failure = cp.card.transmit(cp.bytes.from_hex('00C00000'))\nassert(failure == nil, failure and failure.message)\n",
    )
    .unwrap();
    let app = Application::with_defaults(DynamicBackend {
        present: Arc::new(Mutex::new(false)),
        available: Arc::new(Mutex::new(true)),
        access: None,
    });
    let events = app.subscribe();
    let discovery = app
        .submit(CommandKind::DiscoverAnalysers(root.clone()))
        .unwrap();
    wait_for_terminal(&events, &discovery);
    let mut trace = TraceDocument::new();
    trace.record_reset(ResetMode::Cold, Atr::new(vec![0x3b, 0]));
    trace.record_reset(ResetMode::Warm, Atr::new(vec![0x3b, 1]));
    let replay = app
        .submit(CommandKind::ReplayAnalyser(ReplayAnalyserRequest {
            analyser: "missing".into(),
            run_id: RunId::new("run-missing-command").unwrap(),
            document_id: DocumentId::new("doc-missing-command").unwrap(),
            trace,
            segment: 1,
        }))
        .unwrap();
    let mut failure = None;
    for _ in 0..16 {
        let event = events.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(!matches!(event.kind, EventKind::SessionStateChanged { .. }));
        if event.operation == replay
            && let EventKind::OperationFailed { error, .. } = event.kind
        {
            failure = Some(error);
            break;
        }
    }
    let failure = failure.unwrap();
    assert!(failure.contains("analyser missing"));
    assert!(failure.contains("segment 1"));
    assert!(failure.contains("00C00000"));
    let _ = std::fs::remove_dir_all(root);
    app.shutdown().unwrap();
}
