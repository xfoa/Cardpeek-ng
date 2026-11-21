//! Independent physical-session, trace, analysis, and library workflow tests.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cardpeek_analyser::AnalyserLibrary;
use cardpeek_app::{
    AnswerInteraction, DocumentSnapshot, EventKind, InteractionId, InteractionKind,
    InteractionRequest, InteractionResponse, OperationId, Progress, SessionBackend,
};
use cardpeek_core::{
    ApduResponse, Atr, Protocol, ReaderInfo, ResetMode, ResultDocument, TraceDocument,
    TransportKind,
};
use cardpeek_desktop::state::{
    AnalysisInput, AnalysisOperation, DesktopState, ExportKind, ExportTraceSource,
    MAX_NOTIFICATIONS, NotificationLevel, RunStatus, Screen, node_value, trace_record_matches,
};
use cardpeek_desktop::{Controller, DesktopBackend};
use cardpeek_replay::{ReplayError, ReplaySession};
use cardpeek_transport::{CardSession, SessionCapabilities};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn analysers() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../analysers")
}

#[derive(Debug)]
struct TestError;

impl fmt::Display for TestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("test transport error")
    }
}

impl std::error::Error for TestError {}

struct ReaderSession {
    session: ReplaySession,
}

impl CardSession for ReaderSession {
    type Error = TestError;

    fn protocol(&self) -> Protocol {
        Protocol::T1
    }

    fn capabilities(&self) -> SessionCapabilities {
        SessionCapabilities {
            extended_apdus: true,
        }
    }

    fn atr(&self) -> Result<Atr, Self::Error> {
        self.session.atr().cloned().map_err(TestError::from)
    }

    fn reset(&mut self, mode: ResetMode) -> Result<Atr, Self::Error> {
        match mode {
            ResetMode::Cold => self.session.cold_reset().cloned(),
            ResetMode::Warm => self.session.warm_reset().cloned(),
        }
        .map_err(TestError::from)
    }

    fn transmit(&mut self, command: &[u8]) -> Result<ApduResponse, Self::Error> {
        self.session.transmit(command).map_err(TestError::from)
    }

    fn disconnect(mut self) -> Result<(), Self::Error> {
        self.session.disconnect();
        Ok(())
    }
}

impl From<ReplayError> for TestError {
    fn from(_error: ReplayError) -> Self {
        Self
    }
}

struct ReaderBackend {
    readers: Arc<Mutex<Vec<ReaderInfo>>>,
    connects: Arc<Mutex<usize>>,
}

impl SessionBackend for ReaderBackend {
    type Session = ReaderSession;

    fn list_readers(&self) -> cardpeek_app::Result<Vec<ReaderInfo>> {
        Ok(self.readers.lock().unwrap().clone())
    }

    fn connect(
        &self,
        _request: &cardpeek_app::ConnectRequest,
    ) -> cardpeek_app::Result<Self::Session> {
        *self.connects.lock().unwrap() += 1;
        let trace = TraceDocument::load(fixture("traces/atr-synthetic-001.json")).unwrap();
        let mut session = ReplaySession::new(trace);
        session.connect().map_err(cardpeek_app::transport_error)?;
        Ok(ReaderSession { session })
    }
}

fn physical_controller() -> (Controller<ReaderBackend>, Arc<Mutex<usize>>) {
    let connects = Arc::new(Mutex::new(0));
    let controller = Controller::new(
        ReaderBackend {
            readers: Arc::new(Mutex::new(vec![ReaderInfo {
                name: "Test reader".into(),
                transport: TransportKind::Pcsc,
                card_present: Some(true),
            }])),
            connects: connects.clone(),
        },
        AnalyserLibrary::at(analysers()).unwrap(),
    );
    (controller, connects)
}

fn controller() -> Controller<DesktopBackend> {
    Controller::for_desktop(
        DesktopBackend::new(None, None),
        AnalyserLibrary::at(analysers()).unwrap(),
    )
}

fn wait_for<B: SessionBackend>(
    controller: &Controller<B>,
    state: &mut DesktopState,
    condition: impl Fn(&DesktopState) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        controller.refresh_readers(state);
        controller.poll(state);
        if condition(state) {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!(
        "desktop state did not reach the expected condition: errors={:?} notifications={:?}",
        state.errors, state.notifications
    );
}

fn open_fixture_trace(state: &mut DesktopState) {
    state.set_trace(TraceDocument::load(fixture("traces/atr-synthetic-001.json")).unwrap());
    state.select_analysis_input(AnalysisInput::TraceSegment { segment: 0 });
}

#[test]
fn physical_connect_collect_disconnect_and_reconnect() {
    let (controller, connects) = physical_controller();
    let mut state = DesktopState::default();
    wait_for(&controller, &mut state, |state| {
        state.selected_reader.as_deref() == Some("Test reader") && state.selected_analyser.is_some()
    });
    assert!(!state.can_run());
    assert!(
        state
            .analysis_requirement()
            .unwrap()
            .contains("connected physical reader")
    );

    controller.connect("Test reader".into(), &mut state);
    wait_for(&controller, &mut state, DesktopState::connected);
    assert!(state.card_present());
    assert!(state.can_run());

    controller.run("atr".into(), &mut state);
    wait_for(&controller, &mut state, |state| {
        state.run_status == RunStatus::Complete && state.document.is_some()
    });
    assert_eq!(state.document.as_ref().unwrap().document.node_count(), 2);
    assert_eq!(state.capture_trace.as_ref().unwrap().captures.len(), 1);
    assert!(
        state
            .logs
            .iter()
            .any(|entry| entry.message == "Read 2 ATR bytes")
    );

    controller.transmit("00A4040002A000", &mut state);
    wait_for(&controller, &mut state, |state| {
        state.session_exchanges.len() == 1
    });
    assert_eq!(state.session_exchanges[0].command, "00 A4 04 00 02 A0 00");

    controller.disconnect(&mut state);
    wait_for(&controller, &mut state, |state| !state.connected());
    let retained = state.capture_trace.clone().unwrap();
    assert_ne!(retained.records.len(), 0);
    controller.connect("Test reader".into(), &mut state);
    wait_for(&controller, &mut state, DesktopState::connected);
    assert_eq!(*connects.lock().unwrap(), 2);
}

#[test]
fn trace_actions_and_replay_do_not_change_the_physical_session() {
    let (controller, connects) = physical_controller();
    let mut state = DesktopState::default();
    wait_for(&controller, &mut state, |state| {
        state.selected_analyser.is_some() && !state.readers.is_empty()
    });
    controller.connect("Test reader".into(), &mut state);
    wait_for(&controller, &mut state, DesktopState::connected);
    let physical = state.session.clone().unwrap();

    open_fixture_trace(&mut state);
    controller.select_segment(1, &mut state);
    assert_eq!(state.selected_trace_segment, 1);
    assert_eq!(
        state.analysis_operation(),
        Some(AnalysisOperation::Replay { segment: 1 })
    );
    assert_eq!(
        state.session.as_ref().map(|session| &session.id),
        Some(&physical.id)
    );
    controller.run("atr".into(), &mut state);
    wait_for(&controller, &mut state, |state| {
        state.run_status == RunStatus::Complete && state.document.is_some()
    });
    assert_eq!(*connects.lock().unwrap(), 1);
    assert_eq!(
        state.session.as_ref().map(|session| &session.id),
        Some(&physical.id)
    );
    assert!(state.connected());
    assert!(
        state
            .document
            .as_ref()
            .unwrap()
            .document
            .roots
            .iter()
            .any(|root| { root.children.iter().any(|node| node_value(node) == "3B 01") })
    );
}

#[test]
fn schema_one_trace_replays_each_segment_without_hardware() {
    let controller = controller();
    let mut state = DesktopState::default();
    wait_for(&controller, &mut state, |state| {
        state.selected_analyser.as_deref() == Some("atr")
    });
    open_fixture_trace(&mut state);
    assert_eq!(state.trace.as_ref().unwrap().schema_version, 1);
    assert_eq!(state.trace_preview.as_ref().unwrap().segments.len(), 2);
    assert!(state.session.is_none());

    for segment in 0..2 {
        controller.select_segment(segment, &mut state);
        controller.run("atr".into(), &mut state);
        wait_for(&controller, &mut state, |state| {
            state.run_status == RunStatus::Complete && state.document.is_some()
        });
        assert!(state.session.is_none());
    }
}

#[test]
fn live_input_rejects_disconnected_and_cardless_states_without_trace_fallback() {
    let mut state = DesktopState {
        analysers: cardpeek_analyser::discover(&analysers()).unwrap(),
        selected_analyser: Some("atr".into()),
        ..DesktopState::default()
    };
    open_fixture_trace(&mut state);
    state.select_analysis_input(AnalysisInput::LiveCard);
    assert!(state.trace.is_some());
    assert!(!state.can_run());
    assert!(state.analysis_requirement().is_some());

    state.session = Some(cardpeek_app::SessionInfo {
        id: OperationId::new("physical"),
        reader: ReaderInfo {
            name: "Reader".into(),
            transport: TransportKind::Pcsc,
            card_present: Some(false),
        },
        protocol: Protocol::Other,
        capabilities: SessionCapabilities {
            extended_apdus: false,
        },
        atr: Atr::new(Vec::new()),
        state: cardpeek_app::SessionState::Connected,
    });
    assert!(!state.can_run());
    assert_eq!(
        state.analysis_requirement().as_deref(),
        Some("Live analysis requires a physically present card.")
    );
}

#[test]
fn compatible_capture_bundle_selects_decode_instead_of_replay() {
    let mut state = DesktopState {
        analysers: cardpeek_analyser::discover(&analysers()).unwrap(),
        selected_analyser: Some("atr".into()),
        ..DesktopState::default()
    };
    let mut trace = TraceDocument::new();
    let source = trace.record_reset(ResetMode::Cold, Atr::from_hex("3B00").unwrap());
    trace.captures.push(cardpeek_core::CaptureBundle {
        analyser: "atr".into(),
        analyser_version: "1.0.0".into(),
        capture_schema: "atr/v1".into(),
        segment: 0,
        values: vec![cardpeek_core::CapturedValue {
            name: "atr".into(),
            bytes: cardpeek_core::ByteString::from_hex(8, "3B00").unwrap(),
            source,
        }],
    });
    state.set_trace(trace);
    state.select_analysis_input(AnalysisInput::TraceSegment { segment: 0 });
    assert_eq!(
        state.analysis_operation(),
        Some(AnalysisOperation::Decode { segment: 0 })
    );
    assert_eq!(state.operation_label(), "Decode trace");

    let controller = controller();
    controller.run("atr".into(), &mut state);
    wait_for(&controller, &mut state, |state| {
        state.run_status == RunStatus::Complete && state.document.is_some()
    });
    assert!(state.session.is_none());
    assert_eq!(state.document.as_ref().unwrap().document.node_count(), 2);
}

#[test]
fn exports_result_and_raw_or_sanitised_open_trace() {
    let controller = controller();
    let mut state = DesktopState::default();
    wait_for(&controller, &mut state, |state| {
        state.selected_analyser.is_some()
    });
    open_fixture_trace(&mut state);
    controller.run("atr".into(), &mut state);
    wait_for(&controller, &mut state, |state| {
        state.run_status == RunStatus::Complete && state.document.is_some()
    });
    let directory = tempfile::tempdir().unwrap();

    state.export_kind = ExportKind::Document;
    state.export_destination = directory.path().join("result.json").display().to_string();
    controller.export(&mut state);
    wait_for(&controller, &mut state, |state| {
        state
            .latest_notification()
            .is_some_and(|notice| notice.message.starts_with("Exported document"))
    });
    assert!(
        ResultDocument::from_json(
            &std::fs::read_to_string(directory.path().join("result.json")).unwrap()
        )
        .is_ok()
    );

    for (mode, name) in [
        (cardpeek_app::TraceExportMode::Raw, "raw.json"),
        (cardpeek_app::TraceExportMode::Sanitised, "sanitised.json"),
    ] {
        state.export_kind = ExportKind::Trace;
        state.export_trace_source = ExportTraceSource::OpenTrace;
        state.trace_export_mode = mode;
        let path = directory.path().join(name);
        state.export_destination = path.display().to_string();
        controller.export(&mut state);
        wait_for(&controller, &mut state, |_| path.exists());
        let exported = TraceDocument::load(path).unwrap();
        let expected = match mode {
            cardpeek_app::TraceExportMode::Raw => state.trace.clone().unwrap(),
            cardpeek_app::TraceExportMode::Sanitised => state.trace.clone().unwrap().sanitised(),
        };
        assert_eq!(exported, expected);
    }
}

#[test]
fn library_removal_refreshes_selection() {
    let directories = tempfile::tempdir().unwrap();
    let library = AnalyserLibrary::at(directories.path().join("analysers")).unwrap();
    let controller = Controller::new(DesktopBackend::new(None, None), library.clone());
    let mut state = DesktopState::default();
    wait_for(&controller, &mut state, |state| state.analysers.len() == 2);
    state.selected_analyser = Some("atr".into());
    controller.remove_analyser(&mut state);
    wait_for(&controller, &mut state, |state| {
        state.analysers.len() == 1 && state.selected_analyser.as_deref() == Some("gsm-usim")
    });
    assert!(!library.root().join("atr.lua").exists());
}

#[test]
fn reader_refresh_removes_and_restores_unplugged_readers() {
    let readers = Arc::new(Mutex::new(vec![ReaderInfo {
        name: "Test reader".into(),
        transport: TransportKind::Pcsc,
        card_present: Some(false),
    }]));
    let controller = Controller::new(
        ReaderBackend {
            readers: readers.clone(),
            connects: Arc::new(Mutex::new(0)),
        },
        AnalyserLibrary::at(analysers()).unwrap(),
    );
    let mut state = DesktopState::default();
    wait_for(&controller, &mut state, |state| {
        state.selected_reader.as_deref() == Some("Test reader")
    });
    readers.lock().unwrap().clear();
    wait_for(&controller, &mut state, |state| {
        state.readers.is_empty() && state.selected_reader.is_none()
    });
    readers.lock().unwrap().push(ReaderInfo {
        name: "Test reader".into(),
        transport: TransportKind::Pcsc,
        card_present: Some(true),
    });
    wait_for(&controller, &mut state, |state| {
        state.selected_reader.as_deref() == Some("Test reader")
            && state.readers[0].card_present == Some(true)
    });
}

#[test]
fn interaction_progress_and_cancellation_update_the_state() {
    let mut state = DesktopState::default();
    let operation = OperationId::new("operation-1");
    state.run_operation = Some(operation.clone());
    state.run_status = RunStatus::Running;
    let interaction = InteractionRequest {
        id: InteractionId::new("request-1"),
        kind: InteractionKind::SecretInput {
            prompt: "Enter PIN".into(),
        },
    };
    state.apply_event(event(
        &operation,
        EventKind::InteractionRequested {
            operation: operation.clone(),
            request: interaction.clone(),
        },
    ));
    assert_eq!(state.interaction, Some(interaction));
    let controller = controller();
    controller.answer(
        AnswerInteraction {
            request: InteractionId::new("request-1"),
            response: InteractionResponse::Secret("1234".into()),
        },
        &mut state,
    );
    assert!(state.interaction.is_none());
    state.apply_event(event(
        &operation,
        EventKind::OperationProgress {
            operation: operation.clone(),
            progress: Progress::Determinate {
                completed: 2,
                total: 4,
            },
        },
    ));
    assert_eq!(
        state.progress,
        Some(Progress::Determinate {
            completed: 2,
            total: 4
        })
    );
    state.apply_event(event(
        &operation,
        EventKind::OperationCancelled {
            operation: operation.clone(),
        },
    ));
    assert_eq!(state.run_status, RunStatus::Cancelled);
    assert!(state.progress.is_none());
}

#[test]
fn notifications_retain_bounded_history_with_the_latest_message_last() {
    let mut state = DesktopState::default();
    state.notify("First message");
    state.notify_error("Second message");
    assert_eq!(
        state.latest_notification().unwrap().message,
        "Second message"
    );
    assert_eq!(
        state.latest_notification().unwrap().level,
        NotificationLevel::Error
    );

    for index in 0..MAX_NOTIFICATIONS {
        state.notify(format!("Message {index}"));
    }
    assert_eq!(state.notifications.len(), MAX_NOTIFICATIONS);
    assert_eq!(state.notifications.first().unwrap().message, "Message 0");
    assert_eq!(
        state.latest_notification().unwrap().message,
        format!("Message {}", MAX_NOTIFICATIONS - 1)
    );
}

#[test]
fn workspaces_default_independently_and_trace_search_covers_exact_records() {
    let state = DesktopState::default();
    assert_eq!(state.screen, Screen::Reader);
    assert_eq!(state.analysis_input, AnalysisInput::LiveCard);
    assert!(state.trace.is_none());
    assert!(!state.connected());
    let trace = TraceDocument::load(fixture("traces/atr-synthetic-001.json")).unwrap();
    let record = &trace.records[1];
    assert!(trace_record_matches(record, 0, "00A4040002A000"));
    assert!(trace_record_matches(record, 0, "record-0002"));
    assert!(trace_record_matches(record, 0, "segment 1"));
    assert!(!trace_record_matches(record, 0, "segment 2"));
}

#[test]
fn help_mode_toggles_and_survives_workspace_changes() {
    let mut state = DesktopState::default();
    assert!(!state.help_mode);

    state.toggle_help_mode();
    assert!(state.help_mode);
    for screen in [
        Screen::Analysis,
        Screen::Trace,
        Screen::Library,
        Screen::Reader,
    ] {
        state.screen = screen;
        assert!(state.help_mode);
    }

    state.toggle_help_mode();
    assert!(!state.help_mode);
}

#[test]
fn result_rows_preserve_order_expansion_and_search() {
    let document = ResultDocument::from_json(
        &std::fs::read_to_string(fixture("documents/gsm-usim-synthetic-001.json")).unwrap(),
    )
    .unwrap();
    let mut state = DesktopState::default();
    state.publish_document(DocumentSnapshot {
        run_id: document.run_id.clone(),
        revision: document.revision,
        document: Arc::new(document),
    });
    let rows = state.visible_rows();
    assert_eq!(rows.len(), 69);
    let expanded_ids: Vec<_> = rows.iter().map(|row| row.node.id.to_string()).collect();
    drop(rows);
    state.expanded.remove("node-0001");
    assert_eq!(state.visible_rows().len(), 1);
    state.expand_all();
    assert_eq!(
        state
            .visible_rows()
            .iter()
            .map(|row| row.node.id.to_string())
            .collect::<Vec<_>>(),
        expanded_ids
    );
    state.collapse_to_second_level();
    assert!(state.visible_rows().iter().all(|row| row.depth <= 1));
    state.set_search("IMSI".into());
    assert!(
        state
            .visible_rows()
            .iter()
            .any(|row| row.node.label == "IMSI [6F07]")
    );
    state.set_search("not-present".into());
    assert!(state.visible_rows().is_empty());
}

#[test]
fn search_collapses_matches_and_preserves_manual_expansion() {
    let document = ResultDocument::from_json(
        &std::fs::read_to_string(fixture("documents/gsm-usim-synthetic-001.json")).unwrap(),
    )
    .unwrap();
    let mut state = DesktopState::default();
    state.publish_document(DocumentSnapshot {
        run_id: document.run_id.clone(),
        revision: document.revision,
        document: Arc::new(document),
    });
    state.collapse_to_second_level();
    let expanded = state.expanded.clone();

    state.set_search("sms".into());
    let rows = state.visible_rows();
    let sms = rows
        .iter()
        .find(|row| row.node.id.as_str() == "node-0045")
        .unwrap();
    assert!(!sms.expanded);
    assert!(!rows.iter().any(|row| row.node.id.as_str() == "node-0046"));
    drop(rows);

    state.toggle_node("node-0045");
    let rows = state.visible_rows();
    assert!(rows.iter().any(|row| row.node.id.as_str() == "node-0046"));
    assert!(!rows.iter().any(|row| row.node.label == "File size"));
    drop(rows);
    state.toggle_node("node-0046");
    let rows = state.visible_rows();
    assert!(rows.iter().any(|row| row.node.label == "File size"));
    assert_eq!(state.expanded, expanded);
    drop(rows);

    state.set_search(String::new());
    let mut expected = expanded;
    expected.extend([
        "node-0001".into(),
        "node-0017".into(),
        "node-0045".into(),
        "node-0046".into(),
    ]);
    assert_eq!(state.expanded, expected);
    assert!(state.search_expanded_ids().is_empty());
    assert!(
        state
            .visible_rows()
            .iter()
            .any(|row| row.node.label == "File size")
    );
}

#[test]
fn selected_tree_text_includes_ancestors_and_the_selected_node() {
    let document = ResultDocument::from_json(
        &std::fs::read_to_string(fixture("documents/gsm-usim-synthetic-001.json")).unwrap(),
    )
    .unwrap();
    let mut state = DesktopState::default();
    state.publish_document(DocumentSnapshot {
        run_id: document.run_id.clone(),
        revision: document.revision,
        document: Arc::new(document),
    });
    state.selected_node = Some("node-0045".into());
    let text = state.selected_tree_text().unwrap();
    assert!(text.starts_with("GSM SIM + USIM\t"));
    assert!(text.contains("\n  ADF.USIM [A0000000871002FFFFFFFF8907090000]\t"));
    assert!(text.contains("\n    Short messages (SMS) [6F3C]\tNo value"));
    assert!(!text.contains("SELECT response"));
    assert!(!text.contains("Record 1"));
    assert!(!text.contains("Service provider name"));
    assert!(!text.ends_with('\n'));
    assert_eq!(
        state.tree_text("node-0001").unwrap(),
        "GSM SIM + USIM\tNo value"
    );
}

fn event(operation: &OperationId, kind: EventKind) -> cardpeek_app::Event {
    cardpeek_app::Event {
        sequence: 1,
        operation: operation.clone(),
        kind,
        dropped: None,
    }
}
