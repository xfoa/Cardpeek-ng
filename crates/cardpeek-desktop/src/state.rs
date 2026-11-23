#![allow(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use cardpeek_analyser::AnalyserMetadata;
use cardpeek_app::{
    DocumentSnapshot, Event, EventKind, InteractionRequest, LogLevel, OperationId, Progress,
    SessionInfo, SessionState, TraceExportMode,
};
use cardpeek_core::{Atr, CaptureBundle, TraceDocument, TraceRecord};
use cardpeek_core::{NodeValue, ResultNode, RunId};

pub const MAX_LOGS: usize = 500;
pub const MAX_NOTIFICATIONS: usize = 100;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RunStatus {
    #[default]
    Idle,
    Running,
    Complete,
    Failed,
    Cancelled,
}

impl RunStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "Not run",
            Self::Running => "Running",
            Self::Complete => "Complete",
            Self::Failed => "Failed",
            Self::Cancelled => "Cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Screen {
    #[default]
    Reader,
    Analysis,
    Trace,
    Library,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AnalysisInput {
    #[default]
    LiveCard,
    TraceSegment {
        segment: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnalysisOperation {
    Collect,
    Decode { segment: usize },
    Replay { segment: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationLevel {
    Info,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    pub level: NotificationLevel,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub sequence: u64,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct Exchange {
    pub record: String,
    pub command: String,
    pub data: String,
    pub status: String,
}

#[derive(Clone, Debug)]
pub enum ExportNotice {
    Document { run_id: RunId, path: String },
    Trace { path: String },
}

#[derive(Clone, Debug)]
pub struct ResultRow<'a> {
    pub node: &'a ResultNode,
    pub depth: usize,
    pub expanded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceSegmentPreview {
    pub index: usize,
    pub atr: Option<Atr>,
    pub commands: usize,
    pub captures: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TracePreview {
    pub segments: Vec<TraceSegmentPreview>,
    pub commands: usize,
    pub captures: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExportTraceSource {
    #[default]
    Capture,
    OpenTrace,
}

#[derive(Debug)]
pub struct DesktopState {
    pub readers: Vec<cardpeek_core::ReaderInfo>,
    pub selected_reader: Option<String>,
    pub session: Option<SessionInfo>,
    pub last_session: Option<OperationId>,
    pub session_counter: u64,
    pub new_session_operation: Option<OperationId>,
    pub capture_trace: Option<TraceDocument>,
    pub trace_path: Option<PathBuf>,
    pub trace: Option<TraceDocument>,
    pub trace_preview: Option<TracePreview>,
    pub selected_trace_segment: usize,
    pub analysis_input: AnalysisInput,
    pub analysers: Vec<AnalyserMetadata>,
    pub selected_analyser: Option<String>,
    pub analyser_directory: String,
    pub document: Option<DocumentSnapshot>,
    pub selected_node: Option<String>,
    pub expanded: HashSet<String>,
    pub search_expanded: HashSet<String>,
    pub search: String,
    pub logs: Vec<LogEntry>,
    pub exchanges: Vec<Exchange>,
    pub session_exchanges: Vec<Exchange>,
    pub trace_expanded: HashSet<String>,
    pub trace_search: String,
    pub run_details_open: bool,
    pub interaction: Option<InteractionRequest>,
    pub interaction_operation: Option<OperationId>,
    pub interaction_file: Option<PathBuf>,
    pub run_operation: Option<OperationId>,
    pub run_id: Option<RunId>,
    pub run_status: RunStatus,
    pub progress: Option<Progress>,
    pub pending: HashMap<OperationId, cardpeek_app::OperationKind>,
    pub errors: Vec<String>,
    pub notifications: Vec<Notification>,
    pub run_counter: u64,
    pub screen: Screen,
    pub help_mode: bool,
    pub apdu_command: String,
    pub show_export: bool,
    pub export_kind: ExportKind,
    pub export_trace_source: ExportTraceSource,
    pub export_destination: String,
    pub trace_export_mode: TraceExportMode,
    pub pending_remove: Option<String>,
    pub pending_connection: Option<String>,
}

impl Default for DesktopState {
    fn default() -> Self {
        Self {
            readers: Vec::new(),
            selected_reader: None,
            session: None,
            last_session: None,
            session_counter: 0,
            new_session_operation: None,
            capture_trace: None,
            trace_path: None,
            trace: None,
            trace_preview: None,
            selected_trace_segment: 0,
            analysis_input: AnalysisInput::LiveCard,
            analysers: Vec::new(),
            selected_analyser: None,
            analyser_directory: String::new(),
            document: None,
            selected_node: None,
            expanded: HashSet::new(),
            search_expanded: HashSet::new(),
            search: String::new(),
            logs: Vec::new(),
            exchanges: Vec::new(),
            session_exchanges: Vec::new(),
            trace_expanded: HashSet::new(),
            trace_search: String::new(),
            run_details_open: false,
            interaction: None,
            interaction_operation: None,
            interaction_file: None,
            run_operation: None,
            run_id: None,
            run_status: RunStatus::Idle,
            progress: None,
            pending: HashMap::new(),
            errors: Vec::new(),
            notifications: Vec::new(),
            run_counter: 0,
            screen: Screen::Reader,
            help_mode: false,
            apdu_command: String::new(),
            show_export: false,
            export_kind: ExportKind::Document,
            export_trace_source: ExportTraceSource::Capture,
            export_destination: String::new(),
            trace_export_mode: TraceExportMode::Raw,
            pending_remove: None,
            pending_connection: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExportKind {
    #[default]
    Document,
    Trace,
}

impl DesktopState {
    #[must_use]
    pub fn connected(&self) -> bool {
        self.session.as_ref().is_some_and(|session| {
            session.state == SessionState::Connected
                && session.reader.transport == cardpeek_core::TransportKind::Pcsc
        })
    }

    #[must_use]
    pub fn session_connected(&self) -> bool {
        self.connected()
    }

    #[must_use]
    pub fn run_running(&self) -> bool {
        self.run_status == RunStatus::Running
    }

    #[must_use]
    pub fn card_present(&self) -> bool {
        self.connected()
            && self.session.as_ref().is_some_and(|session| {
                session.reader.card_present.unwrap_or(false) && !session.atr.as_bytes().is_empty()
            })
    }

    #[must_use]
    pub fn new_session_pending(&self) -> bool {
        self.new_session_operation.is_some()
    }

    #[must_use]
    pub fn session_name(&self) -> String {
        format!("Session {}", self.session_counter.max(1))
    }

    #[must_use]
    pub fn card_type(&self) -> Option<&'static str> {
        let session = self.session.as_ref()?;
        self.card_present()
            .then(|| crate::card_type::identify(&session.atr))
            .flatten()
    }

    #[must_use]
    pub fn selected_analyser_metadata(&self) -> Option<&AnalyserMetadata> {
        self.analysers
            .iter()
            .find(|analyser| Some(&analyser.id) == self.selected_analyser.as_ref())
    }

    #[must_use]
    pub fn compatible_analysers(&self) -> Vec<&AnalyserMetadata> {
        self.analysers
            .iter()
            .filter(|analyser| match self.analysis_input {
                AnalysisInput::LiveCard => analyser.capabilities.live_collection,
                AnalysisInput::TraceSegment { segment } => {
                    analyser.capabilities.replay
                        || (analyser.capabilities.offline_decoding
                            && self.capture_for(&analyser.id, segment).is_some())
                }
            })
            .collect()
    }

    #[must_use]
    pub fn capture_for(&self, analyser: &str, segment: usize) -> Option<&CaptureBundle> {
        let metadata = self
            .analysers
            .iter()
            .find(|candidate| candidate.id == analyser)?;
        self.trace.as_ref()?.captures.iter().find(|capture| {
            capture.segment == segment
                && capture.analyser == analyser
                && capture.analyser_version == metadata.version
                && Some(&capture.capture_schema) == metadata.capture_schema.as_ref()
        })
    }

    #[must_use]
    pub fn analysis_operation(&self) -> Option<AnalysisOperation> {
        let analyser = self.selected_analyser_metadata()?;
        match self.analysis_input {
            AnalysisInput::LiveCard => analyser
                .capabilities
                .live_collection
                .then_some(AnalysisOperation::Collect),
            AnalysisInput::TraceSegment { segment } => {
                if analyser.capabilities.offline_decoding
                    && self.capture_for(&analyser.id, segment).is_some()
                {
                    Some(AnalysisOperation::Decode { segment })
                } else if analyser.capabilities.replay
                    && self
                        .trace
                        .as_ref()
                        .and_then(|trace| trace.segment(segment))
                        .is_some_and(|segment| segment.reset().is_some())
                {
                    Some(AnalysisOperation::Replay { segment })
                } else {
                    None
                }
            }
        }
    }

    #[must_use]
    pub fn operation_label(&self) -> &'static str {
        match self.analysis_operation() {
            Some(AnalysisOperation::Collect) => "Analyze live card",
            Some(AnalysisOperation::Decode { .. }) => "Decode trace",
            Some(AnalysisOperation::Replay { .. }) => "Replay trace",
            None => "Analysis unavailable",
        }
    }

    #[must_use]
    pub fn analysis_requirement(&self) -> Option<String> {
        if self.selected_analyser.is_none() {
            return Some("Select an analyser.".into());
        }
        match self.analysis_input {
            AnalysisInput::LiveCard if !self.connected() => {
                Some("Live analysis requires a connected physical reader.".into())
            }
            AnalysisInput::LiveCard if !self.card_present() => {
                Some("Live analysis requires a physically present card.".into())
            }
            AnalysisInput::TraceSegment { .. }
                if self.trace.is_none() || self.trace_preview.is_none() =>
            {
                Some("Open a trace and select a segment.".into())
            }
            AnalysisInput::TraceSegment { segment } if self.analysis_operation().is_none() => {
                Some(format!(
                    "The selected analyser has no compatible capture bundle or replay support for segment {}.",
                    segment + 1
                ))
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn can_run(&self) -> bool {
        self.analysis_operation().is_some()
            && self.analysis_requirement().is_none()
            && !self.run_running()
            && !self.pending.values().any(|kind| {
                matches!(
                    kind,
                    cardpeek_app::OperationKind::RunAnalyser
                        | cardpeek_app::OperationKind::CollectAnalyser
                        | cardpeek_app::OperationKind::DecodeAnalyser
                        | cardpeek_app::OperationKind::ReplayAnalyser
                        | cardpeek_app::OperationKind::Reset
                        | cardpeek_app::OperationKind::Disconnect
                )
            })
    }

    pub fn toggle_help_mode(&mut self) {
        self.help_mode = !self.help_mode;
    }

    pub fn select_analysis_input(&mut self, input: AnalysisInput) {
        self.analysis_input = input;
        if let AnalysisInput::TraceSegment { segment } = input {
            self.selected_trace_segment = segment;
        }
        let compatible = self.compatible_analysers();
        if self
            .selected_analyser
            .as_ref()
            .is_none_or(|selected| !compatible.iter().any(|analyser| &analyser.id == selected))
        {
            self.selected_analyser = compatible.first().map(|analyser| analyser.id.clone());
        }
    }

    pub fn set_trace(&mut self, trace: TraceDocument) {
        let preview = trace_preview(&trace);
        self.selected_trace_segment = self
            .selected_trace_segment
            .min(preview.segments.len().saturating_sub(1));
        if let AnalysisInput::TraceSegment { segment } = &mut self.analysis_input {
            *segment = self.selected_trace_segment;
        }
        self.trace_preview = Some(preview);
        self.trace = Some(trace);
        self.trace_expanded.clear();
    }

    pub fn set_capture_trace(&mut self, trace: TraceDocument) {
        self.capture_trace = Some(trace);
    }

    pub fn open_capture_in_trace(&mut self) -> bool {
        let Some(trace) = self.capture_trace.clone() else {
            return false;
        };
        self.trace_path = None;
        self.set_trace(trace);
        self.select_analysis_input(AnalysisInput::TraceSegment {
            segment: self.selected_trace_segment,
        });
        true
    }

    #[must_use]
    pub fn selected_segment_trace(&self) -> Option<TraceDocument> {
        self.trace
            .as_ref()?
            .extract_segment(self.selected_trace_segment)
            .ok()
    }

    #[must_use]
    pub fn export_trace(&self) -> Option<TraceDocument> {
        match self.export_trace_source {
            ExportTraceSource::Capture => self.capture_trace.clone(),
            ExportTraceSource::OpenTrace => self.trace.clone(),
        }
    }

    pub fn next_run(&mut self) -> Option<(RunId, cardpeek_core::DocumentId)> {
        self.run_counter += 1;
        let run_id = RunId::new(format!("run-{:04}", self.run_counter)).ok()?;
        let document_id =
            cardpeek_core::DocumentId::new(format!("doc-{:04}", self.run_counter)).ok()?;
        self.run_id = Some(run_id.clone());
        self.run_status = RunStatus::Running;
        self.progress = Some(Progress::Indeterminate);
        self.run_operation = None;
        self.document = None;
        self.selected_node = None;
        self.expanded.clear();
        self.search_expanded.clear();
        self.exchanges.clear();
        self.logs.clear();
        Some((run_id, document_id))
    }

    #[allow(clippy::too_many_lines)]
    pub fn apply_event(&mut self, event: Event) {
        let new_session_completed = matches!(event.kind, EventKind::OperationCompleted { .. })
            && self.new_session_operation.as_ref() == Some(&event.operation);
        let new_session_finished = self.new_session_operation.as_ref() == Some(&event.operation)
            && matches!(
                event.kind,
                EventKind::OperationCompleted { .. }
                    | EventKind::OperationFailed { .. }
                    | EventKind::OperationCancelled { .. }
            );
        if new_session_finished {
            self.new_session_operation = None;
        }
        if matches!(
            event.kind,
            EventKind::OperationCompleted { .. }
                | EventKind::OperationFailed { .. }
                | EventKind::OperationCancelled { .. }
        ) {
            self.pending.remove(&event.operation);
        }
        if new_session_completed {
            self.session_counter += 1;
            self.capture_trace = None;
            self.session_exchanges.clear();
            self.notify(format!("{} started.", self.session_name()));
        }
        match event.kind {
            EventKind::SessionStateChanged {
                state,
                reader,
                session,
            } => {
                if reader.transport == cardpeek_core::TransportKind::Pcsc {
                    if let Some(current) = &mut self.session {
                        current.state = state;
                    }
                    if state == SessionState::Connected {
                        self.last_session = Some(session);
                        self.session_counter = 1;
                        self.notify(format!("Connected to {}", reader.name));
                    }
                    if state == SessionState::Connecting {
                        self.notify(format!("Connecting to {}", reader.name));
                    }
                    if state == SessionState::Disconnected {
                        self.notify("Physical reader disconnected.");
                    }
                }
            }
            EventKind::CardStatusChanged {
                card_present,
                protocol,
                atr,
                ..
            } => {
                if let Some(session) = &mut self.session {
                    session.reader.card_present = Some(card_present);
                    session.protocol = protocol;
                    session.atr = atr;
                }
            }
            EventKind::ApduExchanged {
                record,
                command,
                response,
                ..
            } => {
                let exchange = Exchange {
                    record: record.to_string(),
                    command: spaced_hex(&command),
                    data: spaced_hex(&response.data),
                    status: format!("{:04X}", response.status.value()),
                };
                if self.run_operation.as_ref() == Some(&event.operation) {
                    self.exchanges.push(exchange);
                } else {
                    self.session_exchanges.push(exchange);
                }
            }
            EventKind::LogEmitted { level, message, .. } => {
                self.push_log(event.sequence, level, message);
            }
            EventKind::DocumentPublished { run_id, revision } => {
                self.notify(format!(
                    "Document revision {revision} published for {run_id}"
                ));
            }
            EventKind::InteractionRequested { operation, request } => {
                self.interaction_operation = Some(operation);
                self.interaction = Some(request);
            }
            EventKind::OperationProgress {
                operation,
                progress,
            } => {
                if self.run_operation.as_ref() == Some(&operation) {
                    self.progress = Some(progress);
                }
            }
            EventKind::OperationCompleted { operation } => {
                if self.run_operation.as_ref() == Some(&operation) {
                    self.run_status = RunStatus::Complete;
                    self.progress = Some(Progress::Determinate {
                        completed: 1,
                        total: 1,
                    });
                }
            }
            EventKind::OperationFailed { operation, error } => {
                if self.run_operation.as_ref() == Some(&operation) {
                    self.run_status = RunStatus::Failed;
                    self.interaction = None;
                    self.interaction_operation = None;
                    self.interaction_file = None;
                }
                self.errors.push(error.clone());
                self.notify_error(error.clone());
                self.push_log(event.sequence, LogLevel::Error, error);
            }
            EventKind::OperationCancelled { operation } => {
                if self.run_operation.as_ref() == Some(&operation) {
                    self.run_status = RunStatus::Cancelled;
                    self.progress = None;
                    self.interaction = None;
                    self.interaction_operation = None;
                }
            }
        }
    }

    pub fn publish_document(&mut self, snapshot: DocumentSnapshot) {
        if self.document.as_ref().is_some_and(|current| {
            current.run_id == snapshot.run_id && current.revision >= snapshot.revision
        }) {
            return;
        }
        self.selected_node = first_node(&snapshot.document.roots).map(|node| node.id.to_string());
        self.expanded = snapshot
            .document
            .roots
            .iter()
            .flat_map(collect_branch_ids)
            .collect();
        self.search_expanded.clear();
        self.document = Some(snapshot);
    }

    pub fn set_search(&mut self, search: String) {
        let was_searching = !self.search.trim().is_empty();
        let searching = !search.trim().is_empty();
        if was_searching && !searching {
            let search_expanded: Vec<_> = self.search_expanded.drain().collect();
            if let Some(document) = &self.document {
                for id in &search_expanded {
                    if let Some(node) = document
                        .document
                        .roots
                        .iter()
                        .find_map(|node| find(node, id))
                    {
                        self.expanded.extend(
                            ancestor_ids(node, &document.document.roots)
                                .into_iter()
                                .map(str::to_string),
                        );
                    }
                }
            }
            self.expanded.extend(search_expanded);
        } else if was_searching != searching {
            self.search_expanded.clear();
        }
        self.search = search;
    }

    pub fn toggle_node(&mut self, id: &str) {
        if self.search.trim().is_empty() {
            if !self.expanded.remove(id) {
                self.expanded.insert(id.into());
            }
        } else if !self.search_expanded.remove(id) {
            self.search_expanded.insert(id.into());
        }
    }

    #[must_use]
    pub fn visible_rows(&self) -> Vec<ResultRow<'_>> {
        let Some(document) = &self.document else {
            return Vec::new();
        };
        let query = self.search.trim().to_lowercase();
        let mut rows = Vec::new();
        for node in &document.document.roots {
            collect_rows(
                node,
                0,
                &query,
                false,
                &self.expanded,
                &self.search_expanded,
                &mut rows,
            );
        }
        rows
    }

    #[must_use]
    pub fn search_expanded_ids(&self) -> &HashSet<String> {
        &self.search_expanded
    }

    #[must_use]
    pub fn node_visible(&self, node: &ResultNode) -> bool {
        let query = self.search.trim().to_lowercase();
        query.is_empty()
            || node_matches(node, &query)
            || node.children.iter().any(|child| self.node_visible(child))
    }

    #[must_use]
    pub fn visible_nodes(&self) -> Vec<&ResultNode> {
        let query = self.search.trim().to_lowercase();
        self.visible_rows()
            .into_iter()
            .map(|row| row.node)
            .filter(|node| query.is_empty() || node_matches(node, &query))
            .collect()
    }

    #[must_use]
    pub fn selected_tree_text(&self) -> Option<String> {
        self.tree_text(self.selected_node.as_deref()?)
    }

    #[must_use]
    pub fn tree_text(&self, selected_id: &str) -> Option<String> {
        let document = self.document.as_ref()?;
        let selected = document
            .document
            .roots
            .iter()
            .find_map(|root| find(root, selected_id))?;
        let roots = &document.document.roots;
        let mut nodes = ancestor_ids(selected, roots)
            .into_iter()
            .filter_map(|id| roots.iter().find_map(|root| find(root, id)))
            .collect::<Vec<_>>();
        nodes.reverse();
        nodes.push(selected);
        let mut text = String::new();
        for (depth, node) in nodes.into_iter().enumerate() {
            append_tree_text(node, depth, &mut text);
        }
        Some(text.trim_end_matches('\n').into())
    }

    #[must_use]
    pub fn selected(&self) -> Option<&ResultNode> {
        let document = self.document.as_ref()?;
        let selected = self.selected_node.as_ref()?;
        document
            .document
            .roots
            .iter()
            .find_map(|node| find(node, selected))
    }

    pub fn collapse_to_second_level(&mut self) {
        if let Some(document) = &self.document {
            self.expanded = document
                .document
                .roots
                .iter()
                .filter(|node| !node.children.is_empty())
                .map(|node| node.id.to_string())
                .collect();
        }
    }

    pub fn expand_all(&mut self) {
        if let Some(document) = &self.document {
            self.expanded = document
                .document
                .roots
                .iter()
                .flat_map(collect_branch_ids)
                .collect();
        }
    }

    pub fn export_finished(&mut self, notice: ExportNotice) {
        self.show_export = false;
        match notice {
            ExportNotice::Document { run_id, path } => {
                self.notify(format!("Exported document {run_id} to {path}"));
            }
            ExportNotice::Trace { path } => {
                self.notify(format!("Exported trace to {path}"));
            }
        }
    }

    pub fn notify(&mut self, message: impl Into<String>) {
        self.push_notification(NotificationLevel::Info, message.into());
    }

    pub fn notify_error(&mut self, message: impl Into<String>) {
        self.push_notification(NotificationLevel::Error, message.into());
    }

    #[must_use]
    pub fn latest_notification(&self) -> Option<&Notification> {
        self.notifications.last()
    }

    fn push_notification(&mut self, level: NotificationLevel, message: String) {
        if self.notifications.len() == MAX_NOTIFICATIONS {
            self.notifications.remove(0);
        }
        self.notifications.push(Notification { level, message });
    }

    fn push_log(&mut self, sequence: u64, level: LogLevel, message: String) {
        if self.logs.len() == MAX_LOGS {
            self.logs.remove(0);
        }
        self.logs.push(LogEntry {
            sequence,
            level,
            message,
        });
    }
}

#[must_use]
pub fn trace_preview(trace: &TraceDocument) -> TracePreview {
    let mut preview = TracePreview {
        captures: trace.captures.len(),
        ..TracePreview::default()
    };
    for segment in trace.segments() {
        let mut item = TraceSegmentPreview {
            index: segment.index,
            atr: None,
            commands: 0,
            captures: trace
                .captures
                .iter()
                .filter(|capture| capture.segment == segment.index)
                .count(),
        };
        for record in segment.records {
            match record {
                TraceRecord::Reset { atr, .. } if item.atr.is_none() => {
                    item.atr = Some(atr.clone());
                }
                TraceRecord::Command { .. } => {
                    item.commands += 1;
                    preview.commands += 1;
                }
                TraceRecord::Reset { .. } => {}
            }
        }
        preview.segments.push(item);
    }
    preview
}

#[must_use]
pub fn trace_record_matches(record: &TraceRecord, segment: usize, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    let text = match record {
        TraceRecord::Reset { id, mode, atr } => format!(
            "{} reset {:?} {} segment {}",
            id,
            mode,
            spaced_hex(atr.as_bytes()),
            segment + 1
        ),
        TraceRecord::Command {
            id,
            command,
            response,
        } => format!(
            "{} {} {} {:04X} segment {}",
            id,
            spaced_hex(command),
            spaced_hex(&response.data),
            response.status.value(),
            segment + 1
        ),
    };
    let text = text.to_lowercase();
    text.contains(&query) || text.replace(' ', "").contains(&query.replace(' ', ""))
}

#[must_use]
pub fn node_value(node: &ResultNode) -> String {
    node.alternative
        .clone()
        .unwrap_or_else(|| match &node.value {
            Some(NodeValue::Text(value)) => value.clone(),
            Some(NodeValue::Bytes(value)) => spaced_hex(value.elements()),
            None => "No value".into(),
        })
}

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            let _ = write!(output, "{byte:02X}");
            output
        },
    )
}

#[must_use]
pub fn spaced_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn append_tree_text(node: &ResultNode, depth: usize, output: &mut String) {
    output.push_str(&"  ".repeat(depth));
    output.push_str(&node.label);
    output.push('\t');
    output.push_str(&node_value(node));
    output.push('\n');
}

fn first_node(nodes: &[ResultNode]) -> Option<&ResultNode> {
    nodes.first()
}

fn ancestor_ids<'a>(node: &'a ResultNode, roots: &'a [ResultNode]) -> Vec<&'a str> {
    let mut ids = Vec::new();
    let mut parent = node.parent.as_ref();
    while let Some(id) = parent {
        let Some(ancestor) = roots.iter().find_map(|root| find(root, id.as_str())) else {
            break;
        };
        ids.push(ancestor.id.as_str());
        parent = ancestor.parent.as_ref();
    }
    ids
}

fn collect_branch_ids(node: &ResultNode) -> Vec<String> {
    let mut ids = if node.children.is_empty() {
        Vec::new()
    } else {
        vec![node.id.to_string()]
    };
    for child in &node.children {
        ids.extend(collect_branch_ids(child));
    }
    ids
}

fn collect_rows<'a>(
    node: &'a ResultNode,
    depth: usize,
    query: &str,
    within_match: bool,
    expanded_ids: &HashSet<String>,
    search_expanded_ids: &HashSet<String>,
    rows: &mut Vec<ResultRow<'a>>,
) -> bool {
    let matches = within_match || node_matches(node, query);
    let mut visible = matches;
    let mut children = Vec::new();
    for child in &node.children {
        if collect_rows(
            child,
            depth + 1,
            query,
            matches,
            expanded_ids,
            search_expanded_ids,
            &mut children,
        ) {
            visible = true;
        }
    }
    if !visible {
        return false;
    }
    let searching = !query.is_empty();
    let expanded = search_expanded_ids.contains(node.id.as_str())
        || (!searching && expanded_ids.contains(node.id.as_str()));
    rows.push(ResultRow {
        node,
        depth,
        expanded: expanded || searching && !matches,
    });
    if searching && !matches || expanded {
        rows.extend(children);
    }
    true
}

fn find<'a>(node: &'a ResultNode, id: &str) -> Option<&'a ResultNode> {
    if node.id.as_str() == id {
        return Some(node);
    }
    node.children.iter().find_map(|child| find(child, id))
}

fn node_matches(node: &ResultNode, query: &str) -> bool {
    let raw_value = match &node.value {
        Some(NodeValue::Text(value)) => value.clone(),
        Some(NodeValue::Bytes(value)) => value.to_hex(),
        None => String::new(),
    };
    format!(
        "{} {} {} {}",
        node.label,
        node.class,
        node_value(node),
        raw_value
    )
    .to_lowercase()
    .contains(query)
}
