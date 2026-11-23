use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cardpeek_core::{Atr, Protocol, ReaderInfo};
use cardpeek_transport::SessionCapabilities;

use crate::sync::{CommandQueue, lock_unpoisoned};
use crate::worker::WorkerCommand;
use crate::{
    AppError, Command, CommandId, CommandKind, Operation, OperationId, OperationKind,
    OperationStatus, Result, SessionInfo, SessionState,
};

#[derive(Clone, Debug)]
pub(crate) struct SharedState {
    inner: Arc<Mutex<State>>,
}

#[derive(Debug)]
struct State {
    next_command: u64,
    operations: HashMap<OperationId, Operation>,
    commands: HashMap<CommandId, OperationId>,
    session: Option<SessionInfo>,
    readers: Vec<ReaderInfo>,
    worker: Option<WorkerRecord>,
    closed: bool,
}

#[derive(Debug)]
struct WorkerRecord {
    session: OperationId,
    commands: Arc<CommandQueue<WorkerCommand>>,
}

impl SharedState {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                next_command: 1,
                operations: HashMap::new(),
                commands: HashMap::new(),
                session: None,
                readers: Vec::new(),
                worker: None,
                closed: false,
            })),
        }
    }

    pub(crate) fn allocate_ids(&self) -> (CommandId, OperationId) {
        let mut state = lock_unpoisoned(&self.inner);
        let command = CommandId::new(format!("command-{:06}", state.next_command));
        state.next_command += 1;
        let operation = operation_for(&command);
        (command, operation)
    }

    pub(crate) fn register(&self, command: &Command, operation: &OperationId) -> Result<()> {
        let mut state = lock_unpoisoned(&self.inner);
        if state.closed && !matches!(command.kind, CommandKind::Shutdown) {
            return Err(AppError::Shutdown);
        }
        if state.commands.contains_key(&command.id) || state.operations.contains_key(operation) {
            return Err(AppError::DuplicateCommand(command.id.clone()));
        }
        if matches!(command.kind, CommandKind::Connect(_)) && state.worker.is_some() {
            return Err(AppError::SessionAlreadyActive);
        }
        if matches!(
            command.kind,
            CommandKind::Disconnect
                | CommandKind::Reset(_)
                | CommandKind::NewSession
                | CommandKind::Transmit(_)
                | CommandKind::RunAnalyser(_)
                | CommandKind::CollectAnalyser(_)
        ) && state.worker.is_none()
        {
            return Err(AppError::NoActiveSession);
        }
        state.operations.insert(
            operation.clone(),
            Operation {
                id: operation.clone(),
                command: command.id.clone(),
                kind: OperationKind::from(command),
                status: OperationStatus::Pending,
                run_id: match &command.kind {
                    CommandKind::RunAnalyser(request) | CommandKind::CollectAnalyser(request) => {
                        Some(request.run_id.clone())
                    }
                    CommandKind::DecodeAnalyser(request) => Some(request.run_id.clone()),
                    CommandKind::ReplayAnalyser(request) => Some(request.run_id.clone()),
                    _ => None,
                },
            },
        );
        state.commands.insert(command.id.clone(), operation.clone());
        Ok(())
    }

    pub(crate) fn begin(&self, operation: &OperationId) {
        let mut state = lock_unpoisoned(&self.inner);
        if let Some(record) = state.operations.get_mut(operation)
            && record.status == OperationStatus::Pending
        {
            record.status = OperationStatus::Running;
        }
    }

    pub(crate) fn finish(&self, operation: &OperationId, status: OperationStatus) -> bool {
        let mut state = lock_unpoisoned(&self.inner);
        if let Some(record) = state.operations.get_mut(operation)
            && !record.status.is_terminal()
        {
            record.status = status;
            return true;
        }
        false
    }

    pub(crate) fn mark_cancelling(&self, operation: &OperationId) -> Result<()> {
        let mut state = lock_unpoisoned(&self.inner);
        let record = state
            .operations
            .get_mut(operation)
            .ok_or_else(|| AppError::UnknownOperation(operation.clone()))?;
        if record.status.is_terminal() {
            return Err(AppError::OperationFinished(operation.clone()));
        }
        record.status = OperationStatus::Cancelling;
        Ok(())
    }

    pub(crate) fn operation(&self, operation: &OperationId) -> Option<Operation> {
        lock_unpoisoned(&self.inner)
            .operations
            .get(operation)
            .cloned()
    }

    pub(crate) fn operations(&self) -> Vec<Operation> {
        let state = lock_unpoisoned(&self.inner);
        let mut operations: Vec<_> = state.operations.values().cloned().collect();
        operations.sort_by(|left, right| left.id.cmp(&right.id));
        operations
    }

    pub(crate) fn reserve_worker(
        &self,
        operation: &OperationId,
        commands: Arc<CommandQueue<WorkerCommand>>,
    ) {
        lock_unpoisoned(&self.inner).worker = Some(WorkerRecord {
            session: operation.clone(),
            commands,
        });
    }

    pub(crate) fn fail_worker_operations(&self, session: &OperationId) -> Vec<OperationId> {
        let mut state = lock_unpoisoned(&self.inner);
        let mut operations = Vec::new();
        if state
            .worker
            .as_ref()
            .is_some_and(|worker| &worker.session == session)
        {
            for operation in state.operations.values_mut() {
                let queued_session_command = matches!(
                    operation.kind,
                    OperationKind::Disconnect
                        | OperationKind::Reset
                        | OperationKind::NewSession
                        | OperationKind::Transmit
                        | OperationKind::RunAnalyser
                        | OperationKind::CollectAnalyser
                );
                if operation.status == OperationStatus::Pending
                    && operation.id != *session
                    && queued_session_command
                {
                    operation.status = OperationStatus::Failed;
                    operations.push(operation.id.clone());
                }
            }
        }
        operations
    }

    pub(crate) fn set_session(
        &self,
        operation: &OperationId,
        reader: ReaderInfo,
        protocol: Protocol,
        capabilities: SessionCapabilities,
        atr: Atr,
    ) {
        lock_unpoisoned(&self.inner).session = Some(SessionInfo {
            id: operation.clone(),
            reader,
            protocol,
            capabilities,
            atr,
            state: SessionState::Connected,
        });
    }

    pub(crate) fn update_card_status(&self, card_present: bool, protocol: Protocol, atr: Atr) {
        let mut state = lock_unpoisoned(&self.inner);
        if let Some(session) = &mut state.session {
            session.reader.card_present = Some(card_present);
            session.protocol = protocol;
            session.atr = atr;
        }
    }

    pub(crate) fn session(&self) -> Option<SessionInfo> {
        lock_unpoisoned(&self.inner).session.clone()
    }

    pub(crate) fn session_state(&self, session_state: SessionState) {
        let mut state = lock_unpoisoned(&self.inner);
        if let Some(session) = &mut state.session {
            session.state = session_state;
        }
    }

    pub(crate) fn update_atr(&self, atr: Atr) {
        let mut state = lock_unpoisoned(&self.inner);
        if let Some(session) = &mut state.session {
            session.atr = atr;
        }
    }

    pub(crate) fn clear_session(&self) {
        lock_unpoisoned(&self.inner).session = None;
    }

    pub(crate) fn clear_worker(&self, session: &OperationId) {
        let mut state = lock_unpoisoned(&self.inner);
        if state
            .worker
            .as_ref()
            .is_some_and(|worker| &worker.session == session)
        {
            state.worker = None;
        }
    }

    pub(crate) fn forward(&self, command: WorkerCommand) -> Result<()> {
        let state = lock_unpoisoned(&self.inner);
        let worker = state.worker.as_ref().ok_or(AppError::NoActiveSession)?;
        worker
            .commands
            .push(command)
            .map_err(|_| AppError::OperationInProgress)
    }

    pub(crate) fn readers(&self) -> Vec<ReaderInfo> {
        lock_unpoisoned(&self.inner).readers.clone()
    }

    pub(crate) fn set_readers(&self, readers: Vec<ReaderInfo>) {
        lock_unpoisoned(&self.inner).readers = readers;
    }

    pub(crate) fn close(&self) {
        let mut state = lock_unpoisoned(&self.inner);
        if let Some(worker) = &state.worker {
            worker.commands.close();
        }
        state.closed = true;
    }
}

impl OperationKind {
    pub(crate) fn from(command: &Command) -> Self {
        match command.kind {
            CommandKind::EnumerateReaders => Self::EnumerateReaders,
            CommandKind::Connect(_) => Self::Connect,
            CommandKind::Disconnect => Self::Disconnect,
            CommandKind::Reset(_) => Self::Reset,
            CommandKind::NewSession => Self::NewSession,
            CommandKind::Transmit(_) => Self::Transmit,
            CommandKind::DiscoverAnalysers(_) => Self::DiscoverAnalysers,
            CommandKind::RunAnalyser(_) => Self::RunAnalyser,
            CommandKind::CollectAnalyser(_) => Self::CollectAnalyser,
            CommandKind::DecodeAnalyser(_) => Self::DecodeAnalyser,
            CommandKind::ReplayAnalyser(_) => Self::ReplayAnalyser,
            CommandKind::Cancel(_) => Self::Cancel,
            CommandKind::AnswerInteraction(_) => Self::AnswerInteraction,
            CommandKind::ExportDocument(_) => Self::ExportDocument,
            CommandKind::ExportTrace(_) => Self::ExportTrace,
            CommandKind::Shutdown => Self::Shutdown,
        }
    }
}

pub(crate) fn operation_for(command: &CommandId) -> OperationId {
    OperationId::new(format!("operation-for-{}", command.as_str()))
}
