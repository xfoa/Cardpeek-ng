//! GPUI desktop frontend and its application-state adapter.

mod backend;
pub mod card_type;
pub mod controller;
pub mod help;
pub mod input;
pub mod preferences;
pub mod state;
pub mod ui;
#[cfg(target_os = "linux")]
mod x11;

pub use backend::{DesktopBackend, DesktopSession, ReplayBackend};
pub use controller::{Controller, UiMessage};
pub use ui::{App, DesktopController, run};
