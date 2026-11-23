#![allow(missing_docs, clippy::unreadable_literal)]

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use cardpeek_app::{
    AnswerInteraction, InteractionKind, InteractionResponse, Progress, TraceExportMode,
};
use cardpeek_core::{Protocol, ResultNode, RunId, TraceRecord, TransportKind};
use gpui::{
    AnyElement, AppContext, Application, Bounds, ClipboardItem, Context, Div, Entity, FocusHandle,
    FontWeight, Global, Image, ImageFormat, MouseButton, MouseDownEvent, MouseExitEvent,
    MouseMoveEvent, Pixels, Point, Render, Rgba, ScrollStrategy, SharedString, Stateful,
    StatefulInteractiveElement, Styled, Task, TitlebarOptions, UniformListScrollHandle, Window,
    WindowBounds, WindowOptions, anchored, canvas, deferred, div, fill, img, point, prelude::*, px,
    rgb, size, uniform_list,
};

use crate::DesktopBackend;
use crate::controller::Controller;
use crate::help::{self, HelpEntry};
use crate::input::{Cancel, Confirm, TextField, TextFieldEvent, bind_keys};
use crate::preferences::Preferences;
use crate::state::{
    AnalysisInput, DesktopState, ExportKind, ExportTraceSource, NotificationLevel, Screen,
    SessionDialog, node_value, spaced_hex, trace_record_matches,
};

pub type DesktopController = Rc<Controller<DesktopBackend>>;

const INK: Rgba = Rgba {
    r: 24.0 / 255.0,
    g: 38.0 / 255.0,
    b: 42.0 / 255.0,
    a: 1.0,
};
const MUTED: Rgba = Rgba {
    r: 101.0 / 255.0,
    g: 115.0 / 255.0,
    b: 119.0 / 255.0,
    a: 1.0,
};
const CANVAS: Rgba = Rgba {
    r: 244.0 / 255.0,
    g: 246.0 / 255.0,
    b: 245.0 / 255.0,
    a: 1.0,
};
const NAV: Rgba = Rgba {
    r: 23.0 / 255.0,
    g: 45.0 / 255.0,
    b: 49.0 / 255.0,
    a: 1.0,
};
const GREEN: Rgba = Rgba {
    r: 8.0 / 255.0,
    g: 124.0 / 255.0,
    b: 112.0 / 255.0,
    a: 1.0,
};
const GREEN_DARK: Rgba = Rgba {
    r: 5.0 / 255.0,
    g: 102.0 / 255.0,
    b: 92.0 / 255.0,
    a: 1.0,
};
const GREEN_SOFT: Rgba = Rgba {
    r: 228.0 / 255.0,
    g: 243.0 / 255.0,
    b: 239.0 / 255.0,
    a: 1.0,
};
const BORDER: Rgba = Rgba {
    r: 223.0 / 255.0,
    g: 229.0 / 255.0,
    b: 228.0 / 255.0,
    a: 1.0,
};
const WHITE: Rgba = Rgba {
    r: 1.0,
    g: 1.0,
    b: 1.0,
    a: 1.0,
};
const AMBER_SOFT: Rgba = Rgba {
    r: 248.0 / 255.0,
    g: 237.0 / 255.0,
    b: 207.0 / 255.0,
    a: 1.0,
};
const AMBER: Rgba = Rgba {
    r: 135.0 / 255.0,
    g: 99.0 / 255.0,
    b: 19.0 / 255.0,
    a: 1.0,
};
const RED: Rgba = Rgba {
    r: 161.0 / 255.0,
    g: 60.0 / 255.0,
    b: 60.0 / 255.0,
    a: 1.0,
};
const RED_SOFT: Rgba = Rgba {
    r: 251.0 / 255.0,
    g: 234.0 / 255.0,
    b: 234.0 / 255.0,
    a: 1.0,
};

/// # Panics
///
/// Panics if the desktop window cannot be created.
pub fn run(
    controller: DesktopController,
    preferences: Preferences,
    trace_path: Option<std::path::PathBuf>,
) {
    Application::new().run(move |cx| {
        cx.text_system()
            .add_fonts(vec![
                std::borrow::Cow::Borrowed(include_bytes!("../assets/fa-solid-900.otf")),
                std::borrow::Cow::Borrowed(include_bytes!("../assets/fa-regular-400.otf")),
                std::borrow::Cow::Borrowed(include_bytes!("../assets/fa-brands-400.otf")),
            ])
            .expect("Font Awesome loads");
        bind_keys(cx);
        let bounds = Bounds::centered(None, size(px(1280.), px(820.)), cx);
        cx.open_window(
            WindowOptions {
                app_id: Some("cardpeek-ng".into()),
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("Cardpeek-ng".into()),
                    ..Default::default()
                }),
                window_min_size: Some(size(px(900.), px(650.))),
                ..Default::default()
            },
            |_, cx| {
                #[cfg(target_os = "linux")]
                crate::x11::set_window_icon();
                cx.new(|cx| App::new(controller.clone(), preferences, trace_path, cx))
            },
        )
        .expect("desktop window opens");
        cx.activate(true);
    });
}

#[derive(Clone, PartialEq)]
struct TreeCacheKey {
    run_id: RunId,
    revision: u64,
    search: String,
    expanded: Vec<String>,
    search_expanded: Vec<String>,
}

#[derive(Clone, Copy)]
struct PanelResize {
    mouse_y: gpui::Pixels,
    mouse_x: gpui::Pixels,
    tools_height: f32,
    details_width: f32,
}

struct PanelResizeDrag;

struct TreeScrollbarDrag {
    mouse_y: Pixels,
    scroll_offset: Pixels,
}

struct ContextMenu {
    position: Point<Pixels>,
    text: String,
    tree_text: Option<String>,
}

#[derive(Clone, Default)]
struct ActiveHelpTooltip {
    entry: Option<HelpEntry>,
    source: Option<SharedString>,
    position: Point<Pixels>,
}

impl Global for ActiveHelpTooltip {}

trait HelpTarget: StatefulInteractiveElement + Styled + ParentElement + Sized {
    fn help_target(mut self, entry: HelpEntry) -> Self {
        let source = SharedString::from(format!("{:?}", self.interactivity().element_id));
        self.relative().child(help_indicator(entry, source))
    }
}

impl<T: StatefulInteractiveElement + Styled + ParentElement + Sized> HelpTarget for T {}

fn help_indicator(entry: HelpEntry, source: SharedString) -> impl IntoElement {
    canvas(
        |bounds, _, _| bounds,
        move |bounds, listener_bounds, window, _| {
            window.on_mouse_event({
                let source = source.clone();
                move |event: &MouseMoveEvent, _, window, cx| {
                    let active = cx.default_global::<ActiveHelpTooltip>();
                    let next = if listener_bounds.contains(&event.position) {
                        ActiveHelpTooltip {
                            entry: Some(entry),
                            source: Some(source.clone()),
                            position: event.position,
                        }
                    } else if active.source == Some(source.clone()) {
                        ActiveHelpTooltip::default()
                    } else {
                        active.clone()
                    };
                    if next.entry != active.entry
                        || next.source != active.source
                        || next.position != active.position
                    {
                        *active = next;
                        window.refresh();
                    }
                }
            });
            window.on_mouse_event({
                let source = source.clone();
                move |_: &MouseExitEvent, _, window, cx| {
                    let active = cx.default_global::<ActiveHelpTooltip>();
                    if active.source == Some(source.clone()) {
                        *active = ActiveHelpTooltip::default();
                        window.refresh();
                    }
                }
            });
            let mut x = bounds.origin.x;
            while x < bounds.right() {
                let width = px(4.).min(bounds.right() - x);
                window.paint_quad(fill(
                    Bounds {
                        origin: point(x, bounds.bottom() - px(1.)),
                        size: size(width, px(1.)),
                    },
                    GREEN,
                ));
                x += px(8.);
            }
        },
    )
    .absolute()
    .inset_0()
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum NotificationHistory {
    #[default]
    Collapsed,
    Expanded,
}

pub struct App {
    controller: DesktopController,
    state: DesktopState,
    dialog_focus: FocusHandle,
    file_picker_directory: PathBuf,
    _preferences: Preferences,
    search: Entity<TextField>,
    trace_search: Entity<TextField>,
    apdu: Entity<TextField>,
    export: Option<Entity<TextField>>,
    interaction: Option<Entity<TextField>>,
    session_name: Option<Entity<TextField>>,
    interaction_id: Option<String>,
    analyser_menu_open: bool,
    input_menu_open: bool,
    trace_segment_menu_open: bool,
    notification_history: NotificationHistory,
    context_menu: Option<ContextMenu>,
    context_menu_source: Option<String>,
    tree_key: Option<TreeCacheKey>,
    tree_rows: Rc<Vec<(ResultNode, usize, bool)>>,
    tree_scroll: UniformListScrollHandle,
    center_selected: Option<String>,
    tree_scrollbar_drag: Option<TreeScrollbarDrag>,
    tools_height: f32,
    details_width: f32,
    tools_resize: Option<PanelResize>,
    details_resize: Option<PanelResize>,
    _poll: Task<()>,
}

impl App {
    fn new(
        controller: DesktopController,
        preferences: Preferences,
        trace_path: Option<std::path::PathBuf>,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        let search = cx.new(|cx| TextField::new(cx, "", "Find labels or values", false));
        let trace_search =
            cx.new(|cx| TextField::new(cx, "", "Find exact bytes, status, or record ID", false));
        let apdu = cx.new(|cx| TextField::new(cx, "", "00 A4 04 00 02 3F 00 00", false));
        cx.subscribe(&search, |app, _, event, cx| {
            if let TextFieldEvent::Changed(value) = event {
                let was_searching = !app.state.search.trim().is_empty();
                let searching = !value.trim().is_empty();
                app.center_selected = (was_searching && !searching)
                    .then(|| app.state.selected_node.clone())
                    .flatten();
                app.state.set_search(value.clone());
                cx.notify();
            }
        })
        .detach();
        cx.subscribe(&trace_search, |app, _, event, cx| {
            if let TextFieldEvent::Changed(value) = event {
                app.state.trace_search.clone_from(value);
                cx.notify();
            }
        })
        .detach();
        cx.subscribe(&apdu, |app, _, event, cx| {
            if let TextFieldEvent::Changed(value) = event {
                app.state.apdu_command.clone_from(value);
                cx.notify();
            }
        })
        .detach();
        let poll = cx.spawn(|app: gpui::WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            let mut cx = cx.clone();
            async move {
                loop {
                    cx.background_executor()
                        .timer(Duration::from_millis(50))
                        .await;
                    if app
                        .update(&mut cx, |app, cx| {
                            app.controller.refresh_readers(&mut app.state);
                            if app.controller.poll_pending() {
                                app.controller.poll(&mut app.state);
                                app.sync_external_inputs(cx);
                                cx.notify();
                            }
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });
        let mut state = DesktopState {
            trace_path,
            ..DesktopState::default()
        };
        if let Some(path) = &state.trace_path
            && let Ok(trace) = cardpeek_core::TraceDocument::load(path)
        {
            state.set_trace(trace);
            state.screen = Screen::Trace;
        }
        Self {
            controller,
            state,
            dialog_focus: cx.focus_handle(),
            file_picker_directory: directories::BaseDirs::new().map_or_else(
                || PathBuf::from("."),
                |directories| directories.home_dir().to_path_buf(),
            ),
            _preferences: preferences,
            search,
            trace_search,
            apdu,
            export: None,
            interaction: None,
            session_name: None,
            interaction_id: None,
            analyser_menu_open: false,
            input_menu_open: false,
            trace_segment_menu_open: false,
            notification_history: NotificationHistory::Collapsed,
            context_menu: None,
            context_menu_source: None,
            tree_key: None,
            tree_rows: Rc::new(Vec::new()),
            tree_scroll: UniformListScrollHandle::new(),
            center_selected: None,
            tree_scrollbar_drag: None,
            tools_height: 180.,
            details_width: 360.,
            tools_resize: None,
            details_resize: None,
            _poll: poll,
        }
    }

    fn sync_external_inputs(&mut self, cx: &mut Context<'_, Self>) {
        let current_id = self
            .state
            .interaction
            .as_ref()
            .map(|request| request.id.to_string());
        if current_id != self.interaction_id {
            self.interaction_id = current_id;
            self.interaction = None;
            if let Some(request) = self.state.interaction.as_ref()
                && matches!(
                    request.kind,
                    InteractionKind::TextInput { .. } | InteractionKind::SecretInput { .. }
                )
            {
                let default = match &request.kind {
                    InteractionKind::TextInput { default, .. } => {
                        default.clone().unwrap_or_default()
                    }
                    _ => String::new(),
                };
                let masked = matches!(request.kind, InteractionKind::SecretInput { .. });
                let field = cx.new(|cx| TextField::new(cx, default, "Enter response", masked));
                cx.subscribe(&field, |app, _, event, cx| {
                    if matches!(event, TextFieldEvent::Submitted) {
                        app.submit_interaction_text(cx);
                    }
                })
                .detach();
                self.interaction = Some(field);
            }
        }
        if self.state.session_dialog == Some(SessionDialog::EditName) {
            if self.session_name.is_none() {
                let field = cx.new(|cx| {
                    TextField::new(
                        cx,
                        self.state.edited_session_name.clone(),
                        "Session name",
                        false,
                    )
                });
                cx.subscribe(&field, |app, _, event, cx| match event {
                    TextFieldEvent::Changed(value) => {
                        app.state.edited_session_name.clone_from(value);
                        cx.notify();
                    }
                    TextFieldEvent::Submitted => app.save_session_name(cx),
                })
                .detach();
                self.session_name = Some(field);
            }
        } else {
            self.session_name = None;
        }
        if self.state.show_export {
            if let Some(field) = &self.export {
                let destination = self.state.export_destination.clone();
                field.update(cx, |field, cx| {
                    if field.text() != destination {
                        field.set_text(destination, cx);
                    }
                });
            } else {
                let field = cx.new(|cx| {
                    TextField::new(
                        cx,
                        self.state.export_destination.clone(),
                        "Destination",
                        false,
                    )
                });
                cx.subscribe(&field, |app, _, event, cx| {
                    if let TextFieldEvent::Changed(value) = event {
                        app.state.export_destination.clone_from(value);
                        cx.notify();
                    }
                })
                .detach();
                self.export = Some(field);
            }
        } else {
            self.export = None;
        }
    }

    fn connect(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut Context<'_, Self>) {
        if let Some(reader) = self.state.selected_reader.clone() {
            self.controller.connect(reader, &mut self.state);
            cx.notify();
        }
    }

    fn disconnect(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut Context<'_, Self>) {
        self.controller.disconnect(&mut self.state);
        cx.notify();
    }

    fn new_session(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut Context<'_, Self>) {
        self.state.session_dialog = Some(SessionDialog::NewSession);
        cx.notify();
    }

    fn edit_session_name(&mut self, cx: &mut Context<'_, Self>) {
        self.state.session_dialog = Some(SessionDialog::EditName);
        self.state.edited_session_name = self.state.session_name();
        self.session_name = None;
        self.sync_external_inputs(cx);
        cx.notify();
    }

    fn save_session_name(&mut self, cx: &mut Context<'_, Self>) {
        let name = self.state.edited_session_name.clone();
        self.state.rename_session(&name);
        cx.notify();
    }

    fn reset(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut Context<'_, Self>) {
        self.controller.reset(&mut self.state);
        cx.notify();
    }

    fn run_analysis(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut Context<'_, Self>) {
        if let Some(analyser) = self.state.selected_analyser.clone() {
            self.controller.run(analyser, &mut self.state);
            cx.notify();
        }
    }

    fn transmit(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut Context<'_, Self>) {
        self.controller
            .transmit(&self.state.apdu_command.clone(), &mut self.state);
        cx.notify();
    }

    fn open_export(
        &mut self,
        kind: ExportKind,
        source: ExportTraceSource,
        cx: &mut Context<'_, Self>,
    ) {
        self.state.export_kind = kind;
        self.state.export_trace_source = source;
        self.state.export_destination = match kind {
            ExportKind::Document => "cardpeek-result.json",
            ExportKind::Trace => "cardpeek-trace.json",
        }
        .into();
        self.state.show_export = true;
        self.export = None;
        self.sync_external_inputs(cx);
        cx.notify();
    }

    fn remember_file_picker_directory(&mut self, path: &Path) {
        if let Some(directory) = path.parent() {
            self.file_picker_directory = directory.to_path_buf();
        }
    }

    fn select_paths(&mut self, multiple: bool, cx: &mut Context<'_, Self>) {
        let dialog = rfd::AsyncFileDialog::new().set_directory(&self.file_picker_directory);
        cx.spawn(
            move |app: gpui::WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
                let mut cx = cx.clone();
                async move {
                    let paths = if multiple {
                        dialog.pick_files().await.map(|files| {
                            files.iter().map(|file| file.path().to_path_buf()).collect()
                        })
                    } else {
                        dialog
                            .pick_file()
                            .await
                            .map(|file| vec![file.path().to_path_buf()])
                    };
                    app.update(&mut cx, |app, _cx| {
                        if let Some(paths) = paths {
                            if let Some(path) = paths.first() {
                                app.remember_file_picker_directory(path);
                            }
                            if multiple {
                                app.controller.select_analyser_files(paths);
                            } else if let Some(path) = paths.into_iter().next() {
                                app.controller.select_trace_file(path);
                            }
                        }
                    })
                    .ok();
                }
            },
        )
        .detach();
    }

    fn select_save_path(&mut self, interaction: bool, cx: &mut Context<'_, Self>) {
        let suggested_name = self.state.export_destination.clone();
        let file_name = Path::new(&suggested_name).file_name().map_or_else(
            || suggested_name.clone(),
            |name| name.to_string_lossy().into_owned(),
        );
        let receiver = cx.prompt_for_new_path(&self.file_picker_directory, Some(&file_name));
        cx.spawn(
            move |app: gpui::WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
                let mut cx = cx.clone();
                async move {
                    let result = receiver.await;
                    app.update(&mut cx, |app, cx| match result {
                        Ok(Ok(Some(path))) => {
                            app.remember_file_picker_directory(&path);
                            if interaction {
                                app.state.interaction_file = Some(path);
                            } else {
                                app.state.export_destination = path.display().to_string();
                                app.sync_external_inputs(cx);
                            }
                            cx.notify();
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(error)) => app
                            .state
                            .notify_error(format!("Cannot open file picker: {error}")),
                        Err(_) => app
                            .state
                            .notify_error("The file picker closed unexpectedly."),
                    })
                    .ok();
                }
            },
        )
        .detach();
    }

    fn select_interaction_file(&mut self, cx: &mut Context<'_, Self>) {
        let dialog = rfd::AsyncFileDialog::new().set_directory(&self.file_picker_directory);
        cx.spawn(|app: gpui::WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            let mut cx = cx.clone();
            async move {
                let file = dialog.pick_file().await;
                app.update(&mut cx, |app, cx| {
                    if let Some(file) = file {
                        let path = file.path().to_path_buf();
                        app.remember_file_picker_directory(&path);
                        app.state.interaction_file = Some(path);
                        cx.notify();
                    }
                })
                .ok();
            }
        })
        .detach();
    }

    fn header(&self) -> Div {
        let connected = self.state.connected();
        let context = self
            .state
            .session
            .as_ref()
            .filter(|_| connected)
            .map_or_else(
                || {
                    self.state
                        .selected_reader
                        .clone()
                        .unwrap_or_else(|| "No input selected".into())
                },
                |session| session.reader.name.clone(),
            );
        let status = if connected {
            if self.state.card_present() {
                "Card present"
            } else {
                "No card"
            }
        } else {
            "Disconnected"
        };
        div()
            .h(px(76.))
            .w_full()
            .flex_shrink_0()
            .bg(NAV)
            .text_color(WHITE)
            .flex()
            .items_center()
            .justify_between()
            .px_6()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(brand_mark())
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .flex()
                                    .text_size(px(18.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(div().child("Cardpeek-"))
                                    .child(div().text_color(rgb(0xf0d02c)).child("ng")),
                            )
                            .child(
                                div()
                                    .text_size(px(13.))
                                    .text_color(rgb(0xa8bcba))
                                    .child("Smart-card workspace"),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(help_badge(
                        "help-physical-reader",
                        "PHYSICAL READER",
                        rgb(0xc0d5d2),
                        rgb(0x294347),
                        help::PCSC,
                        self.state.help_mode,
                    ))
                    .child(div().text_size(px(13.)).child(context))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().size(px(7.)).rounded_full().bg(if connected {
                                if self.state.card_present() {
                                    rgb(0x60c8a9)
                                } else {
                                    AMBER
                                }
                            } else {
                                MUTED
                            }))
                            .child(
                                div()
                                    .text_size(px(13.))
                                    .text_color(rgb(0xc0d5d2))
                                    .child(status),
                            ),
                    ),
            )
    }

    fn rail(&self, cx: &mut Context<'_, Self>) -> Div {
        div()
            .w(px(72.))
            .h_full()
            .flex_shrink_0()
            .bg(NAV)
            .border_t_1()
            .border_color(rgb(0x294347))
            .py_4()
            .flex()
            .flex_col()
            .items_center()
            .gap_2()
            .child(self.nav_button(
                Screen::Reader,
                "Font Awesome 7 Brands",
                "\u{f287}",
                "Reader",
                cx,
            ))
            .child(self.nav_button(
                Screen::Analysis,
                "Font Awesome 7 Free",
                "\u{f201}",
                "Analysis",
                cx,
            ))
            .child(self.nav_button(
                Screen::Trace,
                "Font Awesome 7 Free",
                "\u{f022}",
                "Trace",
                cx,
            ))
            .child(self.nav_button(
                Screen::Library,
                "Font Awesome 7 Free Solid",
                "\u{f02d}",
                "Library",
                cx,
            ))
            .child(div().flex_1())
            .child(self.help_button(cx))
    }

    fn help_button(&self, cx: &mut Context<'_, Self>) -> Stateful<Div> {
        let active = self.state.help_mode;
        let tooltip = if active {
            "Turn off help mode"
        } else {
            "Turn on help mode"
        };
        div()
            .id("help-mode")
            .w(px(58.))
            .h(px(58.))
            .rounded_lg()
            .flex()
            .items_center()
            .justify_center()
            .cursor_pointer()
            .bg(if active { GREEN } else { NAV })
            .text_color(if active { WHITE } else { rgb(0xa8bcba) })
            .hover(move |style| {
                if active {
                    style.bg(GREEN_DARK)
                } else {
                    style.bg(rgb(0x294347))
                }
            })
            .tooltip(move |_, cx| cx.new(|_| Tooltip(tooltip)).into())
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|app, _, _, cx| {
                    app.state.toggle_help_mode();
                    cx.default_global::<ActiveHelpTooltip>().entry = None;
                    cx.notify();
                }),
            )
            .child(
                div()
                    .text_size(px(24.))
                    .font_family("Font Awesome 7 Free Solid")
                    .font_weight(FontWeight::NORMAL)
                    .child("\u{f059}"),
            )
    }

    fn nav_button(
        &self,
        screen: Screen,
        font_family: &'static str,
        icon: &'static str,
        tooltip: &'static str,
        cx: &mut Context<'_, Self>,
    ) -> impl IntoElement {
        let active = self.state.screen == screen;
        div()
            .id(SharedString::from(format!("nav-{}", screen as u8)))
            .w(px(58.))
            .h(px(58.))
            .rounded_lg()
            .flex()
            .items_center()
            .justify_center()
            .cursor_pointer()
            .bg(if active { GREEN } else { NAV })
            .text_color(if active { WHITE } else { rgb(0xa8bcba) })
            .hover(move |style| {
                if active {
                    style.bg(GREEN_DARK)
                } else {
                    style.bg(rgb(0x294347))
                }
            })
            .tooltip(move |_, cx| cx.new(|_| Tooltip(tooltip)).into())
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |app, _, _, cx| {
                    app.state.screen = screen;
                    app.analyser_menu_open = false;
                    app.input_menu_open = false;
                    app.trace_segment_menu_open = false;
                    cx.notify();
                }),
            )
            .child(
                div()
                    .text_size(px(22.))
                    .font_family(font_family)
                    .font_weight(FontWeight::NORMAL)
                    .child(icon),
            )
    }

    fn reader_page(&self, cx: &mut Context<'_, Self>) -> Stateful<Div> {
        div()
            .id("reader-page")
            .w_full()
            .min_h_full()
            .overflow_y_scroll()
            .p_6()
            .flex()
            .flex_col()
            .gap_5()
            .child(page_head(
                "Reader",
                "Connect a physical PC/SC reader and inspect the current card capture.",
            ))
            .child(
                div()
                    .flex()
                    .gap_5()
                    .w_full()
                    .items_start()
                    .child(div().flex_1().child(self.reader_connection_panel(cx)))
                    .child(div().flex_1().child(self.card_panel(cx))),
            )
            .child(self.capture_panel(cx))
            .child(
                panel()
                    .child(panel_head("Current session exchanges", "PHYSICAL CARD"))
                    .child(self.session_exchanges(cx)),
            )
            .child(self.transmit_tool(cx))
    }

    fn reader_connection_panel(&self, cx: &mut Context<'_, Self>) -> Div {
        let connected = self.state.connected();
        let selected = self
            .state
            .readers
            .iter()
            .find(|reader| Some(&reader.name) == self.state.selected_reader.as_ref());
        let status = if connected {
            if self.state.card_present() {
                "Connected to physical card"
            } else {
                "Connected to physical reader"
            }
        } else if selected.is_some() {
            "Physical reader selected"
        } else {
            "No physical reader detected"
        };
        panel()
            .child(help_panel_head(
                "help-pcsc",
                "Reader connection",
                "PC/SC",
                help::PCSC,
                self.state.help_mode,
            ))
            .child(panel_body()
                .child(field_label("Physical reader"))
                .child(self.reader_list(cx))
                .child(div().mt_4().p_4().rounded_md().bg(CANVAS).flex().items_center().gap_4()
                    .child(reader_session_icon(connected, self.state.card_present()))
                    .child(div().child(div().font_weight(FontWeight::SEMIBOLD).child(status))
                        .child(note("The physical session is independent of open traces and analysis."))))
                .child(div().mt_4().flex().gap_2()
                    .child(if connected {
                        button("disconnect", "Disconnect", ButtonKind::Normal, !self.state.run_running(), cx.listener(Self::disconnect)).into_any_element()
                    } else {
                        button("connect", "Connect", ButtonKind::Primary, selected.is_some(), cx.listener(Self::connect)).into_any_element()
                    })
                    .child(button("reset", "Reset reader", ButtonKind::Normal, self.state.card_present() && !self.state.run_running(), cx.listener(Self::reset)).debug_selector(|| "reset".into()).when(self.state.help_mode, |element| element.help_target(help::RESET))))
        )
    }

    fn capture_panel(&self, cx: &mut Context<'_, Self>) -> Div {
        let new_session_pending = self.state.new_session_pending();
        let resets = self.state.capture_trace.as_ref().map_or(0, |trace| {
            trace
                .records
                .iter()
                .filter(|record| matches!(record, TraceRecord::Reset { .. }))
                .count()
        });
        let commands = self.state.capture_trace.as_ref().map_or(0, |trace| {
            trace
                .records
                .iter()
                .filter(|record| matches!(record, TraceRecord::Command { .. }))
                .count()
        });
        let captures = self
            .state
            .capture_trace
            .as_ref()
            .map_or(0, |trace| trace.captures.len());
        panel()
            .child(help_panel_head(
                "help-trace",
                "Current capture",
                "SESSION TRACE",
                help::TRACE,
                self.state.help_mode,
            ))
            .child(
                panel_body()
                    .flex()
                    .items_center()
                    .gap_4()
                    .child(detail_row("Resets", &resets.to_string()))
                    .child(detail_row("Exchanges", &commands.to_string()))
                    .child(help_detail_row(
                        "help-capture-bundles",
                        "Capture bundles",
                        &captures.to_string(),
                        help::CAPTURE_BUNDLE,
                        self.state.help_mode,
                    ))
                    .child(div().flex_1())
                    .child(button_state(
                        "new-session",
                        "New session",
                        ButtonKind::Normal,
                        self.state.card_present()
                            && !self.state.run_running()
                            && !new_session_pending,
                        new_session_pending,
                        cx.listener(Self::new_session),
                    ))
                    .child(button(
                        "export-capture",
                        "Export current capture",
                        ButtonKind::Normal,
                        self.state.capture_trace.is_some(),
                        cx.listener(|app, _, _, cx| {
                            app.open_export(ExportKind::Trace, ExportTraceSource::Capture, cx);
                        }),
                    ))
                    .child(button(
                        "open-capture-trace",
                        "Open in Trace",
                        ButtonKind::Quiet,
                        self.state.capture_trace.is_some(),
                        cx.listener(|app, _, _, cx| {
                            if app.state.open_capture_in_trace() {
                                app.state.screen = Screen::Trace;
                            }
                            cx.notify();
                        }),
                    )),
            )
    }

    fn reader_list(&self, cx: &mut Context<'_, Self>) -> Div {
        let connected = self.state.connected();
        let mut list = div().mt_2().max_h(px(118.)).flex().flex_col().gap_1();
        let readers: Vec<_> = self
            .state
            .readers
            .iter()
            .filter(|reader| reader.transport == TransportKind::Pcsc)
            .collect();
        if readers.is_empty() {
            list = list.child(empty_box("No readers found"));
        }
        for reader in readers {
            let name = reader.name.clone();
            let selected = self.state.selected_reader.as_ref() == Some(&reader.name);
            list = list.child(
                div()
                    .id(SharedString::from(format!("reader-{name}")))
                    .w_full()
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .border_1()
                    .border_color(if selected { GREEN } else { BORDER })
                    .bg(if selected { GREEN_SOFT } else { WHITE })
                    .text_size(px(14.))
                    .when(!connected, |element| {
                        element
                            .cursor_pointer()
                            .hover(|style| style.bg(GREEN_SOFT))
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(move |app, _, _, cx| {
                                    app.state.selected_reader = Some(name.clone());
                                    cx.notify();
                                }),
                            )
                    })
                    .child(reader.name.clone()),
            );
        }
        list
    }

    fn card_panel(&self, cx: &mut Context<'_, Self>) -> Div {
        let connected = self.state.connected();
        let Some(session) = self.state.session.as_ref().filter(|_| connected) else {
            return panel()
                .child(panel_head("Current physical card", "OFFLINE"))
                .child(empty_box(
                    "Connect a physical PC/SC reader to inspect the current card.",
                ));
        };
        if !self.state.card_present() {
            return panel()
                .child(panel_head("Current physical card", "NO CARD"))
                .child(empty_box(
                    "No card is physically present in the connected reader.",
                ));
        }
        let protocol = protocol_label(session.protocol);
        panel()
            .child(panel_head("Current physical card", "CARD PRESENT"))
            .child(
                panel_body()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_4()
                            .pb_4()
                            .border_b_1()
                            .border_color(BORDER)
                            .child(smart_card())
                            .child(
                                div()
                                    .flex_1()
                                    .child("Current card")
                                    .child(note("Physical session details")),
                            )
                            .child(help_badge(
                                "help-protocol-badge",
                                protocol,
                                GREEN_DARK,
                                GREEN_SOFT,
                                help::PROTOCOL,
                                self.state.help_mode,
                            )),
                    )
                    .child(help_detail_row(
                        "help-card-type",
                        "Card type",
                        self.state.card_type().unwrap_or("Unknown from ATR"),
                        help::CARD_TYPE,
                        self.state.help_mode,
                    ))
                    .child(help_detail_row(
                        "help-connection",
                        "Connection",
                        "Shared PC/SC session",
                        help::PCSC,
                        self.state.help_mode,
                    ))
                    .child(help_detail_row(
                        "help-protocol",
                        "Protocol",
                        protocol,
                        help::PROTOCOL,
                        self.state.help_mode,
                    ))
                    .child(help_detail_row(
                        "help-atr",
                        "ATR",
                        &spaced_hex(session.atr.as_bytes()),
                        help::ATR,
                        self.state.help_mode,
                    ))
                    .child(detail_row("Reader", &session.reader.name))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().flex_1().child(help_detail_row(
                                "help-session",
                                "Session",
                                &self.state.session_name(),
                                help::SESSION,
                                self.state.help_mode,
                            )))
                            .child(button(
                                "edit-session-name",
                                "Edit",
                                ButtonKind::Quiet,
                                !self.state.new_session_pending() && !self.state.run_running(),
                                cx.listener(|app, _, _, cx| app.edit_session_name(cx)),
                            )),
                    ),
            )
    }

    #[allow(clippy::too_many_lines)]
    fn analysis_page(&mut self, cx: &mut Context<'_, Self>) -> Div {
        let has_result = self.state.document.is_some();
        let analyser_name = self.state.selected_analyser_metadata().map_or_else(
            || "No analyser selected".into(),
            |analyser| analyser.title.clone(),
        );
        let page_description = format!("{analyser_name} / {}", self.state.run_status.label());
        let mut result = div().flex_1().min_h_0().w_full();
        if has_result {
            result = result
                .flex()
                .child(self.tree_panel(cx))
                .child(Self::details_resize_handle(cx))
                .child(self.node_details());
        } else {
            result = result.child(panel().size_full().flex().items_center().justify_center()
                .child(div().max_w(px(430.)).child(empty_box(if self.state.run_running() {
                    "Analysis is running. The result will appear when the analyser publishes a revision."
                } else {
                    "Select an explicit input and compatible analyser, then start the operation."
                }))));
        }
        let requirement = self.state.analysis_requirement();
        div()
            .size_full()
            .p_5()
            .flex()
            .flex_col()
            .child(
                div()
                    .flex_shrink_0()
                    .mb_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .child(
                                div()
                                    .text_2xl()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("Analysis"),
                            )
                            .child(note(&page_description)),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .items_center()
                            .child(
                                div().relative().child(self.input_picker(cx)).when(
                                    self.input_menu_open,
                                    |element| {
                                        element.child(deferred(self.input_menu(cx)).priority(1))
                                    },
                                ),
                            )
                            .child(div().relative().child(self.analyser_picker(cx)).when(
                                self.analyser_menu_open,
                                |element| {
                                    element.child(deferred(self.analyser_menu(cx)).priority(1))
                                },
                            ))
                            .child(
                                button(
                                    "run",
                                    self.state.operation_label(),
                                    ButtonKind::Primary,
                                    self.state.can_run(),
                                    cx.listener(Self::run_analysis),
                                )
                                .when(
                                    self.state.help_mode,
                                    |element| {
                                        let entry = match self.state.analysis_operation() {
                                            Some(crate::state::AnalysisOperation::Collect) => {
                                                help::LIVE
                                            }
                                            Some(crate::state::AnalysisOperation::Decode {
                                                ..
                                            }) => help::DECODE,
                                            Some(crate::state::AnalysisOperation::Replay {
                                                ..
                                            }) => help::REPLAY,
                                            None => help::ANALYSER,
                                        };
                                        element.help_target(entry)
                                    },
                                ),
                            )
                            .child(button(
                                "export-document",
                                "Export result",
                                ButtonKind::Normal,
                                has_result,
                                cx.listener(|app, _, _, cx| {
                                    app.open_export(
                                        ExportKind::Document,
                                        ExportTraceSource::Capture,
                                        cx,
                                    );
                                }),
                            )),
                    ),
            )
            .when_some(requirement, |element, text| {
                element.child(div().mb_3().child(note(&text)))
            })
            .child(result)
            .when(self.state.run_details_open, |element| {
                element
                    .child(Self::tools_resize_handle(cx))
                    .child(self.run_details(cx))
            })
            .when(!self.state.run_details_open, |element| {
                element.child(button(
                    "open-run-details",
                    "Show run details",
                    ButtonKind::Quiet,
                    true,
                    cx.listener(|app, _, _, cx| {
                        app.state.run_details_open = true;
                        cx.notify();
                    }),
                ))
            })
    }

    fn tools_resize_handle(cx: &mut Context<'_, Self>) -> Stateful<Div> {
        div()
            .id("tools-resize")
            .h(px(7.))
            .flex_shrink_0()
            .flex()
            .items_center()
            .justify_center()
            .cursor_row_resize()
            .hover(|style| style.bg(GREEN_SOFT))
            .active(|style| style.bg(BORDER))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|app, event: &MouseDownEvent, _, cx| {
                    app.tools_resize = Some(PanelResize {
                        mouse_y: event.position.y,
                        mouse_x: event.position.x,
                        tools_height: app.tools_height,
                        details_width: app.details_width,
                    });
                    cx.stop_propagation();
                }),
            )
            .on_drag(PanelResizeDrag, |_, _, _, cx| cx.new(|_| gpui::EmptyView))
            .on_drag_move::<PanelResizeDrag>(cx.listener(
                |app, event: &gpui::DragMoveEvent<PanelResizeDrag>, _, cx| {
                    if let Some(resize) = app.tools_resize {
                        let delta = f32::from(resize.mouse_y - event.event.position.y);
                        app.tools_height = (resize.tools_height + delta).clamp(120., 480.);
                        cx.notify();
                    }
                },
            ))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|app, _, _, _| app.tools_resize = None),
            )
            .on_mouse_up_out(
                MouseButton::Left,
                cx.listener(|app, _, _, _| app.tools_resize = None),
            )
            .child(div().w(px(32.)).h(px(3.)).rounded_full().bg(MUTED))
    }

    fn details_resize_handle(cx: &mut Context<'_, Self>) -> Stateful<Div> {
        div()
            .id("details-resize")
            .w(px(9.))
            .mx(px(-1.))
            .h_full()
            .flex_shrink_0()
            .flex()
            .items_center()
            .justify_center()
            .cursor_col_resize()
            .hover(|style| style.bg(GREEN_SOFT))
            .active(|style| style.bg(BORDER))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|app, event: &MouseDownEvent, _, cx| {
                    app.details_resize = Some(PanelResize {
                        mouse_y: event.position.y,
                        mouse_x: event.position.x,
                        tools_height: app.tools_height,
                        details_width: app.details_width,
                    });
                    cx.stop_propagation();
                }),
            )
            .on_drag(PanelResizeDrag, |_, _, _, cx| cx.new(|_| gpui::EmptyView))
            .on_drag_move::<PanelResizeDrag>(cx.listener(
                |app, event: &gpui::DragMoveEvent<PanelResizeDrag>, _, cx| {
                    if let Some(resize) = app.details_resize {
                        let delta = f32::from(resize.mouse_x - event.event.position.x);
                        app.details_width = (resize.details_width + delta).clamp(240., 600.);
                        cx.notify();
                    }
                },
            ))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|app, _, _, _| app.details_resize = None),
            )
            .on_mouse_up_out(
                MouseButton::Left,
                cx.listener(|app, _, _, _| app.details_resize = None),
            )
            .child(div().w(px(3.)).h(px(32.)).rounded_full().bg(MUTED))
    }

    fn analyser_picker(&self, cx: &mut Context<'_, Self>) -> Stateful<Div> {
        let label = self
            .state
            .analysers
            .iter()
            .find(|analyser| Some(&analyser.id) == self.state.selected_analyser.as_ref())
            .map_or_else(
                || "No analyser selected".into(),
                |analyser| {
                    if analyser.id == "atr" {
                        format!("Card read {}", analyser.version)
                    } else {
                        format!("{} {}", analyser.title, analyser.version)
                    }
                },
            );
        button(
            "analyser-picker",
            "",
            ButtonKind::Normal,
            !self.state.run_running() && !self.state.analysers.is_empty(),
            cx.listener(|app, _, window, cx| {
                app.analyser_menu_open = !app.analyser_menu_open;
                app.input_menu_open = false;
                window.prevent_default();
                cx.stop_propagation();
                cx.notify();
            }),
        )
        .debug_selector(|| "analyser-picker".into())
        .w(px(150.))
        .overflow_hidden()
        .child(
            div()
                .flex_1()
                .min_w_0()
                .overflow_hidden()
                .text_ellipsis()
                .child(label),
        )
        .child(
            div()
                .flex_shrink_0()
                .pl_2()
                .font_family("Font Awesome 7 Free Solid")
                .text_size(px(12.))
                .child("\u{f078}"),
        )
        .when(self.state.help_mode, |element| {
            element.help_target(help::ANALYSER)
        })
    }

    fn input_picker(&self, cx: &mut Context<'_, Self>) -> Stateful<Div> {
        let label = match self.state.analysis_input {
            AnalysisInput::LiveCard => "Live card".into(),
            AnalysisInput::TraceSegment { segment } => format!("Trace segment {}", segment + 1),
        };
        button(
            "analysis-input",
            label,
            ButtonKind::Normal,
            !self.state.run_running(),
            cx.listener(|app, _, window, cx| {
                app.input_menu_open = !app.input_menu_open;
                app.analyser_menu_open = false;
                window.prevent_default();
                cx.stop_propagation();
                cx.notify();
            }),
        )
        .when(self.state.help_mode, |element| {
            let entry = match self.state.analysis_input {
                AnalysisInput::LiveCard => help::LIVE,
                AnalysisInput::TraceSegment { .. } => help::SEGMENT,
            };
            element.help_target(entry)
        })
    }

    fn analyser_menu(&self, cx: &mut Context<'_, Self>) -> Stateful<Div> {
        let mut menu = div()
            .id("analyser-menu")
            .occlude()
            .on_mouse_down_out(cx.listener(|app, _, _, cx| {
                app.analyser_menu_open = false;
                cx.notify();
            }))
            .absolute()
            .top(px(38.))
            .left_0()
            .w(px(310.))
            .max_h(px(240.))
            .rounded_md()
            .border_1()
            .border_color(BORDER)
            .bg(WHITE)
            .shadow_lg()
            .p_1()
            .flex()
            .flex_col();
        for analyser in self.state.compatible_analysers() {
            let id = analyser.id.clone();
            let selected = self.state.selected_analyser.as_ref() == Some(&id);
            let title = if id == "atr" {
                "Card read".to_string()
            } else {
                analyser.title.clone()
            };
            menu = menu.child(
                div()
                    .id(SharedString::from(format!("analyser-{id}")))
                    .px_3()
                    .py_2()
                    .rounded_sm()
                    .cursor_pointer()
                    .bg(if selected { GREEN_SOFT } else { WHITE })
                    .hover(|style| style.bg(CANVAS))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |app, _, _, cx| {
                            app.state.selected_analyser = Some(id.clone());
                            app.analyser_menu_open = false;
                            cx.notify();
                        }),
                    )
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(format!("{title} {}", analyser.version)),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(MUTED)
                            .child(analyser.description.clone()),
                    ),
            );
        }
        menu
    }

    fn input_menu(&self, cx: &mut Context<'_, Self>) -> Stateful<Div> {
        let mut menu = div()
            .id("analysis-input-menu")
            .occlude()
            .on_mouse_down_out(cx.listener(|app, _, _, cx| {
                app.input_menu_open = false;
                cx.notify();
            }))
            .absolute()
            .top(px(38.))
            .left_0()
            .w(px(330.))
            .max_h(px(280.))
            .overflow_y_scroll()
            .rounded_md()
            .border_1()
            .border_color(BORDER)
            .bg(WHITE)
            .shadow_lg()
            .p_1()
            .flex()
            .flex_col();
        menu = menu.child(
            div()
                .id("input-live")
                .px_3()
                .py_2()
                .rounded_sm()
                .cursor_pointer()
                .bg(if self.state.analysis_input == AnalysisInput::LiveCard {
                    GREEN_SOFT
                } else {
                    WHITE
                })
                .hover(|style| style.bg(CANVAS))
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|app, _, _, cx| {
                        app.state.select_analysis_input(AnalysisInput::LiveCard);
                        app.input_menu_open = false;
                        cx.notify();
                    }),
                )
                .child("Live card"),
        );
        if let Some(trace) = &self.state.trace {
            let path = self.state.trace_path.as_ref().map_or_else(
                || "Current capture".into(),
                |path| path.display().to_string(),
            );
            for segment in trace.segments() {
                let index = segment.index;
                let selected =
                    self.state.analysis_input == AnalysisInput::TraceSegment { segment: index };
                menu = menu.child(
                    div()
                        .id(("analysis-segment", index))
                        .px_3()
                        .py_2()
                        .rounded_sm()
                        .cursor_pointer()
                        .bg(if selected { GREEN_SOFT } else { WHITE })
                        .hover(|style| style.bg(CANVAS))
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |app, _, _, cx| {
                                app.controller.select_segment(index, &mut app.state);
                                app.input_menu_open = false;
                                cx.notify();
                            }),
                        )
                        .child(
                            div()
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(format!("Trace segment {}", index + 1)),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(MUTED)
                                .child(format!("{path} / {} records", segment.records.len())),
                        ),
                );
            }
        }
        menu
    }

    fn tree_panel(&mut self, cx: &mut Context<'_, Self>) -> Div {
        let node_count = self
            .state
            .document
            .as_ref()
            .map_or(0, |document| document.document.node_count());
        panel()
            .flex_1()
            .h_full()
            .min_w_0()
            .flex()
            .flex_col()
            .child(
                div()
                    .px_4()
                    .h(px(50.))
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(BORDER)
                    .child(help_text(
                        "help-result-document",
                        "Decoded data",
                        help::RESULT_DOCUMENT,
                        self.state.help_mode,
                    ))
                    .child(
                        div()
                            .text_xs()
                            .text_color(MUTED)
                            .child(format!("{node_count} nodes")),
                    ),
            )
            .child(
                div()
                    .p_3()
                    .flex()
                    .gap_2()
                    .border_b_1()
                    .border_color(BORDER)
                    .child(div().flex_1().relative().child(self.search.clone()).when(
                        !self.state.search.is_empty(),
                        |element| {
                            element.child(
                                icon_button("clear-search", "\u{f00d}", "Clear search", true)
                                    .absolute()
                                    .right(px(7.))
                                    .top(px(5.))
                                    .on_mouse_down(
                                        MouseButton::Left,
                                        cx.listener(|app, _, _, cx| {
                                            app.search.update(cx, |search, cx| {
                                                search.set_text("", cx);
                                            });
                                            cx.notify();
                                        }),
                                    ),
                            )
                        },
                    ))
                    .child(
                        icon_button("collapse-all", "\u{f100}", "Collapse all", true)
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(|app, _, _, cx| {
                                    app.state.collapse_to_second_level();
                                    cx.notify();
                                }),
                            ),
                    )
                    .child(
                        icon_button("expand-all", "\u{f103}", "Expand all", true).on_mouse_down(
                            MouseButton::Left,
                            cx.listener(|app, _, _, cx| {
                                app.state.expand_all();
                                cx.notify();
                            }),
                        ),
                    ),
            )
            .child(self.result_tree(cx))
            .child(
                div()
                    .h(px(30.))
                    .flex_shrink_0()
                    .px_3()
                    .flex()
                    .items_center()
                    .border_t_1()
                    .border_color(BORDER)
                    .text_xs()
                    .text_color(MUTED)
                    .child("Immutable document / Local data"),
            )
    }

    fn result_tree(&mut self, cx: &mut Context<'_, Self>) -> AnyElement {
        let searching = !self.state.search.trim().is_empty();
        let key = self.state.document.as_ref().map(|document| TreeCacheKey {
            run_id: document.run_id.clone(),
            revision: document.revision,
            search: self.state.search.clone(),
            expanded: self.state.expanded.iter().cloned().collect(),
            search_expanded: self.state.search_expanded.iter().cloned().collect(),
        });
        if self.tree_key != key {
            self.tree_rows = Rc::new(
                self.state
                    .visible_rows()
                    .into_iter()
                    .map(|row| (row.node.clone(), row.depth, row.expanded))
                    .collect(),
            );
            self.tree_key = key;
            if let Some(selected) = self.center_selected.take()
                && let Some(index) = self
                    .tree_rows
                    .iter()
                    .position(|(node, _, _)| node.id.as_str() == selected)
            {
                self.tree_scroll
                    .scroll_to_item_strict(index, ScrollStrategy::Center);
            }
        }
        if searching && self.tree_rows.is_empty() {
            return div()
                .flex_1()
                .min_h_0()
                .p_2()
                .child(empty_box("No matching result nodes."))
                .into_any_element();
        }
        let row_count = self.tree_rows.len();
        let rows = self.tree_rows.clone();
        let list = uniform_list(
            "result-tree",
            row_count,
            cx.processor(move |app, range: std::ops::Range<usize>, _, cx| {
                range
                    .map(|index| {
                        let (node, depth, expanded) = rows[index].clone();
                        app.tree_node(&node, depth, expanded, index, cx)
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .track_scroll(self.tree_scroll.clone())
        .absolute()
        .inset_0()
        .w_full()
        .min_w_0()
        .min_h_0();
        let scroll_state = self.tree_scroll.0.borrow();
        let viewport = scroll_state.base_handle.bounds().size.height;
        let content = scroll_state
            .last_item_size
            .unwrap_or_default()
            .contents
            .height;
        let offset = px(-f32::from(scroll_state.base_handle.offset().y));
        drop(scroll_state);
        let scrollbar = (content > viewport && viewport > px(0.)).then(|| {
            let track = (viewport - px(8.)).max(px(1.));
            let thumb = (track * (viewport / content)).max(px(32.)).min(track);
            let travel = (track - thumb).max(px(0.));
            let max_offset = (content - viewport).max(px(1.));
            let top = px(4.) + travel * (offset / max_offset).clamp(0., 1.);
            self.tree_scrollbar(cx, top, thumb, track, viewport, content)
        });
        div()
            .relative()
            .flex_1()
            .w_full()
            .min_w_0()
            .min_h_0()
            .child(list)
            .children(scrollbar)
            .into_any_element()
    }

    fn tree_scrollbar(
        &self,
        cx: &mut Context<'_, Self>,
        top: Pixels,
        thumb: Pixels,
        track: Pixels,
        viewport: Pixels,
        content: Pixels,
    ) -> Stateful<Div> {
        let scroll = self.tree_scroll.clone();
        let entity = cx.entity();
        let start_scroll = scroll.clone();
        div()
            .id("tree-scrollbar")
            .occlude()
            .absolute()
            .top(top)
            .right(px(2.))
            .w(px(6.))
            .h(thumb)
            .rounded_full()
            .bg(MUTED)
            .cursor_pointer()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |app, event: &MouseDownEvent, _, cx| {
                    let offset = -f32::from(start_scroll.0.borrow().base_handle.offset().y);
                    app.tree_scrollbar_drag = Some(TreeScrollbarDrag {
                        mouse_y: event.position.y,
                        scroll_offset: px(offset),
                    });
                    cx.stop_propagation();
                }),
            )
            .child(canvas(
                |_, _, _| (),
                move |_, (), window, _| {
                    window.on_mouse_event({
                        let scroll = scroll.clone();
                        let entity = entity.clone();
                        move |event: &MouseMoveEvent, _, _, cx| {
                            if !event.dragging() {
                                return;
                            }
                            let Some(drag) = entity.read(cx).tree_scrollbar_drag.as_ref() else {
                                return;
                            };
                            let travel = f32::from(track - thumb).max(1.);
                            let delta = f32::from(event.position.y - drag.mouse_y);
                            let scroll_delta = f32::from(content - viewport) * delta / travel;
                            let offset = f32::from(drag.scroll_offset) + scroll_delta;
                            scroll.0.borrow().base_handle.set_offset(point(
                                px(0.),
                                px(-offset.clamp(0., f32::from(content - viewport))),
                            ));
                            cx.notify(entity.entity_id());
                        }
                    });
                    let entity = entity.clone();
                    window.on_mouse_event(move |_: &gpui::MouseUpEvent, _, _, cx| {
                        entity.update(cx, |app, _| {
                            app.tree_scrollbar_drag = None;
                        });
                    });
                },
            ))
    }

    #[allow(clippy::too_many_lines)]
    fn tree_node(
        &self,
        node: &ResultNode,
        depth: usize,
        expanded: bool,
        index: usize,
        cx: &mut Context<'_, Self>,
    ) -> AnyElement {
        let id = node.id.to_string();
        let has_children = !node.children.is_empty();
        let selected = self.state.selected_node.as_ref() == Some(&id);
        let source = format!("tree-node-{id}");
        let source_for_menu = source.clone();
        let pinned = self.context_menu_source.as_deref() == Some(source.as_str());
        let value = node_value(node)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let copy_text = format!("{}\t{}", node.label, value);
        let tree_text = self.state.tree_text(&id);
        let symbol = node.class.chars().next().unwrap_or('#').to_string();
        div()
            .id(SharedString::from(format!("node-{id}")))
            .w_full()
            .min_w_0()
            .h(px(30.))
            .flex_shrink_0()
            .overflow_hidden()
            .pl(px(f32::from(
                u16::try_from(depth.min(32)).unwrap_or(32) * 14 + 6,
            )))
            .pr_3()
            .rounded_sm()
            .flex()
            .items_center()
            .gap_2()
            .cursor_pointer()
            .bg(if selected || pinned {
                GREEN_SOFT
            } else if index.is_multiple_of(2) {
                WHITE
            } else {
                CANVAS
            })
            .when(self.context_menu.is_none(), |element| {
                element.hover(move |style| {
                    if selected {
                        style.bg(GREEN_SOFT)
                    } else {
                        style.bg(BORDER)
                    }
                })
            })
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |app, _, _, cx| {
                    app.state.selected_node = Some(id.clone());
                    if has_children {
                        app.state.toggle_node(&id);
                    }
                    cx.notify();
                }),
            )
            .on_mouse_down(
                MouseButton::Right,
                cx.listener(move |app, event: &MouseDownEvent, _, cx| {
                    app.context_menu_source = Some(source_for_menu.clone());
                    app.context_menu = Some(ContextMenu {
                        position: event.position,
                        text: copy_text.clone(),
                        tree_text: tree_text.clone(),
                    });
                    cx.notify();
                }),
            )
            .child(
                div()
                    .w(px(10.))
                    .text_xs()
                    .text_color(MUTED)
                    .font_family("Font Awesome 7 Free Solid")
                    .child(if has_children {
                        if expanded { "\u{f078}" } else { "\u{f054}" }
                    } else {
                        ""
                    }),
            )
            .child(
                div()
                    .size(px(20.))
                    .rounded_sm()
                    .bg(if selected { GREEN } else { CANVAS })
                    .text_color(if selected { WHITE } else { MUTED })
                    .text_xs()
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(symbol),
            )
            .child(
                div()
                    .min_w_0()
                    .overflow_hidden()
                    .text_sm()
                    .text_ellipsis()
                    .child(node.label.clone()),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .text_xs()
                    .text_color(MUTED)
                    .text_ellipsis()
                    .child(value),
            )
            .into_any_element()
    }

    #[allow(clippy::too_many_lines)]
    fn node_details(&self) -> AnyElement {
        let Some(node) = self.state.selected() else {
            return panel()
                .w_3_5()
                .h_full()
                .child(empty_box("Select a result node."))
                .into_any_element();
        };
        let size = node
            .size_bits
            .map_or_else(|| "Not specified".into(), |size| format!("{size} bits"));
        let mime_type = node.mime_type.as_deref().unwrap_or("Not specified");
        let source = node.provenance.as_ref().map_or_else(
            || "Not specified".into(),
            |source| source.record.to_string(),
        );
        let document = self.state.document.as_ref().map_or_else(
            || "Not available".into(),
            |document| format!("{} / rev. {}", document.document.id, document.revision),
        );
        panel()
            .w(px(self.details_width))
            .flex_shrink_0()
            .h_full()
            .id("node-details")
            .overflow_y_scroll()
            .child(
                div()
                    .p_4()
                    .border_b_1()
                    .border_color(BORDER)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_lg()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(node.label.clone()),
                            )
                            .child(badge(&node.class, MUTED, CANVAS)),
                    )
                    .child(note(&format!("{} / {source}", node.id))),
            )
            .child(
                div()
                    .m_4()
                    .p_4()
                    .rounded_md()
                    .bg(GREEN_SOFT)
                    .child(
                        div()
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(GREEN_DARK)
                            .child("HUMAN-READABLE VALUE"),
                    )
                    .child(div().mt_2().text_sm().child(node_value(node))),
            )
            .child(
                div()
                    .px_4()
                    .pb_4()
                    .child(detail_row("Exact size", &size))
                    .child(help_detail_row(
                        "help-node-id",
                        "Node ID",
                        &node.id.to_string(),
                        help::NODE_ID,
                        self.state.help_mode,
                    ))
                    .child(help_detail_row(
                        "help-value-class",
                        "Value class",
                        &node.class,
                        help::VALUE_CLASS,
                        self.state.help_mode,
                    ))
                    .child(help_detail_row(
                        "help-mime-type",
                        "MIME type",
                        mime_type,
                        help::MIME_TYPE,
                        self.state.help_mode,
                    ))
                    .child(help_detail_row(
                        "help-source-record",
                        "Source record",
                        &source,
                        help::SOURCE_RECORD,
                        self.state.help_mode,
                    ))
                    .child(help_detail_row(
                        "help-document",
                        "Document",
                        &document,
                        help::RESULT_DOCUMENT,
                        self.state.help_mode,
                    )),
            )
            .into_any_element()
    }

    fn run_details(&self, cx: &mut Context<'_, Self>) -> Div {
        let progress = progress_percent(self.state.progress.as_ref());
        panel()
            .h(px(self.tools_height))
            .w_full()
            .flex_shrink_0()
            .flex()
            .flex_col()
            .child(
                div()
                    .h(px(42.))
                    .flex_shrink_0()
                    .px_3()
                    .flex()
                    .items_center()
                    .gap_3()
                    .border_b_1()
                    .border_color(BORDER)
                    .child(div().font_weight(FontWeight::SEMIBOLD).child("Run details"))
                    .child(
                        div()
                            .text_xs()
                            .text_color(MUTED)
                            .child(self.state.run_status.label()),
                    )
                    .child(
                        div().w(px(90.)).h(px(4.)).rounded_full().bg(CANVAS).child(
                            div()
                                .h_full()
                                .w(gpui::relative(f32::from(progress.min(100) as u16) / 100.))
                                .rounded_full()
                                .bg(GREEN),
                        ),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(MUTED)
                            .child(format!("{progress}%")),
                    )
                    .child(div().flex_1())
                    .child(button(
                        "close-run-details",
                        "Hide",
                        ButtonKind::Quiet,
                        true,
                        cx.listener(|app, _, _, cx| {
                            app.state.run_details_open = false;
                            cx.notify();
                        }),
                    )),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .child(
                        div()
                            .w_1_2()
                            .min_w_0()
                            .border_r_1()
                            .border_color(BORDER)
                            .child(self.run_exchanges(cx)),
                    )
                    .child(div().w_1_2().min_w_0().child(self.activity_log(cx))),
            )
    }

    fn run_exchanges(&self, cx: &mut Context<'_, Self>) -> AnyElement {
        exchange_list(
            "run-exchanges",
            &self.state.exchanges,
            self.state.help_mode,
            cx,
        )
    }

    fn session_exchanges(&self, cx: &mut Context<'_, Self>) -> AnyElement {
        exchange_list(
            "session-exchanges",
            &self.state.session_exchanges,
            self.state.help_mode,
            cx,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn trace_page(&mut self, cx: &mut Context<'_, Self>) -> Div {
        let path = self.state.trace_path.as_ref().map_or_else(
            || "Current capture".into(),
            |path| path.display().to_string(),
        );
        let segments = self
            .state
            .trace
            .as_ref()
            .map_or(0, |trace| trace.segments().len());
        let records = self
            .state
            .trace
            .as_ref()
            .map_or(0, |trace| trace.records.len());
        let captures = self
            .state
            .trace
            .as_ref()
            .map_or(0, |trace| trace.captures.len());
        div()
            .size_full()
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        page_head(
                            "Trace",
                            "Inspect exact records in capture order without changing hardware.",
                        )
                        .when(self.state.help_mode, |element| {
                            element.child(help_text(
                                "help-trace-page",
                                "What is a trace?",
                                help::TRACE,
                                true,
                            ))
                        }),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                button(
                                    "load-current-session",
                                    "Load current session",
                                    ButtonKind::Normal,
                                    self.state.capture_trace.is_some(),
                                    cx.listener(|app, _, _, cx| {
                                        app.state.open_capture_in_trace();
                                        cx.notify();
                                    }),
                                )
                                .when(self.state.help_mode, |element| {
                                    element.help_target(help::LOAD_CURRENT_SESSION)
                                }),
                            )
                            .child(button(
                                "open-trace",
                                "Import trace",
                                ButtonKind::Normal,
                                true,
                                cx.listener(|app, _, _, cx| app.select_paths(false, cx)),
                            ))
                            .child(button(
                                "export-open-trace",
                                "Export trace",
                                ButtonKind::Normal,
                                self.state.trace.is_some(),
                                cx.listener(|app, _, _, cx| {
                                    app.open_export(
                                        ExportKind::Trace,
                                        ExportTraceSource::OpenTrace,
                                        cx,
                                    );
                                }),
                            )),
                    ),
            )
            .child(
                panel()
                    .p_3()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(path),
                    )
                    .child(note(&format!(
                        "{segments} segments / {records} records / {captures} capture bundles"
                    )))
                    .child(button(
                        "decode-segment",
                        "Decode in Analysis",
                        ButtonKind::Primary,
                        self.state.trace.is_some(),
                        cx.listener(|app, _, _, cx| {
                            let segment = app.state.selected_trace_segment;
                            app.state
                                .select_analysis_input(AnalysisInput::TraceSegment { segment });
                            app.state.screen = Screen::Analysis;
                            cx.notify();
                        }),
                    )),
            )
            .child(
                panel()
                    .p_3()
                    .flex()
                    .gap_3()
                    .items_center()
                    .child(
                        div().relative().child(self.trace_segment_picker(cx)).when(
                            self.trace_segment_menu_open,
                            |element| {
                                element.child(deferred(self.trace_segment_menu(cx)).priority(1))
                            },
                        ),
                    )
                    .child(div().w(px(320.)).child(self.trace_search.clone())),
            )
            .child(panel().flex_1().min_h_0().child(self.trace_records(cx)))
    }

    fn trace_segment_picker(&self, cx: &mut Context<'_, Self>) -> Stateful<Div> {
        button(
            "trace-segment-picker",
            format!("Segment {}", self.state.selected_trace_segment + 1),
            ButtonKind::Normal,
            self.state.trace.is_some(),
            cx.listener(|app, _, window, cx| {
                app.trace_segment_menu_open = !app.trace_segment_menu_open;
                window.prevent_default();
                cx.stop_propagation();
                cx.notify();
            }),
        )
        .debug_selector(|| "trace-segment-picker".into())
        .w(px(150.))
        .child(
            div()
                .pl_2()
                .font_family("Font Awesome 7 Free Solid")
                .text_size(px(12.))
                .child("\u{f078}"),
        )
        .when(self.state.help_mode, |element| {
            element.help_target(help::SEGMENT)
        })
    }

    fn trace_segment_menu(&self, cx: &mut Context<'_, Self>) -> Stateful<Div> {
        let mut menu = div()
            .id("trace-segment-menu")
            .occlude()
            .on_mouse_down_out(cx.listener(|app, _, _, cx| {
                app.trace_segment_menu_open = false;
                cx.notify();
            }))
            .absolute()
            .top(px(38.))
            .left_0()
            .w(px(220.))
            .max_h(px(280.))
            .overflow_y_scroll()
            .rounded_md()
            .border_1()
            .border_color(BORDER)
            .bg(WHITE)
            .shadow_lg()
            .p_1()
            .flex()
            .flex_col();
        if let Some(trace) = &self.state.trace {
            for segment in trace.segments() {
                let index = segment.index;
                let selected = index == self.state.selected_trace_segment;
                menu = menu.child(
                    div()
                        .id(("trace-segment", index))
                        .px_3()
                        .py_2()
                        .rounded_sm()
                        .cursor_pointer()
                        .bg(if selected { GREEN_SOFT } else { WHITE })
                        .hover(|style| style.bg(CANVAS))
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |app, _, _, cx| {
                                app.controller.select_segment(index, &mut app.state);
                                app.trace_segment_menu_open = false;
                                cx.notify();
                            }),
                        )
                        .child(format!("Segment {}", index + 1)),
                );
            }
        }
        menu
    }

    fn trace_records(&mut self, cx: &mut Context<'_, Self>) -> AnyElement {
        let Some(trace) = &self.state.trace else {
            return empty_box("Open a trace or open the current Reader capture.")
                .into_any_element();
        };
        let query = self.state.trace_search.clone();
        let selected_segment = self.state.selected_trace_segment;
        let rows: Vec<(usize, TraceRecord)> = trace
            .segments()
            .into_iter()
            .filter(|segment| segment.index == selected_segment)
            .flat_map(|segment| {
                segment
                    .records
                    .iter()
                    .cloned()
                    .map(move |record| (segment.index, record))
            })
            .filter(|(segment, record)| trace_record_matches(record, *segment, &query))
            .collect();
        if rows.is_empty() {
            return empty_box("No trace records match the selected segment and search.")
                .into_any_element();
        }
        let rows = Rc::new(rows);
        uniform_list(
            "trace-records",
            rows.len(),
            cx.processor(move |app, range: std::ops::Range<usize>, _, cx| {
                range
                    .map(|index| {
                        let (segment, record) = rows[index].clone();
                        app.trace_record(segment, &record, index, cx)
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .size_full()
        .into_any_element()
    }

    #[allow(clippy::too_many_lines)]
    fn trace_record(
        &self,
        segment: usize,
        record: &TraceRecord,
        index: usize,
        cx: &mut Context<'_, Self>,
    ) -> AnyElement {
        let id = record.id().to_string();
        let expanded = self.state.trace_expanded.contains(&id);
        let captures = self.state.trace.as_ref().map_or(0, |trace| {
            trace
                .captures
                .iter()
                .filter(|capture| {
                    capture.segment == segment
                        && capture
                            .values
                            .iter()
                            .any(|value| value.source.as_str() == id)
                })
                .count()
        });
        let (summary, details, copy_text) = match record {
            TraceRecord::Reset { mode, atr, .. } => {
                let bytes = spaced_hex(atr.as_bytes());
                (
                    format!("RESET {mode:?} / {bytes}"),
                    vec![("ATR", bytes.clone())],
                    format!("RESET\t{id}\t{bytes}"),
                )
            }
            TraceRecord::Command {
                command, response, ..
            } => {
                let tx = spaced_hex(command);
                let rx = spaced_hex(&response.data);
                let status = format!("{:04X}", response.status.value());
                (
                    format!("TX {tx}"),
                    vec![
                        ("TX", tx.clone()),
                        ("RX", rx.clone()),
                        ("Status", status.clone()),
                    ],
                    format!("TX\t{tx}\nRX\t{rx}\t{status}"),
                )
            }
        };
        let summary_help = match record {
            TraceRecord::Reset { .. } => help::RESET,
            TraceRecord::Command { .. } => help::APDU,
        };
        let height = if expanded && matches!(record, TraceRecord::Command { .. }) {
            116.
        } else if expanded {
            76.
        } else {
            40.
        };
        div()
            .id(SharedString::from(format!("trace-record-{id}")))
            .h(px(height))
            .w_full()
            .min_w_0()
            .overflow_hidden()
            .p_2()
            .bg(if index.is_multiple_of(2) {
                WHITE
            } else {
                CANVAS
            })
            .when(
                self.context_menu_source.as_deref() == Some(format!("trace-record-{id}").as_str()),
                |element| element.bg(BORDER),
            )
            .when(self.context_menu.is_none(), |element| {
                element.hover(|style| style.bg(BORDER))
            })
            .on_mouse_down(
                MouseButton::Left,
                cx.listener({
                    let id = id.clone();
                    move |app, _, _, cx| {
                        if !app.state.trace_expanded.remove(&id) {
                            app.state.trace_expanded.insert(id.clone());
                        }
                        cx.notify();
                    }
                }),
            )
            .on_mouse_down(
                MouseButton::Right,
                cx.listener({
                    let id = id.clone();
                    move |app, event: &MouseDownEvent, _, cx| {
                        let id = id.clone();
                        app.context_menu_source = Some(format!("trace-record-{id}"));
                        app.context_menu = Some(ContextMenu {
                            position: event.position,
                            text: copy_text.clone(),
                            tree_text: None,
                        });
                        cx.notify();
                    }
                }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_xs()
                    .child(div().w(px(16.)).child(if expanded { "v" } else { ">" }))
                    .child(
                        div()
                            .id(SharedString::from(format!("help-trace-record-{id}")))
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .text_ellipsis()
                            .when(self.state.help_mode, |element| {
                                element.help_target(summary_help).child(help_content(
                                    div()
                                        .w_full()
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .child(summary.clone()),
                                ))
                            })
                            .when(!self.state.help_mode, |element| element.child(summary)),
                    )
                    .child(div().text_color(MUTED).child(format!(
                        "Segment {} / {id} / {captures} captures",
                        segment + 1
                    ))),
            )
            .when(expanded, |element| {
                element.child(div().pl_6().pt_1().children(details.into_iter().map(
                    |(label, value)| {
                        div()
                            .flex()
                            .gap_2()
                            .text_xs()
                            .child(div().w(px(48.)).text_color(MUTED).child(label))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .overflow_hidden()
                                    .text_ellipsis()
                                    .child(value),
                            )
                    },
                )))
            })
            .into_any_element()
    }

    fn activity_log(&self, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let mut list = div()
            .id("activity-log")
            .size_full()
            .overflow_y_scroll()
            .p_2();
        list = list.child(
            div()
                .flex()
                .justify_between()
                .items_center()
                .pb_2()
                .child(note(&format!(
                    "{} retained messages",
                    self.state.logs.len()
                )))
                .child(button(
                    "clear-log",
                    "Clear log",
                    ButtonKind::Quiet,
                    true,
                    cx.listener(|app, _, _, cx| {
                        app.state.logs.clear();
                        cx.notify();
                    }),
                )),
        );
        for (index, log) in self.state.logs.iter().rev().take(50).enumerate() {
            let copy_text = format!("#{}\t{:?}\t{}", log.sequence, log.level, log.message);
            let source = format!("activity-log-{}", log.sequence);
            let source_for_menu = source.clone();
            list = list.child(
                div()
                    .flex()
                    .gap_3()
                    .py_1()
                    .px_2()
                    .text_xs()
                    .bg(if index.is_multiple_of(2) {
                        WHITE
                    } else {
                        CANVAS
                    })
                    .when(
                        self.context_menu_source.as_deref() == Some(source.as_str()),
                        |element| element.bg(BORDER),
                    )
                    .when(self.context_menu.is_none(), |element| {
                        element.hover(|style| style.bg(BORDER))
                    })
                    .on_mouse_down(
                        MouseButton::Right,
                        cx.listener(move |app, event: &MouseDownEvent, _, cx| {
                            app.context_menu_source = Some(source_for_menu.clone());
                            app.context_menu = Some(ContextMenu {
                                position: event.position,
                                text: copy_text.clone(),
                                tree_text: None,
                            });
                            cx.notify();
                        }),
                    )
                    .child(
                        div()
                            .w(px(34.))
                            .text_color(MUTED)
                            .child(format!("#{}", log.sequence)),
                    )
                    .child(
                        div()
                            .w(px(50.))
                            .text_color(if matches!(log.level, cardpeek_app::LogLevel::Error) {
                                RED
                            } else {
                                GREEN_DARK
                            })
                            .child(format!("{:?}", log.level)),
                    )
                    .child(div().flex_1().child(log.message.clone())),
            );
        }
        list
    }

    fn transmit_tool(&self, cx: &mut Context<'_, Self>) -> Div {
        div()
            .p_4()
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(div().flex_1().child(self.apdu.clone()))
                    .child(
                        button(
                            "send-apdu",
                            "Send APDU",
                            ButtonKind::Primary,
                            self.state.card_present() && !self.state.apdu_command.trim().is_empty(),
                            cx.listener(Self::transmit),
                        )
                        .when(self.state.help_mode, |element| {
                            element.help_target(help::APDU)
                        }),
                    ),
            )
            .child(note("Exact bytes only. No implicit retry or GET RESPONSE."))
    }

    #[allow(clippy::too_many_lines)]
    fn library_page(&self, cx: &mut Context<'_, Self>) -> Div {
        let mut library = div()
            .id("analyser-library")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll();
        if self.state.analysers.is_empty() {
            library = library.child(empty_box(
                "No analysers installed. Add a trusted Lua script to make analysis available.",
            ));
        }
        for analyser in &self.state.analysers {
            let id = analyser.id.clone();
            let file = analyser
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("analyser.lua");
            library = library.child(
                div()
                    .p_4()
                    .flex()
                    .items_center()
                    .gap_4()
                    .border_b_1()
                    .border_color(BORDER)
                    .child(
                        div()
                            .id(SharedString::from(format!("help-lua-{id}")))
                            .size(px(42.))
                            .rounded_md()
                            .bg(GREEN_SOFT)
                            .text_color(GREEN_DARK)
                            .font_weight(FontWeight::BOLD)
                            .flex()
                            .items_center()
                            .justify_center()
                            .when(self.state.help_mode, |element| {
                                element.help_target(help::LUA).child(help_content(
                                    div()
                                        .size_full()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .child("Lua"),
                                ))
                            })
                            .when(!self.state.help_mode, |element| element.child("Lua")),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(analyser.title.clone()),
                            )
                            .child(note(&analyser.description))
                            .child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .text_color(MUTED)
                                    .child(format!("{file} / {}", analyser.id)),
                            )
                            .child(
                                div()
                                    .mt_2()
                                    .flex()
                                    .gap_1()
                                    .when(analyser.capabilities.live_collection, |element| {
                                        element.child(help_badge(
                                            SharedString::from(format!("help-live-badge-{id}")),
                                            "LIVE",
                                            GREEN_DARK,
                                            GREEN_SOFT,
                                            help::LIVE,
                                            self.state.help_mode,
                                        ))
                                    })
                                    .when(analyser.capabilities.offline_decoding, |element| {
                                        element.child(help_badge(
                                            SharedString::from(format!("help-decode-badge-{id}")),
                                            "DECODE",
                                            GREEN_DARK,
                                            GREEN_SOFT,
                                            help::DECODE,
                                            self.state.help_mode,
                                        ))
                                    })
                                    .when(analyser.capabilities.replay, |element| {
                                        element.child(help_badge(
                                            SharedString::from(format!("help-replay-badge-{id}")),
                                            "REPLAY",
                                            AMBER,
                                            AMBER_SOFT,
                                            help::REPLAY,
                                            self.state.help_mode,
                                        ))
                                    })
                                    .child(
                                        div()
                                            .id(SharedString::from(format!(
                                                "help-capture-schema-{id}"
                                            )))
                                            .text_xs()
                                            .text_color(MUTED)
                                            .when(self.state.help_mode, |element| {
                                                element.help_target(help::CAPTURE_SCHEMA).child(
                                                    help_content(
                                                        div().child(
                                                            analyser
                                                                .capture_schema
                                                                .clone()
                                                                .unwrap_or_else(|| {
                                                                    "No capture schema".into()
                                                                }),
                                                        ),
                                                    ),
                                                )
                                            })
                                            .when(!self.state.help_mode, |element| {
                                                element.child(
                                                    analyser.capture_schema.clone().unwrap_or_else(
                                                        || "No capture schema".into(),
                                                    ),
                                                )
                                            }),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .id(SharedString::from(format!("help-version-{id}")))
                            .text_sm()
                            .text_color(MUTED)
                            .when(self.state.help_mode, |element| {
                                element
                                    .help_target(help::ANALYSER_VERSION)
                                    .child(help_content(
                                        div().child(format!("v{}", analyser.version)),
                                    ))
                            })
                            .when(!self.state.help_mode, |element| {
                                element.child(format!("v{}", analyser.version))
                            }),
                    )
                    .child(badge("INSTALLED", MUTED, CANVAS))
                    .child(button(
                        SharedString::from(format!("remove-{id}")),
                        "Remove",
                        ButtonKind::Quiet,
                        !self.state.run_running(),
                        cx.listener(move |app, _, _, cx| {
                            app.state.selected_analyser = Some(id.clone());
                            app.state.pending_remove = Some(id.clone());
                            cx.notify();
                        }),
                    )),
            );
        }
        div()
            .size_full()
            .p_6()
            .child(
                div()
                    .mb_5()
                    .child(page_head("Library", "Manage trusted analysers, capabilities, and capture schemas.")),
            )
            .child(
                div()
                    .flex()
                    .gap_5()
                    .items_start()
                    .child(
                        panel()
                            .w_2_3()
                            .min_h(px(400.))
                            .flex()
                            .flex_col()
                            .child(div().px_4().h(px(54.)).flex().items_center().justify_between().border_b_1().border_color(BORDER).child(div().child(div().font_weight(FontWeight::SEMIBOLD).child("Analyser library")).child(note("Metadata is read without executing scripts"))).child(badge(format!("{} INSTALLED", self.state.analysers.len()), MUTED, CANVAS)))
                            .child(library)
                            .child(div().p_3().flex().items_center().justify_between().child(note("User library / Shared with the CLI")).child(button("add-analyser", "Add analyser", ButtonKind::Primary, !self.state.run_running(), cx.listener(|app, _, _, cx| {
                                app.select_paths(true, cx);
                            })))),
                    )
                    .child(
                        panel()
                            .w_1_3()
                            .child(setting_section("Manual analyser selection", "Choose the analyser in Analysis. The application does not issue automatic detection probes."))
                            .child(setting_section("Library location", &self.state.analyser_directory))
                            .child(div().m_4().p_3().rounded_md().bg(AMBER_SOFT).child(div().font_weight(FontWeight::SEMIBOLD).text_color(AMBER).child("Only import scripts you trust")).child(note("Analysers can access local files and system facilities. They are not sandboxed.")))
                            .child(div().m_4().p_3().rounded_md().bg(GREEN_SOFT).child(help_text("help-telemetry", "This app sends no telemetry", help::TELEMETRY, self.state.help_mode)).child(note("Card data and traces stay on this device unless you export them."))),
                    ),
            )
    }

    fn dialogs(&self, cx: &mut Context<'_, Self>) -> Option<AnyElement> {
        if self.state.session_dialog == Some(SessionDialog::NewSession) {
            return Self::new_session_dialog(cx).into_any_element().into();
        }
        if self.state.session_dialog == Some(SessionDialog::EditName) {
            return self.session_name_dialog(cx).into_any_element().into();
        }
        if self.state.interaction.is_some() {
            return self.interaction_dialog(cx).into_any_element().into();
        }
        if self.state.show_export {
            return self.export_dialog(cx).into_any_element().into();
        }
        if self.state.pending_remove.is_some() {
            return self.remove_dialog(cx).into_any_element().into();
        }
        None
    }

    fn new_session_dialog(cx: &mut Context<'_, Self>) -> Div {
        modal(
            "Start a new session?",
            "The reader will stay connected. The card will be reset.",
            div().p_5().child(notice_box(
                "The current capture will be replaced",
                "Export the current capture first if you need to keep it.",
                AMBER,
                AMBER_SOFT,
            )),
            div()
                .child(button(
                    "cancel-new-session",
                    "Cancel",
                    ButtonKind::Normal,
                    true,
                    cx.listener(|app, _, _, cx| {
                        app.state.session_dialog = None;
                        cx.notify();
                    }),
                ))
                .child(button(
                    "confirm-new-session",
                    "Start new session",
                    ButtonKind::Primary,
                    true,
                    cx.listener(|app, _, _, cx| {
                        app.state.session_dialog = None;
                        app.controller.new_session(&mut app.state);
                        cx.notify();
                    }),
                )),
        )
    }

    fn session_name_dialog(&self, cx: &mut Context<'_, Self>) -> Div {
        let mut body = div()
            .p_5()
            .flex()
            .flex_col()
            .gap_2()
            .child(field_label("Session name"));
        if let Some(field) = &self.session_name {
            body = body.child(field.clone());
        }
        modal(
            "Edit session name",
            "This name labels the current capture session.",
            body,
            div()
                .child(button(
                    "cancel-session-name",
                    "Cancel",
                    ButtonKind::Normal,
                    true,
                    cx.listener(|app, _, _, cx| {
                        app.state.session_dialog = None;
                        cx.notify();
                    }),
                ))
                .child(button(
                    "save-session-name",
                    "Save name",
                    ButtonKind::Primary,
                    !self.state.edited_session_name.trim().is_empty(),
                    cx.listener(|app, _, _, cx| app.save_session_name(cx)),
                )),
        )
    }

    fn remove_dialog(&self, cx: &mut Context<'_, Self>) -> Div {
        let id = self.state.pending_remove.clone().unwrap_or_default();
        let title = self
            .state
            .analysers
            .iter()
            .find(|analyser| analyser.id == id)
            .map_or_else(|| id.clone(), |analyser| analyser.title.clone());
        modal(
            "Remove analyser?",
            &format!("{title} will be removed from the user library."),
            div().p_5().child(notice_box("This changes the library on disk", "The installed Lua file will be deleted. Other sessions and the CLI will use the updated library.", RED, RED_SOFT)),
            div().child(button("cancel-remove", "Cancel", ButtonKind::Normal, true, cx.listener(|app, _, _, cx| {
                app.state.pending_remove = None;
                cx.notify();
            }))).child(button("confirm-remove", "Remove analyser", ButtonKind::Danger, true, cx.listener(|app, _, _, cx| {
                app.state.pending_remove = None;
                app.controller.remove_analyser(&mut app.state);
                cx.notify();
            }))),
        )
    }

    fn export_dialog(&self, cx: &mut Context<'_, Self>) -> Div {
        let trace = self.state.export_kind == ExportKind::Trace;
        let mut body = div().p_5().flex().flex_col().gap_3();
        if trace {
            body = body
                .child(radio_option(
                    "Raw trace",
                    "Exact ATR and APDU data. Required for faithful replay.",
                    self.state.trace_export_mode == TraceExportMode::Raw,
                    cx.listener(|app, _, _, cx| {
                        app.state.trace_export_mode = TraceExportMode::Raw;
                        cx.notify();
                    }),
                ))
                .child(radio_option(
                    "Sanitised trace",
                    "Redact ATR, command data, and response data.",
                    self.state.trace_export_mode == TraceExportMode::Sanitised,
                    cx.listener(|app, _, _, cx| {
                        app.state.trace_export_mode = TraceExportMode::Sanitised;
                        cx.notify();
                    }),
                ))
                .child(notice_box(
                    "Card data is sensitive",
                    "Review exports before sharing. Sanitisation cannot remove every secret.",
                    AMBER,
                    AMBER_SOFT,
                ));
        } else {
            body = body.child(notice_box(
                "Versioned result document",
                "The export preserves stable node identifiers, decoded values, and provenance.",
                GREEN_DARK,
                GREEN_SOFT,
            ));
        }
        body = body.child(field_label("Destination"));
        if let Some(field) = &self.export {
            body = body.child(
                div()
                    .flex()
                    .gap_2()
                    .child(div().flex_1().child(field.clone()))
                    .child(button(
                        "browse-export",
                        "Browse",
                        ButtonKind::Normal,
                        true,
                        cx.listener(|app, _, _, cx| app.select_save_path(false, cx)),
                    )),
            );
        }
        modal(
            if trace {
                "Export session trace"
            } else {
                "Export analysis result"
            },
            if trace {
                "Save the recorded exchanges for replay or sharing."
            } else {
                "Save the immutable result document as native JSON."
            },
            body,
            div()
                .child(button(
                    "cancel-export",
                    "Cancel",
                    ButtonKind::Normal,
                    true,
                    cx.listener(|app, _, _, cx| {
                        app.state.show_export = false;
                        cx.notify();
                    }),
                ))
                .child(button(
                    "confirm-export",
                    "Export JSON",
                    ButtonKind::Primary,
                    true,
                    cx.listener(|app, _, _, cx| {
                        app.controller.export(&mut app.state);
                        cx.notify();
                    }),
                )),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn interaction_dialog(&self, cx: &mut Context<'_, Self>) -> Div {
        let Some(request) = self.state.interaction.clone() else {
            return div();
        };
        let id = request.id.clone();
        let prompt = match &request.kind {
            InteractionKind::Question { prompt }
            | InteractionKind::Notice { prompt }
            | InteractionKind::TextInput { prompt, .. }
            | InteractionKind::SecretInput { prompt }
            | InteractionKind::FileSelection { prompt, .. } => prompt.clone(),
        };
        let mut body = div().p_5().child(div().mb_4().child(prompt));
        let mut footer = div();
        match request.kind {
            InteractionKind::Question { .. } => {
                let no_id = id.clone();
                footer = footer
                    .child(button(
                        "answer-no",
                        "No",
                        ButtonKind::Normal,
                        true,
                        cx.listener(move |app, _, _, cx| {
                            app.answer(no_id.clone(), InteractionResponse::Bool(false));
                            cx.notify();
                        }),
                    ))
                    .child(button(
                        "answer-yes",
                        "Yes",
                        ButtonKind::Primary,
                        true,
                        cx.listener(move |app, _, _, cx| {
                            app.answer(id.clone(), InteractionResponse::Bool(true));
                            cx.notify();
                        }),
                    ));
            }
            InteractionKind::Notice { .. } => {
                footer = footer.child(button(
                    "acknowledge-interaction",
                    "OK",
                    ButtonKind::Primary,
                    true,
                    cx.listener(move |app, _, _, cx| {
                        app.answer(id.clone(), InteractionResponse::Acknowledged);
                        cx.notify();
                    }),
                ));
            }
            InteractionKind::FileSelection { must_exist, .. } => {
                body = body
                    .child(button(
                        "choose-interaction-file",
                        "Choose file",
                        ButtonKind::Normal,
                        true,
                        cx.listener(move |app, _, _, cx| {
                            if must_exist {
                                app.select_interaction_file(cx);
                            } else {
                                app.select_save_path(true, cx);
                            }
                        }),
                    ))
                    .child(note(&self.state.interaction_file.as_ref().map_or_else(
                        || "No file selected".into(),
                        |path| path.display().to_string(),
                    )));
                footer = footer.child(button(
                    "use-interaction-file",
                    "Use selected file",
                    ButtonKind::Primary,
                    self.state.interaction_file.is_some(),
                    cx.listener(move |app, _, _, cx| {
                        if let Some(path) = app.state.interaction_file.clone() {
                            app.answer(id.clone(), InteractionResponse::File(path));
                            cx.notify();
                        }
                    }),
                ));
            }
            kind @ (InteractionKind::TextInput { .. } | InteractionKind::SecretInput { .. }) => {
                if let Some(field) = &self.interaction {
                    body = body.child(field.clone());
                }
                if matches!(kind, InteractionKind::SecretInput { .. }) {
                    body = body.child(note("Secret values never enter application logs."));
                }
                footer = footer.child(button(
                    "submit-interaction",
                    "Submit",
                    ButtonKind::Primary,
                    true,
                    cx.listener(|app, _, _, cx| {
                        app.submit_interaction_text(cx);
                    }),
                ));
            }
        }
        modal(
            "Analyser request",
            "The worker waits for this correlated response or cancellation.",
            body,
            footer,
        )
    }

    fn cancel_dialog(&mut self, cx: &mut Context<'_, Self>) {
        if self.state.session_dialog.is_some() {
            self.state.session_dialog = None;
        } else if self.state.interaction.is_some() {
            self.controller.cancel(&self.state);
            self.state.interaction = None;
            self.state.interaction_operation = None;
            self.interaction = None;
            self.interaction_id = None;
        } else if self.state.show_export {
            self.state.show_export = false;
        } else if self.state.pending_remove.is_some() {
            self.state.pending_remove = None;
        } else {
            return;
        }
        cx.notify();
    }

    fn confirm_interaction(&mut self, cx: &mut Context<'_, Self>) {
        let Some(request) = self.state.interaction.clone() else {
            return;
        };
        let response = match request.kind {
            InteractionKind::Question { .. } => InteractionResponse::Bool(true),
            InteractionKind::Notice { .. } => InteractionResponse::Acknowledged,
            _ => return,
        };
        self.answer(request.id, response);
        cx.notify();
    }

    fn submit_interaction_text(&mut self, cx: &mut Context<'_, Self>) {
        let Some(request) = self.state.interaction.clone() else {
            return;
        };
        let Some(field) = self.interaction.as_ref() else {
            return;
        };
        let text = field.read(cx).text().to_string();
        let response = if matches!(request.kind, InteractionKind::SecretInput { .. }) {
            InteractionResponse::Secret(text)
        } else {
            InteractionResponse::Text(text)
        };
        self.answer(request.id, response);
        cx.notify();
    }

    fn answer(&mut self, request: cardpeek_app::InteractionId, response: InteractionResponse) {
        self.controller
            .answer(AnswerInteraction { request, response }, &mut self.state);
        self.interaction = None;
        self.interaction_id = None;
    }

    fn context_menu(&self, cx: &mut Context<'_, Self>) -> Option<AnyElement> {
        let menu = self.context_menu.as_ref()?;
        let text = menu.text.clone();
        let tree = menu.tree_text.clone();
        Some(
            deferred(
                div()
                    .id("context-menu")
                    .occlude()
                    .absolute()
                    .left(menu.position.x)
                    .top(menu.position.y)
                    .w(px(120.))
                    .p_1()
                    .rounded_md()
                    .border_1()
                    .border_color(BORDER)
                    .bg(WHITE)
                    .shadow_lg()
                    .on_mouse_down_out(cx.listener(|app, _, _, cx| {
                        app.context_menu = None;
                        app.context_menu_source = None;
                        cx.notify();
                    }))
                    .child(
                        div()
                            .id("context-copy")
                            .px_3()
                            .py_2()
                            .rounded_sm()
                            .cursor_pointer()
                            .text_sm()
                            .hover(|style| style.bg(CANVAS))
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(move |app, _, _, cx| {
                                    cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                                    app.context_menu = None;
                                    app.context_menu_source = None;
                                    cx.notify();
                                }),
                            )
                            .child("Copy"),
                    )
                    .children(tree.map(|text| {
                        div()
                            .id("context-copy-tree")
                            .px_3()
                            .py_2()
                            .rounded_sm()
                            .cursor_pointer()
                            .text_sm()
                            .hover(|style| style.bg(CANVAS))
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(move |app, _, _, cx| {
                                    cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                                    app.context_menu = None;
                                    app.context_menu_source = None;
                                    cx.notify();
                                }),
                            )
                            .child("Copy tree")
                    })),
            )
            .with_priority(2)
            .into_any_element(),
        )
    }

    fn status_bar(&self, cx: &mut Context<'_, Self>) -> Div {
        let latest = self.state.latest_notification();
        let is_error =
            latest.is_some_and(|notification| notification.level == NotificationLevel::Error);
        let message = latest.map_or_else(
            || "Ready".into(),
            |notification| notification.message.clone(),
        );
        let history_label = if self.notification_history == NotificationHistory::Expanded {
            "Hide history".into()
        } else {
            format!("History ({})", self.state.notifications.len())
        };
        div()
            .w_full()
            .flex_shrink_0()
            .flex()
            .flex_col()
            .border_t_1()
            .border_color(BORDER)
            .bg(WHITE)
            .when(
                self.notification_history == NotificationHistory::Expanded,
                |element| element.child(self.notification_history(cx)),
            )
            .child(
                div()
                    .id("status-bar")
                    .h(px(36.))
                    .w_full()
                    .px_4()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .size(px(7.))
                            .flex_shrink_0()
                            .rounded_full()
                            .bg(if is_error { RED } else { GREEN }),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .text_ellipsis()
                            .text_sm()
                            .text_color(if is_error { RED } else { INK })
                            .child(message),
                    )
                    .child(
                        button(
                            "notification-history",
                            history_label,
                            ButtonKind::Quiet,
                            true,
                            cx.listener(|app, _, _, cx| {
                                app.notification_history = match app.notification_history {
                                    NotificationHistory::Collapsed => NotificationHistory::Expanded,
                                    NotificationHistory::Expanded => NotificationHistory::Collapsed,
                                };
                                cx.notify();
                            }),
                        )
                        .h(px(26.))
                        .text_xs(),
                    ),
            )
    }

    #[allow(clippy::too_many_lines)]
    fn notification_history(&self, cx: &mut Context<'_, Self>) -> Div {
        let mut history = div()
            .max_h(px(260.))
            .w_full()
            .flex()
            .flex_col()
            .border_b_1()
            .border_color(BORDER);
        history = history.child(
            div()
                .min_h(px(42.))
                .px_4()
                .py_2()
                .flex_shrink_0()
                .flex()
                .items_center()
                .justify_between()
                .border_b_1()
                .border_color(BORDER)
                .child(
                    div()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("Notifications"),
                )
                .child(
                    button(
                        "clear-notifications",
                        "Clear history",
                        ButtonKind::Quiet,
                        !self.state.notifications.is_empty(),
                        cx.listener(|app, _, _, cx| {
                            app.state.notifications.clear();
                            cx.notify();
                        }),
                    )
                    .h(px(28.))
                    .text_xs(),
                ),
        );
        if self.state.notifications.is_empty() {
            return history.child(
                div()
                    .id("notification-history-list")
                    .overflow_y_scroll()
                    .child(empty_box("No notifications yet.")),
            );
        }
        let mut messages = div()
            .id("notification-history-list")
            .max_h(px(218.))
            .w_full()
            .overflow_y_scroll()
            .flex()
            .flex_col();
        for (index, notification) in self.state.notifications.iter().enumerate().rev() {
            let is_error = notification.level == NotificationLevel::Error;
            let copy_text = notification.message.clone();
            let source = format!("notification-{index}");
            let source_for_menu = source.clone();
            messages = messages.child(
                div()
                    .h(px(38.))
                    .w_full()
                    .px_4()
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .gap_3()
                    .border_b_1()
                    .border_color(BORDER)
                    .cursor_pointer()
                    .when(
                        self.context_menu_source.as_deref() == Some(source.as_str()),
                        |element| element.bg(BORDER),
                    )
                    .when(self.context_menu.is_none(), |element| {
                        element.hover(|style| style.bg(BORDER))
                    })
                    .on_mouse_down(
                        MouseButton::Right,
                        cx.listener(move |app, event: &MouseDownEvent, _, cx| {
                            app.context_menu_source = Some(source_for_menu.clone());
                            app.context_menu = Some(ContextMenu {
                                position: event.position,
                                text: copy_text.clone(),
                                tree_text: None,
                            });
                            cx.notify();
                        }),
                    )
                    .child(
                        div()
                            .w(px(44.))
                            .flex_shrink_0()
                            .text_xs()
                            .text_color(if is_error { RED } else { MUTED })
                            .child(if is_error { "Error" } else { "Status" }),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_sm()
                            .child(notification.message.clone()),
                    ),
            );
        }
        history.child(messages)
    }

    fn help_overlay(&self, cx: &mut Context<'_, Self>) -> Option<AnyElement> {
        render_help_overlay(self.state.help_mode, cx)
    }
}

impl Render for App {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let dialog_open = self.state.session_dialog.is_some()
            || self.state.interaction.is_some()
            || self.state.show_export
            || self.state.pending_remove.is_some();
        let dialog_keyboard = dialog_open
            && !self.state.interaction.as_ref().is_some_and(|request| {
                matches!(
                    request.kind,
                    InteractionKind::TextInput { .. } | InteractionKind::SecretInput { .. }
                )
            });
        if dialog_keyboard {
            window.focus(&self.dialog_focus);
        }
        let content = match self.state.screen {
            Screen::Reader => self.reader_page(cx).into_any_element(),
            Screen::Analysis => self.analysis_page(cx).into_any_element(),
            Screen::Trace => self.trace_page(cx).into_any_element(),
            Screen::Library => self.library_page(cx).into_any_element(),
        };
        div()
            .relative()
            .size_full()
            .track_focus(&self.dialog_focus)
            .when(dialog_open, |element| {
                element.key_context("CardpeekDialog").on_action(cx.listener(
                    |app, _: &Cancel, _, cx| {
                        app.cancel_dialog(cx);
                    },
                ))
            })
            .when(dialog_keyboard, |element| {
                element.on_action(cx.listener(|app, _: &Confirm, _, cx| {
                    app.confirm_interaction(cx);
                }))
            })
            .overflow_hidden()
            .bg(CANVAS)
            .text_color(INK)
            .font_family("sans-serif")
            .child(
                div()
                    .size_full()
                    .flex()
                    .flex_col()
                    .child(self.header())
                    .child(
                        div().flex_1().min_h_0().flex().child(self.rail(cx)).child(
                            div()
                                .id("main-pane")
                                .flex_1()
                                .min_w_0()
                                .min_h_0()
                                .overflow_y_scroll()
                                .child(content),
                        ),
                    )
                    .child(self.status_bar(cx)),
            )
            .children(self.dialogs(cx))
            .children(self.context_menu(cx))
            .children(self.help_overlay(cx))
    }
}

#[derive(Clone, Copy)]
enum ButtonKind {
    Normal,
    Primary,
    Quiet,
    Danger,
}

fn icon_button(
    id: impl Into<gpui::ElementId>,
    icon: &'static str,
    tooltip: &'static str,
    enabled: bool,
) -> Stateful<Div> {
    div()
        .id(id)
        .size(px(28.))
        .flex_shrink_0()
        .flex()
        .items_center()
        .justify_center()
        .rounded_md()
        .font_family("Font Awesome 7 Free Solid")
        .text_sm()
        .text_color(if enabled { MUTED } else { BORDER })
        .when(enabled, |element| {
            element
                .cursor_pointer()
                .hover(|style| style.bg(CANVAS).text_color(INK))
                .active(|style| style.bg(GREEN_SOFT))
                .tooltip(move |_, cx| cx.new(|_| Tooltip(tooltip)).into())
        })
        .child(icon)
}

struct Tooltip(&'static str);

impl Render for Tooltip {
    fn render(&mut self, _: &mut Window, _: &mut Context<'_, Self>) -> impl IntoElement {
        div()
            .px_2()
            .py_1()
            .rounded_md()
            .bg(NAV)
            .text_color(WHITE)
            .text_xs()
            .child(self.0)
    }
}

fn render_help_overlay<V: 'static>(enabled: bool, cx: &mut Context<'_, V>) -> Option<AnyElement> {
    if !enabled {
        return None;
    }
    let active = cx.try_global::<ActiveHelpTooltip>()?.clone();
    let entry = active.entry?;
    Some(
        deferred(
            anchored()
                .position(point(
                    active.position.x + px(12.),
                    active.position.y + px(16.),
                ))
                .snap_to_window_with_margin(px(8.))
                .child(cx.new(|_| HelpTooltip(entry))),
        )
        .with_priority(3)
        .into_any_element(),
    )
}

struct HelpTooltip(HelpEntry);

impl Render for HelpTooltip {
    fn render(&mut self, _: &mut Window, _: &mut Context<'_, Self>) -> impl IntoElement {
        div()
            .id("immediate-help-tooltip")
            .debug_selector(|| "immediate-help-tooltip".to_owned())
            .w(px(340.))
            .p_3()
            .rounded_md()
            .border_1()
            .border_color(GREEN)
            .bg(NAV)
            .text_color(WHITE)
            .shadow_lg()
            .child(
                div()
                    .mb_1()
                    .text_sm()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(self.0.title),
            )
            .child(
                div()
                    .text_xs()
                    .line_height(px(18.))
                    .child(self.0.explanation),
            )
    }
}

fn help_text(
    id: &'static str,
    text: impl Into<SharedString>,
    entry: HelpEntry,
    enabled: bool,
) -> AnyElement {
    let text = text.into();
    if enabled {
        div()
            .id(id)
            .debug_selector(|| id.into())
            .help_target(entry)
            .child(help_content(div().child(text)))
            .into_any_element()
    } else {
        div().child(text).into_any_element()
    }
}

fn help_content(content: Div) -> Div {
    content.size_full()
}

fn help_badge(
    id: impl Into<gpui::ElementId>,
    label: impl Into<SharedString>,
    foreground: Rgba,
    background: Rgba,
    entry: HelpEntry,
    enabled: bool,
) -> AnyElement {
    if enabled {
        let id = id.into();
        badge(label, foreground, background)
            .id(id)
            .help_target(entry)
            .into_any_element()
    } else {
        badge(label, foreground, background).into_any_element()
    }
}

fn button(
    id: impl Into<gpui::ElementId>,
    label: impl Into<SharedString>,
    kind: ButtonKind,
    enabled: bool,
    on_click: impl Fn(&MouseDownEvent, &mut Window, &mut gpui::App) + 'static,
) -> Stateful<Div> {
    button_state(id, label, kind, enabled, false, on_click)
}

fn button_state(
    id: impl Into<gpui::ElementId>,
    label: impl Into<SharedString>,
    kind: ButtonKind,
    enabled: bool,
    pending: bool,
    on_click: impl Fn(&MouseDownEvent, &mut Window, &mut gpui::App) + 'static,
) -> Stateful<Div> {
    let (background, foreground) = match kind {
        ButtonKind::Primary => (
            if enabled { GREEN } else { BORDER },
            if enabled { WHITE } else { MUTED },
        ),
        ButtonKind::Normal => (WHITE, if enabled { INK } else { MUTED }),
        ButtonKind::Quiet => (CANVAS, if enabled { GREEN_DARK } else { MUTED }),
        ButtonKind::Danger => (if enabled { RED } else { BORDER }, WHITE),
    };
    div()
        .id(id)
        .h(px(38.))
        .px_3()
        .flex_shrink_0()
        .rounded_md()
        .border_1()
        .border_color(match kind {
            ButtonKind::Normal => BORDER,
            _ => background,
        })
        .bg(if pending { GREEN_SOFT } else { background })
        .text_color(if pending { GREEN_DARK } else { foreground })
        .text_size(px(14.))
        .font_weight(FontWeight::MEDIUM)
        .flex()
        .items_center()
        .justify_center()
        .when(enabled, |element| {
            element
                .cursor_pointer()
                .hover(move |style| {
                    style.bg(match kind {
                        ButtonKind::Primary => GREEN_DARK,
                        ButtonKind::Normal => CANVAS,
                        ButtonKind::Quiet => GREEN_SOFT,
                        ButtonKind::Danger => rgb(0x843030),
                    })
                })
                .active(|style| style.bg(GREEN_SOFT))
                .on_mouse_down(MouseButton::Left, on_click)
        })
        .child(label.into())
}

#[allow(clippy::too_many_lines)]
fn exchange_list(
    id: &'static str,
    exchanges: &[crate::state::Exchange],
    help_mode: bool,
    cx: &mut Context<'_, App>,
) -> AnyElement {
    if exchanges.is_empty() {
        return empty_box("No APDU exchanges.").into_any_element();
    }
    let rows = Rc::new(exchanges.to_vec());
    uniform_list(
        id,
        rows.len(),
        cx.processor(move |app, range: std::ops::Range<usize>, _, cx| {
            range
                .map(|index| {
                    let exchange = rows[index].clone();
                    let source = format!("{id}-{index}");
                    let source_for_menu = source.clone();
                    let pinned = app.context_menu_source.as_deref() == Some(source.as_str());
                    let copy_text = format!(
                        "TX\t{}\t{}\nRX\t{}\t{}",
                        exchange.command, exchange.record, exchange.data, exchange.status
                    );
                    div()
                        .id(index)
                        .h(px(62.))
                        .w_full()
                        .min_w_0()
                        .overflow_hidden()
                        .p_2()
                        .bg(if index.is_multiple_of(2) {
                            WHITE
                        } else {
                            CANVAS
                        })
                        .when(pinned, |element| element.bg(BORDER))
                        .when(app.context_menu.is_none(), |element| {
                            element.hover(|style| style.bg(BORDER))
                        })
                        .on_mouse_down(
                            MouseButton::Right,
                            cx.listener(move |app, event: &MouseDownEvent, _, cx| {
                                app.context_menu_source = Some(source_for_menu.clone());
                                app.context_menu = Some(ContextMenu {
                                    position: event.position,
                                    text: copy_text.clone(),
                                    tree_text: None,
                                });
                                cx.notify();
                            }),
                        )
                        .child(
                            div()
                                .flex()
                                .gap_3()
                                .items_center()
                                .text_xs()
                                .child(
                                    div()
                                        .id(("exchange-tx", index))
                                        .w(px(22.))
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(GREEN_DARK)
                                        .when(help_mode, |element| element.help_target(help::TX))
                                        .child("TX"),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .child(exchange.command.clone()),
                                )
                                .child(div().text_color(MUTED).child(exchange.record.clone())),
                        )
                        .child(
                            div()
                                .flex()
                                .gap_3()
                                .items_center()
                                .text_xs()
                                .child(
                                    div()
                                        .id(("exchange-rx", index))
                                        .w(px(22.))
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(MUTED)
                                        .when(help_mode, |element| element.help_target(help::RX))
                                        .child("RX"),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .child(exchange.data.clone()),
                                )
                                .child(
                                    div()
                                        .id(("exchange-status", index))
                                        .text_color(MUTED)
                                        .when(help_mode, |element| {
                                            element.help_target(help::STATUS_WORD)
                                        })
                                        .child(exchange.status.clone()),
                                ),
                        )
                })
                .collect::<Vec<_>>()
        }),
    )
    .size_full()
    .into_any_element()
}

fn panel() -> Div {
    div()
        .bg(WHITE)
        .rounded_lg()
        .border_1()
        .border_color(BORDER)
        .overflow_hidden()
}

fn panel_head(title: &'static str, badge_label: &'static str) -> Stateful<Div> {
    panel_head_with_id(
        SharedString::from(format!("panel-{title}")),
        title,
        badge_label,
    )
}

fn panel_head_with_id(
    id: impl Into<gpui::ElementId>,
    title: &'static str,
    badge_label: &'static str,
) -> Stateful<Div> {
    div()
        .id(id)
        .h(px(54.))
        .px_4()
        .flex()
        .items_center()
        .justify_between()
        .border_b_1()
        .border_color(BORDER)
        .child(div().font_weight(FontWeight::SEMIBOLD).child(title))
        .child(badge(badge_label, MUTED, CANVAS))
}

fn help_panel_head(
    id: &'static str,
    title: &'static str,
    badge_label: &'static str,
    entry: HelpEntry,
    enabled: bool,
) -> Stateful<Div> {
    div()
        .id(id)
        .h(px(54.))
        .px_4()
        .flex()
        .items_center()
        .justify_between()
        .border_b_1()
        .border_color(BORDER)
        .child(
            div()
                .id(SharedString::from(format!("{id}-title")))
                .debug_selector(|| format!("{id}-title"))
                .when(enabled, |element| {
                    element.help_target(entry).child(help_content(
                        div().font_weight(FontWeight::SEMIBOLD).child(title),
                    ))
                })
                .when(!enabled, |element| {
                    element.font_weight(FontWeight::SEMIBOLD).child(title)
                }),
        )
        .child(badge(badge_label, MUTED, CANVAS))
}

fn panel_body() -> Div {
    div().p_4()
}

fn badge(label: impl Into<SharedString>, foreground: Rgba, background: Rgba) -> Div {
    div()
        .px_2()
        .h(px(23.))
        .rounded_sm()
        .bg(background)
        .text_color(foreground)
        .text_size(px(11.))
        .font_weight(FontWeight::SEMIBOLD)
        .flex()
        .items_center()
        .child(label.into())
}

fn page_head(title: &'static str, description: &'static str) -> Div {
    div()
        .child(
            div()
                .text_2xl()
                .font_weight(FontWeight::SEMIBOLD)
                .child(title),
        )
        .child(note(description))
}

fn field_label(label: &'static str) -> Div {
    div()
        .mt_4()
        .text_sm()
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(MUTED)
        .child(label)
}

fn note(text: &str) -> Div {
    div()
        .mt_1()
        .text_size(px(14.))
        .line_height(px(20.))
        .text_color(MUTED)
        .child(text.to_owned())
}

fn help_detail_row(
    id: &'static str,
    label: &'static str,
    value: &str,
    entry: HelpEntry,
    enabled: bool,
) -> Stateful<Div> {
    let element = detail_row_with_id(id, label, value)
        .relative()
        .debug_selector(|| id.into());
    if enabled {
        element
            .help_target(entry)
            .child(help_content(div().absolute().inset_0()))
    } else {
        element
    }
}

fn detail_row(label: &'static str, value: &str) -> Stateful<Div> {
    detail_row_with_id(SharedString::from(format!("detail-{label}")), label, value)
}

fn detail_row_with_id(
    id: impl Into<gpui::ElementId>,
    label: &'static str,
    value: &str,
) -> Stateful<Div> {
    div()
        .id(id)
        .py_3()
        .border_b_1()
        .border_color(BORDER)
        .flex()
        .gap_4()
        .child(
            div()
                .w(px(100.))
                .flex_shrink_0()
                .whitespace_nowrap()
                .text_sm()
                .text_color(MUTED)
                .child(label),
        )
        .child(div().flex_1().min_w_0().text_sm().child(value.to_owned()))
}

fn setting_section(title: &'static str, text: &str) -> Div {
    div()
        .p_4()
        .border_b_1()
        .border_color(BORDER)
        .child(div().font_weight(FontWeight::SEMIBOLD).child(title))
        .child(note(text))
}

fn notice_box(title: &'static str, text: &'static str, foreground: Rgba, background: Rgba) -> Div {
    div()
        .p_3()
        .rounded_md()
        .bg(background)
        .child(
            div()
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(foreground)
                .child(title),
        )
        .child(note(text))
}

fn radio_option(
    title: &'static str,
    text: &'static str,
    selected: bool,
    on_click: impl Fn(&MouseDownEvent, &mut Window, &mut gpui::App) + 'static,
) -> impl IntoElement {
    div()
        .id(SharedString::from(format!("trace-mode-{title}")))
        .p_3()
        .rounded_md()
        .border_1()
        .border_color(if selected { GREEN } else { BORDER })
        .bg(if selected { GREEN_SOFT } else { WHITE })
        .cursor_pointer()
        .on_mouse_down(MouseButton::Left, on_click)
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .size(px(16.))
                        .flex_shrink_0()
                        .rounded_full()
                        .border_2()
                        .border_color(if selected { GREEN } else { MUTED })
                        .bg(WHITE)
                        .flex()
                        .items_center()
                        .justify_center()
                        .when(selected, |element| {
                            element.child(div().size(px(8.)).rounded_full().bg(GREEN))
                        }),
                )
                .child(div().font_weight(FontWeight::SEMIBOLD).child(title)),
        )
        .child(div().pl_6().child(note(text)))
}

fn modal(title: &'static str, subtitle: &str, body: Div, actions: Div) -> Div {
    div()
        .absolute()
        .inset_0()
        .bg(gpui::rgba(0x10252999))
        .flex()
        .items_center()
        .justify_center()
        .child(
            div()
                .w(px(520.))
                .max_h(px(650.))
                .rounded_lg()
                .bg(WHITE)
                .shadow_2xl()
                .child(
                    div()
                        .p_5()
                        .border_b_1()
                        .border_color(BORDER)
                        .child(
                            div()
                                .text_xl()
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(title),
                        )
                        .child(note(subtitle)),
                )
                .child(body)
                .child(
                    div()
                        .p_4()
                        .border_t_1()
                        .border_color(BORDER)
                        .flex()
                        .justify_end()
                        .gap_2()
                        .child(actions.flex().gap_2()),
                ),
        )
}

fn brand_mark() -> impl IntoElement {
    img(std::sync::Arc::new(Image::from_bytes(
        ImageFormat::Png,
        include_bytes!("../../../resources/icon.png").to_vec(),
    )))
    .size(px(42.))
}

fn reader_session_icon(connected: bool, card_present: bool) -> Div {
    let color = if !connected {
        MUTED
    } else if card_present {
        GREEN
    } else {
        AMBER
    };
    let background = if !connected {
        BORDER
    } else if card_present {
        GREEN_SOFT
    } else {
        AMBER_SOFT
    };
    let badge = if !connected {
        "\u{f00d}"
    } else if card_present {
        "\u{f00c}"
    } else {
        "\u{f068}"
    };
    div()
        .relative()
        .size(px(52.))
        .rounded_lg()
        .bg(background)
        .text_color(color)
        .flex()
        .items_center()
        .justify_center()
        .child(
            div()
                .font_family("Font Awesome 7 Brands")
                .text_size(px(24.))
                .child("\u{f287}"),
        )
        .child(
            div()
                .absolute()
                .bottom(px(-3.))
                .right(px(-3.))
                .size(px(17.))
                .rounded_full()
                .border_2()
                .border_color(CANVAS)
                .bg(color)
                .text_color(WHITE)
                .flex()
                .items_center()
                .justify_center()
                .font_family("Font Awesome 7 Free Solid")
                .text_size(px(9.))
                .child(badge),
        )
}

fn smart_card() -> Div {
    div()
        .w(px(82.))
        .h(px(54.))
        .rounded_md()
        .bg(GREEN_SOFT)
        .border_1()
        .border_color(GREEN)
        .p_2()
        .child(
            div()
                .w(px(23.))
                .h(px(18.))
                .rounded_sm()
                .bg(rgb(0xd9bc68))
                .border_1()
                .border_color(AMBER),
        )
        .child(
            div()
                .mt_2()
                .w(px(40.))
                .h(px(3.))
                .rounded_full()
                .bg(rgb(0x8cbcaf)),
        )
}

fn empty_box(text: &'static str) -> Div {
    div()
        .p_4()
        .text_sm()
        .text_color(MUTED)
        .text_center()
        .child(text)
}

fn protocol_label(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::T0 => "T=0",
        Protocol::T1 => "T=1",
        Protocol::Other => "Other",
    }
}

fn progress_percent(progress: Option<&Progress>) -> u64 {
    match progress {
        Some(Progress::Determinate { completed, total }) if *total > 0 => {
            completed.saturating_mul(100) / total
        }
        Some(Progress::Indeterminate) => 25,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use gpui::{Modifiers, TestAppContext, point, size};

    use super::*;

    #[derive(Clone, Copy)]
    struct HelpTargetView {
        edge: bool,
    }

    impl Render for HelpTargetView {
        fn render(&mut self, _: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
            div()
                .size_full()
                .child(
                    div()
                        .id("test-help-target")
                        .debug_selector(|| "test-help-target".to_owned())
                        .absolute()
                        .left_0()
                        .top_0()
                        .when(self.edge, |element| element.right(px(10.)).bottom(px(10.)))
                        .w(px(100.))
                        .h(px(20.))
                        .help_target(help::ATR)
                        .child("ATR"),
                )
                .children(render_help_overlay(true, cx))
        }
    }

    #[gpui::test]
    fn help_tooltip_stays_inside_the_window(cx: &mut TestAppContext) {
        let window = cx.update(|cx| {
            cx.open_window(WindowOptions::default(), |_, cx| {
                cx.new(|_| HelpTargetView { edge: true })
            })
            .unwrap()
        });
        let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
        visual.simulate_resize(size(px(640.), px(480.)));
        let target = visual.debug_bounds("test-help-target").unwrap();
        visual.simulate_mouse_move(target.center(), None, Modifiers::none());
        visual.read_global(|active: &ActiveHelpTooltip, _| {
            assert_eq!(active.entry, Some(help::ATR));
        });
        let bounds = visual.debug_bounds("immediate-help-tooltip").unwrap();
        assert!(bounds.left() >= px(8.));
        assert!(bounds.top() >= px(8.));
        assert!(bounds.right() <= px(632.));
        assert!(bounds.bottom() <= px(472.));
    }

    #[gpui::test]
    fn help_tooltip_clears_when_the_pointer_leaves(cx: &mut TestAppContext) {
        let window = cx.update(|cx| {
            cx.open_window(WindowOptions::default(), |_, cx| {
                cx.new(|_| HelpTargetView { edge: false })
            })
            .unwrap()
        });
        let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
        visual.simulate_resize(size(px(640.), px(480.)));
        visual.simulate_mouse_move(point(px(10.), px(10.)), None, Modifiers::none());
        visual.read_global(|active: &ActiveHelpTooltip, _| {
            assert_eq!(active.entry, Some(help::ATR));
        });
        visual.simulate_mouse_move(point(px(300.), px(300.)), None, Modifiers::none());
        visual.read_global(|active: &ActiveHelpTooltip, _| {
            assert_eq!(active.entry, None);
        });
    }

    #[gpui::test]
    fn help_targets_activate_on_all_tabs(cx: &mut TestAppContext) {
        let directory = tempfile::tempdir().unwrap();
        let controller = Rc::new(crate::Controller::new(
            DesktopBackend::new(None, None),
            cardpeek_analyser::AnalyserLibrary::at(directory.path()).unwrap(),
        ));
        let window = cx.update(|cx| {
            cx.open_window(WindowOptions::default(), |_, cx| {
                cx.new(|cx| {
                    App::new(
                        controller,
                        Preferences::load(directory.path().join("preferences")),
                        None,
                        cx,
                    )
                })
            })
            .unwrap()
        });
        window
            .update(cx, |app, _, cx| {
                app.state.help_mode = true;
                cx.notify();
            })
            .unwrap();
        let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
        visual.simulate_resize(size(px(1280.), px(820.)));
        for (screen, selector, entry) in [
            (Screen::Reader, "help-pcsc-title", help::PCSC),
            (Screen::Reader, "reset", help::RESET),
            (Screen::Reader, "help-capture-bundles", help::CAPTURE_BUNDLE),
            (Screen::Analysis, "analyser-picker", help::ANALYSER),
            (Screen::Trace, "trace-segment-picker", help::SEGMENT),
            (Screen::Library, "help-telemetry", help::TELEMETRY),
        ] {
            window
                .update(cx, |app, _, cx| {
                    app.state.screen = screen;
                    cx.notify();
                })
                .unwrap();
            let bounds = visual
                .debug_bounds(selector)
                .unwrap_or_else(|| panic!("missing bounds for {selector}"));
            visual.simulate_mouse_move(bounds.center(), None, Modifiers::none());
            visual.read_global(|active: &ActiveHelpTooltip, _| {
                assert_eq!(active.entry, Some(entry));
            });
            assert!(visual.debug_bounds("immediate-help-tooltip").is_some());
        }
    }

    #[gpui::test]
    fn file_picker_starts_at_home_and_remembers_the_selected_directory(cx: &mut TestAppContext) {
        let directory = tempfile::tempdir().unwrap();
        let selected_directory = directory.path().join("selected");
        std::fs::create_dir(&selected_directory).unwrap();
        let controller = Rc::new(crate::Controller::new(
            DesktopBackend::new(None, None),
            cardpeek_analyser::AnalyserLibrary::at(directory.path()).unwrap(),
        ));
        let app = cx.new(|cx| {
            App::new(
                controller,
                Preferences::load(directory.path().join("preferences")),
                None,
                cx,
            )
        });
        app.update(cx, |app, _| {
            let expected_home = directories::BaseDirs::new().map_or_else(
                || PathBuf::from("."),
                |directories| directories.home_dir().to_path_buf(),
            );
            assert_eq!(app.file_picker_directory, expected_home);

            app.remember_file_picker_directory(&selected_directory.join("trace.json"));
            assert_eq!(app.file_picker_directory, selected_directory);
        });
    }

    #[gpui::test]
    fn escape_cancels_dialogs_with_and_without_text_input(cx: &mut TestAppContext) {
        cx.update(bind_keys);
        let directory = tempfile::tempdir().unwrap();
        let controller = Rc::new(crate::Controller::new(
            DesktopBackend::new(None, None),
            cardpeek_analyser::AnalyserLibrary::at(directory.path()).unwrap(),
        ));
        let window = cx.update(|cx| {
            cx.open_window(WindowOptions::default(), |_, cx| {
                cx.new(|cx| {
                    App::new(
                        controller,
                        Preferences::load(directory.path().join("preferences")),
                        None,
                        cx,
                    )
                })
            })
            .unwrap()
        });
        window
            .update(cx, |app, _, cx| {
                app.state.session_dialog = Some(SessionDialog::NewSession);
                cx.notify();
            })
            .unwrap();
        cx.simulate_keystrokes(window.into(), "escape");
        window
            .update(cx, |app, _, cx| {
                assert_eq!(app.state.session_dialog, None);

                app.state.interaction = Some(cardpeek_app::InteractionRequest {
                    id: cardpeek_app::InteractionId::new("test-interaction"),
                    kind: InteractionKind::TextInput {
                        prompt: "Enter text".into(),
                        default: None,
                    },
                });
                app.sync_external_inputs(cx);
                cx.notify();
            })
            .unwrap();
        cx.simulate_keystrokes(window.into(), "escape");
        window
            .update(cx, |app, _, _| {
                assert_eq!(app.state.interaction, None);
                assert!(app.interaction.is_none());
            })
            .unwrap();
    }
}
