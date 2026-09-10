//! The full-screen view of a debugging session, in the terminal.
//!
//! The same [`Session`] the line-oriented REPL drives sits behind a set of panes: the
//! source with the current line and the breakpoints marked, the variables in scope and
//! the state, the stack, memory, the backtrace, and the opcodes around the program
//! counter, with a command line at the bottom that takes every REPL command. Keys step
//! without typing: `n`, `s`, `c`, `f`, `i` forward and their capitals backward, the way
//! gdb's TUI works; `q` returns to the prompt and `Q` leaves the debugger.
//!
//! Nothing here decides anything about the trace: every pane shows what the session
//! answers, so the view and the REPL cannot disagree.

use std::io::{self, IsTerminal, Stdout};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use soldb_repl::{
    breakpoint_lines, DebuggerCommand, DisplayMode, Output, Renderer, Session, StateInfo,
    StopReason,
};

/// How the view was left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Back to the line-oriented prompt.
    Repl,
    /// The debugger should end.
    Quit,
}

/// The panes, in the order `Tab` cycles them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pane {
    Source,
    Variables,
    Stack,
    Memory,
    Backtrace,
    Opcodes,
    Console,
}

impl Pane {
    const ALL: [Self; 7] = [
        Self::Source,
        Self::Variables,
        Self::Stack,
        Self::Memory,
        Self::Backtrace,
        Self::Opcodes,
        Self::Console,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::Source => "Source",
            Self::Variables => "Variables",
            Self::Stack => "Stack",
            Self::Memory => "Memory",
            Self::Backtrace => "Backtrace",
            Self::Opcodes => "Opcodes",
            Self::Console => "Console",
        }
    }

    fn next(self) -> Self {
        let index = Self::ALL.iter().position(|pane| *pane == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    fn previous(self) -> Self {
        let index = Self::ALL.iter().position(|pane| *pane == self).unwrap_or(0);
        Self::ALL[(index + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// Runs the view over `session` until the user leaves it.
///
/// # Errors
///
/// [`io::ErrorKind::Unsupported`] when stdin or stdout is not a terminal, which a
/// frontend reports as a message rather than a failure; otherwise when the terminal
/// cannot be put into raw mode or drawn to.
pub fn run(session: &mut Session) -> io::Result<Exit> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the full-screen view needs a terminal on stdin and stdout",
        ));
    }
    let mut terminal = Screen::enter()?;
    let mut view = View::new();
    view.refresh(session);
    let exit = loop {
        terminal.draw(|frame| view.draw(frame, session))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if let Some(exit) = view.handle_key(key, session) {
                break exit;
            }
        }
    };
    drop(terminal);
    Ok(exit)
}

/// The raw-mode alternate screen, restored however the view ends.
struct Screen(Terminal<CrosstermBackend<Stdout>>);

impl Screen {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(Self(terminal))
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = self.0.show_cursor();
    }
}

impl std::ops::Deref for Screen {
    type Target = Terminal<CrosstermBackend<Stdout>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Screen {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// What the panes show, refreshed after every command.
struct View {
    focus: Pane,
    /// Scroll offset per pane, in lines from the top.
    scroll: [u16; Pane::ALL.len()],
    /// Whether the source pane follows the current line.
    follow: bool,
    /// The command being typed, when the console has the cursor.
    input: Option<String>,
    /// What the last commands answered, newest last.
    console: Vec<String>,
    /// The panes' contents.
    source: Vec<Line<'static>>,
    source_current: Option<usize>,
    variables: Vec<Line<'static>>,
    stack: Vec<Line<'static>>,
    memory: Vec<Line<'static>>,
    backtrace: Vec<Line<'static>>,
    opcodes: Vec<Line<'static>>,
    opcode_current: Option<usize>,
    status: String,
    help: bool,
}

impl View {
    fn new() -> Self {
        Self {
            focus: Pane::Source,
            scroll: [0; Pane::ALL.len()],
            follow: true,
            input: None,
            console: vec!["Keys: n s c f i step forward, N S C F I backward, b breaks on the source line, : types a command, Tab moves focus, ? help, q back to the prompt, Q quit".to_owned()],
            source: Vec::new(),
            source_current: None,
            variables: Vec::new(),
            stack: Vec::new(),
            memory: Vec::new(),
            backtrace: Vec::new(),
            opcodes: Vec::new(),
            opcode_current: None,
            status: String::new(),
            help: false,
        }
    }

    /// Reads every pane from the session.
    fn refresh(&mut self, session: &mut Session) {
        let renderer = Renderer::new(false);
        self.status = match session.stop(StopReason::Moved) {
            Some(stop) => {
                let mut text = format!(
                    "step {}/{}  pc {}  {}  gas {}",
                    stop.step, stop.last_step, stop.pc, stop.op, stop.gas
                );
                if let Some(location) = &stop.location {
                    text.push_str("  ");
                    text.push_str(&location.path);
                    text.push(':');
                    text.push_str(&location.line.to_string());
                    if let Some(function) = &location.function {
                        text.push_str(" in ");
                        text.push_str(function);
                    }
                }
                text
            }
            None => "no trace loaded".to_owned(),
        };
        self.refresh_source(session);
        self.variables = match session.variables(None) {
            Output::Variables {
                locals,
                unavailable,
                state,
                ..
            } => {
                let mut lines = Vec::new();
                if locals.is_empty() {
                    lines.push(dim(match unavailable {
                        Some(reason) => format!("locals unavailable: {reason}"),
                        None => "no variables in scope".to_owned(),
                    }));
                }
                for variable in &locals {
                    lines.push(variable_line(
                        &variable.ty,
                        &variable.name,
                        &variable.value,
                        variable.place.as_deref(),
                    ));
                }
                lines.push(dim("State:".to_owned()));
                match state {
                    StateInfo::Variables { variables } => {
                        for variable in &variables {
                            lines.push(variable_line(
                                &variable.ty,
                                &variable.name,
                                &variable.value,
                                variable.place.as_deref(),
                            ));
                        }
                    }
                    StateInfo::None => lines.push(dim("  no state variables declared".to_owned())),
                    StateInfo::NoLayout => lines.push(dim("  no storage layout loaded".to_owned())),
                    StateInfo::NoStorage => lines.push(dim("  no storage recorded".to_owned())),
                }
                lines
            }
            other => text_lines(&renderer, &other),
        };
        self.stack = match session.stack(None) {
            Output::Stack { words, .. } => {
                if words.is_empty() {
                    vec![dim("empty".to_owned())]
                } else {
                    words
                        .iter()
                        .enumerate()
                        .rev()
                        .map(|(index, word)| {
                            Line::from(vec![
                                Span::styled(
                                    format!("[{index:>2}] "),
                                    Style::default().fg(Color::DarkGray),
                                ),
                                Span::raw(word.clone()),
                            ])
                        })
                        .collect()
                }
            }
            other => text_lines(&renderer, &other),
        };
        self.memory = match session.memory(None, None) {
            Output::Memory(memory) => memory
                .words
                .iter()
                .map(|word| {
                    Line::from(vec![
                        Span::styled(
                            format!("0x{:04x}: ", word.offset),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::raw(word.hex.clone()),
                    ])
                })
                .collect(),
            other => text_lines(&renderer, &other),
        };
        self.backtrace = text_lines(&renderer, &session.backtrace());
        self.refresh_opcodes(session);
        if self.follow {
            self.center_on_current();
        }
    }

    /// The whole current source, the current line and the breakpoints marked.
    fn refresh_source(&mut self, session: &Session) {
        self.source.clear();
        self.source_current = None;
        let state = session.state();
        let Some(map) = state.step_map() else {
            self.source.push(dim("no debug metadata loaded".to_owned()));
            return;
        };
        let Some(location) = state.location() else {
            self.source
                .push(dim(match map.executing_address(state.current_step) {
                    Some(address) => format!("no source for this step in {address}"),
                    None => "no source for this step".to_owned(),
                }));
            return;
        };
        let Some(contract) = map.contracts().get(location.key.contract) else {
            return;
        };
        let breakpoints = breakpoint_lines(state);
        let Some(count) = contract.line_count(location.key.source_id) else {
            return;
        };
        for line in 1..=count {
            let text = contract
                .line_text(location.key.source_id, line)
                .unwrap_or_default()
                .to_owned();
            let current = line == location.line;
            let marked = breakpoints
                .iter()
                .any(|(path, at)| *at == line && path == &location.path);
            let mark = match (current, marked) {
                (true, _) => "=>",
                (false, true) => " *",
                (false, false) => "  ",
            };
            let style = if current {
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Yellow)
            } else {
                Style::default()
            };
            self.source.push(Line::from(vec![
                Span::styled(
                    format!("{mark} {line:>4} | "),
                    if marked {
                        Style::default().fg(Color::Red)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    },
                ),
                Span::styled(text, style),
            ]));
            if current {
                self.source_current = Some(self.source.len() - 1);
            }
        }
    }

    /// The instructions of the executing program around the program counter.
    fn refresh_opcodes(&mut self, session: &Session) {
        self.opcodes.clear();
        self.opcode_current = None;
        let state = session.state();
        let Some(map) = state.step_map() else {
            return;
        };
        let Some(contract) = map.contract_at_step(state.current_step) else {
            self.opcodes
                .push(dim("no program loaded for this step".to_owned()));
            return;
        };
        let Some(step) = state.current_step_data() else {
            return;
        };
        for instruction in &contract.info.instructions {
            let mnemonic = instruction.mnemonic().unwrap_or("?").to_owned();
            let arguments = instruction.arguments().join(" ");
            let current = instruction.offset == step.pc;
            let style = if current {
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Yellow)
            } else {
                Style::default()
            };
            self.opcodes.push(Line::from(vec![
                Span::styled(
                    format!(
                        "{} {:>5} ",
                        if current { "=>" } else { "  " },
                        instruction.offset
                    ),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(format!("{mnemonic} {arguments}"), style),
            ]));
            if current {
                self.opcode_current = Some(self.opcodes.len() - 1);
            }
        }
    }

    /// Scrolls the source and opcode panes so the current line sits in the middle.
    fn center_on_current(&mut self) {
        if let Some(current) = self.source_current {
            self.scroll[pane_index(Pane::Source)] = current.saturating_sub(8) as u16;
        }
        if let Some(current) = self.opcode_current {
            self.scroll[pane_index(Pane::Opcodes)] = current.saturating_sub(4) as u16;
        }
    }

    /// Runs one REPL command and shows its answer in the console.
    fn run_command(&mut self, line: &str, session: &mut Session) -> Option<Exit> {
        let renderer = Renderer::new(false);
        let command = DebuggerCommand::parse(line);
        if !line.trim().is_empty() {
            self.console.push(format!("soldb> {}", line.trim()));
        }
        for output in session.execute(command) {
            match output {
                Output::Quit => return Some(Exit::Quit),
                Output::Tui => {}
                other => {
                    for text in renderer.render(&other).lines() {
                        self.console.push(text.to_owned());
                    }
                }
            }
        }
        self.follow = true;
        self.refresh(session);
        self.scroll[pane_index(Pane::Console)] = u16::MAX;
        None
    }

    fn handle_key(&mut self, key: KeyEvent, session: &mut Session) -> Option<Exit> {
        if self.help {
            self.help = false;
            return None;
        }
        if let Some(input) = self.input.as_mut() {
            match key.code {
                KeyCode::Enter => {
                    let line = self.input.take().unwrap_or_default();
                    return self.run_command(&line, session);
                }
                KeyCode::Esc => self.input = None,
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Char(character) => input.push(character),
                _ => {}
            }
            return None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return match key.code {
                // Ctrl-X A, as in gdb: back to the prompt.
                KeyCode::Char('x' | 'a') => Some(Exit::Repl),
                KeyCode::Char('c') => Some(Exit::Quit),
                _ => None,
            };
        }
        let command = match key.code {
            KeyCode::Char('q') => return Some(Exit::Repl),
            KeyCode::Char('Q') => return Some(Exit::Quit),
            KeyCode::Char('?') => {
                self.help = true;
                return None;
            }
            KeyCode::Char(':') => {
                self.input = Some(String::new());
                return None;
            }
            KeyCode::Tab => {
                self.focus = self.focus.next();
                return None;
            }
            KeyCode::BackTab => {
                self.focus = self.focus.previous();
                return None;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.scroll_by(1);
                return None;
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.scroll_by(-1);
                return None;
            }
            KeyCode::PageDown => {
                self.scroll_by(10);
                return None;
            }
            KeyCode::PageUp => {
                self.scroll_by(-10);
                return None;
            }
            KeyCode::Char('g') => {
                self.follow = true;
                self.center_on_current();
                return None;
            }
            KeyCode::Char('m') => {
                let mode = match session.state().display_mode {
                    DisplayMode::Source => DisplayMode::Assembly,
                    DisplayMode::Assembly => DisplayMode::Source,
                };
                "mode ".to_owned() + mode.as_str()
            }
            KeyCode::Char('b') => match session.state().location() {
                Some(location) => format!("break {}:{}", location.path, location.line),
                None => return None,
            },
            KeyCode::Char('n') => "next".to_owned(),
            KeyCode::Char('s') => "step".to_owned(),
            KeyCode::Char('c') => "continue".to_owned(),
            KeyCode::Char('f') => "finish".to_owned(),
            KeyCode::Char('i') => "nexti".to_owned(),
            KeyCode::Char('N') => "reverse-next".to_owned(),
            KeyCode::Char('S') => "reverse-step".to_owned(),
            KeyCode::Char('C') => "reverse-continue".to_owned(),
            KeyCode::Char('F') => "reverse-finish".to_owned(),
            KeyCode::Char('I') => "reverse-nexti".to_owned(),
            _ => return None,
        };
        self.run_command(&command, session)
    }

    fn scroll_by(&mut self, delta: i32) {
        let index = pane_index(self.focus);
        let current = i32::from(self.scroll[index]);
        self.scroll[index] = (current + delta).clamp(0, i32::from(u16::MAX - 1)) as u16;
        if matches!(self.focus, Pane::Source | Pane::Opcodes) {
            self.follow = false;
        }
    }

    fn draw(&mut self, frame: &mut Frame<'_>, session: &Session) {
        let area = frame.area();
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(8),
                Constraint::Length(8),
                Constraint::Length(2),
            ])
            .split(area);
        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(rows[0]);
        let left = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(top[0]);
        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(45),
                Constraint::Percentage(25),
                Constraint::Percentage(30),
            ])
            .split(top[1]);
        self.pane(frame, Pane::Source, left[0], &self.source);
        self.pane(frame, Pane::Opcodes, left[1], &self.opcodes);
        self.pane(frame, Pane::Variables, right[0], &self.variables);
        self.pane(frame, Pane::Stack, right[1], &self.stack);
        self.pane(frame, Pane::Memory, right[2], &self.memory);
        let bottom = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(rows[1]);
        self.pane(frame, Pane::Backtrace, bottom[0], &self.backtrace);
        let console = self
            .console
            .iter()
            .map(|line| Line::from(line.clone()))
            .collect::<Vec<_>>();
        self.pane(frame, Pane::Console, bottom[1], &console);
        self.draw_status(frame, rows[2], session);
        if self.help {
            self.draw_help(frame, area);
        }
    }

    fn pane(&self, frame: &mut Frame<'_>, pane: Pane, area: Rect, lines: &[Line<'static>]) {
        let focused = self.focus == pane;
        let border = if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border)
            .title(format!(" {} ", pane.title()));
        let inner_height = area.height.saturating_sub(2) as usize;
        let max_scroll = lines.len().saturating_sub(inner_height) as u16;
        let scroll = self.scroll[pane_index(pane)].min(max_scroll);
        let paragraph = Paragraph::new(lines.to_vec())
            .block(block)
            .scroll((scroll, 0));
        frame.render_widget(paragraph, area);
    }

    fn draw_status(&self, frame: &mut Frame<'_>, area: Rect, session: &Session) {
        let status = Line::from(vec![
            Span::styled(
                format!(" {} ", self.status),
                Style::default().fg(Color::Black).bg(Color::Cyan),
            ),
            Span::raw(format!(
                "  mode {}  breakpoints {}",
                session.state().display_mode.as_str(),
                session.state().breakpoints().len()
            )),
        ]);
        let prompt = match &self.input {
            Some(input) => Line::from(vec![
                Span::styled("soldb> ", Style::default().fg(Color::Cyan)),
                Span::raw(input.clone()),
                Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
            ]),
            None => Line::from(Span::styled(
                " n/s/c/f/i step  N/S/C/F/I back  b break  m mode  : command  Tab focus  ? help  q prompt  Q quit",
                Style::default().fg(Color::DarkGray),
            )),
        };
        frame.render_widget(Paragraph::new(vec![status, prompt]), area);
    }

    fn draw_help(&self, frame: &mut Frame<'_>, area: Rect) {
        let width = area.width.min(70);
        let height = area.height.min(20);
        let popup = Rect {
            x: area.x + (area.width - width) / 2,
            y: area.y + (area.height - height) / 2,
            width,
            height,
        };
        let lines = [
            "n  next        s  step        c  continue     f  finish     i  nexti",
            "N  back over   S  back into   C  back to bp   F  back out   I  back one",
            "b  break on the current line     m  toggle source/asm     g  recenter",
            ":  type any REPL command (Enter runs it, Esc cancels)",
            "Tab / Shift-Tab  move focus     j/k, arrows, PgUp/PgDn  scroll the pane",
            "q  back to the prompt   Q  quit   Ctrl-X A  back to the prompt",
            "",
            "Press any key to close.",
        ]
        .into_iter()
        .map(|line| Line::from(line.to_owned()))
        .collect::<Vec<_>>();
        let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Keys ")
                .style(Style::default().bg(Color::Black)),
        );
        frame.render_widget(ratatui::widgets::Clear, popup);
        frame.render_widget(paragraph, popup);
    }
}

fn pane_index(pane: Pane) -> usize {
    Pane::ALL
        .iter()
        .position(|candidate| *candidate == pane)
        .unwrap_or(0)
}

fn dim(text: String) -> Line<'static> {
    Line::from(Span::styled(text, Style::default().fg(Color::DarkGray)))
}

fn variable_line(ty: &str, name: &str, value: &str, place: Option<&str>) -> Line<'static> {
    let mut spans = vec![
        Span::styled(format!("{ty} "), Style::default().fg(Color::Cyan)),
        Span::styled(
            name.to_owned(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(" = "),
        Span::styled(value.to_owned(), Style::default().fg(Color::Green)),
    ];
    if let Some(place) = place {
        spans.push(Span::styled(
            format!(" [{place}]"),
            Style::default().fg(Color::DarkGray),
        ));
    }
    Line::from(spans)
}

/// An answer as plain lines, for a pane that shows text.
fn text_lines(renderer: &Renderer, output: &Output) -> Vec<Line<'static>> {
    renderer.lines(output).into_iter().map(Line::from).collect()
}
