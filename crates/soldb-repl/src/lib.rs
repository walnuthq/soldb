#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayMode {
    Source,
    Assembly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebuggerState {
    pub current_step: usize,
    pub display_mode: DisplayMode,
}

impl Default for DebuggerState {
    fn default() -> Self {
        Self {
            current_step: 0,
            display_mode: DisplayMode::Source,
        }
    }
}
