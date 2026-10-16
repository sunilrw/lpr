//! Emoji / ASCII symbol handling.
//!
//! Classic Windows consoles (conhost, PowerShell 5.1 with raster fonts) render
//! emoji as `?`. `Sym` wraps each icon so output switches to plain ASCII when
//! the terminal can't display emoji — detected automatically, or forced via:
//!   LPR_ASCII=1 / NO_EMOJI=1   -> always ASCII
//!   LPR_EMOJI=1                -> always emoji

use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

static ASCII_MODE: AtomicBool = AtomicBool::new(false);
static DETECTED: OnceLock<()> = OnceLock::new();

fn detect_ascii() -> bool {
    if std::env::var_os("LPR_EMOJI").is_some() {
        return false;
    }
    if std::env::var_os("LPR_ASCII").is_some() || std::env::var_os("NO_EMOJI").is_some() {
        return true;
    }
    if cfg!(windows) {
        // Emoji render correctly in Windows Terminal, VS Code, WezTerm, ConEmu.
        // Classic conhost.exe / PowerShell 5.1 cannot — default to ASCII there.
        return std::env::var_os("WT_SESSION").is_none()
            && std::env::var_os("TERM_PROGRAM").is_none()
            && std::env::var_os("WEZTERM_EXECUTABLE").is_none()
            && std::env::var("ConEmuANSI").map(|v| v != "ON").unwrap_or(true);
    }
    matches!(std::env::var("TERM").as_deref(), Ok("dumb"))
}

fn ensure_detected() {
    DETECTED.get_or_init(|| ASCII_MODE.store(detect_ascii(), Ordering::Relaxed));
}

/// Force ASCII mode on (used by `--ascii` global flag).
pub fn force_ascii() {
    ensure_detected();
    ASCII_MODE.store(true, Ordering::Relaxed);
}

pub fn ascii_mode() -> bool {
    ensure_detected();
    ASCII_MODE.load(Ordering::Relaxed)
}

/// A terminal icon: emoji when supported, ASCII fallback otherwise.
/// Usable inline in format strings: `println!("{SYM_OK} done")`.
pub struct Sym(pub &'static str, pub &'static str);

impl Display for Sym {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.write_str(if ascii_mode() { self.1 } else { self.0 })
    }
}

impl Sym {
    /// Plain `&str` for non-format contexts (TUI spans, table cells...).
    pub fn s(&self) -> &'static str {
        if ascii_mode() {
            self.1
        } else {
            self.0
        }
    }
}

pub static SYM_SHIELD: Sym = Sym("🛡\u{FE0F}", "");
pub static SYM_OK: Sym = Sym("✔", "[OK]");
pub static SYM_DONE: Sym = Sym("✅", "[OK]");
#[allow(dead_code)]
pub static SYM_FAIL: Sym = Sym("✖", "[X]");
pub static SYM_WARN: Sym = Sym("⚠\u{FE0F}", "[!]");
pub static SYM_TIP: Sym = Sym("💡", "[i]");
pub static SYM_BULLET: Sym = Sym("🔹", "-");
#[allow(dead_code)]
pub static SYM_ARROW: Sym = Sym("→", "->");
pub static SYM_UP: Sym = Sym("↑", "^");
pub static SYM_DOWN: Sym = Sym("↓", "v");
#[allow(dead_code)]
pub static SYM_PLAY: Sym = Sym("▶", ">");
pub static SYM_GLOBE: Sym = Sym("🌐", "");
pub static SYM_CAL: Sym = Sym("📅", "");
pub static SYM_FOLDER: Sym = Sym("📁", "");
pub static SYM_DIR: Sym = Sym("📂", "");
pub static SYM_SERVER: Sym = Sym("🖥\u{FE0F}", "");
pub static SYM_SAVE: Sym = Sym("💾", "");
pub static SYM_CHART: Sym = Sym("📊", "");
pub static SYM_LIST: Sym = Sym("📋", "");
pub static SYM_FILE: Sym = Sym("📄", "");
pub static SYM_BOOKS: Sym = Sym("📚", "");
pub static SYM_BRAIN: Sym = Sym("🧠", "");
pub static SYM_NOTE: Sym = Sym("📝", "");
pub static SYM_LOCK: Sym = Sym("🔐", "");
pub static SYM_ROCKET: Sym = Sym("🚀", "");
pub static SYM_BSQ: Sym = Sym("🟦", "");
pub static SYM_PSQ: Sym = Sym("🟪", "");
pub static SYM_ZAP: Sym = Sym("⚡", "");
pub static SYM_MAIL: Sym = Sym("📧", "");
pub static SYM_MAILBOX: Sym = Sym("📬", "");
pub static SYM_SEARCH: Sym = Sym("🔍", "");
pub static SYM_RADIO: Sym = Sym("📡", "");
pub static SYM_SPARK: Sym = Sym("✨", "");
pub static SYM_GEAR: Sym = Sym("⚙\u{FE0F}", "");

/// TUI list-selection marker (with trailing space).
pub static SYM_SEL: Sym = Sym("▶ ", "> ");
