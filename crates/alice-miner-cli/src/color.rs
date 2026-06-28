//! `color` — the ONE place that decides whether the live dashboard emits ANSI
//! color, and whether the in-place ratatui panel is allowed at all.
//!
//! The rules (precedence top to bottom) follow the de-facto CLI conventions so the
//! miner is a good citizen in journals, pipes, and dumb terminals:
//!
//!   1. `FORCE_COLOR` set (to anything non-empty) → color ON, unconditionally (the
//!      standard "I know what I'm doing, keep color even in a pipe" override).
//!   2. `--no-color` flag, `NO_COLOR` env set (the https://no-color.org standard),
//!      or `TERM=dumb` → color OFF.
//!   3. stdout is not a TTY → color OFF (a pipe / redirect / launchd|systemd journal
//!      stays clean + greppable).
//!   4. otherwise → color ON.
//!
//! Separately, the in-place **ratatui panel** is NEVER used when stdout is not a TTY
//! (a journal must stay a clean, line-oriented Snapshot log, not a screen-painting
//! stream) — see [`use_tui`]. These are pure decisions over `(flag, env, isatty)` so
//! they're unit-testable without a terminal.

use std::io::IsTerminal;

/// The environment inputs to the color/TTY decision, captured so the logic is pure
/// and testable (the live path reads the real env + the real stdout TTY).
#[derive(Debug, Clone, Copy, Default)]
pub struct ColorEnv {
    /// The `--no-color` CLI flag.
    pub no_color_flag: bool,
    /// `NO_COLOR` is present in the environment (any value, per the standard).
    pub no_color_env: bool,
    /// `FORCE_COLOR` is present + non-empty (the force-on override).
    pub force_color: bool,
    /// `TERM` == `dumb`.
    pub term_dumb: bool,
    /// stdout is a TTY.
    pub is_tty: bool,
}

impl ColorEnv {
    /// Capture the real environment + the real stdout TTY status. `no_color_flag`
    /// comes from the parsed `--no-color` CLI flag.
    pub fn detect(no_color_flag: bool) -> Self {
        let force_color = std::env::var_os("FORCE_COLOR")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        ColorEnv {
            no_color_flag,
            no_color_env: std::env::var_os("NO_COLOR").is_some(),
            force_color,
            term_dumb: std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false),
            is_tty: std::io::stdout().is_terminal(),
        }
    }

    /// Whether to emit ANSI color (see the module rules: FORCE_COLOR wins, then the
    /// opt-outs, then the TTY check).
    pub fn color_enabled(&self) -> bool {
        if self.force_color {
            return true;
        }
        if self.no_color_flag || self.no_color_env || self.term_dumb {
            return false;
        }
        self.is_tty
    }

    /// Whether the in-place ratatui panel may be used. NEVER off a TTY (so a journal /
    /// pipe gets the plain line renderer, not screen-paint escapes), regardless of
    /// FORCE_COLOR (forcing color doesn't make a pipe a screen). `TERM=dumb` also
    /// rules the panel out (it can't position the cursor).
    pub fn use_tui(&self) -> bool {
        self.is_tty && !self.term_dumb
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(no_color_flag: bool, no_color_env: bool, force: bool, dumb: bool, tty: bool) -> ColorEnv {
        ColorEnv {
            no_color_flag,
            no_color_env,
            force_color: force,
            term_dumb: dumb,
            is_tty: tty,
        }
    }

    #[test]
    fn force_color_beats_every_opt_out() {
        // FORCE_COLOR wins even with --no-color + NO_COLOR + dumb + a pipe.
        assert!(env(true, true, true, true, false).color_enabled());
    }

    #[test]
    fn opt_outs_disable_color_on_a_tty() {
        assert!(!env(true, false, false, false, true).color_enabled(), "--no-color");
        assert!(!env(false, true, false, false, true).color_enabled(), "NO_COLOR");
        assert!(!env(false, false, false, true, true).color_enabled(), "TERM=dumb");
    }

    #[test]
    fn non_tty_disables_color_by_default() {
        // A pipe / journal with no flags → no color.
        assert!(!env(false, false, false, false, false).color_enabled());
        // A plain interactive TTY → color on.
        assert!(env(false, false, false, false, true).color_enabled());
    }

    #[test]
    fn tui_only_on_a_tty() {
        // Off a TTY the panel is never used, even with FORCE_COLOR (a pipe isn't a screen).
        assert!(!env(false, false, true, false, false).use_tui());
        // A dumb terminal can't paint either.
        assert!(!env(false, false, false, true, true).use_tui());
        // A real TTY → panel allowed.
        assert!(env(false, false, false, false, true).use_tui());
    }
}
