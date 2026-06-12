//! Terminal I/O for the REPL, mirroring the C++ `Console`: a `> ` prompt and
//! ANSI-colored output lines.

use std::io::{self, Write};

/// ANSI output color, matching the colors the C++ CLI uses.
#[derive(Clone, Copy)]
pub enum Color {
    /// Green — used for successful `[done]` output.
    Green,
    /// Red — used for failed `[failed]` output and errors.
    Red,
    /// Blue — used for the startup logo.
    Blue,
    /// White — used for usage and version output.
    White,
}

impl Color {
    fn code(self) -> &'static str {
        match self {
            Color::Green => "\u{1b}[32m",
            Color::Red => "\u{1b}[31m",
            Color::Blue => "\u{1b}[34m",
            Color::White => "\u{1b}[37m",
        }
    }
}

/// Renders one colored line (color code + text + reset + newline), matching
/// the C++ `Console::Write` output bytes.
fn render(line: &str, color: Color) -> String {
    format!("{}{line}\u{1b}[0m\n", color.code())
}

/// Writes one colored line to stdout, matching the C++ `Console::Write`.
pub fn write(line: &str, color: Color) {
    let mut out = io::stdout();
    let _ = out.write_all(render(line, color).as_bytes());
    let _ = out.flush();
}

/// Prints the `> ` prompt and reads one non-empty line from stdin.
///
/// Returns `None` on end-of-input (Ctrl-D), which the REPL treats like `exit`.
/// Empty lines re-prompt, as in the C++ readline loop.
pub fn read() -> Option<String> {
    loop {
        {
            let mut out = io::stdout();
            let _ = write!(out, "> ");
            let _ = out.flush();
        }
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => return None,
            Ok(_) => {
                if line.trim().is_empty() {
                    continue;
                }
                return Some(line);
            }
            Err(_) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_wraps_text_in_color_code_reset_and_newline() {
        assert_eq!(
            render("[done]", Color::Green),
            "\u{1b}[32m[done]\u{1b}[0m\n"
        );
        assert_eq!(
            render("[failed]", Color::Red),
            "\u{1b}[31m[failed]\u{1b}[0m\n"
        );
        assert_eq!(render("logo", Color::Blue), "\u{1b}[34mlogo\u{1b}[0m\n");
        assert_eq!(render("usage", Color::White), "\u{1b}[37musage\u{1b}[0m\n");
    }
}
