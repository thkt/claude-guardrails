use std::env;
use std::io::{stderr, IsTerminal};
use std::sync::LazyLock;

/// Whether stderr takes ANSI. A payload bound for another stream decides its
/// own colouring and passes it down; this answers only for stderr.
pub(crate) fn stderr_takes_color() -> bool {
    use_color()
}

/// Yellow only when the caller says so, for text whose destination stream is
/// not the one `use_color` inspects.
pub(crate) fn yellow_if(color: bool, text: &str) -> String {
    wrap_with(color, "33", text)
}

fn use_color() -> bool {
    static COLOR: LazyLock<bool> =
        LazyLock::new(|| use_color_with(env::var_os("NO_COLOR").is_none(), stderr().is_terminal()));
    *COLOR
}

fn use_color_with(no_color_unset: bool, stderr_is_tty: bool) -> bool {
    no_color_unset && stderr_is_tty
}

fn wrap(ansi_code: &str, text: &str) -> String {
    wrap_with(use_color(), ansi_code, text)
}

fn wrap_with(color: bool, ansi_code: &str, text: &str) -> String {
    if color {
        format!("\x1b[{ansi_code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

pub fn red(text: &str) -> String {
    wrap("31", text)
}

pub fn yellow(text: &str) -> String {
    wrap("33", text)
}

pub fn bold_red(text: &str) -> String {
    wrap("1;31", text)
}

#[cfg(test)]
pub(crate) fn strip_ansi(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for inner in chars.by_ref() {
                if inner == 'm' {
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_applies_ansi_codes() {
        // Expected values are literal ANSI SGR sequences, not re-derived from the
        // impl's format string, so a change to the escape format is caught.
        for (ansi_code, expected) in [
            ("31", "\x1b[31mtext\x1b[0m"),
            ("33", "\x1b[33mtext\x1b[0m"),
            ("1;31", "\x1b[1;31mtext\x1b[0m"),
        ] {
            assert_eq!(
                wrap_with(true, ansi_code, "text"),
                expected,
                "code={ansi_code}"
            );
        }
    }

    #[test]
    fn wrap_returns_plain_text_without_color() {
        for code in ["31", "33", "1;31"] {
            assert_eq!(wrap_with(false, code, "text"), "text", "code={code}");
        }
    }

    #[test]
    fn use_color_requires_tty_and_no_color_unset() {
        for (no_color_unset, stderr_is_tty, expected) in [
            (true, true, true),
            (false, true, false),
            (true, false, false),
            (false, false, false),
        ] {
            assert_eq!(
                use_color_with(no_color_unset, stderr_is_tty),
                expected,
                "no_color_unset={no_color_unset} stderr_is_tty={stderr_is_tty}"
            );
        }
    }
}
