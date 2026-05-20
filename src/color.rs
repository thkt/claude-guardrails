use std::env;
use std::io::{stderr, IsTerminal};
use std::sync::LazyLock;

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
        for (ansi_code, label) in [("31", "red"), ("33", "yellow"), ("1;31", "bold_red")] {
            let result = wrap_with(true, ansi_code, "text");
            let expected = format!("\x1b[{ansi_code}mtext\x1b[0m");
            assert_eq!(
                result, expected,
                "{label} should wrap with code {ansi_code}"
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
