// Events in words, for the Touch ID prompt: what is about to be signed. Names as Keykin's own
// (src/destructive.ts NAMES and EVENT_NAMES), plus the few the command line is used for.
// Words only: what is hard to undo is the box's call, never this list's.

use serde_json::Value;

fn name(kind: u64) -> Option<(&'static str, bool)> {
    // (name, whether it is one of yours: "your follow list", not "a follow list")
    Some(match kind {
        0 => ("profile", true),
        1 => ("note", false),
        3 => ("follow list", true),
        4 | 13 | 14 => ("DM", false),
        5 => ("deletion", false),
        6 | 16 => ("repost", false),
        7 => ("reaction", false),
        62 => ("request to vanish", false),
        1111 => ("comment", false),
        9734 => ("zap request", false),
        10000 => ("mute list", true),
        10001 => ("pinned notes", true),
        10002 => ("relay list", true),
        10003 => ("bookmarks", true),
        10046 => ("login page", true),
        10050 => ("DM relays", true),
        22242 => ("relay login", false),
        24242 => ("upload login", false),
        27235 => ("web login", false),
        30000 => ("follow set", false),
        30001 => ("list", false),
        30023 => ("article", false),
        30078 => ("app data", false),
        31989 => ("app recommendation", false),
        31990 => ("app handler", false),
        _ => return None,
    })
}

fn article(w: &str) -> &'static str {
    if w.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    }
}

/// "a note (kind 1): “hello there”", "your follow list (kind 3)", "an event of kind 31234".
pub fn describe(ev: &Value) -> String {
    let kind = ev["kind"].as_u64().unwrap_or(1);
    let what = match name(kind) {
        Some((n, true)) => format!("your {n} (kind {kind})"),
        Some((n, false)) => format!("{} {n} (kind {kind})", article(n)),
        None => format!("an event of kind {kind}"),
    };
    let content: String = ev["content"].as_str().unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ");
    // A note's words say what it is; a list's or an app's content is JSON or encrypted, so it says nothing.
    let readable = !content.is_empty() && !content.starts_with(['{', '[']) && matches!(kind, 1 | 1111 | 30023 | 6 | 16 | 7);
    if !readable {
        return what;
    }
    let short: String = content.chars().take(60).collect();
    let more = if content.chars().count() > 60 { "…" } else { "" };
    format!("{what}: “{short}{more}”")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn in_words() {
        assert_eq!(describe(&json!({ "kind": 1, "content": "hello\n  there" })), "a note (kind 1): “hello there”");
        assert_eq!(describe(&json!({ "kind": 3, "content": "" })), "your follow list (kind 3)");
        assert_eq!(describe(&json!({ "kind": 31990, "content": "{\"name\":\"x\"}" })), "an app handler (kind 31990)");
        assert_eq!(describe(&json!({ "kind": 62, "content": "" })), "a request to vanish (kind 62)");
        assert_eq!(describe(&json!({ "kind": 31234, "content": "x" })), "an event of kind 31234");
        assert!(describe(&json!({ "kind": 1, "content": "a".repeat(80) })).ends_with("…”"));
    }
}
