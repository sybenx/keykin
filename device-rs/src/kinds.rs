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
        1063 | 3063 => ("file", false),
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
        30063 => ("app release", false),
        30078 => ("app data", false),
        31989 => ("app recommendation", false),
        31990 => ("app handler", false),
        32267 => ("app listing", false),
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
    // Which app, release, file or upload it is about: the part of the event that names it.
    let tag = |k: &str| ev["tags"].as_array().and_then(|ts| ts.iter().find(|t| t[0].as_str() == Some(k))).and_then(|t| t[1].as_str()).map(str::to_string);
    let about = match kind {
        30063 | 32267 => tag("d"),
        1063 | 3063 => tag("url").map(|u| u.rsplit('/').next().unwrap_or(&u).to_string()).or_else(|| tag("x").map(|x| format!("file {}…", &x[..x.len().min(12)]))),
        24242 => tag("t").map(|t| match tag("x") { Some(x) => format!("{t} {}…", &x[..x.len().min(12)]), None => t }),
        _ => None,
    };
    let shown = if readable { Some(content) } else { about };
    let Some(text) = shown.filter(|t| !t.is_empty()) else { return what };
    let short: String = text.chars().take(60).collect();
    let more = if text.chars().count() > 60 { "…" } else { "" };
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
        // A release, a listing, a file and an upload say which one.
        assert_eq!(describe(&json!({ "kind": 30063, "content": "", "tags": [["d", "app.pinket@1.4.0"]] })), "an app release (kind 30063): “app.pinket@1.4.0”");
        assert_eq!(describe(&json!({ "kind": 32267, "content": "{}", "tags": [["d", "app.pinket"]] })), "an app listing (kind 32267): “app.pinket”");
        assert_eq!(describe(&json!({ "kind": 3063, "content": "", "tags": [["url", "https://cdn.example/a/Pinket.apk"]] })), "a file (kind 3063): “Pinket.apk”");
        assert_eq!(describe(&json!({ "kind": 24242, "content": "Upload", "tags": [["t", "upload"], ["x", "ab".repeat(32)]] })), "an upload login (kind 24242): “upload abababababab…”");
    }
}
