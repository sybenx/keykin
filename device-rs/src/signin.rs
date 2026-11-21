// `keykin join`: signing in the way Marble on Mac does (Keykin SPEC 11.6, `add=`; OAuth for native apps,
// RFC 8252 with PKCE). A verifier that never leaves this program but to the box, a state, and a listener on
// http://127.0.0.1:<random port>/ for ten minutes. Marble Web opens in the browser with this device's invite,
// the challenge, that address and the state; after Add on the account page, the browser comes back here with
// the approval code and the join text. The box hands the piece to no one without both.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use base64::Engine as _;
use sha2::{Digest, Sha256};

pub const LIFE: Duration = Duration::from_secs(600);

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("random");
    b
}
/// PKCE S256: base64url(SHA-256(verifier)).
pub fn challenge_of(verifier: &str) -> String {
    b64(&Sha256::digest(verifier.as_bytes()))
}

pub struct Asked {
    pub verifier: String,
    pub state: String,
    pub listener: TcpListener,
    pub port: u16,
}

pub fn start() -> Result<Asked, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("keykin couldn’t listen for your browser: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    Ok(Asked { verifier: b64(&random(32)), state: b64(&random(16)), listener, port })
}

/// The page to open: Marble Web, which finds your account page and carries the four on.
pub fn url(web: &str, a: &Asked, invite: &str) -> String {
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let ret = format!("http://127.0.0.1:{}/done", a.port);
    format!("{}/#challenge={}&return={}&state={}&add={}", web.trim_end_matches('/'), challenge_of(&a.verifier), enc(&ret), a.state, enc(invite))
}

/// What came back through the browser: the join text and the approval code, and the tab to answer.
pub struct Approval {
    pub join: String,
    pub code: String,
    pub tab: TcpStream,
}

/// Listens until the approval comes (sent on `tx`) or ten minutes pass. Anything else is answered and left alone.
pub fn listen(listener: TcpListener, state: String, tx: Sender<Approval>) {
    let until = Instant::now() + LIFE;
    while Instant::now() < until {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(a) = read(stream, &state) {
                    let _ = tx.send(a);
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(150)),
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

fn read(mut stream: TcpStream, state: &str) -> Option<Approval> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = vec![0u8; 16 * 1024];
    let mut got = 0;
    while got < buf.len() {
        match stream.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => {
                got += n;
                if buf[..got].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let head = String::from_utf8_lossy(&buf[..got]);
    let target = head.lines().next().and_then(|l| l.strip_prefix("GET ")).and_then(|l| l.split(' ').next()).unwrap_or("");
    let Ok(u) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
        reply(stream, 400, "That isn’t a request keykin knows.");
        return None;
    };
    if u.path() != "/done" {
        reply(stream, 404, "Nothing here.");
        return None;
    }
    let q = |k: &str| u.query_pairs().find(|(n, _)| n == k).map(|(_, v)| v.into_owned());
    // The state this join made: anything else (another tab, another program on this computer) is left alone.
    if q("state").as_deref() != Some(state) {
        reply(stream, 400, "This wasn’t for this sign-in, so keykin left it alone.");
        return None;
    }
    match (q("code"), q("join")) {
        (Some(code), Some(join)) => Some(Approval { join, code, tab: stream }),
        _ => {
            reply(stream, 400, "Something was missing, so keykin left it alone.");
            None
        }
    }
}

pub fn reply(mut stream: TcpStream, status: u16, words: &str) {
    let esc = words.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let body = format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Keykin</title>\
         <style>body{{font:16px/1.5 -apple-system,system-ui,sans-serif;max-width:32em;margin:18vh auto;padding:0 20px;color:#1f1b16;background:#f7f3ec}}\
         @media(prefers-color-scheme:dark){{body{{color:#f3eee6;background:#1e1c19}}}}h1{{font-size:22px}}</style><h1>Keykin</h1><p id=said>{esc}</p>"
    );
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let _ = write!(stream, "HTTP/1.1 {status} {reason}\r\ncontent-type: text/html; charset=utf-8\r\ncache-control: no-store\r\nreferrer-policy: no-referrer\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
    let _ = stream.flush();
}

/// Your account page's address as typed beside the six digits: https, or http only on this computer.
pub fn page_addr(page: &str) -> Result<String, String> {
    let p = page.trim().trim_end_matches('/');
    let full = if p.contains("://") { p.to_string() } else { format!("https://{p}") };
    let u = url::Url::parse(&full).map_err(|_| "Type your account page’s address, as it shows it.".to_string())?;
    let local = matches!(u.host_str(), Some("127.0.0.1") | Some("localhost"));
    if !(u.scheme() == "https" || (u.scheme() == "http" && local)) || u.host_str().is_none() || !u.username().is_empty() || u.password().is_some() {
        return Err("Type your account page’s address, as it shows it.".into());
    }
    Ok(u.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_is_s256() {
        // RFC 7636 appendix B.
        assert_eq!(challenge_of("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn the_page_address_typed() {
        assert_eq!(page_addr("account.syb.lol").unwrap(), "https://account.syb.lol");
        assert_eq!(page_addr(" https://account.syb.lol/ ").unwrap(), "https://account.syb.lol");
        assert_eq!(page_addr("http://127.0.0.1:7561").unwrap(), "http://127.0.0.1:7561");
        assert!(page_addr("http://account.syb.lol").is_err());
        assert!(page_addr("https://me:pw@account.syb.lol").is_err());
        assert!(page_addr("").is_err());
    }

    #[test]
    fn only_this_sign_ins_approval_is_taken() {
        let a = start().unwrap();
        let port = a.port;
        let (tx, rx) = std::sync::mpsc::channel();
        let state = a.state.clone();
        let t = std::thread::spawn(move || listen(a.listener, state, tx));
        let get = |path: &str| {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(s, "GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").unwrap();
            s
        };
        let mut wrong = get("/done?state=nope&code=1&join=x");
        let mut said = String::new();
        wrong.read_to_string(&mut said).unwrap();
        assert!(said.contains("left it alone"));
        assert!(rx.try_recv().is_err());
        let _tab = get(&format!("/done?state={}&code=123456&join=%7B%7D", a.state));
        let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((got.code.as_str(), got.join.as_str()), ("123456", "{}"));
        t.join().unwrap();
    }
}
