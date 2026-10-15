//! A C2PA Verifiable Segment Info (VSI) signing proxy and verifier for DASH-IF livesim2.
//!
//! `proxy` sits in front of livesim2 and acts as a live packager: for each representation it
//! signs the init segment once, then signs every new media segment, in order, as livesim2 makes
//! it available. Players fetch the MPD (passed through unchanged) and the signed segments from
//! the proxy.
//!
//! `verify` follows a proxied representation like a player would and validates each segment
//! with `LiveVideoValidator` as it appears.

use std::{
    collections::{BTreeMap, HashMap},
    io::Read,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context as _, Result};
use c2pa::{
    create_signer,
    live_video::{Ed25519SessionKey, LiveVideoValidator, LiveVideoVsiSigner},
    status_tracker::StatusTracker,
    BoxedSigner, Reader, SigningAlg,
};

/// livesim2's testpic content uses 2 s segments numbered from the Unix epoch.
const SEGMENT_SECONDS: u64 = 2;
/// livesim2's default timeShiftBufferDepth is 60 s; keep a little more than that.
const CACHED_SEGMENTS: usize = 40;
/// How long each session key is valid for.
const SESSION_KEY_VALIDITY_SECS: u64 = 24 * 3600;

fn usage() -> ! {
    eprintln!(
        "usage:\n  livesim2-c2pa proxy  [--upstream URL] [--listen ADDR] [--asset PATH] [--reps A48,V300] [--config DIR] [--tamper-every N]\n  \
         livesim2-c2pa verify [--url BASE] [--rep V300] [--count N]\n\n\
         defaults: --upstream http://localhost:8888 --listen 127.0.0.1:9090 --asset livesim2/testpic_2s \
         --reps A48,V300 --config ./config --url http://127.0.0.1:9090/livesim2/testpic_2s --count 10"
    );
    std::process::exit(2)
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| usage());
    let mut opts = HashMap::new();
    while let Some(key) = args.next() {
        let Some(name) = key.strip_prefix("--") else {
            usage()
        };
        opts.insert(name.to_string(), args.next().unwrap_or_else(|| usage()));
    }
    let opt = |name: &str, default: &str| opts.get(name).cloned().unwrap_or(default.to_string());
    match command.as_str() {
        "proxy" => proxy(
            &opt("upstream", "http://localhost:8888"),
            &opt("listen", "127.0.0.1:9090"),
            &opt("asset", "livesim2/testpic_2s"),
            &opt("reps", "A48,V300"),
            &opt("config", "config"),
            opts.get("tamper-every")
                .map(|n| n.parse())
                .transpose()
                .context("--tamper-every")?,
        ),
        "verify" => verify(
            &opt("url", "http://127.0.0.1:9090/livesim2/testpic_2s"),
            &opt("rep", "V300"),
            opt("count", "10").parse().context("--count")?,
        ),
        _ => usage(),
    }
}

// ── proxy ──────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Track {
    init: Option<Vec<u8>>,
    segments: BTreeMap<u64, Vec<u8>>,
}

type Tracks = Arc<Mutex<HashMap<String, Track>>>;

/// `tamper_every`: for testing players, corrupt one media byte of every Nth signed segment
/// after signing it, as a man in the middle would.
fn proxy(
    upstream: &str,
    listen: &str,
    asset: &str,
    reps: &str,
    config: &str,
    tamper_every: Option<u64>,
) -> Result<()> {
    let cert = std::fs::read(format!("{config}/es256_certs.pem")).context("signing cert")?;
    let key = std::fs::read(format!("{config}/es256_private.key")).context("signing key")?;
    let upstream_asset = format!("{}/{asset}", upstream.trim_end_matches('/'));

    let tracks: Tracks = Arc::default();
    for rep in reps.split(',').map(str::trim).filter(|r| !r.is_empty()) {
        // One manifest signer and one session key per representation (track).
        let signer = create_signer::from_keys(&cert, &key, SigningAlg::Es256, None)?;
        let rep = rep.to_string();
        let base = upstream_asset.clone();
        let tracks = tracks.clone();
        tracks.lock().unwrap().insert(rep.clone(), Track::default());
        thread::spawn(move || {
            if let Err(error) = package(&base, &rep, signer, &tracks, tamper_every) {
                eprintln!("[{rep}] packager stopped: {error:#}");
            }
        });
    }

    let server = tiny_http::Server::http(listen).map_err(|e| anyhow!("listen on {listen}: {e}"))?;
    eprintln!("proxy: http://{listen}/{asset}/Manifest.mpd  (upstream {upstream_asset})");
    let server = Arc::new(server);
    for request in server.incoming_requests() {
        let tracks = tracks.clone();
        let upstream = upstream.trim_end_matches('/').to_string();
        thread::spawn(move || serve(request, &upstream, &tracks));
    }
    Ok(())
}

/// Signs `rep`'s init segment, then every new media segment in order, forever.
fn package(
    base: &str,
    rep: &str,
    signer: BoxedSigner,
    tracks: &Tracks,
    tamper_every: Option<u64>,
) -> Result<()> {
    let manifest = format!(
        r#"{{"claim_generator_info":[{{"name":"livesim2-c2pa","version":"0.1.0"}}],
            "title":"livesim2 {rep}",
            "assertions":[{{"label":"c2pa.actions","data":{{"actions":[{{"action":"c2pa.created",
            "digitalSourceType":"http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"}}]}}}}]}}"#
    );
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;

    // The session starts at the newest complete segment.
    let mut next = now_secs() / SEGMENT_SECONDS - 1;
    let mut vsi = LiveVideoVsiSigner::from_signing_key(
        manifest,
        signer.as_ref(),
        Ed25519SessionKey::from_bytes(&seed),
        format!("{rep}-session-1").into_bytes(),
        next,
        SESSION_KEY_VALIDITY_SECS,
    )?;
    let init = fetch(&format!("{base}/{rep}/init.mp4"))?;
    let signed_init = vsi.sign_init_segment(&init, "video/mp4", signer.as_ref())?;
    tracks.lock().unwrap().get_mut(rep).unwrap().init = Some(signed_init);
    eprintln!("[{rep}] init signed; session starts at segment {next}");

    loop {
        let newest = now_secs() / SEGMENT_SECONDS - 1;
        while next <= newest {
            let raw = match fetch(&format!("{base}/{rep}/{next}.m4s")) {
                Ok(raw) => raw,
                Err(error) => {
                    eprintln!("[{rep}] segment {next} not available yet: {error:#}");
                    break;
                }
            };
            let mut signed = vsi
                .sign_media_segment(&raw)
                .with_context(|| format!("signing segment {next}"))?;
            let tampered = tamper_every.is_some_and(|n| n > 0 && next.is_multiple_of(n));
            if tampered {
                // The last byte is media data in `mdat`, which the VSI hash covers.
                *signed.last_mut().expect("non-empty segment") ^= 0xff;
            }
            let mut tracks = tracks.lock().unwrap();
            let track = tracks.get_mut(rep).unwrap();
            track.segments.insert(next, signed);
            while track.segments.len() > CACHED_SEGMENTS {
                track.segments.pop_first();
            }
            drop(tracks);
            eprintln!(
                "[{rep}] signed segment {next}{}",
                if tampered { " (then tampered)" } else { "" }
            );
            next += 1;
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn serve(request: tiny_http::Request, upstream: &str, tracks: &Tracks) {
    let path = request.url().split('?').next().unwrap_or("").to_string();
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let (status, body, content_type) = if path == "/" {
        (
            200,
            PLAYER_PAGE.as_bytes().to_vec(),
            "text/html; charset=utf-8",
        )
    } else if path.ends_with(".mpd") {
        // Relative segment URLs resolve back to this proxy. Declare the VSI emsg scheme so
        // DASH clients deliver those in-band events to the application.
        match fetch(&format!("{upstream}{}", request.url())) {
            Ok(body) => (200, declare_vsi_events(&body), "application/dash+xml"),
            Err(error) => (502, error.to_string().into_bytes(), "text/plain"),
        }
    } else if let [.., rep, file] = parts.as_slice() {
        let lookup = || {
            let tracks = tracks.lock().unwrap();
            let track = tracks.get(*rep);
            if *file == "init.mp4" {
                track.and_then(|t| t.init.clone())
            } else {
                file.strip_suffix(".m4s")
                    .and_then(|n| n.parse::<u64>().ok())
                    .and_then(|n| track.and_then(|t| t.segments.get(&n).cloned()))
            }
        };
        // Players request a segment as soon as the MPD says it's available, which can be a
        // moment before the packager has signed it. Wait briefly for a just-published one.
        let just_published = file
            .strip_suffix(".m4s")
            .and_then(|n| n.parse::<u64>().ok())
            .is_some_and(|n| n + 2 >= now_secs() / SEGMENT_SECONDS);
        let mut body = lookup();
        for _ in 0..30 {
            if body.is_some() || !just_published {
                break;
            }
            thread::sleep(Duration::from_millis(50));
            body = lookup();
        }
        let content_type = if rep.starts_with('A') {
            "audio/mp4"
        } else {
            "video/mp4"
        };
        match body {
            Some(body) => (200, body, content_type),
            None => (404, b"not signed (yet)".to_vec(), "text/plain"),
        }
    } else {
        (404, b"not found".to_vec(), "text/plain")
    };
    let response = tiny_http::Response::from_data(body)
        .with_status_code(status)
        .with_header(header("Content-Type", content_type))
        .with_header(header("Access-Control-Allow-Origin", "*"));
    let _ = request.respond(response);
}

/// Adds `<InbandEventStream schemeIdUri="urn:c2pa:verifiable-segment-info" value="fseg"/>` as
/// the first child of each AdaptationSet, ahead of `Role` as the MPD schema orders them.
fn declare_vsi_events(mpd: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(mpd);
    let mut out = String::with_capacity(text.len() + 512);
    let mut rest = text.as_ref();
    while let Some(start) = rest.find("<AdaptationSet") {
        let Some(end) = rest[start..].find('>') else {
            break;
        };
        let end = start + end + 1;
        out.push_str(&rest[..end]);
        out.push_str(
            r#"<InbandEventStream schemeIdUri="urn:c2pa:verifiable-segment-info" value="fseg"></InbandEventStream>"#,
        );
        rest = &rest[end..];
    }
    out.push_str(rest);
    out.into_bytes()
}

/// A dash.js player for the proxied stream that counts the C2PA VSI events it receives.
const PLAYER_PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>livesim2 + C2PA VSI</title>
<script src="https://cdn.jsdelivr.net/npm/dashjs@4.7.4/dist/dash.all.min.js"></script>
<style>
  body { font: 15px system-ui, sans-serif; margin: 16px; background: #fff; color: #111; }
  video { width: 100%; max-width: 720px; background: #000; display: block; }
  #log { font: 13px ui-monospace, monospace; white-space: pre; max-height: 40vh; overflow: auto; }
</style>
</head>
<body>
<h1>livesim2 testpic_2s, signed with C2PA VSI</h1>
<video id="video" controls muted autoplay></video>
<p><strong id="count">0</strong> C2PA verifiable-segment-info events received</p>
<div id="log"></div>
<script>
  const SCHEME = "urn:c2pa:verifiable-segment-info";
  const player = dashjs.MediaPlayer().create();
  player.initialize(document.getElementById("video"), "/livesim2/testpic_2s/Manifest.mpd", true);
  let count = 0;
  player.on(SCHEME, (e) => {
    count += 1;
    document.getElementById("count").textContent = count;
    const bytes = e.event.messageData ? e.event.messageData.byteLength : 0;
    const line = `${new Date().toISOString()}  id=${e.event.id}  ${bytes}-byte COSE_Sign1\n`;
    const log = document.getElementById("log");
    log.textContent = line + log.textContent;
  }, null, { mode: dashjs.MediaPlayer.events.EVENT_MODE_ON_RECEIVE });
</script>
</body>
</html>
"#;

fn header(name: &str, value: &str) -> tiny_http::Header {
    tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
}

// ── verify ─────────────────────────────────────────────────────────────────────

fn verify(base: &str, rep: &str, count: u64) -> Result<()> {
    let base = base.trim_end_matches('/');
    let init = fetch(&format!("{base}/{rep}/init.mp4"))?;

    let mut validator = LiveVideoValidator::new();
    // livesim2's media time counts from the Unix epoch.
    validator.set_media_time_origin(chrono::DateTime::UNIX_EPOCH);
    let mut tracker = StatusTracker::default();
    validator.validate_init_segment(&init, &mut tracker)?;
    let reader = Reader::from_context(c2pa::Context::new())
        .with_stream("video/mp4", std::io::Cursor::new(&init))?;
    eprintln!(
        "init: {:?}, manifest {}",
        reader.validation_state(),
        reader
            .active_manifest()
            .and_then(|m| m.label())
            .unwrap_or("?")
    );
    validator.validate_session_keys_from_reader(&reader, None, &mut tracker)?;
    report_failures(&tracker, "init")?;

    // Start at the live edge, like a player, and follow the stream.
    let mut next = now_secs() / SEGMENT_SECONDS - 2;
    let mut ok = 0;
    while ok < count {
        let segment = match fetch(&format!("{base}/{rep}/{next}.m4s")) {
            Ok(segment) => segment,
            Err(_) => {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        let mut tracker = StatusTracker::default();
        validator.validate_verifiable_segment_info(&segment, &mut tracker)?;
        report_failures(&tracker, &format!("segment {next}"))?;
        eprintln!("segment {next}: valid ({} bytes)", segment.len());
        ok += 1;
        next += 1;
    }
    eprintln!("{ok} consecutive live segments of {rep} validated");
    Ok(())
}

fn report_failures(tracker: &StatusTracker, what: &str) -> Result<()> {
    let failures: Vec<String> = tracker
        .filter_errors()
        .map(|item| {
            format!(
                "{} ({})",
                item.validation_status.as_deref().unwrap_or("?"),
                item.description
            )
        })
        .collect();
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("{what} failed validation: {}", failures.join("; "))
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────

fn fetch(url: &str) -> Result<Vec<u8>> {
    let response = ureq::get(url)
        .call()
        .with_context(|| format!("GET {url}"))?;
    let mut body = Vec::new();
    response.into_reader().read_to_end(&mut body)?;
    Ok(body)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}
