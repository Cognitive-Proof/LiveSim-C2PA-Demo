# LiveSim C2PA Demo

A live DASH stream from [DASH-IF livesim2](https://github.com/Dash-Industry-Forum/livesim2), signed segment by segment with [C2PA](https://c2pa.org) **Verifiable Segment Info (VSI)** and verified in the browser before dash.js plays each segment.

It uses the experimental C2PA 2.5 *Live Media* support being added to [c2pa-rs](https://github.com/contentauth/c2pa-rs) in [contentauth/c2pa-rs#2862](https://github.com/contentauth/c2pa-rs/issues/2862).

```
livesim2 (:8888) ──► proxy (:9090) ──────────────► player (:8070)
 live DASH            signs init + each segment     dash.js + c2pa-rs (wasm)
                      with a C2PA session key       verifies each segment's VSI,
                                                    flags or blocks invalid ones
```

## How VSI works

- The **init segment** carries a C2PA manifest, signed with an X.509 certificate. Its `c2pa.session-keys` assertion announces short-lived Ed25519 session keys, each bound to that certificate.
- Each **media segment** carries an `emsg` box (`urn:c2pa:verifiable-segment-info`) holding a COSE_Sign1 signature, made with a session key, over:
  - the segment's `sequenceNumber`
  - a `c2pa.hash.bmff.v3` hash of the segment
  - the init manifest's ID
- A player can then verify every segment on its own, as it arrives, with no manifest per segment. It checks:
  - that the signature is valid
  - that the hash matches the segment
  - that sequence numbers always increase
  - that the session key was valid at the segment's presentation time

## What's here

| Path | What |
|---|---|
| `proxy/` | Rust signing proxy in front of livesim2, acting as a live packager. It signs each track's init segment once, then each new media segment in order with `LiveVideoVsiSigner`, and caches the last ~40. It adds an `InbandEventStream` for the VSI scheme to the MPD. `verify` mode follows the live edge and validates segments natively. |
| `player/` | Rust → WebAssembly verifier (`LiveVerifier`, using `LiveVideoValidator`) and a dash.js response interceptor that checks every segment before it reaches the SourceBuffer. `demo/index.html` plays the stream and lists each segment's verdict. Adapted from [Cognitive-Proof/dash-c2pa](https://github.com/Cognitive-Proof/dash-c2pa). |
| `docker-compose.yml` | Builds livesim2 v1.14.0 from its GitHub tag and runs it on port 8888. |

## Prerequisites

- Docker
- Rust (stable)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) and the `wasm32-unknown-unknown` target:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```
- Python 3, or any static file server

## Run it

In separate terminals, from the repo root.

1. Start livesim2 (the first run builds the image):
   ```bash
   docker compose up -d livesim2
   ```
2. Start the signing proxy:
   ```bash
   cd proxy && cargo run -q -- proxy
   ```
3. Build the wasm player and serve it:
   ```bash
   cd player && wasm-pack build --target web --release && python3 -m http.server 8070 --bind 127.0.0.1
   ```

Then open <http://127.0.0.1:8070/demo/index.html>. After a few seconds the video plays and each segment of both tracks is listed as `Valid`.

Use the **Policy** menu to switch between:
- `annotate`: report only
- `block invalid segments`: an invalid segment's body is replaced with an empty buffer, so dash.js skips it and playback continues

## See tampering get caught

Restart the proxy so it corrupts one media byte of every 5th segment *after* signing it, as a man in the middle would:

```bash
cd proxy && cargo run -q -- proxy --tamper-every 5
```

Reload the page. Exactly those segments show as `Invalid`, with `livevideo.segment.invalid: segment bmffHash verification failed`. With the `block` policy they're dropped and the stream keeps playing.

## Verify from the command line

```bash
cd proxy && cargo run -q -- verify --rep V300 --count 10
```

This follows the proxied stream from the live edge and validates each segment with `LiveVideoValidator`, using the Unix epoch as the media-time origin, since livesim2's `tfdt` counts from 1970.

`proxy/scripts/capture-and-sign.sh` is the offline version. It fetches the init segment and the latest N segments directly from livesim2, then signs and validates them with `c2patool`, built from the same c2pa-rs commit:

```bash
cargo install c2patool --git https://github.com/mrappard/c2pa-rs-text-support \
  --rev 8f16c0f78673461ba41c184e71d29a6492be571c --features unstable_live_video
head -c 32 /dev/urandom > proxy/config/session.key
proxy/scripts/capture-and-sign.sh 5 V300
```

## Status and limitations

- **Experimental.**
  - c2pa-rs is pinned to the head of the stacked PR chain [#2864](https://github.com/contentauth/c2pa-rs/pull/2864) → [#2870](https://github.com/contentauth/c2pa-rs/pull/2870) on a fork, behind the `unstable_live_video` feature, until it merges.
  - The C2PA 2.5 Live Media spec it implements is itself still being finalized.
- **Test credentials.** `proxy/config/` holds the public ES256 test certificate and key from c2pa-rs's samples. Manifests therefore validate as `Valid` (`signingCredential.untrusted`), not `Trusted`. The proxy generates a fresh random session key per track each time it starts.
- **Proxy only.** livesim2 isn't modified; signing happens in the proxy. Segments published before the proxy started are not signed and return 404.
- **Continuity resets on every init fetch.** dash.js re-fetches the init segment after a seek, quality switch or MediaSource reset, then re-requests earlier segments. The player therefore resets sequence-number continuity whenever a track's init is fetched.
- **Whole segments only.** Low-latency chunked delivery isn't supported: a segment is signed once it's complete.

## License

MIT, see [LICENSE](LICENSE). livesim2 is BSD-3-Clause and is built from its upstream repository, not vendored here. dash.js is loaded from a CDN.
