//! Browser-side C2PA verification of fragmented MP4 segments.
//!
//! The C2PA manifest lives in the init segment; each media segment is
//! validated against it with [`c2pa::Reader::with_fragment_async`].

use std::cell::RefCell;
use std::io::Cursor;
use std::sync::Arc;

use c2pa::settings::{Settings, TrustAnchor};
use c2pa::{Context, Reader};
use serde::Serialize;
use wasm_bindgen::prelude::*;

mod live;
pub use live::LiveVerifier;

#[derive(Serialize)]
struct SegmentResult {
    /// `Invalid`, `Valid` or `Trusted`.
    state: String,
    /// Full manifest store JSON, including `validation_status`.
    manifest: String,
}

thread_local! {
    /// Context for the last trust-anchor PEM seen, so the PEM is parsed once
    /// per stream rather than once per segment.
    static CONTEXT: RefCell<Option<(Option<String>, Arc<Context>)>> = const { RefCell::new(None) };
}

/// Build a [`Context`] whose trust list is `trust_anchors` (PEM certificates).
///
/// With `None`, no trust list is configured: a well-formed signature yields
/// `Valid` with `signingCredential.untrusted`, never `Trusted`.
pub fn context(trust_anchors: Option<&str>) -> c2pa::Result<Context> {
    let mut settings = Settings::default();
    if let Some(pem) = trust_anchors {
        settings.trust.anchors = Some(vec![TrustAnchor {
            trust_anchors: pem.to_owned(),
            ..TrustAnchor::default()
        }]);
    }
    Context::new().with_settings(settings)
}

pub(crate) fn shared_context(trust_anchors: Option<String>) -> c2pa::Result<Arc<Context>> {
    CONTEXT.with_borrow_mut(|cached| {
        if let Some((pem, ctx)) = cached {
            if *pem == trust_anchors {
                return Ok(ctx.clone());
            }
        }
        let ctx = context(trust_anchors.as_deref())?.into_shared();
        *cached = Some((trust_anchors, ctx.clone()));
        Ok(ctx)
    })
}

/// Validate one media segment against its init segment.
///
/// `format` is the MIME type, e.g. `video/mp4`. `trustAnchors` is an optional
/// PEM bundle of root certificates; a segment signed under one of them reports
/// `Trusted` instead of `Valid`.
#[wasm_bindgen(js_name = verifySegment)]
pub async fn verify_segment(
    format: String,
    init: Vec<u8>,
    segment: Vec<u8>,
    #[wasm_bindgen(js_name = trustAnchors)] trust_anchors: Option<String>,
) -> Result<JsValue, JsError> {
    let to_js = |e: c2pa::Error| JsError::new(&e.to_string());
    let ctx = shared_context(trust_anchors.filter(|s| !s.trim().is_empty())).map_err(to_js)?;
    let reader = Reader::from_shared_context(&ctx)
        .with_fragment_async(&format, Cursor::new(init), Cursor::new(segment))
        .await
        .map_err(to_js)?;

    let result = SegmentResult {
        state: format!("{:?}", reader.validation_state()),
        manifest: reader.json(),
    };
    Ok(serde_wasm_bindgen::to_value(&result)?)
}
