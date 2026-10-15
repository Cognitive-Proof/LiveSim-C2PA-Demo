//! Browser-side C2PA verification of live streams signed with Verifiable Segment Info (VSI).
//!
//! A VSI stream's init segment carries a C2PA manifest with a `c2pa.session-keys` assertion.
//! Each media segment carries a session-key signature over its hash in an `emsg` box, so it
//! can be checked on its own, in order, without its own manifest.

use std::io::Cursor;
use std::sync::Arc;

use c2pa::live_video::{moof_sequence_number, LiveVideoValidator};
use c2pa::status_tracker::StatusTracker;
use c2pa::{Context, Reader, ValidationState};
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::shared_context;

#[derive(Serialize)]
struct Failure {
    code: String,
    explanation: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LiveSegmentResult {
    /// `Invalid`, `Valid` or `Trusted`.
    state: String,
    /// The segment's `moof/mfhd` sequence number, if it has one.
    sequence_number: Option<u32>,
    /// The `livevideo.*` (and other) failures logged for this segment.
    failures: Vec<Failure>,
}

/// Verifies one track of a live VSI stream, segment by segment.
#[wasm_bindgen]
pub struct LiveVerifier {
    validator: LiveVideoValidator,
    context: Arc<Context>,
    init_state: ValidationState,
    manifest: String,
}

#[wasm_bindgen]
impl LiveVerifier {
    /// Reads and validates a VSI stream's init segment.
    ///
    /// `mediaTimeOriginMs` is the wall-clock time (ms since the Unix epoch) of media time 0,
    /// for DASH `MPD@availabilityStartTime + Period@start`. Session keys are checked against
    /// each segment's presentation time from it. Throws if the init segment's manifest has
    /// no valid session keys, i.e. the stream isn't VSI-signed.
    pub async fn create(
        format: String,
        init: Vec<u8>,
        #[wasm_bindgen(js_name = trustAnchors)] trust_anchors: Option<String>,
        #[wasm_bindgen(js_name = mediaTimeOriginMs)] media_time_origin_ms: Option<f64>,
    ) -> Result<LiveVerifier, JsError> {
        let to_js = |e: c2pa::Error| JsError::new(&e.to_string());
        let context =
            shared_context(trust_anchors.filter(|s| !s.trim().is_empty())).map_err(to_js)?;
        let reader = Reader::from_shared_context(&context)
            .with_stream_async(&format, Cursor::new(&init))
            .await
            .map_err(to_js)?;

        let mut validator = LiveVideoValidator::new();
        if let Some(ms) = media_time_origin_ms {
            let origin = chrono::DateTime::from_timestamp_millis(ms as i64)
                .ok_or_else(|| JsError::new("mediaTimeOriginMs is out of range"))?;
            validator.set_media_time_origin(origin);
        }
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&init, &mut tracker)
            .map_err(to_js)?;
        validator
            .validate_session_keys_from_reader(&reader, None, &mut tracker)
            .map_err(to_js)?;
        let failures = failures(&tracker);
        if !failures.is_empty() {
            let reasons: Vec<String> = failures
                .iter()
                .map(|f| format!("{}: {}", f.code, f.explanation))
                .collect();
            return Err(JsError::new(&format!(
                "not a valid VSI init segment: {}",
                reasons.join("; ")
            )));
        }

        Ok(LiveVerifier {
            validator,
            context,
            init_state: reader.validation_state(),
            manifest: reader.json(),
        })
    }

    /// Validation state of the init segment's manifest: `Valid` or `Trusted`.
    #[wasm_bindgen(getter, js_name = initState)]
    pub fn init_state(&self) -> String {
        format!("{:?}", self.init_state)
    }

    /// The init segment's manifest store JSON.
    #[wasm_bindgen(getter)]
    pub fn manifest(&self) -> String {
        self.manifest.clone()
    }

    /// Verifies the next media segment of this track.
    ///
    /// Returns `{ state, sequenceNumber, failures }`. `state` is `Invalid` if any check
    /// failed: a bad or missing VSI signature, a hash mismatch, an unknown or expired
    /// session key, or a sequence number that doesn't increase. Otherwise it's the state of
    /// the manifest that authorized the session key.
    #[wasm_bindgen(js_name = verifySegment)]
    pub fn verify_segment(&mut self, segment: Vec<u8>) -> Result<JsValue, JsError> {
        let mut tracker = StatusTracker::default();
        // Failures are logged to the tracker; an `Err` only means validation couldn't proceed.
        let _ = self
            .validator
            .validate_verifiable_segment_info_with_context(&segment, &self.context, &mut tracker);
        let failures = failures(&tracker);
        let state = if failures.is_empty() {
            let key_state = self
                .validator
                .session_key_manifest_state()
                .unwrap_or(self.init_state);
            format!("{key_state:?}")
        } else {
            "Invalid".to_string()
        };
        let result = LiveSegmentResult {
            state,
            sequence_number: moof_sequence_number(&segment),
            failures,
        };
        Ok(serde_wasm_bindgen::to_value(&result)?)
    }
}

fn failures(tracker: &StatusTracker) -> Vec<Failure> {
    tracker
        .filter_errors()
        .map(|item| Failure {
            code: item
                .validation_status
                .as_deref()
                .unwrap_or("error")
                .to_string(),
            explanation: item.description.to_string(),
        })
        .collect()
}
