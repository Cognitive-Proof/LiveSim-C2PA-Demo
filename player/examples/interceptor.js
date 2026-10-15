// dash.js response interceptor that verifies each fMP4 media segment with C2PA.
//
// Build the wasm package first:  wasm-pack build --target web --release
// Tested with dash.js 5.2.1 in demo/index.html.

import init, { LiveVerifier, verifySegment } from '../pkg/dash_c2pa_live.js';

const INIT_SEGMENT = 'InitializationSegment';
const MEDIA_SEGMENT = 'MediaSegment';

/**
 * @typedef {object} C2paResult
 * @property {string} key       `${mediaType}:${representationId}`
 * @property {string} url
 * @property {'manifest'|'vsi'} method  whole-manifest check against the init segment, or
 *   a live Verifiable Segment Info (VSI) check of the segment's own `emsg` signature
 * @property {string} [state]   `Invalid`, `Valid` or `Trusted`
 * @property {object} [manifest] manifest store JSON, including `validation_status`
 *   (for VSI, the init segment's manifest)
 * @property {number} [sequenceNumber] VSI only: the segment's `mfhd` sequence number
 * @property {{code: string, explanation: string}[]} [failures] VSI only: why it's `Invalid`
 * @property {string} [error]   verification threw (e.g. no manifest)
 * @property {boolean} blocked  the segment was withheld from the SourceBuffer
 */

/**
 * @param {dashjs.MediaPlayerClass} player
 * @param {(result: C2paResult) => void} onResult
 * @param {object} [options]
 * @param {'annotate'|'block'} [options.policy='annotate']
 *   `annotate` buffers every segment and only reports. `block` drops the bytes
 *   of segments whose state is `Invalid` (or that fail to verify), so they
 *   never reach the SourceBuffer and playback skips over them.
 * @param {string} [options.trustAnchors] PEM root certificates. Segments
 *   signed under one of them report `Trusted` instead of `Valid`.
 * @param {number} [options.mediaTimeOrigin] For live VSI streams: wall-clock time (ms since
 *   the Unix epoch) of media time 0, i.e. `MPD@availabilityStartTime + Period@start`. Session
 *   keys are checked against each segment's presentation time from it.
 */
export async function attachC2paVerifier(
    player,
    onResult,
    { policy = 'annotate', trustAnchors, mediaTimeOrigin } = {},
) {
    await init();
    const block = policy === 'block';

    // Init segment bytes per track (mediaType + representation id).
    const initSegments = new Map();
    // A LiveVerifier per track whose init segment announces VSI session keys. It requires
    // sequence numbers to increase, so each init fetch starts a fresh one: dash.js re-fetches
    // the init segment when it restarts a track (after a seek, a quality switch or a
    // MediaSource reset) and then legitimately re-requests earlier segments.
    const liveVerifiers = new Map();

    player.addResponseInterceptor(async (response) => {
        const req = response.request?.customData?.request;
        // Aborted requests also pass through interceptors, with partial data.
        const ok = response.status >= 200 && response.status <= 299;
        if (!req || !ok || !(response.data instanceof ArrayBuffer)) {
            return response;
        }

        const key = `${req.mediaType}:${req.representation?.id}`;
        const bytes = new Uint8Array(response.data);

        if (req.type === INIT_SEGMENT) {
            initSegments.set(key, bytes);
            liveVerifiers.get(key)?.free();
            liveVerifiers.delete(key);
            const format = req.mediaType === 'audio' ? 'audio/mp4' : 'video/mp4';
            try {
                liveVerifiers.set(
                    key,
                    await LiveVerifier.create(format, bytes, trustAnchors, mediaTimeOrigin),
                );
            } catch {
                // Not a VSI stream: segments are checked against the init manifest instead.
            }
            return response;
        }
        if (req.type !== MEDIA_SEGMENT) {
            return response;
        }
        const initBytes = initSegments.get(key);
        if (!initBytes) {
            return response;
        }

        const format = req.mediaType === 'audio' ? 'audio/mp4' : 'video/mp4';
        const live = liveVerifiers.get(key);
        let result;
        try {
            if (live) {
                const { state, sequenceNumber, failures } = live.verifySegment(bytes);
                result = {
                    key,
                    url: response.url,
                    method: 'vsi',
                    state,
                    sequenceNumber,
                    failures,
                    manifest: JSON.parse(live.manifest),
                };
            } else {
                const { state, manifest } = await verifySegment(format, initBytes, bytes, trustAnchors);
                result = { key, url: response.url, method: 'manifest', state, manifest: JSON.parse(manifest) };
            }
        } catch (e) {
            result = { key, url: response.url, method: live ? 'vsi' : 'manifest', error: String(e) };
        }
        result.blocked = block && (result.error !== undefined || result.state === 'Invalid');
        onResult(result);

        if (result.blocked) {
            // Keep the 2xx status and hand dash.js an empty body. A non-2xx
            // status would send it down the download-error path, which
            // blacklists the whole BaseURL and stalls the track. A zero-byte
            // append is a no-op success, so dash.js moves on to the next
            // segment and its GapController jumps the hole in the buffer.
            response.data = new ArrayBuffer(0);
        }
        return response;
    });
}
