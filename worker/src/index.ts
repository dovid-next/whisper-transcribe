interface Env {
  REPLICATE_API_TOKEN: string;
  ALLOWED_ORIGINS: string;
  API_PASSWORD: string;
  ADMIN_SECRET: string;
  GOOGLE_CLOUD_API_KEY?: string;
  GOOGLE_SERVICE_ACCOUNT?: string; // JSON string of service account key
  GOOGLE_GCS_BUCKET?: string;
  PIN_SECURITY: KVNamespace;
}

interface ServiceAccount {
  client_email: string;
  private_key: string;
  project_id: string;
}

interface ReplicatePrediction {
  id: string;
  status: "starting" | "processing" | "succeeded" | "failed" | "canceled";
  output?: {
    // incredibly-fast-whisper format
    text?: string;
    chunks?: Array<{
      timestamp: [number, number];
      text: string;
    }>;
    // standard whisper format
    transcription?: string;
    detected_language?: string;
    segments?: Array<{
      start: number;
      end: number;
      text: string;
    }>;
  };
  error?: string;
}

interface LockoutState {
  failedAttempts: number;
  locked: boolean;
  lockedAt: string;
  lastFailureIp: string;
}

// incredibly-fast-whisper: ~10x faster. Used by default.
const WHISPER_FAST_VERSION =
  "3ab86df6c8f54c11309d4d1f930ac292bad43ace52d10c80d87eb258b3c9f79c";
// openai/whisper: standard, supports initial_prompt for context hints.
const WHISPER_STANDARD_VERSION =
  "8099696689d249cf8b122d833c36ac3f75505c666a395ca40ef26f68e7d3d16e";

const MAX_ATTEMPTS = 3;
const LOCKOUT_KEY = "password_lockout";

// --- Lockout helpers ---

async function getLockoutState(env: Env): Promise<LockoutState> {
  const raw = await env.PIN_SECURITY.get(LOCKOUT_KEY);
  if (!raw) {
    return { failedAttempts: 0, locked: false, lockedAt: "", lastFailureIp: "" };
  }
  return JSON.parse(raw);
}

async function setLockoutState(env: Env, state: LockoutState): Promise<void> {
  await env.PIN_SECURITY.put(LOCKOUT_KEY, JSON.stringify(state));
}

async function recordFailure(env: Env, ip: string): Promise<LockoutState> {
  const state = await getLockoutState(env);
  const updated: LockoutState = {
    ...state,
    failedAttempts: state.failedAttempts + 1,
    lastFailureIp: ip,
  };
  if (updated.failedAttempts >= MAX_ATTEMPTS) {
    updated.locked = true;
    updated.lockedAt = new Date().toISOString();
  }
  await setLockoutState(env, updated);
  return updated;
}

async function resetFailures(env: Env): Promise<void> {
  await setLockoutState(env, {
    failedAttempts: 0,
    locked: false,
    lockedAt: "",
    lastFailureIp: "",
  });
}

// --- Constant-time comparison ---

function timingSafeEqual(a: string, b: string): boolean {
  const lenA = a.length;
  const lenB = b.length;
  const maxLen = Math.max(lenA, lenB);
  let mismatch = lenA ^ lenB;
  for (let i = 0; i < maxLen; i++) {
    const charA = i < lenA ? a.charCodeAt(i) : 0;
    const charB = i < lenB ? b.charCodeAt(i) : 0;
    mismatch |= charA ^ charB;
  }
  return mismatch === 0;
}

// --- CORS ---

function corsHeaders(origin: string, allowedOrigins: string): HeadersInit {
  if (allowedOrigins !== "*") {
    const allowed = allowedOrigins.split(",").map((s) => s.trim());
    if (!allowed.includes(origin)) {
      return {
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Password, X-Admin-Secret",
        "Access-Control-Max-Age": "86400",
      };
    }
  }
  return {
    "Access-Control-Allow-Origin": allowedOrigins === "*" ? "*" : origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-API-Password, X-Admin-Secret",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(
  data: unknown,
  status: number,
  origin: string,
  allowedOrigins: string,
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      ...corsHeaders(origin, allowedOrigins),
    },
  });
}

// --- Auth with lockout ---

async function authenticate(
  request: Request,
  env: Env,
  origin: string,
): Promise<Response | null> {
  const state = await getLockoutState(env);

  // If locked, reject immediately
  if (state.locked) {
    return jsonResponse(
      {
        error: "Access locked after too many failed attempts. Contact admin to unlock.",
        locked: true,
      },
      423,
      origin,
      env.ALLOWED_ORIGINS,
    );
  }

  const authHeader = request.headers.get("X-API-Password") || "";
  const valid = timingSafeEqual(authHeader, env.API_PASSWORD);

  if (!valid) {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const updated = await recordFailure(env, ip);
    const remaining = Math.max(0, MAX_ATTEMPTS - updated.failedAttempts);

    if (updated.locked) {
      return jsonResponse(
        {
          error: "Access locked after too many failed attempts. Contact admin to unlock.",
          locked: true,
        },
        423,
        origin,
        env.ALLOWED_ORIGINS,
      );
    }

    return jsonResponse(
      {
        error: `Invalid password. ${remaining} attempt(s) remaining.`,
        remainingAttempts: remaining,
      },
      401,
      origin,
      env.ALLOWED_ORIGINS,
    );
  }

  // Successful auth — reset failures if any existed
  if (state.failedAttempts > 0) {
    await resetFailures(env);
  }

  return null; // null = authenticated OK
}

// --- Replicate helpers ---

async function fetchWithRetry(
  url: string,
  init: RequestInit,
  maxRetries = 5,
): Promise<Response> {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const response = await fetch(url, init);
    if (response.status === 429 && attempt < maxRetries) {
      // Parse retry_after or default to 10 seconds
      const body = await response.text();
      let waitSec = 10;
      try {
        const parsed = JSON.parse(body);
        if (parsed.retry_after) waitSec = parsed.retry_after;
      } catch { /* use default */ }
      await new Promise((r) => setTimeout(r, waitSec * 1000));
      continue;
    }
    return response;
  }
  throw new Error("Rate limited: too many retries");
}

function fileToDataUri(fileData: ArrayBuffer, fileName: string): string {
  const bytes = new Uint8Array(fileData);
  let binary = "";
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  const base64 = btoa(binary);
  const ext = fileName.split(".").pop()?.toLowerCase() || "mp3";
  const mimeMap: Record<string, string> = {
    mp3: "audio/mpeg",
    wav: "audio/wav",
    m4a: "audio/mp4",
    mp4: "video/mp4",
    webm: "video/webm",
    ogg: "audio/ogg",
    flac: "audio/flac",
    aac: "audio/aac",
    wma: "audio/x-ms-wma",
    opus: "audio/opus",
    avi: "video/x-msvideo",
    mkv: "video/x-matroska",
    mov: "video/quicktime",
  };
  const mime = mimeMap[ext] || "audio/mpeg";
  return `data:${mime};base64,${base64}`;
}

async function createPrediction(
  fileData: ArrayBuffer,
  fileName: string,
  language: string | null,
  token: string,
  context: string = "",
): Promise<ReplicatePrediction> {
  const dataUri = fileToDataUri(fileData, fileName);
  const hasContext = context.trim().length > 0;

  // If context is provided, use the standard whisper model (supports initial_prompt).
  // Otherwise, use the incredibly-fast-whisper model (~10x faster).
  const version = hasContext ? WHISPER_STANDARD_VERSION : WHISPER_FAST_VERSION;

  let input: Record<string, unknown>;
  if (hasContext) {
    input = {
      audio: dataUri,
      model: "large-v3",
      transcription: "plain text",
      translate: false,
      temperature: 0,
      initial_prompt: context.trim().slice(0, 500),
    };
  } else {
    input = {
      audio: dataUri,
      task: "transcribe",
      batch_size: 24,
    };
  }

  if (language && language !== "auto") {
    input.language = language;
  }

  const response = await fetchWithRetry("https://api.replicate.com/v1/predictions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Prefer: "wait",
    },
    body: JSON.stringify({ version, input }),
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`Replicate ${response.status}: ${errBody.slice(0, 300)}`);
  }

  return response.json();
}

async function createPredictionFromUrl(
  audioUrl: string,
  language: string | null,
  token: string,
  context: string = "",
): Promise<ReplicatePrediction> {
  const hasContext = context.trim().length > 0;
  const version = hasContext ? WHISPER_STANDARD_VERSION : WHISPER_FAST_VERSION;

  let input: Record<string, unknown>;
  if (hasContext) {
    input = {
      audio: audioUrl,
      model: "large-v3",
      transcription: "plain text",
      translate: false,
      temperature: 0,
      initial_prompt: context.trim().slice(0, 500),
    };
  } else {
    input = {
      audio: audioUrl,
      task: "transcribe",
      batch_size: 24,
    };
  }

  if (language && language !== "auto") {
    input.language = language;
  }

  const response = await fetchWithRetry("https://api.replicate.com/v1/predictions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Prefer: "wait",
    },
    body: JSON.stringify({ version, input }),
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`Replicate ${response.status}: ${errBody.slice(0, 300)}`);
  }

  return response.json();
}

// --- Google Cloud service account auth (for GCS + long-running recognize) ---

function base64UrlEncode(data: ArrayBuffer | Uint8Array | string): string {
  let bytes: Uint8Array;
  if (typeof data === "string") {
    bytes = new TextEncoder().encode(data);
  } else if (data instanceof ArrayBuffer) {
    bytes = new Uint8Array(data);
  } else {
    bytes = data;
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function parseServiceAccount(json: string): ServiceAccount {
  const sa = JSON.parse(json);
  return {
    client_email: sa.client_email,
    private_key: sa.private_key,
    project_id: sa.project_id,
  };
}

async function createJWT(sa: ServiceAccount, scope: string): Promise<string> {
  const header = { alg: "RS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: sa.client_email,
    scope,
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };

  const encHeader = base64UrlEncode(JSON.stringify(header));
  const encPayload = base64UrlEncode(JSON.stringify(payload));
  const unsigned = `${encHeader}.${encPayload}`;

  const pemBody = sa.private_key
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");
  const keyBuffer = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));

  const key = await crypto.subtle.importKey(
    "pkcs8",
    keyBuffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned),
  );

  return `${unsigned}.${base64UrlEncode(signature)}`;
}

async function getAccessToken(sa: ServiceAccount): Promise<string> {
  const jwt = await createJWT(
    sa,
    "https://www.googleapis.com/auth/cloud-platform",
  );
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`OAuth token error: ${err.slice(0, 200)}`);
  }
  const data = (await res.json()) as { access_token: string };
  return data.access_token;
}

// --- Google Cloud Storage ---

async function uploadToGCS(
  token: string,
  bucket: string,
  objectName: string,
  data: ArrayBuffer,
  contentType: string,
): Promise<string> {
  const url = `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o?uploadType=media&name=${encodeURIComponent(objectName)}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": contentType,
    },
    body: data,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`GCS upload ${res.status}: ${err.slice(0, 200)}`);
  }
  return `gs://${bucket}/${objectName}`;
}

async function deleteFromGCS(
  token: string,
  bucket: string,
  objectName: string,
): Promise<void> {
  try {
    await fetch(
      `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(objectName)}`,
      { method: "DELETE", headers: { Authorization: `Bearer ${token}` } },
    );
  } catch {
    // Best effort — don't fail the request if cleanup fails
  }
}

// --- Google Cloud Speech-to-Text v2 with Chirp 2 ---
// v2 supports auto-detection of audio format (no encoding guesswork)
// Chirp 2 is Google's flagship universal speech model

const GCP_LOCATION = "us-central1"; // Chirp 2 supported region
const V2_API_BASE = `https://${GCP_LOCATION}-speech.googleapis.com/v2`;

function v2LanguageCodes(language: string | null): string[] {
  if (!language || language === "auto") {
    // Chirp 2 supports "auto" language detection
    return ["auto"];
  }
  const langMap: Record<string, string> = {
    en: "en-US", he: "iw-IL", es: "es-US", fr: "fr-FR", de: "de-DE",
    it: "it-IT", pt: "pt-BR", ru: "ru-RU", zh: "cmn-Hans-CN", ja: "ja-JP",
    ko: "ko-KR", ar: "ar-XA", hi: "hi-IN", nl: "nl-NL", pl: "pl-PL",
    tr: "tr-TR", uk: "uk-UA", vi: "vi-VN", th: "th-TH", id: "id-ID",
    sv: "sv-SE", da: "da-DK", fi: "fi-FI", no: "nb-NO", el: "el-GR",
    cs: "cs-CZ", ro: "ro-RO", hu: "hu-HU",
  };
  return [langMap[language] || language];
}

function buildV2Config(
  language: string | null,
  context: string,
): Record<string, unknown> {
  const config: Record<string, unknown> = {
    auto_decoding_config: {}, // Google auto-detects format from file header
    model: "chirp_2",
    language_codes: v2LanguageCodes(language),
    features: {
      enable_automatic_punctuation: true,
    },
  };

  if (context.trim()) {
    const phrases = context
      .split(/[\n,]+/)
      .map((p) => p.trim())
      .filter((p) => p.length > 0 && p.length < 100)
      .slice(0, 500);
    if (phrases.length > 0) {
      config.adaptation = {
        phrase_sets: [{
          inline_phrase_set: {
            phrases: phrases.map((p) => ({ value: p, boost: 15 })),
          },
        }],
      };
    }
  }

  return config;
}

// v2 inline sync recognize (for files <10MB)
interface V2RecognizeResponse {
  results?: Array<{
    alternatives?: Array<{
      transcript?: string;
      words?: Array<{
        word?: string;
        speakerLabel?: string;
        startOffset?: string;
        endOffset?: string;
      }>;
    }>;
    languageCode?: string;
  }>;
}

async function recognizeInlineV2(
  token: string,
  projectId: string,
  audioBytes: ArrayBuffer,
  language: string | null,
  context: string,
): Promise<V2RecognizeResponse> {
  const bytes = new Uint8Array(audioBytes);
  let binary = "";
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  const base64 = btoa(binary);

  const config = buildV2Config(language, context);
  const url = `${V2_API_BASE}/projects/${projectId}/locations/${GCP_LOCATION}/recognizers/_:recognize`;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ config, content: base64 }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Google Speech v2 ${res.status}: ${err.slice(0, 1500)}`);
  }

  return res.json();
}

// v2 batch recognize (async, for GCS-hosted files)
async function startV2BatchRecognize(
  token: string,
  projectId: string,
  gcsUri: string,
  language: string | null,
  context: string,
): Promise<string> {
  const config = buildV2Config(language, context);
  const url = `${V2_API_BASE}/projects/${projectId}/locations/${GCP_LOCATION}/recognizers/_:batchRecognize`;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      config,
      files: [{ uri: gcsUri }],
      recognition_output_config: {
        inline_response_config: {}, // Return results inline in the operation
      },
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Google Speech v2 ${res.status}: ${err.slice(0, 1500)}`);
  }

  const data = (await res.json()) as { name: string };
  return data.name;
}

interface V2Operation {
  name: string;
  done?: boolean;
  error?: { code?: number; message?: string };
  response?: {
    "@type"?: string;
    results?: Record<string, {
      transcript?: V2RecognizeResponse;
      error?: { message?: string };
    }>;
  };
}

async function checkV2Operation(
  token: string,
  operationName: string,
): Promise<V2Operation> {
  const url = `${V2_API_BASE}/${operationName}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.json();
}

function v2ResultsToTranscript(response: V2RecognizeResponse | undefined): {
  transcript: string;
  language: string;
  segments: Array<{ start: number; end: number; text: string }>;
} {
  const results = response?.results || [];

  // Build word list with speaker labels
  const allWords: Array<{
    word: string;
    speaker: string;
    start: number;
    end: number;
  }> = [];

  for (const result of results) {
    const alt = result.alternatives?.[0];
    if (alt?.words) {
      for (const w of alt.words) {
        allWords.push({
          word: w.word || "",
          speaker: w.speakerLabel || "",
          start: parseFloat((w.startOffset || "0s").replace("s", "")),
          end: parseFloat((w.endOffset || "0s").replace("s", "")),
        });
      }
    }
  }

  // Group consecutive words by speaker
  const segs: Array<{ start: number; end: number; text: string; speaker: string }> = [];
  let cur: { start: number; end: number; text: string; speaker: string } | null = null;
  for (const w of allWords) {
    if (!cur || cur.speaker !== w.speaker) {
      if (cur) segs.push(cur);
      cur = { start: w.start, end: w.end, text: w.word, speaker: w.speaker };
    } else {
      cur.text += " " + w.word;
      cur.end = w.end;
    }
  }
  if (cur) segs.push(cur);

  // Build transcript with speaker labels
  const transcript = segs.length > 0
    ? segs.map((s) => (s.speaker ? `${s.speaker}: ${s.text}` : s.text)).join("\n\n")
    : results.map((r) => r.alternatives?.[0]?.transcript || "").filter(Boolean).join(" ");

  const languageCode = results[0]?.languageCode || "unknown";

  return {
    transcript,
    language: languageCode,
    segments: segs.map((s) => ({ start: s.start, end: s.end, text: s.text })),
  };
}

// Encode a Google job into a single opaque jobId so the client can poll.
// Contains operation name + GCS object so we can clean up after polling.
function encodeGoogleJobId(operationName: string, gcsObject: string): string {
  const payload = JSON.stringify({ op: operationName, obj: gcsObject });
  return "gcp_" + base64UrlEncode(payload);
}

function decodeGoogleJobId(jobId: string): { op: string; obj: string } | null {
  if (!jobId.startsWith("gcp_")) return null;
  try {
    const b64 = jobId.slice(4).replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const json = atob(padded);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

// (Legacy v1 inline path removed — now uses v2 + chirp_2 via service account.)

function extractResult(output: ReplicatePrediction["output"]): {
  transcript: string;
  language: string;
  segments: Array<{ start: number; end: number; text: string }>;
} | null {
  if (!output) return null;
  // incredibly-fast-whisper: { text, chunks }
  if (output.text !== undefined) {
    return {
      transcript: output.text,
      language: "auto-detected",
      segments: (output.chunks || []).map((c) => ({
        start: c.timestamp[0],
        end: c.timestamp[1],
        text: c.text,
      })),
    };
  }
  // standard whisper: { transcription, detected_language, segments }
  if (output.transcription !== undefined) {
    return {
      transcript: output.transcription,
      language: output.detected_language || "unknown",
      segments: output.segments || [],
    };
  }
  return null;
}

async function getPrediction(
  id: string,
  token: string,
): Promise<ReplicatePrediction> {
  const response = await fetch(
    `https://api.replicate.com/v1/predictions/${id}`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  return response.json();
}

function isValidJobId(id: string): boolean {
  return /^[a-z0-9]{20,}$/.test(id);
}

// --- Admin unlock endpoint ---

async function handleAdminUnlock(
  request: Request,
  env: Env,
  origin: string,
): Promise<Response> {
  // Admin unlock requires a separate admin secret (not the user password)
  const adminHeader = request.headers.get("X-Admin-Secret") || "";

  if (!timingSafeEqual(adminHeader, env.ADMIN_SECRET)) {
    return jsonResponse(
      { error: "Unauthorized" },
      401,
      origin,
      env.ALLOWED_ORIGINS,
    );
  }

  await resetFailures(env);
  return jsonResponse(
    { message: "Lockout reset successfully", failedAttempts: 0, locked: false },
    200,
    origin,
    env.ALLOWED_ORIGINS,
  );
}

// --- Main handler ---

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          ...corsHeaders(origin, env.ALLOWED_ORIGINS),
          "Access-Control-Allow-Headers":
            "Content-Type, X-API-Password, X-Admin-Secret",
        },
      });
    }

    // Admin unlock endpoint (POST /admin/unlock)
    if (url.pathname === "/admin/unlock" && request.method === "POST") {
      return handleAdminUnlock(request, env, origin);
    }

    // Authenticate all POST requests and /status endpoint
    if (request.method === "POST" || url.pathname.startsWith("/status/")) {
      const authResult = await authenticate(request, env, origin);
      if (authResult) return authResult; // non-null = auth failed
    }

    try {
      // POST /transcribe
      if (url.pathname === "/transcribe" && request.method === "POST") {
        const contentType = request.headers.get("Content-Type") || "";

        if (contentType.includes("multipart/form-data")) {
          const formData = await request.formData();
          const file = formData.get("file") as File | null;
          const language = (formData.get("language") as string) || null;
          const provider = (formData.get("provider") as string) || "replicate";
          const context = (formData.get("context") as string) || "";

          if (!file) {
            return jsonResponse(
              { error: "No file provided" },
              400,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }

          if (file.size > 100 * 1024 * 1024) {
            return jsonResponse(
              { error: "File too large. Max 100MB." },
              413,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }

          const arrayBuffer = await file.arrayBuffer();

          // Google Cloud provider (v2 + chirp_2, service account auth)
          if (provider === "google") {
            if (!env.GOOGLE_SERVICE_ACCOUNT) {
              return jsonResponse(
                { error: "Google Cloud provider is not configured. Contact admin." },
                400,
                origin,
                env.ALLOWED_ORIGINS,
              );
            }
            const sa = parseServiceAccount(env.GOOGLE_SERVICE_ACCOUNT);
            const token = await getAccessToken(sa);

            // Path A: small files — inline sync recognize
            if (file.size <= 10 * 1024 * 1024) {
              const resp = await recognizeInlineV2(
                token,
                sa.project_id,
                arrayBuffer,
                language,
                context,
              );
              return jsonResponse(
                v2ResultsToTranscript(resp),
                200,
                origin,
                env.ALLOWED_ORIGINS,
              );
            }

            // Path B: larger files — upload to GCS, batchRecognize, poll
            if (!env.GOOGLE_GCS_BUCKET) {
              return jsonResponse(
                { error: "Google Cloud large-file path is not configured. Contact admin." },
                400,
                origin,
                env.ALLOWED_ORIGINS,
              );
            }

            // Random object name so uploads don't collide
            const ext = file.name.split(".").pop()?.toLowerCase() || "bin";
            const uuid = crypto.randomUUID();
            const objectName = `uploads/${uuid}.${ext}`;

            const mimeMap: Record<string, string> = {
              mp3: "audio/mpeg",
              wav: "audio/wav",
              m4a: "audio/mp4",
              mp4: "video/mp4",
              webm: "video/webm",
              ogg: "audio/ogg",
              flac: "audio/flac",
              aac: "audio/aac",
              opus: "audio/opus",
            };
            const contentTypeHeader = mimeMap[ext] || "application/octet-stream";

            const gcsUri = await uploadToGCS(
              token,
              env.GOOGLE_GCS_BUCKET,
              objectName,
              arrayBuffer,
              contentTypeHeader,
            );

            try {
              const operationName = await startV2BatchRecognize(
                token,
                sa.project_id,
                gcsUri,
                language,
                context,
              );
              const jobId = encodeGoogleJobId(operationName, objectName);
              return jsonResponse(
                { jobId, status: "starting" },
                202,
                origin,
                env.ALLOWED_ORIGINS,
              );
            } catch (err) {
              // Clean up GCS on failure to start
              await deleteFromGCS(token, env.GOOGLE_GCS_BUCKET, objectName);
              throw err;
            }
          }

          // Replicate provider (default)
          const prediction = await createPrediction(
            arrayBuffer,
            file.name,
            language,
            env.REPLICATE_API_TOKEN,
            context,
          );

          const result = extractResult(prediction.output);
          if (prediction.status === "succeeded" && result) {
            return jsonResponse(result, 200, origin, env.ALLOWED_ORIGINS);
          } else if (prediction.status === "failed") {
            return jsonResponse(
              { error: "Transcription failed" },
              500,
              origin,
              env.ALLOWED_ORIGINS,
            );
          } else {
            return jsonResponse(
              { jobId: prediction.id, status: prediction.status },
              202,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }
        } else if (contentType.includes("application/json")) {
          const body = (await request.json()) as {
            url?: string;
            language?: string;
            context?: string;
          };
          if (!body.url) {
            return jsonResponse(
              { error: "No url provided" },
              400,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }
          const prediction = await createPredictionFromUrl(
            body.url,
            body.language || null,
            env.REPLICATE_API_TOKEN,
            body.context || "",
          );

          const result = extractResult(prediction.output);
          if (prediction.status === "succeeded" && result) {
            return jsonResponse(result, 200, origin, env.ALLOWED_ORIGINS);
          } else if (prediction.status === "failed") {
            return jsonResponse(
              { error: "Transcription failed" },
              500,
              origin,
              env.ALLOWED_ORIGINS,
            );
          } else {
            return jsonResponse(
              { jobId: prediction.id, status: prediction.status },
              202,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }
        } else {
          return jsonResponse(
            { error: "Unsupported Content-Type" },
            400,
            origin,
            env.ALLOWED_ORIGINS,
          );
        }
      }

      // GET /status/:jobId
      if (url.pathname.startsWith("/status/") && request.method === "GET") {
        const jobId = url.pathname.split("/status/")[1];
        if (!jobId) {
          return jsonResponse(
            { error: "Invalid job ID" },
            400,
            origin,
            env.ALLOWED_ORIGINS,
          );
        }

        // Google Cloud long-running operation
        if (jobId.startsWith("gcp_")) {
          const decoded = decodeGoogleJobId(jobId);
          if (!decoded || !env.GOOGLE_SERVICE_ACCOUNT || !env.GOOGLE_GCS_BUCKET) {
            return jsonResponse(
              { error: "Invalid Google job ID or provider not configured" },
              400,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }

          const sa = parseServiceAccount(env.GOOGLE_SERVICE_ACCOUNT);
          const token = await getAccessToken(sa);
          const op = await checkV2Operation(token, decoded.op);

          if (op.done) {
            // Clean up GCS (best effort — always try to delete)
            await deleteFromGCS(token, env.GOOGLE_GCS_BUCKET, decoded.obj);

            if (op.error) {
              return jsonResponse(
                { status: "failed", error: op.error.message || "Transcription failed" },
                200,
                origin,
                env.ALLOWED_ORIGINS,
              );
            }
            // v2 batchRecognize returns results keyed by GCS URI
            const results = op.response?.results || {};
            const firstKey = Object.keys(results)[0];
            const fileResult = firstKey ? results[firstKey] : undefined;
            if (fileResult?.error) {
              return jsonResponse(
                { status: "failed", error: fileResult.error.message || "Transcription failed" },
                200,
                origin,
                env.ALLOWED_ORIGINS,
              );
            }
            const gResult = v2ResultsToTranscript(fileResult?.transcript);
            return jsonResponse(
              { status: "succeeded", ...gResult },
              200,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }

          return jsonResponse(
            { status: "processing" },
            200,
            origin,
            env.ALLOWED_ORIGINS,
          );
        }

        // Replicate prediction
        if (!isValidJobId(jobId)) {
          return jsonResponse(
            { error: "Invalid job ID" },
            400,
            origin,
            env.ALLOWED_ORIGINS,
          );
        }

        const prediction = await getPrediction(jobId, env.REPLICATE_API_TOKEN);
        const result = extractResult(prediction.output);

        if (prediction.status === "succeeded" && result) {
          return jsonResponse(
            { status: "succeeded", ...result },
            200,
            origin,
            env.ALLOWED_ORIGINS,
          );
        } else if (prediction.status === "failed") {
          return jsonResponse(
            { status: "failed", error: "Transcription failed" },
            200,
            origin,
            env.ALLOWED_ORIGINS,
          );
        } else {
          return jsonResponse(
            { status: prediction.status },
            200,
            origin,
            env.ALLOWED_ORIGINS,
          );
        }
      }

      // Health check
      if (url.pathname === "/" && request.method === "GET") {
        return jsonResponse({ status: "ok" }, 200, origin, env.ALLOWED_ORIGINS);
      }

      return jsonResponse(
        { error: "Not found" },
        404,
        origin,
        env.ALLOWED_ORIGINS,
      );
    } catch (err) {
      const debug = err instanceof Error ? err.message : String(err);
      return jsonResponse(
        { error: "Internal server error", debug },
        500,
        origin,
        env.ALLOWED_ORIGINS,
      );
    }
  },
};
