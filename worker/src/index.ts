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

// --- Gemini 2.5 Pro transcription via Vertex AI ---
// Gemini handles audio transcription with natural speaker diarization
// via prompt, and accepts context hints inline.

const GCP_LOCATION = "us-central1";
const GEMINI_MODEL = "gemini-2.5-pro";

function languageHint(language: string | null): string {
  if (!language || language === "auto") return "";
  const names: Record<string, string> = {
    en: "English", he: "Hebrew", es: "Spanish", fr: "French", de: "German",
    it: "Italian", pt: "Portuguese", ru: "Russian", zh: "Mandarin", ja: "Japanese",
    ko: "Korean", ar: "Arabic", hi: "Hindi", nl: "Dutch", pl: "Polish",
    tr: "Turkish", uk: "Ukrainian", vi: "Vietnamese", th: "Thai", id: "Indonesian",
    sv: "Swedish", da: "Danish", fi: "Finnish", no: "Norwegian", el: "Greek",
    cs: "Czech", ro: "Romanian", hu: "Hungarian", yi: "Yiddish",
  };
  return names[language] || language;
}

function buildGeminiTranscriptionPrompt(
  language: string | null,
  context: string,
): string {
  let prompt = `You are a professional transcriptionist. Transcribe this audio verbatim.

Rules:
- Identify different speakers and label each turn (e.g., "Speaker 1:", "Speaker 2:").
- If speaker names are clearly established in the audio or provided in the context below, use the actual names instead of generic Speaker labels.
- Put each speaker turn on its own paragraph, separated by a blank line.
- Preserve the natural speech: keep meaningful fillers ("you know", "like") but collapse repeated stutters.
- Do NOT include timestamps.
- Do NOT include any preamble, explanation, or summary — output ONLY the transcript.`;

  const lang = languageHint(language);
  if (lang) {
    prompt += `\n\nThe audio is primarily in ${lang}.`;
  }

  if (context.trim()) {
    prompt += `\n\nContext (names, organizations, jargon, or topics that may appear — use these spellings exactly when you recognize them):\n${context.trim()}`;
  }

  return prompt;
}

interface GeminiResponse {
  candidates?: Array<{
    content?: {
      parts?: Array<{ text?: string }>;
    };
    finishReason?: string;
  }>;
  error?: { message?: string };
}

async function callGemini(
  token: string,
  projectId: string,
  audioPart: Record<string, unknown>,
  prompt: string,
): Promise<string> {
  const url = `https://${GCP_LOCATION}-aiplatform.googleapis.com/v1/projects/${projectId}/locations/${GCP_LOCATION}/publishers/google/models/${GEMINI_MODEL}:generateContent`;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      contents: [
        {
          role: "user",
          parts: [audioPart, { text: prompt }],
        },
      ],
      generationConfig: {
        temperature: 0,
        maxOutputTokens: 65536,
      },
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Gemini ${res.status}: ${err.slice(0, 1500)}`);
  }

  const data = (await res.json()) as GeminiResponse;
  if (data.error) {
    throw new Error(`Gemini: ${data.error.message || "unknown error"}`);
  }

  const transcript = data.candidates?.[0]?.content?.parts
    ?.map((p) => p.text || "")
    .join("") || "";

  if (!transcript) {
    const finish = data.candidates?.[0]?.finishReason || "no output";
    throw new Error(`Gemini produced no transcript (${finish})`);
  }

  return transcript.trim();
}

async function transcribeWithGeminiInline(
  token: string,
  projectId: string,
  audio: ArrayBuffer,
  mimeType: string,
  language: string | null,
  context: string,
): Promise<string> {
  const bytes = new Uint8Array(audio);
  let binary = "";
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  const base64 = btoa(binary);

  const audioPart = {
    inline_data: { mime_type: mimeType, data: base64 },
  };
  const prompt = buildGeminiTranscriptionPrompt(language, context);
  return callGemini(token, projectId, audioPart, prompt);
}

async function transcribeWithGeminiGcs(
  token: string,
  projectId: string,
  gcsUri: string,
  mimeType: string,
  language: string | null,
  context: string,
): Promise<string> {
  const audioPart = {
    file_data: { mime_type: mimeType, file_uri: gcsUri },
  };
  const prompt = buildGeminiTranscriptionPrompt(language, context);
  return callGemini(token, projectId, audioPart, prompt);
}

// --- Gemini Batch Prediction (async, for long files) ---
// Submits a batch job that runs entirely on Google's infrastructure.
// Returns immediately with a job name; client polls /status to check.

interface BatchJobResponse {
  name?: string;
  state?:
    | "JOB_STATE_QUEUED"
    | "JOB_STATE_PENDING"
    | "JOB_STATE_RUNNING"
    | "JOB_STATE_SUCCEEDED"
    | "JOB_STATE_FAILED"
    | "JOB_STATE_CANCELLING"
    | "JOB_STATE_CANCELLED"
    | "JOB_STATE_PAUSED"
    | "JOB_STATE_EXPIRED"
    | "JOB_STATE_UPDATING"
    | "JOB_STATE_PARTIALLY_SUCCEEDED";
  error?: { code?: number; message?: string };
  outputInfo?: {
    gcsOutputDirectory?: string;
  };
}

async function submitGeminiBatch(
  token: string,
  projectId: string,
  inputJsonlGcsUri: string,
  outputGcsPrefix: string,
): Promise<string> {
  const url = `https://${GCP_LOCATION}-aiplatform.googleapis.com/v1/projects/${projectId}/locations/${GCP_LOCATION}/batchPredictionJobs`;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      displayName: `transcript-${Date.now()}`,
      model: `publishers/google/models/${GEMINI_MODEL}`,
      inputConfig: {
        instancesFormat: "jsonl",
        gcsSource: { uris: [inputJsonlGcsUri] },
      },
      outputConfig: {
        predictionsFormat: "jsonl",
        gcsDestination: { outputUriPrefix: outputGcsPrefix },
      },
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Gemini batch submit ${res.status}: ${err.slice(0, 1500)}`);
  }

  const data = (await res.json()) as BatchJobResponse;
  if (!data.name) {
    throw new Error("Gemini batch: no job name returned");
  }
  return data.name;
}

async function checkGeminiBatch(
  token: string,
  jobName: string,
): Promise<BatchJobResponse> {
  const url = `https://${GCP_LOCATION}-aiplatform.googleapis.com/v1/${jobName}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.json();
}

async function listGcsObjects(
  token: string,
  bucket: string,
  prefix: string,
): Promise<string[]> {
  const url = `https://storage.googleapis.com/storage/v1/b/${bucket}/o?prefix=${encodeURIComponent(prefix)}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return [];
  const data = (await res.json()) as { items?: Array<{ name: string }> };
  return (data.items || []).map((i) => i.name);
}

async function readGcsObject(
  token: string,
  bucket: string,
  objectName: string,
): Promise<string> {
  const url = `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(objectName)}?alt=media`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(`GCS read ${res.status}`);
  }
  return res.text();
}

function parseBatchOutputJsonl(jsonl: string): string {
  // Each line is a JSON object with a `response` (or `predictions`) field
  // containing the Gemini response.
  let transcript = "";
  for (const line of jsonl.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed) as {
        response?: GeminiResponse;
        // Some batch outputs use 'predictions' or 'status' fields
        status?: string;
      };
      const resp = obj.response;
      if (resp?.candidates) {
        for (const cand of resp.candidates) {
          for (const part of cand.content?.parts || []) {
            if (part.text) transcript += part.text;
          }
        }
      }
    } catch {
      // Skip unparseable lines
    }
  }
  return transcript.trim();
}

// Encode a Gemini batch job into an opaque jobId for client polling.
// Includes job name + GCS object names for cleanup.
function encodeBatchJobId(
  jobName: string,
  audioObj: string,
  jsonlObj: string,
  outputPrefix: string,
): string {
  const payload = JSON.stringify({
    j: jobName,
    a: audioObj,
    i: jsonlObj,
    o: outputPrefix,
  });
  return "gcb_" + base64UrlEncode(payload);
}

function decodeBatchJobId(jobId: string): {
  j: string;
  a: string;
  i: string;
  o: string;
} | null {
  if (!jobId.startsWith("gcb_")) return null;
  try {
    const b64 = jobId.slice(4).replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

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

          // Google provider — uses Gemini 2.5 Pro via Vertex AI
          if (provider === "google") {
            if (!env.GOOGLE_SERVICE_ACCOUNT) {
              return jsonResponse(
                { error: "Google (Gemini) provider is not configured. Contact admin." },
                400,
                origin,
                env.ALLOWED_ORIGINS,
              );
            }
            const sa = parseServiceAccount(env.GOOGLE_SERVICE_ACCOUNT);
            const token = await getAccessToken(sa);

            const ext = file.name.split(".").pop()?.toLowerCase() || "bin";
            const mimeMap: Record<string, string> = {
              mp3: "audio/mpeg",
              wav: "audio/wav",
              m4a: "audio/mp4",
              mp4: "video/mp4",
              webm: "video/webm",
              ogg: "audio/ogg",
              flac: "audio/flac",
              aac: "audio/aac",
              opus: "audio/ogg",
            };
            const contentTypeHeader = mimeMap[ext] || "application/octet-stream";

            // Small files (<20MB): send inline
            if (file.size <= 19 * 1024 * 1024) {
              const transcript = await transcribeWithGeminiInline(
                token,
                sa.project_id,
                arrayBuffer,
                contentTypeHeader,
                language,
                context,
              );
              return jsonResponse(
                { transcript, language: languageHint(language) || "auto", segments: [] },
                200,
                origin,
                env.ALLOWED_ORIGINS,
              );
            }

            // Larger files: use batch prediction (async, runs on Google's side,
            // bypasses Cloudflare Worker timeout limits)
            if (!env.GOOGLE_GCS_BUCKET) {
              return jsonResponse(
                { error: "GCS bucket is not configured for large-file Gemini path. Contact admin." },
                400,
                origin,
                env.ALLOWED_ORIGINS,
              );
            }

            const uuid = crypto.randomUUID();
            const audioObj = `uploads/${uuid}.${ext}`;
            const jsonlObj = `uploads/${uuid}.input.jsonl`;
            const outputPrefix = `uploads/${uuid}-out/`;

            // 1. Upload audio
            const gcsUri = await uploadToGCS(
              token,
              env.GOOGLE_GCS_BUCKET,
              audioObj,
              arrayBuffer,
              contentTypeHeader,
            );

            // 2. Build & upload JSONL request
            const prompt = buildGeminiTranscriptionPrompt(language, context);
            const jsonlLine = JSON.stringify({
              request: {
                contents: [
                  {
                    role: "user",
                    parts: [
                      { fileData: { mimeType: contentTypeHeader, fileUri: gcsUri } },
                      { text: prompt },
                    ],
                  },
                ],
                generationConfig: {
                  temperature: 0,
                  maxOutputTokens: 65536,
                },
              },
            });
            const jsonlBytes = new TextEncoder().encode(jsonlLine + "\n");
            const jsonlBuffer = new ArrayBuffer(jsonlBytes.byteLength);
            new Uint8Array(jsonlBuffer).set(jsonlBytes);

            await uploadToGCS(
              token,
              env.GOOGLE_GCS_BUCKET,
              jsonlObj,
              jsonlBuffer,
              "application/jsonl",
            );

            // 3. Submit batch job
            try {
              const jobName = await submitGeminiBatch(
                token,
                sa.project_id,
                `gs://${env.GOOGLE_GCS_BUCKET}/${jsonlObj}`,
                `gs://${env.GOOGLE_GCS_BUCKET}/${outputPrefix}`,
              );
              const jobId = encodeBatchJobId(jobName, audioObj, jsonlObj, outputPrefix);
              return jsonResponse(
                { jobId, status: "starting" },
                202,
                origin,
                env.ALLOWED_ORIGINS,
              );
            } catch (err) {
              // Clean up uploaded files on failure
              await deleteFromGCS(token, env.GOOGLE_GCS_BUCKET, audioObj);
              await deleteFromGCS(token, env.GOOGLE_GCS_BUCKET, jsonlObj);
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

        // Gemini batch prediction job (long-file path)
        if (jobId.startsWith("gcb_")) {
          const decoded = decodeBatchJobId(jobId);
          if (
            !decoded ||
            !env.GOOGLE_SERVICE_ACCOUNT ||
            !env.GOOGLE_GCS_BUCKET
          ) {
            return jsonResponse(
              { error: "Invalid batch job ID or provider not configured" },
              400,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }

          const bucket = env.GOOGLE_GCS_BUCKET;
          const sa = parseServiceAccount(env.GOOGLE_SERVICE_ACCOUNT);
          const token = await getAccessToken(sa);
          const job = await checkGeminiBatch(token, decoded.j);

          const state = job.state;
          const finished =
            state === "JOB_STATE_SUCCEEDED" ||
            state === "JOB_STATE_FAILED" ||
            state === "JOB_STATE_CANCELLED" ||
            state === "JOB_STATE_EXPIRED" ||
            state === "JOB_STATE_PARTIALLY_SUCCEEDED";

          if (!finished) {
            return jsonResponse(
              { status: "processing", state },
              200,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }

          // Job is done — fetch output, return transcript, clean up GCS.
          const cleanup = async () => {
            // Delete audio + jsonl + all output files
            await deleteFromGCS(token, bucket, decoded.a);
            await deleteFromGCS(token, bucket, decoded.i);
            const outObjs = await listGcsObjects(
              token,
              bucket,
              decoded.o,
            );
            for (const o of outObjs) {
              await deleteFromGCS(token, bucket, o);
            }
          };

          if (
            state === "JOB_STATE_FAILED" ||
            state === "JOB_STATE_CANCELLED" ||
            state === "JOB_STATE_EXPIRED"
          ) {
            await cleanup();
            return jsonResponse(
              {
                status: "failed",
                error: job.error?.message || `Batch ${state}`,
              },
              200,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }

          // Read output JSONL from GCS (look for predictions.jsonl in the
          // output prefix directory)
          const outDir =
            job.outputInfo?.gcsOutputDirectory ||
            `gs://${bucket}/${decoded.o}`;
          const prefixInBucket = outDir.replace(`gs://${bucket}/`, "");
          const outObjs = await listGcsObjects(token, bucket, prefixInBucket);
          const predictionsObj = outObjs.find((o) => o.endsWith(".jsonl"));

          if (!predictionsObj) {
            await cleanup();
            return jsonResponse(
              { status: "failed", error: "No batch output found" },
              200,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }

          const jsonl = await readGcsObject(token, bucket, predictionsObj);
          const transcript = parseBatchOutputJsonl(jsonl);
          await cleanup();

          return jsonResponse(
            {
              status: "succeeded",
              transcript,
              language: "auto",
              segments: [],
            },
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
