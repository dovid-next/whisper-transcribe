interface Env {
  REPLICATE_API_TOKEN: string;
  ALLOWED_ORIGINS: string;
  API_PASSWORD: string;
  ADMIN_SECRET: string;
  GOOGLE_CLOUD_API_KEY?: string;
  PIN_SECURITY: KVNamespace;
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

// --- Google Cloud Speech-to-Text ---

interface GoogleSpeechResponse {
  results?: Array<{
    alternatives?: Array<{
      transcript?: string;
      words?: Array<{
        word: string;
        speakerTag?: number;
        startTime?: string;
        endTime?: string;
      }>;
    }>;
    languageCode?: string;
  }>;
  error?: { message?: string };
}

async function transcribeWithGoogle(
  fileData: ArrayBuffer,
  fileName: string,
  language: string | null,
  apiKey: string,
  context: string = "",
): Promise<{ transcript: string; language: string; segments: Array<{ start: number; end: number; text: string }> }> {
  const bytes = new Uint8Array(fileData);
  let binary = "";
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  const base64 = btoa(binary);

  const ext = fileName.split(".").pop()?.toLowerCase() || "mp3";
  const encodingMap: Record<string, string> = {
    mp3: "MP3",
    wav: "LINEAR16",
    flac: "FLAC",
    opus: "OGG_OPUS",
    ogg: "OGG_OPUS",
    webm: "WEBM_OPUS",
  };
  const encoding = encodingMap[ext] || "ENCODING_UNSPECIFIED";

  // Google expects BCP-47 (e.g., "en-US"). Map some common codes.
  const langMap: Record<string, string> = {
    en: "en-US", he: "iw-IL", es: "es-ES", fr: "fr-FR", de: "de-DE",
    it: "it-IT", pt: "pt-BR", ru: "ru-RU", zh: "zh-CN", ja: "ja-JP",
    ko: "ko-KR", ar: "ar-SA", hi: "hi-IN", nl: "nl-NL", pl: "pl-PL",
    tr: "tr-TR", uk: "uk-UA", vi: "vi-VN", th: "th-TH", id: "id-ID",
    sv: "sv-SE", da: "da-DK", fi: "fi-FI", no: "no-NO", el: "el-GR",
    cs: "cs-CZ", ro: "ro-RO", hu: "hu-HU",
  };
  const languageCode = language && language !== "auto" ? (langMap[language] || language) : "en-US";

  const config: Record<string, unknown> = {
    encoding,
    languageCode,
    enableAutomaticPunctuation: true,
    enableWordTimeOffsets: true,
    model: "latest_long",
    diarizationConfig: {
      enableSpeakerDiarization: true,
      minSpeakerCount: 2,
      maxSpeakerCount: 6,
    },
  };

  // Phrases bias for context
  if (context.trim()) {
    // Split context into phrases by newlines or commas
    const phrases = context
      .split(/[\n,]+/)
      .map((p) => p.trim())
      .filter((p) => p.length > 0 && p.length < 100)
      .slice(0, 500);
    if (phrases.length > 0) {
      config.speechContexts = [{ phrases, boost: 15 }];
    }
  }

  const response = await fetch(
    `https://speech.googleapis.com/v1/speech:recognize?key=${apiKey}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        config,
        audio: { content: base64 },
      }),
    },
  );

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`Google Cloud ${response.status}: ${errBody.slice(0, 300)}`);
  }

  const data = (await response.json()) as GoogleSpeechResponse;
  if (data.error) {
    throw new Error(`Google Cloud: ${data.error.message || "unknown error"}`);
  }

  // Build transcript with speaker labels from words
  const results = data.results || [];
  const allWords: Array<{ word: string; speaker: number; start: number; end: number }> = [];
  for (const result of results) {
    const alt = result.alternatives?.[0];
    if (alt?.words) {
      for (const w of alt.words) {
        allWords.push({
          word: w.word,
          speaker: w.speakerTag || 0,
          start: parseFloat((w.startTime || "0s").replace("s", "")),
          end: parseFloat((w.endTime || "0s").replace("s", "")),
        });
      }
    }
  }

  // Group into segments by speaker
  const segments: Array<{ start: number; end: number; text: string; speaker: number }> = [];
  let current: { start: number; end: number; text: string; speaker: number } | null = null;
  for (const w of allWords) {
    if (!current || current.speaker !== w.speaker) {
      if (current) segments.push(current);
      current = { start: w.start, end: w.end, text: w.word, speaker: w.speaker };
    } else {
      current.text += " " + w.word;
      current.end = w.end;
    }
  }
  if (current) segments.push(current);

  // Build final transcript with speaker labels
  const transcript = segments
    .map((s) => (s.speaker > 0 ? `Speaker ${s.speaker}: ${s.text}` : s.text))
    .join("\n\n");

  // Fallback: if no diarization, use simple concat
  const fallbackTranscript =
    results
      .map((r) => r.alternatives?.[0]?.transcript || "")
      .filter((s) => s)
      .join(" ");

  return {
    transcript: transcript || fallbackTranscript,
    language: results[0]?.languageCode || languageCode,
    segments: segments.map((s) => ({ start: s.start, end: s.end, text: s.text })),
  };
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

          // Google Cloud provider
          if (provider === "google") {
            if (!env.GOOGLE_CLOUD_API_KEY) {
              return jsonResponse(
                { error: "Google Cloud provider is not configured. Contact admin." },
                400,
                origin,
                env.ALLOWED_ORIGINS,
              );
            }
            if (file.size > 10 * 1024 * 1024) {
              return jsonResponse(
                { error: "Google Cloud provider only supports files <10MB (~1 min audio). Use Replicate for longer files." },
                413,
                origin,
                env.ALLOWED_ORIGINS,
              );
            }
            const gResult = await transcribeWithGoogle(
              arrayBuffer,
              file.name,
              language,
              env.GOOGLE_CLOUD_API_KEY,
              context,
            );
            return jsonResponse(gResult, 200, origin, env.ALLOWED_ORIGINS);
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
        if (!jobId || !isValidJobId(jobId)) {
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
    } catch (_err) {
      return jsonResponse(
        { error: "Internal server error" },
        500,
        origin,
        env.ALLOWED_ORIGINS,
      );
    }
  },
};
