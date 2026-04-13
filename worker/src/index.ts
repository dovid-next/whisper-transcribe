interface Env {
  REPLICATE_API_TOKEN: string;
  ALLOWED_ORIGINS: string;
  API_PASSWORD: string;
  ADMIN_SECRET: string;
  PIN_SECURITY: KVNamespace;
}

interface ReplicatePrediction {
  id: string;
  status: "starting" | "processing" | "succeeded" | "failed" | "canceled";
  output?: {
    transcription: string;
    detected_language: string;
    segments: Array<{
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

const WHISPER_MODEL_VERSION =
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

async function createPrediction(
  fileData: ArrayBuffer,
  fileName: string,
  language: string | null,
  token: string,
): Promise<ReplicatePrediction> {
  // Convert in chunks to avoid call stack overflow on large files
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
  const dataUri = `data:${mime};base64,${base64}`;

  const input: Record<string, unknown> = {
    audio: dataUri,
    model: "large-v3",
    transcription: "plain text",
    translate: false,
    temperature: 0,
  };

  if (language && language !== "auto") {
    input.language = language;
  }

  const response = await fetch("https://api.replicate.com/v1/predictions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Prefer: "wait",
    },
    body: JSON.stringify({ version: WHISPER_MODEL_VERSION, input }),
  });

  if (!response.ok) {
    throw new Error("Transcription service error");
  }

  return response.json();
}

async function createPredictionFromUrl(
  audioUrl: string,
  language: string | null,
  token: string,
): Promise<ReplicatePrediction> {
  const input: Record<string, unknown> = {
    audio: audioUrl,
    model: "large-v3",
    transcription: "plain text",
    translate: false,
    temperature: 0,
  };

  if (language && language !== "auto") {
    input.language = language;
  }

  const response = await fetch("https://api.replicate.com/v1/predictions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Prefer: "wait",
    },
    body: JSON.stringify({ version: WHISPER_MODEL_VERSION, input }),
  });

  if (!response.ok) {
    throw new Error("Transcription service error");
  }

  return response.json();
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
        let prediction: ReplicatePrediction;

        if (contentType.includes("multipart/form-data")) {
          const formData = await request.formData();
          const file = formData.get("file") as File | null;
          const language = (formData.get("language") as string) || null;

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
          prediction = await createPrediction(
            arrayBuffer,
            file.name,
            language,
            env.REPLICATE_API_TOKEN,
          );
        } else if (contentType.includes("application/json")) {
          const body = (await request.json()) as {
            url?: string;
            language?: string;
          };
          if (!body.url) {
            return jsonResponse(
              { error: "No url provided" },
              400,
              origin,
              env.ALLOWED_ORIGINS,
            );
          }
          prediction = await createPredictionFromUrl(
            body.url,
            body.language || null,
            env.REPLICATE_API_TOKEN,
          );
        } else {
          return jsonResponse(
            { error: "Unsupported Content-Type" },
            400,
            origin,
            env.ALLOWED_ORIGINS,
          );
        }

        if (prediction.status === "succeeded" && prediction.output) {
          return jsonResponse(
            {
              transcript: prediction.output.transcription,
              language: prediction.output.detected_language,
              segments: prediction.output.segments,
            },
            200,
            origin,
            env.ALLOWED_ORIGINS,
          );
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

        if (prediction.status === "succeeded" && prediction.output) {
          return jsonResponse(
            {
              status: "succeeded",
              transcript: prediction.output.transcription,
              language: prediction.output.detected_language,
              segments: prediction.output.segments,
            },
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
      return jsonResponse(
        { error: "Internal server error" },
        500,
        origin,
        env.ALLOWED_ORIGINS,
      );
    }
  },
};
