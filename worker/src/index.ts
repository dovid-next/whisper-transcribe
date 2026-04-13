interface Env {
  REPLICATE_API_TOKEN: string;
  ALLOWED_ORIGINS: string;
  API_PASSWORD: string;
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

const WHISPER_MODEL_VERSION =
  "8099696689d249cf8b122d833c36ac3f75505c666a395ca40ef26f68e7d3d16e";

// Constant-time string comparison to prevent timing attacks
function timingSafeEqual(a: string, b: string): boolean {
  const lenA = a.length;
  const lenB = b.length;
  // Always iterate over the longer string to avoid leaking length
  const maxLen = Math.max(lenA, lenB);
  let mismatch = lenA ^ lenB; // nonzero if lengths differ
  for (let i = 0; i < maxLen; i++) {
    const charA = i < lenA ? a.charCodeAt(i) : 0;
    const charB = i < lenB ? b.charCodeAt(i) : 0;
    mismatch |= charA ^ charB;
  }
  return mismatch === 0;
}

function corsHeaders(origin: string, allowedOrigins: string): HeadersInit {
  // If allowedOrigins is a specific domain, only allow that origin
  if (allowedOrigins !== "*") {
    const allowed = allowedOrigins.split(",").map((s) => s.trim());
    if (!allowed.includes(origin)) {
      return {
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Password",
        "Access-Control-Max-Age": "86400",
      };
    }
  }
  return {
    "Access-Control-Allow-Origin": allowedOrigins === "*" ? "*" : origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-API-Password",
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

function authenticate(request: Request, env: Env): boolean {
  const authHeader = request.headers.get("X-API-Password") || "";
  return timingSafeEqual(authHeader, env.API_PASSWORD);
}

async function createPrediction(
  fileData: ArrayBuffer,
  fileName: string,
  language: string | null,
  token: string,
): Promise<ReplicatePrediction> {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(fileData)));
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
    body: JSON.stringify({
      version: WHISPER_MODEL_VERSION,
      input,
    }),
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
    body: JSON.stringify({
      version: WHISPER_MODEL_VERSION,
      input,
    }),
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
    {
      headers: { Authorization: `Bearer ${token}` },
    },
  );
  return response.json();
}

// Validate job ID format (Replicate uses UUIDs)
function isValidJobId(id: string): boolean {
  return /^[a-z0-9]{20,}$/.test(id);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders(origin, env.ALLOWED_ORIGINS),
      });
    }

    // Authenticate all POST requests and /status endpoint
    if (
      request.method === "POST" ||
      url.pathname.startsWith("/status/")
    ) {
      if (!authenticate(request, env)) {
        return jsonResponse(
          { error: "Unauthorized" },
          401,
          origin,
          env.ALLOWED_ORIGINS,
        );
      }
    }

    try {
      // POST /transcribe — single file transcription
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

      // GET /status/:jobId — check transcription status (authenticated above)
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

        const prediction = await getPrediction(
          jobId,
          env.REPLICATE_API_TOKEN,
        );

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

      // Health check — no auth needed, no service info leaked
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
