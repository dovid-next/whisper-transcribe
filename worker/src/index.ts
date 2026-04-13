interface Env {
  REPLICATE_API_TOKEN: string;
  ALLOWED_ORIGINS: string;
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

function corsHeaders(origin: string, allowedOrigins: string): HeadersInit {
  return {
    "Access-Control-Allow-Origin": allowedOrigins === "*" ? "*" : origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
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
      ...corsHeaders(origin, allowedOrigins),
    },
  });
}

async function createPrediction(
  fileData: ArrayBuffer,
  fileName: string,
  language: string | null,
  token: string,
): Promise<ReplicatePrediction> {
  // Convert file to base64 data URI for Replicate
  const base64 = btoa(
    String.fromCharCode(...new Uint8Array(fileData)),
  );
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
    const errText = await response.text();
    throw new Error(`Replicate API error (${response.status}): ${errText}`);
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
    const errText = await response.text();
    throw new Error(`Replicate API error (${response.status}): ${errText}`);
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

          // Check file size (100MB limit for base64 in Worker memory)
          if (file.size > 100 * 1024 * 1024) {
            return jsonResponse(
              {
                error:
                  "File too large. Max 100MB for direct upload. Use URL upload for larger files.",
              },
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
              { error: "No url provided in JSON body" },
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
            { error: prediction.error || "Transcription failed" },
            500,
            origin,
            env.ALLOWED_ORIGINS,
          );
        } else {
          // Still processing — return prediction ID for polling
          return jsonResponse(
            { jobId: prediction.id, status: prediction.status },
            202,
            origin,
            env.ALLOWED_ORIGINS,
          );
        }
      }

      // GET /status/:jobId — check transcription status
      if (url.pathname.startsWith("/status/") && request.method === "GET") {
        const jobId = url.pathname.split("/status/")[1];
        if (!jobId) {
          return jsonResponse(
            { error: "No job ID provided" },
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
            {
              status: "failed",
              error: prediction.error || "Transcription failed",
            },
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
        return jsonResponse(
          { status: "ok", service: "transcriptor-api" },
          200,
          origin,
          env.ALLOWED_ORIGINS,
        );
      }

      return jsonResponse(
        { error: "Not found" },
        404,
        origin,
        env.ALLOWED_ORIGINS,
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : "Internal error";
      return jsonResponse(
        { error: message },
        500,
        origin,
        env.ALLOWED_ORIGINS,
      );
    }
  },
};
