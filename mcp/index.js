import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import fs from "fs";
import path from "path";

// Configuration — set your Worker URL and password here or via environment variables
const API_URL =
  process.env.TRANSCRIPTOR_API_URL ||
  "https://transcriptor-api.dovid-b43.workers.dev";
const API_PASSWORD =
  process.env.TRANSCRIPTOR_PASSWORD || "transcribe2026";

const server = new Server(
  { name: "transcriptor", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "transcribe",
      description:
        "Transcribe an audio or video file to text using Whisper AI. Supports mp3, wav, m4a, mp4, webm, ogg, flac, and more. Auto-detects language.",
      inputSchema: {
        type: "object",
        properties: {
          file_path: {
            type: "string",
            description: "Absolute path to the audio or video file to transcribe",
          },
          language: {
            type: "string",
            description:
              'Language code (e.g., "en", "he", "es"). Omit or use "auto" for auto-detection.',
            default: "auto",
          },
        },
        required: ["file_path"],
      },
    },
    {
      name: "transcribe_batch",
      description:
        "Transcribe multiple audio/video files to text. Returns all transcripts.",
      inputSchema: {
        type: "object",
        properties: {
          file_paths: {
            type: "array",
            items: { type: "string" },
            description: "Array of absolute paths to audio/video files",
          },
          language: {
            type: "string",
            description: 'Language code or "auto" for auto-detection.',
            default: "auto",
          },
        },
        required: ["file_paths"],
      },
    },
    {
      name: "transcribe_url",
      description:
        "Transcribe audio/video from a URL (e.g., a direct link to an mp3 or video file).",
      inputSchema: {
        type: "object",
        properties: {
          url: {
            type: "string",
            description: "Direct URL to an audio or video file",
          },
          language: {
            type: "string",
            description: 'Language code or "auto" for auto-detection.',
            default: "auto",
          },
        },
        required: ["url"],
      },
    },
  ],
}));

async function transcribeFile(filePath, language = "auto") {
  const absolutePath = path.resolve(filePath);

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`File not found: ${absolutePath}`);
  }

  const fileBuffer = fs.readFileSync(absolutePath);
  const fileName = path.basename(absolutePath);

  // Build multipart form data manually for fetch
  const boundary = "----FormBoundary" + Math.random().toString(36).slice(2);
  const ext = path.extname(fileName).toLowerCase().slice(1);
  const mimeMap = {
    mp3: "audio/mpeg",
    wav: "audio/wav",
    m4a: "audio/mp4",
    mp4: "video/mp4",
    webm: "video/webm",
    ogg: "audio/ogg",
    flac: "audio/flac",
    aac: "audio/aac",
    opus: "audio/opus",
    avi: "video/x-msvideo",
    mkv: "video/x-matroska",
    mov: "video/quicktime",
  };
  const mime = mimeMap[ext] || "application/octet-stream";

  const parts = [];

  // File part
  parts.push(
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: ${mime}\r\n\r\n`,
  );
  parts.push(fileBuffer);
  parts.push("\r\n");

  // Language part
  parts.push(
    `--${boundary}\r\nContent-Disposition: form-data; name="language"\r\n\r\n${language}\r\n`,
  );

  parts.push(`--${boundary}--\r\n`);

  // Combine into a single buffer
  const bodyParts = parts.map((p) =>
    typeof p === "string" ? Buffer.from(p) : p,
  );
  const body = Buffer.concat(bodyParts);

  const response = await fetch(`${API_URL}/transcribe`, {
    method: "POST",
    headers: {
      "Content-Type": `multipart/form-data; boundary=${boundary}`,
      "X-API-Password": API_PASSWORD,
    },
    body,
  });

  const data = await response.json();

  if (data.error) {
    throw new Error(data.error);
  }

  // If we got a jobId, poll for the result
  if (data.jobId) {
    return await pollForResult(data.jobId);
  }

  return data;
}

async function transcribeUrl(url, language = "auto") {
  const response = await fetch(`${API_URL}/transcribe`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Password": API_PASSWORD },
    body: JSON.stringify({ url, language }),
  });

  const data = await response.json();

  if (data.error) {
    throw new Error(data.error);
  }

  if (data.jobId) {
    return await pollForResult(data.jobId);
  }

  return data;
}

async function pollForResult(jobId) {
  for (let i = 0; i < 120; i++) {
    await new Promise((r) => setTimeout(r, 5000));

    const response = await fetch(`${API_URL}/status/${jobId}`);
    const data = await response.json();

    if (data.status === "succeeded") {
      return data;
    }
    if (data.status === "failed") {
      throw new Error(data.error || "Transcription failed");
    }
  }
  throw new Error("Transcription timed out");
}

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    if (name === "transcribe") {
      const result = await transcribeFile(args.file_path, args.language);
      return {
        content: [
          {
            type: "text",
            text: `Language: ${result.language || "unknown"}\n\n${result.transcript}`,
          },
        ],
      };
    }

    if (name === "transcribe_batch") {
      const results = [];
      for (const filePath of args.file_paths) {
        try {
          const result = await transcribeFile(filePath, args.language);
          results.push(
            `=== ${path.basename(filePath)} (${result.language || "unknown"}) ===\n${result.transcript}`,
          );
        } catch (err) {
          results.push(
            `=== ${path.basename(filePath)} ===\nERROR: ${err.message}`,
          );
        }
      }
      return {
        content: [{ type: "text", text: results.join("\n\n\n") }],
      };
    }

    if (name === "transcribe_url") {
      const result = await transcribeUrl(args.url, args.language);
      return {
        content: [
          {
            type: "text",
            text: `Language: ${result.language || "unknown"}\n\n${result.transcript}`,
          },
        ],
      };
    }

    return {
      content: [{ type: "text", text: `Unknown tool: ${name}` }],
      isError: true,
    };
  } catch (err) {
    return {
      content: [{ type: "text", text: `Error: ${err.message}` }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
