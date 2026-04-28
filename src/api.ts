const API_BASE = import.meta.env.VITE_API_URL || "https://transcriptor-api.dovid-b43.workers.dev";

export interface TranscriptResult {
  transcript: string;
  language: string;
  segments?: Array<{ start: number; end: number; text: string }>;
}

interface TranscribeResponse {
  transcript?: string;
  language?: string;
  segments?: Array<{ start: number; end: number; text: string }>;
  jobId?: string;
  status?: string;
  state?: string;
  error?: string;
}

// Optional callback so the UI can show batch state (PENDING / QUEUED / RUNNING)
export type ProgressCallback = (info: {
  state?: string;
  elapsedSec: number;
}) => void;
let currentProgressCallback: ProgressCallback | null = null;
export function setProgressCallback(cb: ProgressCallback | null) {
  currentProgressCallback = cb;
}

// Current AbortController — allows cancelling in-flight requests
let currentAbortController: AbortController | null = null;

export function cancelTranscription() {
  if (currentAbortController) {
    currentAbortController.abort();
    currentAbortController = null;
  }
}

export async function transcribeFile(
  file: File,
  language: string,
  password: string,
  provider: string = "replicate",
  context: string = "",
): Promise<TranscriptResult> {
  currentAbortController = new AbortController();
  const signal = currentAbortController.signal;

  const formData = new FormData();
  formData.append("file", file);
  formData.append("language", language);
  formData.append("provider", provider);
  if (context.trim()) formData.append("context", context.trim());

  const response = await fetch(`${API_BASE}/transcribe`, {
    method: "POST",
    headers: {
      "X-API-Password": password,
    },
    body: formData,
    signal,
  });

  const data: TranscribeResponse & { locked?: boolean; remainingAttempts?: number } = await response.json();

  if (response.status === 423) {
    throw new Error("LOCKED: Access locked after too many failed attempts. Contact admin to unlock.");
  }

  if (response.status === 401) {
    const msg = data.remainingAttempts !== undefined
      ? `Invalid password. ${data.remainingAttempts} attempt(s) remaining.`
      : "Invalid password.";
    throw new Error(msg);
  }

  if (data.error) {
    throw new Error(data.error);
  }

  if (data.transcript) {
    return {
      transcript: data.transcript,
      language: data.language || "unknown",
      segments: data.segments,
    };
  }

  if (data.jobId) {
    return pollForResult(data.jobId, password, signal);
  }

  throw new Error("Unexpected response from server");
}

async function pollForResult(jobId: string, password: string, signal: AbortSignal): Promise<TranscriptResult> {
  // Poll for up to 60 minutes. Gemini Batch Prediction can take 10-30 min
  // for long audio files (provisioning + queuing + running).
  const isBatchJob = jobId.startsWith("gcb_");
  // Faster polling early on (every 5s), then slow down for batch jobs (every 15s after 1 min)
  const fastInterval = 5000;
  const slowInterval = 15000;
  const fastDuration = 60_000; // first minute = fast polling
  const maxDuration = 60 * 60 * 1000; // 60 minutes total

  const start = Date.now();
  while (Date.now() - start < maxDuration) {
    const elapsed = Date.now() - start;
    const interval = isBatchJob && elapsed > fastDuration ? slowInterval : fastInterval;
    await new Promise((r) => setTimeout(r, interval));

    if (signal.aborted) throw new Error("Cancelled");

    const response = await fetch(`${API_BASE}/status/${jobId}`, {
      headers: { "X-API-Password": password },
      signal,
    });
    const data: TranscribeResponse = await response.json();

    if (currentProgressCallback) {
      currentProgressCallback({
        state: data.state,
        elapsedSec: Math.floor((Date.now() - start) / 1000),
      });
    }

    if (data.status === "succeeded" && data.transcript) {
      return {
        transcript: data.transcript,
        language: data.language || "unknown",
        segments: data.segments,
      };
    }

    if (data.status === "failed") {
      throw new Error(data.error || "Transcription failed");
    }
  }

  throw new Error("Transcription timed out");
}
