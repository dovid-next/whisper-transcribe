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
  error?: string;
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
): Promise<TranscriptResult> {
  currentAbortController = new AbortController();
  const signal = currentAbortController.signal;

  const formData = new FormData();
  formData.append("file", file);
  formData.append("language", language);

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
  const maxAttempts = 120;
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise((r) => setTimeout(r, 5000));

    if (signal.aborted) throw new Error("Cancelled");

    const response = await fetch(`${API_BASE}/status/${jobId}`, {
      headers: { "X-API-Password": password },
      signal,
    });
    const data: TranscribeResponse = await response.json();

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
