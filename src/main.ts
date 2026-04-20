import "./style.css";
import { transcribeFile, cancelTranscription } from "./api.ts";
import type { TranscriptResult } from "./api.ts";

interface FileEntry {
  file: File;
  status: "queued" | "processing" | "done" | "error";
  result?: TranscriptResult;
  error?: string;
}

const state: {
  files: FileEntry[];
  isProcessing: boolean;
  cancelled: boolean;
  password: string;
} = {
  files: [],
  isProcessing: false,
  cancelled: false,
  password: "",
};

// DOM elements
const dropZone = document.getElementById("drop-zone")!;
const fileInput = document.getElementById("file-input") as HTMLInputElement;
const fileList = document.getElementById("file-list")!;
const fileCount = document.getElementById("file-count")!;
const fileItems = document.getElementById("file-items")!;
const clearFiles = document.getElementById("clear-files")!;
const addMore = document.getElementById("add-more")!;
const transcribeBtn = document.getElementById("transcribe-btn") as HTMLButtonElement;
const progressSection = document.getElementById("progress-section")!;
const progressText = document.getElementById("progress-text")!;
const progressCount = document.getElementById("progress-count")!;
const progressBar = document.getElementById("progress-bar")!;
const currentFileEl = document.getElementById("current-file")!;
const errorMsg = document.getElementById("error-msg")!;
const resultsSection = document.getElementById("results-section")!;
const resultsList = document.getElementById("results-list")!;
const downloadAll = document.getElementById("download-all")!;
const languageSelect = document.getElementById("language") as HTMLSelectElement;
const contextTextarea = document.getElementById("context") as HTMLTextAreaElement;
const passwordInput = document.getElementById("password") as HTMLInputElement;
const unlockBtn = document.getElementById("unlock-btn")!;
const passwordGate = document.getElementById("password-gate")!;
const appEl = document.getElementById("app")!;

// Start locked
appEl.classList.add("app-locked");

// Check for saved password
const savedPassword = localStorage.getItem("transcriptor-password");
if (savedPassword) {
  state.password = savedPassword;
  appEl.classList.remove("app-locked");
  passwordGate.classList.add("unlocked");
  passwordInput.value = "••••••••";
  unlockBtn.textContent = "Unlocked";
}

// Password unlock
unlockBtn.addEventListener("click", () => {
  const pw = passwordInput.value.trim();
  if (pw && pw !== "••••••••") {
    state.password = pw;
    localStorage.setItem("transcriptor-password", pw);
    appEl.classList.remove("app-locked");
    passwordGate.classList.add("unlocked");
    passwordInput.value = "••••••••";
    unlockBtn.textContent = "Unlocked";
  }
});

passwordInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") unlockBtn.click();
});

// Drop zone events
dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("drag-over");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("drag-over");
});

dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("drag-over");
  if (e.dataTransfer?.files) {
    addFiles(Array.from(e.dataTransfer.files));
  }
});

fileInput.addEventListener("change", () => {
  if (fileInput.files) {
    addFiles(Array.from(fileInput.files));
    fileInput.value = "";
  }
});

clearFiles.addEventListener("click", () => {
  state.files = [];
  renderFileList();
});

addMore.addEventListener("click", () => {
  fileInput.click();
});

transcribeBtn.addEventListener("click", () => {
  if (state.isProcessing) {
    state.cancelled = true;
    cancelTranscription();
    transcribeBtn.textContent = "Cancelling...";
    transcribeBtn.disabled = true;
  } else {
    startTranscription();
  }
});
downloadAll.addEventListener("click", downloadAllTranscripts);

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function addFiles(files: File[]) {
  const audioVideoTypes = /^(audio|video)\//;
  const allowedExts =
    /\.(mp3|wav|m4a|mp4|webm|ogg|flac|aac|wma|opus|avi|mkv|mov|ts)$/i;

  for (const file of files) {
    if (audioVideoTypes.test(file.type) || allowedExts.test(file.name)) {
      state.files.push({ file, status: "queued" });
    }
  }
  renderFileList();
}

function renderFileList() {
  if (state.files.length === 0) {
    fileList.hidden = true;
    dropZone.classList.remove("has-files");
    transcribeBtn.disabled = true;
    return;
  }

  fileList.hidden = false;
  dropZone.classList.add("has-files");
  transcribeBtn.disabled = false;

  fileCount.textContent = `${state.files.length} file${state.files.length !== 1 ? "s" : ""} selected`;

  fileItems.innerHTML = state.files
    .map(
      (entry, _i) => `
    <li>
      <span class="file-name">${escapeHtml(entry.file.name)}</span>
      <span class="file-size">${formatSize(entry.file.size)}</span>
      <span class="file-status ${entry.status}">${statusLabel(entry.status)}</span>
    </li>
  `,
    )
    .join("");
}

function statusLabel(status: string): string {
  switch (status) {
    case "queued":
      return "Queued";
    case "processing":
      return '<span class="spinner-inline"></span>Processing';
    case "done":
      return "Done";
    case "error":
      return "Failed";
    default:
      return "";
  }
}

function escapeHtml(str: string): string {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

async function startTranscription() {
  if (state.files.length === 0 || state.isProcessing) return;

  state.isProcessing = true;
  state.cancelled = false;
  transcribeBtn.disabled = false;
  transcribeBtn.textContent = "Cancel";
  errorMsg.hidden = true;
  progressSection.hidden = false;
  resultsSection.hidden = true;
  resultsList.innerHTML = "";

  const language = languageSelect.value;
  const context = contextTextarea.value;
  const providerInput = document.querySelector<HTMLInputElement>(
    'input[name="provider"]:checked',
  );
  const provider = providerInput?.value || "replicate";
  const total = state.files.length;
  let completed = 0;

  // Reset all statuses
  for (const entry of state.files) {
    entry.status = "queued";
    entry.result = undefined;
    entry.error = undefined;
  }
  renderFileList();

  // Process files sequentially (Replicate limits concurrent predictions)
  for (let idx = 0; idx < state.files.length; idx++) {
    if (state.cancelled) break;

    const entry = state.files[idx];
    entry.status = "processing";
    renderFileList();

    progressText.textContent = "Transcribing...";
    progressCount.textContent = `${completed}/${total}`;
    progressBar.style.width = `${(completed / total) * 100}%`;
    currentFileEl.textContent = entry.file.name;

    try {
      entry.result = await transcribeFile(entry.file, language, state.password, provider, context);
      entry.status = "done";
      completed++;
      addResultCard(entry, idx);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      entry.status = "error";
      entry.error = msg;
      completed++;

      if (msg.startsWith("LOCKED:") || msg.includes("attempt(s) remaining")) {
        localStorage.removeItem("transcriptor-password");
        state.password = "";
        appEl.classList.add("app-locked");
        passwordGate.classList.remove("unlocked");
        passwordInput.value = "";
        unlockBtn.textContent = "Unlock";
        errorMsg.hidden = false;
        if (msg.startsWith("LOCKED:")) {
          errorMsg.innerHTML = 'Access locked after too many failed attempts.<br>To reset, run: <strong>unlock transcriptor</strong>';
        } else {
          errorMsg.textContent = msg;
        }
        break;
      }
    }

    renderFileList();
    progressCount.textContent = `${completed}/${total}`;
    progressBar.style.width = `${(completed / total) * 100}%`;
  }

  progressText.textContent = state.cancelled ? "Cancelled" : "Complete!";
  currentFileEl.textContent = "";
  state.isProcessing = false;
  state.cancelled = false;
  transcribeBtn.disabled = false;
  transcribeBtn.textContent = "Transcribe";

  // Show results if any succeeded
  const successCount = state.files.filter((f) => f.status === "done").length;
  if (successCount > 0) {
    resultsSection.hidden = false;
    downloadAll.style.display = successCount > 1 ? "" : "none";
  }

  // Show errors
  const errors = state.files.filter((f) => f.status === "error");
  if (errors.length > 0) {
    errorMsg.hidden = false;
    errorMsg.textContent = `${errors.length} file(s) failed: ${errors.map((e) => e.file.name).join(", ")}`;
  }
}

function addResultCard(entry: FileEntry, index: number) {
  if (!entry.result) return;

  const card = document.createElement("div");
  card.className = "result-card expanded";
  card.innerHTML = `
    <div class="result-card-header" data-index="${index}">
      <span class="result-card-title">${escapeHtml(entry.file.name)}</span>
      <div class="result-card-meta">
        <span class="lang-badge">${escapeHtml(entry.result.language)}</span>
        <span class="expand-icon">&#9660;</span>
      </div>
    </div>
    <div class="result-card-body">
      <textarea readonly>${escapeHtml(entry.result.transcript)}</textarea>
      <div class="result-card-actions">
        <button class="btn-secondary copy-btn" data-index="${index}">Copy</button>
        <button class="btn-secondary download-btn" data-index="${index}">Download .txt</button>
      </div>
    </div>
  `;

  // Toggle expand
  card.querySelector(".result-card-header")!.addEventListener("click", () => {
    card.classList.toggle("expanded");
  });

  // Copy
  card.querySelector(".copy-btn")!.addEventListener("click", () => {
    navigator.clipboard.writeText(entry.result!.transcript);
    const btn = card.querySelector(".copy-btn") as HTMLButtonElement;
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = "Copy"), 2000);
  });

  // Download
  card.querySelector(".download-btn")!.addEventListener("click", () => {
    downloadTranscript(entry.file.name, entry.result!.transcript);
  });

  resultsList.appendChild(card);
}

function downloadTranscript(filename: string, text: string) {
  const baseName = filename.replace(/\.[^.]+$/, "");
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${baseName}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

async function downloadAllTranscripts() {
  const completed = state.files.filter(
    (f) => f.status === "done" && f.result,
  );
  if (completed.length === 0) return;

  // If only one file, just download it directly
  if (completed.length === 1) {
    downloadTranscript(
      completed[0].file.name,
      completed[0].result!.transcript,
    );
    return;
  }

  // For multiple files, create a combined text file with separators
  const combined = completed
    .map((entry) => {
      const baseName = entry.file.name.replace(/\.[^.]+$/, "");
      return `=== ${baseName} ===\n\n${entry.result!.transcript}`;
    })
    .join("\n\n\n");

  const blob = new Blob([combined], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "transcriptions.txt";
  a.click();
  URL.revokeObjectURL(url);
}
