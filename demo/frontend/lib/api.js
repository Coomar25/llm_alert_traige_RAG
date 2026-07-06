// Central place for the backend base URL. Override with NEXT_PUBLIC_API_BASE.
export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8077";

async function getJSON(path) {
  const res = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

export const getOverview = () => getJSON("/api/overview");
export const getPhases = () => getJSON("/api/phases");
export const getAlerts = () => getJSON("/api/alerts");
export const getAlert = (id) => getJSON(`/api/alerts/${id}`);

// Shared display helpers -----------------------------------------------------

export const PALETTE = {
  llmOnly: "#2a78d6", // categorical slot 1 (blue)
  llmRag: "#1baf7a", // categorical slot 2 (aqua)
  good: "#0ca30c",
  bad: "#d03b3b",
};

export const pct = (x) => (x == null ? "—" : `${(x * 100).toFixed(1)}%`);
export const secs = (ms) => (ms == null ? "—" : `${(ms / 1000).toFixed(1)}s`);

export const TAG_META = {
  both_correct: { label: "Both correct", color: "#0ca30c" },
  rag_fixed: { label: "RAG fixed it", color: "#2a78d6" },
  rag_broke: { label: "RAG broke it", color: "#d03b3b" },
  both_wrong: { label: "Both wrong", color: "#898781" },
};
