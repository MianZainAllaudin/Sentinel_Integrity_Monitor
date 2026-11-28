const BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

async function request(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json", ...opts.headers },
    ...opts,
  });
  let data = {};
  try { data = await res.json(); } catch { /* ignore */ }
  if (!res.ok) {
    const msg = (data && data.error && data.error.message) || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

export const api = {
  health: () => request("/api/v1/health"),
  status: () => request("/api/v1/status"),
  scan: (root) => request("/api/v1/scans", { method: "POST", body: JSON.stringify({ root_path: root }) }),
  accept: (scanId, confirm) => request("/api/v1/accept", { method: "POST", body: JSON.stringify({ scan_id: scanId, confirm }) }),
  scans: (folderId) => request("/api/v1/scans" + (folderId ? "?folder_id=" + encodeURIComponent(folderId) : "")),
  scanDetail: (id) => request("/api/v1/scans/" + encodeURIComponent(id)),
  clearScans: (folderId) => request("/api/v1/scans" + (folderId ? "?folder_id=" + encodeURIComponent(folderId) : ""), { method: "DELETE" }),
  browse: (path) => request("/api/v1/fs/list" + (path ? "?path=" + encodeURIComponent(path) : "")),
  folders: () => request("/api/v1/folders"),
  untrack: (id) => request("/api/v1/folders/" + encodeURIComponent(id), { method: "DELETE" }),
  init: (root) => request("/api/v1/baselines", { method: "POST", body: JSON.stringify({ root_path: root }) }),
};
