<template>
  <div class="page">
    <h1>Folder Integrity</h1>

    <section class="card scan-panel">
      <div class="row">
        <input v-model="root" list="tracked-folders" placeholder="Folder to monitor (e.g. C:/Projects/MyApp)" class="input" />
        <datalist id="tracked-folders"><option v-for="f in folders" :key="f.id" :value="f.root_path" /></datalist>
        <button :disabled="scanning || !root" @click="runScan" class="btn btn-primary">Verify</button>
        <button :disabled="scanning || !result || result.status !== 'CHANGED'" @click="openAccept" class="btn">Accept Changes</button>
        <button :disabled="scanning || !root" @click="initRoot" class="btn btn-ghost">Init Baseline</button>
      </div>
      <p v-if="root" class="hint">Each folder has its own baseline, audit log and history, stored outside the monitored folder and shared with the command line.</p>
    </section>

    <section v-if="error" class="card alert">{{ error }}</section>

    <section v-if="result" class="card result-card">
      <div class="status-row">
        <span class="badge" :class="`badge-${result.status}`">{{ result.status }}</span>
        <span class="meta">{{ result.root_path }} &middot; {{ result.completed_at }}</span>
      </div>
      <div class="summary">
        <div class="stat"><div class="val">{{ result.summary.added }}</div><div class="lab">Added</div></div>
        <div class="stat"><div class="val">{{ result.summary.modified }}</div><div class="lab">Modified</div></div>
        <div class="stat"><div class="val">{{ result.summary.deleted }}</div><div class="lab">Deleted</div></div>
        <div class="stat"><div class="val">{{ result.summary.moved }}</div><div class="lab">Moved</div></div>
        <div class="stat"><div class="val">{{ result.summary.errors }}</div><div class="lab">Errors</div></div>
      </div>

      <table v-if="result.changes.length" class="tbl">
        <thead><tr><th>Status</th><th>Path</th><th>Old Path</th><th>Severity</th><th>Reason</th></tr></thead>
        <tbody>
          <tr v-for="c in result.changes" :key="c.path">
            <td><span class="chip" :class="`chip-${c.status}`">{{ c.status }}</span></td>
            <td>{{ c.path }}</td>
            <td>{{ c.old_path || "&mdash;" }}</td>
            <td><span class="chip" :class="`chip-sev-${c.severity}`">{{ c.severity }}</span></td>
            <td>{{ c.reason }}</td>
          </tr>
        </tbody>
      </table>
      <p v-if="result.changes.length === 0" class="empty">No changes detected.</p>

      <div v-if="result.errors.length" class="errs">
        <h3>Scan Errors</h3>
        <ul><li v-for="e in result.errors" :key="e.code">{{ e.code }} &mdash; {{ e.message }}</li></ul>
      </div>
    </section>

    <div v-if="acceptOpen" class="overlay" @click.self="acceptOpen = false">
      <div class="dlg-body">
        <h2>Accept Changes</h2>
        <p>Approve the current scan state as the new baseline for <strong>{{ root }}</strong>.</p>
        <div class="actions">
          <button @click="acceptOpen = false">Cancel</button>
          <button @click="doAccept" class="btn btn-primary">Accept</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from "vue";
import { api } from "../api/client.js";

const root = ref("");
const scanning = ref(false);
const result = ref(null);
const error = ref(null);
const acceptOpen = ref(false);
const lastScanId = ref(null);
const folders = ref([]);

async function loadFolders() {
  try {
    const data = await api.folders();
    folders.value = data.data.folders || [];
  } catch { folders.value = []; }
}
onMounted(loadFolders);

async function runScan() {
  scanning.value = true;
  error.value = null;
  result.value = null;
  try {
    const data = await api.scan(root.value);
    result.value = data.data;
    lastScanId.value = data.data.scan_id;
  } catch (e) {
    error.value = e.message;
  } finally {
    scanning.value = false;
  }
}

async function initRoot() {
  scanning.value = true;
  error.value = null;
  try {
    await api.init(root.value);
  } catch (e) {
    error.value = e.message;
    scanning.value = false;
    return;
  }
  scanning.value = false;
  await loadFolders();
  await runScan();
}

function openAccept() { acceptOpen.value = true; }

async function doAccept() {
  if (!lastScanId.value) return;
  try {
    await api.accept(lastScanId.value, true);
    acceptOpen.value = false;
    await runScan();
  } catch (e) {
    error.value = e.message;
  }
}
</script>

<style>
.page { max-width: 900px; margin: 0 auto; padding: 24px; }
h1 { font-size: 1.5rem; margin: 0 0 16px 0; letter-spacing: -0.5px; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 18px 20px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
.scan-panel .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.input { flex: 1; min-width: 260px; padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 0.95rem; outline: none; }
.input:focus { border-color: #3b82f6; }
.btn { padding: 8px 14px; border-radius: 6px; border: 1px solid #d1d5db; background: #fff; color: #111827; font-size: 0.9rem; cursor: pointer; }
.btn:hover { border-color: #9ca3af; }
.btn:disabled { opacity: 0.55; cursor: not-allowed; }
.btn-primary { background: #111827; color: #fff; border-color: #111827; }
.btn-primary:hover { background: #1f2937; }
.btn-ghost { background: transparent; }
.hint { margin: 6px 0 0 0; font-size: 0.85rem; color: #6b7280; }
.alert { background: #fef2f2; border-color: #fecaca; color: #991b1b; }
.status-row { display: flex; gap: 16px; align-items: center; margin-bottom: 14px; flex-wrap: wrap; }
.badge { padding: 4px 10px; border-radius: 999px; font-size: 0.85rem; font-weight: 700; color: #fff; }
.badge-CLEAN { background: #16a34a; }
.badge-CHANGED { background: #ca8a04; }
.badge-ERROR { background: #dc2626; }
.badge-BASELINE_INVALID { background: #4f46e5; }
.meta { font-size: 0.85rem; color: #6b7280; }
.summary { display: flex; gap: 14px; margin-bottom: 14px; flex-wrap: wrap; }
.stat { display: flex; flex-direction: column; align-items: center; padding: 10px 14px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; min-width: 70px; }
.stat .val { font-size: 1.5rem; font-weight: 800; color: #111827; }
.stat .lab { font-size: 0.75rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.4px; }
.tbl { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.9rem; }
.tbl th { text-align: left; padding: 8px; border-bottom: 1px solid #e5e7eb; color: #6b7280; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.3px; }
.tbl td { padding: 8px; border-bottom: 1px solid #f1f5f9; }
.tbl tr:hover { background: #f8fafc; }
.chip { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; color: #fff; }
.chip-ADDED { background: #16a34a; }
.chip-MODIFIED { background: #ca8a04; }
.chip-DELETED { background: #dc2626; }
.chip-MOVED { background: #2563eb; }
.chip-sev-LOW { background: #6b7280; }
.chip-sev-MEDIUM { background: #ca8a04; }
.chip-sev-HIGH { background: #dc2626; }
.empty { color: #6b7280; font-size: 0.9rem; margin-top: 10px; }
.errs { margin-top: 12px; border-top: 1px solid #f1f5f9; padding-top: 10px; }
.errs h3 { font-size: 0.9rem; margin: 0 0 6px 0; color: #dc2626; }
.errs ul { margin: 0; padding-left: 18px; color: #374151; font-size: 0.9rem; }
.dlg { padding: 0; border: none; border-radius: 10px; box-shadow: 0 20px 40px rgba(0,0,0,0.2); }
.dlg::backdrop { background: rgba(0,0,0,0.4); }
.dlg-body { padding: 24px; }
.dlg-body h2 { margin: 0 0 8px 0; font-size: 1.25rem; }
.dlg-body p { margin: 0 0 16px 0; color: #374151; font-size: 0.95rem; }
.dlg-body .actions { display: flex; gap: 8px; justify-content: flex-end; }
.overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; z-index: 50; }
.dlg-body { background: #fff; border-radius: 10px; padding: 20px 24px; max-width: 420px; box-shadow: 0 20px 40px rgba(0,0,0,0.2); }
</style>
