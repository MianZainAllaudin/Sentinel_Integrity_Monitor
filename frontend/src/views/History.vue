<template>
  <div class="page">
    <h1>Scan History</h1>

    <section v-if="error" class="card alert">{{ error }}</section>

    <div class="card">
      <div class="hist-bar">
        <span class="meta">{{ scans.length }} saved scan{{ scans.length === 1 ? "" : "s" }} (kept across restarts)</span>
        <span class="hist-actions">
          <button @click="load" :disabled="loading" class="btn">Refresh</button>
          <button @click="confirmOpen = true" :disabled="loading || scans.length === 0" class="btn btn-danger">Clear History</button>
        </span>
      </div>
      <table class="tbl">
        <thead><tr><th>Date</th><th>Folder</th><th>Status</th><th>Changes</th><th>Action</th></tr></thead>
        <tbody>
          <tr v-for="s in scans" :key="s.scan_id">
            <td>{{ fmt(s.completed_at) }}</td>
            <td>{{ s.root_path }}</td>
            <td><span class="badge" :class="`badge-${s.status}`">{{ s.status }}</span></td>
            <td>{{ total(s.summary) }}</td>
            <td><button @click="pick(s)" class="btn">Detail</button></td>
          </tr>
        </tbody>
      </table>
      <p v-if="!loading && scans.length === 0" class="empty">No scans recorded yet.</p>
    </div>

    <div v-if="selected" class="card">
      <h2>Scan Detail</h2>
      <p><strong>Scan ID:</strong> {{ selected.scan_id }}</p>
      <p><strong>Folder:</strong> {{ selected.root_path }}</p>
      <p><strong>Status:</strong> <span class="badge" :class="`badge-${selected.status}`">{{ selected.status }}</span></p>
      <p><strong>Summary:</strong> {{ JSON.stringify(selected.summary) }}</p>
      <p v-if="selected.changes && selected.changes.length"><strong>Changes:</strong></p>
      <ul v-if="selected.changes && selected.changes.length">
        <li v-for="c in selected.changes" :key="c.path">{{ c.status }} &mdash; {{ c.path }} ({{ c.severity }})</li>
      </ul>
      <p v-if="selected.errors && selected.errors.length"><strong>Errors:</strong></p>
      <ul v-if="selected.errors && selected.errors.length">
        <li v-for="e in selected.errors" :key="e.code + (e.path || '')">{{ e.code }} &mdash; {{ e.message }}</li>
      </ul>
    </div>

    <div v-if="confirmOpen" class="overlay" @click.self="confirmOpen = false">
      <div class="dlg-body">
        <h2>Clear History</h2>
        <p>Delete all {{ scans.length }} saved scan records? Baselines and the audit log are not affected. This cannot be undone.</p>
        <div class="dlg-actions">
          <button @click="confirmOpen = false" class="btn">Cancel</button>
          <button @click="clearAll" class="btn btn-danger">Clear History</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from "vue";
import { api } from "../api/client.js";

const scans = ref([]);
const selected = ref(null);
const loading = ref(false);
const error = ref(null);
const confirmOpen = ref(false);

function fmt(ts) {
  const d = new Date(ts);
  return isNaN(d) ? ts : d.toLocaleString();
}

function total(sum) {
  if (!sum) return 0;
  return (sum.added || 0) + (sum.modified || 0) + (sum.deleted || 0) + (sum.moved || 0);
}

async function load() {
  loading.value = true;
  error.value = null;
  try {
    const data = await api.scans();
    scans.value = data.data.scans || [];
    if (selected.value && !scans.value.some((s) => s.scan_id === selected.value.scan_id)) selected.value = null;
  } catch (e) {
    scans.value = [];
    error.value = e.message;
  } finally {
    loading.value = false;
  }
}

async function pick(s) {
  error.value = null;
  try {
    const data = await api.scanDetail(s.scan_id);
    selected.value = data.data;
  } catch (e) {
    error.value = e.message;
  }
}

async function clearAll() {
  confirmOpen.value = false;
  error.value = null;
  try {
    await api.clearScans();
    selected.value = null;
    await load();
  } catch (e) {
    error.value = e.message;
  }
}

onMounted(load);
</script>

<style>
.page { max-width: 900px; margin: 0 auto; padding: 24px; }
h1 { font-size: 1.5rem; margin: 0 0 16px 0; letter-spacing: -0.5px; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 18px 20px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
.tbl { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
.tbl th { text-align: left; padding: 8px; border-bottom: 1px solid #e5e7eb; color: #6b7280; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.3px; }
.tbl td { padding: 8px; border-bottom: 1px solid #f1f5f9; }
.tbl tr:hover { background: #f8fafc; }
.btn { padding: 6px 12px; border-radius: 6px; border: 1px solid #d1d5db; background: #fff; color: #111827; font-size: 0.9rem; cursor: pointer; }
.btn:hover { border-color: #9ca3af; }
.empty { color: #6b7280; font-size: 0.9rem; margin-top: 10px; }
.badge { padding: 4px 10px; border-radius: 999px; font-size: 0.85rem; font-weight: 700; color: #fff; }
.badge-CLEAN { background: #16a34a; }
.badge-CHANGED { background: #ca8a04; }
.badge-ERROR { background: #dc2626; }
.badge-BASELINE_INVALID { background: #4f46e5; }
h2 { font-size: 1.25rem; margin: 0 0 10px 0; }
ul { margin: 6px 0 0 0; padding-left: 18px; color: #374151; }
.alert { background: #fef2f2; border-color: #fecaca; color: #991b1b; }
.hist-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; gap: 10px; flex-wrap: wrap; }
.hist-actions { display: flex; gap: 8px; }
.meta { color: #6b7280; font-size: 0.85rem; }
.btn:disabled { opacity: 0.55; cursor: not-allowed; }
.btn-danger { background: #dc2626; color: #fff; border-color: #dc2626; }
.btn-danger:hover { background: #b91c1c; border-color: #b91c1c; }
.overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; z-index: 50; }
.dlg-body { background: #fff; border-radius: 10px; padding: 20px 24px; max-width: 420px; box-shadow: 0 20px 40px rgba(0,0,0,0.2); }
.dlg-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 14px; }
</style>
