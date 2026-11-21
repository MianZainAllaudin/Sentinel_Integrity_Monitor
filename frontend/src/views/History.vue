<template>
  <div class="page">
    <h1>Scan History</h1>
    <div class="card">
      <table class="tbl">
        <thead><tr><th>Date</th><th>Folder</th><th>Status</th><th>Changes</th><th>Action</th></tr></thead>
        <tbody>
          <tr v-for="s in scans" :key="s.scan_id">
            <td>{{ s.completed_at }}</td>
            <td>{{ s.root_path }}</td>
            <td><span class="badge" :class="`badge-${s.status}`">{{ s.status }}</span></td>
            <td>{{ s.summary.added + s.summary.modified + s.summary.deleted + s.summary.moved }}</td>
            <td><button @click="pick(s)" class="btn">Detail</button></td>
          </tr>
        </tbody>
      </table>
      <p v-if="scans.length === 0" class="empty">No scans recorded yet.</p>
    </div>

    <div v-if="selected" class="card">
      <h2>Scan Detail</h2>
      <p><strong>Scan ID:</strong> {{ selected.scan_id }}</p>
      <p><strong>Status:</strong> <span class="badge" :class="`badge-${selected.status}`">{{ selected.status }}</span></p>
      <p><strong>Summary:</strong> {{ JSON.stringify(selected.summary) }}</p>
      <p v-if="selected.changes && selected.changes.length"><strong>Changes:</strong></p>
      <ul v-if="selected.changes && selected.changes.length">
        <li v-for="c in selected.changes" :key="c.path">{{ c.status }} &mdash; {{ c.path }} ({{ c.severity }})</li>
      </ul>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from "vue";
import { api } from "../api/client.js";

const scans = ref([]);
const selected = ref(null);

async function load() {
  try {
    const data = await api.status();
    scans.value = data.data.scans || [];
  } catch { scans.value = []; }
}

function pick(s) { selected.value = s; }

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
</style>
