<template>
  <div class="page">
    <h1>Tracked Folders</h1>

    <section class="card">
      <div class="row">
        <input v-model="newRoot" class="input" placeholder="Folder to track (e.g. D:\Projects\MyApp)" @keyup.enter="track" />
        <button :disabled="busy || !newRoot" @click="track" class="btn btn-primary">Track &amp; Create Baseline</button>
      </div>
      <p class="hint">Each tracked folder has its own baseline, audit log and scan history. The command line uses the same ones.</p>
    </section>

    <section v-if="error" class="card alert">{{ error }}</section>
    <section v-if="notice" class="card ok">{{ notice }}</section>

    <section class="card">
      <div class="hist-bar">
        <span class="meta">{{ folders.length }} tracked folder{{ folders.length === 1 ? "" : "s" }}</span>
        <button @click="load" :disabled="busy" class="btn">Refresh</button>
      </div>
      <table v-if="folders.length" class="tbl">
        <thead><tr><th>Folder</th><th>Last scan</th><th>Status</th><th>Scans</th><th>Actions</th></tr></thead>
        <tbody>
          <tr v-for="f in folders" :key="f.id">
            <td>
              <div>{{ f.root_path }}</div>
              <div class="sub" v-if="!f.root_exists">folder not found on disk</div>
              <div class="sub" v-else-if="!f.has_baseline">baseline file missing</div>
              <div class="sub">state: {{ f.state_dir }}</div>
              <div class="sub">CLI: <code>sentinel verify "{{ f.root_path }}"</code></div>
            </td>
            <td>{{ f.last_scan ? fmt(f.last_scan.completed_at) : "—" }}</td>
            <td>
              <span v-if="f.last_scan" class="badge" :class="`badge-${f.last_scan.status}`">{{ f.last_scan.status }}</span>
              <span v-else class="meta">not scanned yet</span>
            </td>
            <td>{{ f.scan_count }}</td>
            <td class="acts">
              <button :disabled="busy" @click="verify(f)" class="btn">Verify</button>
              <button :disabled="busy" @click="ask('rebaseline', f)" class="btn">Re-baseline</button>
              <button :disabled="busy" @click="ask('untrack', f)" class="btn btn-danger">Stop tracking</button>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else-if="!busy" class="empty">No tracked folders yet. Enter a folder above to start tracking it.</p>
    </section>

    <div v-if="pending" class="overlay" @click.self="pending = null">
      <div class="dlg-body">
        <h2>{{ pending.kind === "untrack" ? "Stop tracking" : "Re-baseline" }}</h2>
        <p v-if="pending.kind === 'untrack'">Stop tracking <strong>{{ pending.folder.root_path }}</strong>? It disappears from this list, but its baseline, audit log and history stay on disk.</p>
        <p v-else>Replace the baseline of <strong>{{ pending.folder.root_path }}</strong> with the folder's current contents? Changes made since the last baseline are accepted without review. This is recorded in the audit log.</p>
        <div class="dlg-actions">
          <button @click="pending = null" class="btn">Cancel</button>
          <button @click="confirm" class="btn btn-danger">{{ pending.kind === "untrack" ? "Stop tracking" : "Re-baseline" }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from "vue";
import { api } from "../api/client.js";

const folders = ref([]);
const newRoot = ref("");
const busy = ref(false);
const error = ref(null);
const notice = ref(null);
const pending = ref(null);

function fmt(ts) {
  const d = new Date(ts);
  return isNaN(d) ? ts : d.toLocaleString();
}

async function load() {
  busy.value = true;
  try {
    const data = await api.folders();
    folders.value = data.data.folders || [];
  } catch (e) {
    folders.value = [];
    error.value = e.message;
  } finally {
    busy.value = false;
  }
}

async function run(action, okMessage) {
  busy.value = true;
  error.value = null;
  notice.value = null;
  try {
    const message = await action();
    notice.value = okMessage || message;
  } catch (e) {
    error.value = e.message;
  }
  busy.value = false;
  await load();
}

function track() {
  const root = newRoot.value.trim();
  if (!root) return;
  run(async () => {
    await api.init(root);
    newRoot.value = "";
  }, "Folder tracked and baseline created.");
}

function verify(f) {
  run(async () => {
    const data = await api.scan(f.root_path);
    return `${f.root_path}: ${data.data.status}`;
  });
}

function ask(kind, folder) {
  pending.value = { kind, folder };
}

function confirm() {
  const { kind, folder } = pending.value;
  pending.value = null;
  if (kind === "untrack") run(() => api.untrack(folder.id), "Stopped tracking " + folder.root_path);
  else run(() => api.init(folder.root_path), "Baseline replaced for " + folder.root_path);
}

onMounted(load);
</script>

<style>
.row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.sub { color: #6b7280; font-size: 0.78rem; margin-top: 2px; word-break: break-all; }
.sub code { background: #f1f5f9; padding: 1px 4px; border-radius: 4px; }
.acts { white-space: nowrap; }
.acts .btn { margin-right: 6px; }
.ok { background: #f0fdf4; border-color: #bbf7d0; color: #166534; }
</style>
