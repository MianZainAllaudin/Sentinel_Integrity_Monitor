<template>
  <div class="overlay" @click.self="$emit('close')">
    <div class="dlg-body picker">
      <h2>Select a folder</h2>

      <div class="pk-bar">
        <button class="btn" :disabled="busy || !data || !data.parent" @click="open(data.parent)">Up</button>
        <input v-model="typed" class="input" placeholder="Type or paste a folder path" @keyup.enter="open(typed)" />
        <button class="btn" :disabled="busy" @click="open(typed)">Go</button>
      </div>

      <div v-if="data" class="pk-links">
        <button v-for="l in data.shortcuts" :key="l.label + l.path" class="btn btn-ghost" @click="open(l.path)">{{ l.label }}</button>
      </div>

      <p v-if="error" class="pk-err">{{ error }}</p>

      <ul class="pk-list">
        <li
          v-for="e in (data ? data.entries : [])"
          :key="e.path"
          :class="{ 'pk-dim': !e.is_dir }"
          :title="e.is_dir ? 'Open folder' : 'Files cannot be monitored, only folders'"
          @click="e.is_dir && open(e.path)"
        >
          <span class="pk-ico">{{ e.is_dir ? "▸" : "·" }}</span>{{ e.name }}
        </li>
        <li v-if="data && data.entries.length === 0" class="pk-dim">This folder is empty.</li>
      </ul>
      <p v-if="data && data.truncated" class="meta">Only the first {{ data.entries.length }} entries are shown.</p>
      <p class="meta">Sentinel monitors whole folders. Files are shown greyed out for reference.</p>

      <div class="dlg-actions">
        <button @click="$emit('close')" class="btn">Cancel</button>
        <button :disabled="busy || !data" @click="$emit('select', data.path)" class="btn btn-primary">Select this folder</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from "vue";
import { api } from "../api/client.js";

const props = defineProps({ start: { type: String, default: "" } });
defineEmits(["select", "close"]);

const data = ref(null);
const typed = ref("");
const error = ref(null);
const busy = ref(false);

async function open(path) {
  busy.value = true;
  error.value = null;
  try {
    const res = await api.browse(path);
    data.value = res.data;
    typed.value = res.data.path;
  } catch (e) {
    error.value = e.message;
  } finally {
    busy.value = false;
  }
}

onMounted(async () => {
  await open(props.start);
  if (!data.value) await open("");  // typed path was invalid: fall back to the home folder
});
</script>

<style>
.dlg-body.picker { width: 92vw; max-width: 620px; }
.pk-bar { display: flex; gap: 8px; margin-bottom: 8px; }
.pk-bar .input { flex: 1; min-width: 0; }
.pk-links { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 8px; }
.pk-err { color: #991b1b; background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 6px 10px; font-size: 0.85rem; }
.pk-list { list-style: none; margin: 0 0 8px 0; padding: 0; max-height: 300px; overflow-y: auto; border: 1px solid #e5e7eb; border-radius: 6px; }
.pk-list li { padding: 6px 10px; cursor: pointer; border-bottom: 1px solid #f1f5f9; font-size: 0.9rem; word-break: break-all; }
.pk-list li:hover { background: #f1f5f9; }
.pk-list li.pk-dim { color: #9ca3af; cursor: default; }
.pk-list li.pk-dim:hover { background: transparent; }
.pk-ico { display: inline-block; width: 18px; color: #6b7280; }
</style>
