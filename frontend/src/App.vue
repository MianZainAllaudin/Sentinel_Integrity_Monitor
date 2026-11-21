<template>
  <div class="app">
    <nav class="bar">
      <div class="brand">Sentinel</div>
      <button @click="view = 'dashboard'" :class="{ active: view === 'dashboard' }">Dashboard</button>
      <button @click="view = 'history'" :class="{ active: view === 'history' }">History</button>
    </nav>

    <main class="wrap">
      <component :is="view === 'dashboard' ? Dashboard : History" />
    </main>
  </div>
</template>

<script setup>
import { ref } from "vue";
import Dashboard from "./views/Dashboard.vue";
import History from "./views/History.vue";
const view = ref("dashboard");
</script>

<style>
* { box-sizing: border-box; }
body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #f4f6f8; color: #1f2937; }
.app { display: flex; flex-direction: column; height: 100vh; }
.bar { display: flex; align-items: center; gap: 16px; padding: 14px 24px; background: #111827; color: #fff; }
.brand { font-weight: 700; font-size: 1.125rem; letter-spacing: 0.5px; }
.bar button { background: transparent; border: 1px solid #374151; color: #e5e7eb; padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 0.9rem; }
.bar button.active { background: #3b82f6; border-color: #3b82f6; color: #fff; }
.bar button:hover:not(.active) { background: #1f2937; border-color: #6b7280; }
.wrap { flex: 1; overflow: auto; padding: 24px; }
</style>
