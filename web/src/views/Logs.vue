<script setup>
import { ref, onMounted, inject } from 'vue'
import { api } from '../api'

const say = inject('toast')
const text = ref('')
const lines = ref(200)
const busy = ref(false)
const auto = ref(false)
let timer = null

async function load() {
  busy.value = true
  try {
    text.value = (await api.logs(lines.value)).text || ''
  } catch (e) {
    say(e.message, 'err')
  } finally {
    busy.value = false
  }
}

function toggleAuto() {
  auto.value = !auto.value
  if (auto.value) timer = setInterval(load, 5000)
  else clearInterval(timer)
}

onMounted(load)
</script>

<template>
  <div class="card">
    <h2>服务日志</h2>
    <div class="row" style="margin-bottom:12px">
      <label class="muted">行数</label>
      <select v-model.number="lines" style="width:110px" @change="load">
        <option :value="100">100</option>
        <option :value="200">200</option>
        <option :value="500">500</option>
        <option :value="1000">1000</option>
      </select>
      <button :disabled="busy" @click="load">刷新</button>
      <label class="muted"><input type="checkbox" :checked="auto" @change="toggleAuto" /> 每 5 秒自动刷新</label>
    </div>
    <pre class="log">{{ text || '（无日志）' }}</pre>
  </div>
</template>
