<script setup>
import { ref, onMounted, inject } from 'vue'
import { api } from '../api'

const say = inject('toast')
const records = ref([])
const total = ref(0)
const file = ref('')
const q = ref('')
const limit = ref(200)
const busy = ref(false)
const auto = ref(false)
let timer = null

function when(t) {
  if (!t) return '-'
  const d = new Date(t)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

function where(r) {
  const s = [r.country, r.region, r.city].filter(Boolean).join(' · ')
  return s || (r.geoError ? '查询失败' : '—')
}

async function load() {
  busy.value = true
  try {
    const d = await api.connections(limit.value, q.value)
    records.value = d.records || []
    total.value = d.total || 0
    file.value = d.file || ''
  } catch (e) {
    say(e.message, 'err')
  } finally {
    busy.value = false
  }
}

function toggleAuto() {
  auto.value = !auto.value
  if (auto.value) timer = setInterval(load, 10000)
  else clearInterval(timer)
}

onMounted(load)
</script>

<template>
  <div class="card">
    <h2>连接日志 <span class="muted">（只记录连接成功的；共 {{ total }} 条，显示最近 {{ records.length }} 条）</span></h2>
    <div class="row" style="margin-bottom:12px">
      <input v-model="q" placeholder="搜索 用户 / IP / 省市 / 运营商" style="width:260px" @keyup.enter="load" />
      <select v-model.number="limit" style="width:110px" @change="load">
        <option :value="50">50</option>
        <option :value="200">200</option>
        <option :value="500">500</option>
        <option :value="2000">2000</option>
      </select>
      <button :disabled="busy" @click="load">刷新</button>
      <label class="muted"><input type="checkbox" :checked="auto" @change="toggleAuto" /> 每 10 秒自动刷新</label>
    </div>

    <table v-if="records.length">
      <thead>
        <tr><th style="width:170px">时间</th><th style="width:120px">用户</th><th style="width:150px">来源 IP</th><th>归属地</th><th style="width:200px">运营商 / ASN</th></tr>
      </thead>
      <tbody>
        <tr v-for="(r, i) in records" :key="i">
          <td class="mono">{{ when(r.time) }}</td>
          <td class="mono">{{ r.user }}</td>
          <td class="mono">{{ r.ip }}</td>
          <td>{{ where(r) }}</td>
          <td class="muted mono">{{ [r.isp, r.asn && ('AS' + r.asn)].filter(Boolean).join(' · ') || '—' }}</td>
        </tr>
      </tbody>
    </table>
    <p v-else-if="!busy" class="muted">还没有连接记录（有人成功连上后会出现在这里）</p>

    <p class="muted mono" style="font-size:12px;margin-top:10px" v-if="file">日志文件：{{ file }}</p>
  </div>
</template>
