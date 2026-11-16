<script setup>
import { ref, onMounted, inject } from 'vue'
import { api } from '../api'

const say = inject('toast')
const o = ref(null)
const busy = ref('')
const emit = defineEmits(['go'])

async function load() {
  try {
    o.value = await api.overview()
  } catch (e) {
    say(e.message, 'err')
  }
}

async function svc(action) {
  busy.value = action
  try {
    await api.service(action)
    await load()
    say('已' + ({ start: '启动', stop: '停止', restart: '重启' }[action]))
  } catch (e) {
    say(e.message, 'err')
  } finally {
    busy.value = ''
  }
}

onMounted(load)
</script>

<template>
  <div v-if="!o" class="muted">加载中…</div>
  <template v-else>
    <div class="grid">
      <div class="card">
        <div class="muted">服务状态</div>
        <div style="font-size:22px;margin:6px 0">
          <span class="tag" :class="o.service.active === 'active' ? 'ok' : 'err'">{{ o.service.active }}</span>
        </div>
        <div class="muted mono">
          {{ o.service.name }} ·
          {{ o.service.enabled === 'container' ? '容器托管（面板管理进程）' : 'enabled=' + o.service.enabled }}
        </div>
      </div>
      <div class="card">
        <div class="muted">证书</div>
        <div style="font-size:22px;margin:6px 0">
          <span v-if="o.cert.exists" class="tag" :class="o.cert.daysLeft < 15 ? 'err' : o.cert.daysLeft < 30 ? 'warn' : 'ok'">
            {{ o.cert.daysLeft }} 天
          </span>
          <span v-else class="tag err">未安装</span>
        </div>
        <div class="muted mono">{{ o.cert.subject || '—' }}<span v-if="o.cert.notAfter"> · {{ o.cert.notAfter }}</span></div>
      </div>
      <div class="card">
        <div class="muted">VPN 用户</div>
        <div style="font-size:22px;margin:6px 0">{{ o.users.count }}</div>
        <div class="muted mono">{{ o.users.names.join(', ') || '无' }}</div>
      </div>
      <div class="card">
        <div class="muted">监听</div>
        <div style="font-size:22px;margin:6px 0">{{ o.config.vpnPort }}</div>
        <div class="muted mono">TCP + UDP（DTLS）</div>
      </div>
    </div>

    <div class="card">
      <h2>服务控制</h2>
      <div class="row">
        <button :disabled="!!busy" @click="svc('start')">启动</button>
        <button :disabled="!!busy" @click="svc('restart')">重启</button>
        <button class="danger" :disabled="!!busy" @click="svc('stop')">停止</button>
        <span class="muted">{{ busy ? '执行中…' : '' }}</span>
      </div>
    </div>

    <div class="card">
      <h2>当前配置</h2>
      <div class="kv"><span class="muted">域名</span><span class="mono">{{ o.config.domain || '未设置' }}</span></div>
      <div class="kv"><span class="muted">客户端网段</span><span class="mono">{{ o.config.vpnNet }}</span></div>
      <div class="kv"><span class="muted">MTU</span><span class="mono">{{ o.config.vpnMtu }}</span></div>
      <div class="kv"><span class="muted">DNS</span><span class="mono">{{ (o.config.vpnDns || []).join(', ') }}</span></div>
      <div class="row" style="margin-top:12px">
        <button @click="emit('go', 'cf')">修改配置</button>
        <button @click="emit('go', 'us')">管理用户</button>
        <button @click="emit('go', 'ct')">管理证书</button>
      </div>
    </div>
  </template>
</template>
