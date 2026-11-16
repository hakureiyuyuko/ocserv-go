<script setup>
import { ref, onMounted, inject } from 'vue'
import { api } from '../api'

const say = inject('toast')
const form = ref({ domain: '', vpnPort: 443, vpnNet: '10.66.66.0/24', vpnMtu: 1400, vpnDnsText: '1.1.1.1' })
const unit = ref('')
const mode = ref('systemd')
const busy = ref(false)

async function load() {
  try {
    const c = await api.config()
    form.value = {
      domain: c.domain || '',
      vpnPort: c.vpnPort,
      vpnNet: c.vpnNet,
      vpnMtu: c.vpnMtu,
      vpnDnsText: (c.vpnDns || []).join(', ')
    }
    unit.value = c.unit || ''
    mode.value = c.mode || 'systemd'
  } catch (e) {
    say(e.message, 'err')
  }
}

async function save(apply) {
  busy.value = true
  try {
    const dns = form.value.vpnDnsText.split(/[,，\s]+/).map((s) => s.trim()).filter(Boolean)
    const r = await api.saveConfig({
      domain: form.value.domain,
      vpnPort: Number(form.value.vpnPort),
      vpnNet: form.value.vpnNet,
      vpnMtu: Number(form.value.vpnMtu),
      vpnDns: dns,
      apply
    })
    unit.value = r.unit || unit.value
    say(apply ? '已保存并重启服务' : '已保存（未重启服务）')
  } catch (e) {
    say(e.message, 'err')
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="card">
    <h2>VPN 参数</h2>
    <div class="row" style="margin-bottom:10px">
      <label class="muted" style="width:110px">域名</label>
      <input v-model="form.domain" placeholder="vpn.example.com" style="width:300px" />
    </div>
    <div class="row" style="margin-bottom:10px">
      <label class="muted" style="width:110px">监听端口</label>
      <input v-model="form.vpnPort" type="number" style="width:120px" />
      <label class="muted" style="width:110px;margin-left:16px">MTU</label>
      <input v-model="form.vpnMtu" type="number" style="width:120px" />
    </div>
    <div class="row" style="margin-bottom:10px">
      <label class="muted" style="width:110px">客户端网段</label>
      <input v-model="form.vpnNet" placeholder="10.66.66.0/24" style="width:200px" />
      <span class="muted">服务端会自动用网段的第一个地址</span>
    </div>
    <div class="row" style="margin-bottom:10px">
      <label class="muted" style="width:110px">DNS</label>
      <input v-model="form.vpnDnsText" placeholder="1.1.1.1, 8.8.8.8" style="width:300px" />
    </div>
    <div class="row" style="margin-top:14px">
      <button :disabled="busy" @click="save(false)">仅保存</button>
      <button class="primary" :disabled="busy" @click="save(true)">保存并重启服务</button>
      <span v-if="mode === 'container'" class="muted">容器托管模式：参数保存在 panel.json，点「保存并重启服务」立即生效</span>
      <span v-else-if="mode === 'openrc'" class="muted">保存会重写 OpenRC 脚本（/etc/init.d/）；重启会断开在线用户</span>
      <span v-else class="muted">保存会重写 systemd 单元；重启会断开在线用户</span>
    </div>
  </div>

  <div class="card">
    <h2>{{ mode === 'container' ? '运行方式' : mode === 'openrc' ? '生成的 OpenRC 脚本' : '生成的 systemd 单元' }}</h2>
    <p v-if="mode === 'container'" class="muted" style="margin:0">
      当前是托管模式：面板自己管理 VPN 进程（start / stop / restart 都直接作用于子进程），
      参数保存在面板配置文件里，不依赖 systemd / OpenRC。容器重启后由入口脚本再次托管。
    </p>
    <p v-else-if="mode === 'openrc'" class="muted" style="margin:0 0 8px">
      Alpine 等 OpenRC 系统：保存会写入 /etc/init.d/ 并加入 default 运行级。
    </p>
    <pre v-if="mode !== 'container'" class="log">{{ unit }}</pre>
  </div>
</template>
