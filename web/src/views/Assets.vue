<script setup>
import { ref, onMounted, inject, computed } from 'vue'
import { api } from '../api'

const say = inject('toast')
const info = ref(null)
const busy = ref(false)
const picked = ref(null)
const script = ref('')

const fetchScript = computed(() => {
  return [
    '# 在你自己的 Cisco 设备/网关上执行（把 BASE 换成设备地址）',
    'BASE=https://192.168.1.1',
    'set -e',
    'for p in /+CSCOE+/logon.html /+CSCOE+/logon_custom.css /+CSCOE+/win.js \\',
    '         /+CSCOU+/csco_logo.gif /+CSCOU+/login-header-icon.jpg \\',
    '         /+CSCOU+/login-header-middle.jpg /+CSCOU+/login-header-end.jpg; do',
    '  mkdir -p ".$(dirname "$p")"',
    '  curl -sk "$BASE$p" -o ".$p" || true',
    'done',
    '# 抬头蓝色 Banner 的背景图（缺了它 Banner 会是空白）',
    'curl -sk "$BASE/+CSCOU+/gradient.gif?r=255&g=255&b=255" -o ".+CSCOU+/gradient.gif" || true',
    'tar czf cisco-assets.tar.gz +CSCOE+ +CSCOU+'
  ].join('\n')
})

async function load() {
  try {
    info.value = await api.assets()
  } catch (e) {
    say(e.message, 'err')
  }
}

function pick(ev) {
  picked.value = ev.target.files && ev.target.files[0] ? ev.target.files[0] : null
}

async function upload() {
  if (!picked.value) return say('先选择一个 .tar.gz 包', 'warn')
  busy.value = true
  try {
    const r = await api.uploadAssets(picked.value)
    say(`已导入 ${r.count} 个文件`)
    picked.value = null
    await load()
  } catch (e) {
    say(e.message, 'err')
  } finally {
    busy.value = false
  }
}

async function clearAll() {
  if (!confirm('清空已上传的资源，恢复内置占位页？')) return
  try {
    await api.clearAssets()
    say('已恢复内置占位页')
    await load()
  } catch (e) {
    say(e.message, 'err')
  }
}

function copy() {
  navigator.clipboard?.writeText(fetchScript.value).then(
    () => say('抓取脚本已复制'),
    () => say('复制失败，请手动选择', 'warn')
  )
}

onMounted(load)
</script>

<template>
  <div class="card">
    <h2>关于</h2>
    <p class="muted" style="margin:0">
      套件<b>不自带</b> Cisco 的图片与 CSS（厂商素材，我们不提供）。想还原你手上设备的登录页外观，
      请自己从设备抓取静态文件、打包成 <code>.tar.gz</code> 后上传到这里；
      服务端会优先使用你上传的文件，找不到时回落到内置占位内容。
    </p>
  </div>

  <div class="card">
    <h2>1. 在设备上抓取并打包</h2>
    <div class="row" style="margin-bottom:8px">
      <button @click="copy">复制抓取脚本</button>
      <span class="muted">与你设备同网段的一台 Linux/macOS 上执行</span>
    </div>
    <pre class="log">{{ fetchScript }}</pre>
    <p class="muted" style="font-size:12px;margin:8px 0 0">
      只要 <code>+CSCOE+</code> / <code>+CSCOU+</code> 下有文件即可；带上 <code>+CSCOE+/logon.html</code>
      会<b>整页替换</b>登录页（表单字段须仍为 username / password，POST 到 /+webvpn+/index.html）。
      页面里的<b>组名</b>（<code>&lt;option&gt;</code>、<code>group_list</code>）会在上传时自动去掉，
      不会把你设备的连接组名公开出去。
    </p>
  </div>

  <div class="card">
    <h2>2. 上传</h2>
    <div class="row">
      <input type="file" accept=".gz,.tgz,application/gzip" @change="pick" style="max-width:320px" />
      <button class="primary" :disabled="busy || !picked" @click="upload">
        {{ busy ? '导入中…' : '上传并导入' }}
      </button>
      <span v-if="picked" class="muted mono">{{ picked.name }}</span>
    </div>
    <p v-if="info" class="muted" style="font-size:12px;margin:8px 0 0">
      限制：包内总量 ≤ {{ (info.limits || {}).maxTotalMB }}MB、单文件 ≤ {{ (info.limits || {}).maxFileMB }}MB、最多 {{ (info.limits || {}).maxFiles }} 个文件；
      只接受 <code>+CSCOT+</code> / <code>+CSCOU+</code> / <code>+CSCOE+</code> 下的路径。
    </p>
  </div>

  <div class="card">
    <h2>已导入的资源 <span class="muted">（{{ info ? info.count : 0 }}）</span></h2>
    <div v-if="!info" class="muted">加载中…</div>
    <template v-else>
      <p class="muted" v-if="info.hasLogon">已包含 <code>+CSCOE+/logon.html</code>：登录页整页替换。</p>
      <table v-if="(info.files || []).length">
        <thead><tr><th>路径</th><th>大小</th></tr></thead>
        <tbody>
          <tr v-for="f in (info.files || [])" :key="f.path">
            <td class="mono">{{ f.path }}</td>
            <td class="mono">{{ (f.size / 1024).toFixed(1) }} KB</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">还没有导入任何资源，当前使用内置占位页。</p>
      <div class="row" style="margin-top:12px">
        <button class="danger" :disabled="!(info.files || []).length" @click="clearAll">清空并恢复内置页</button>
        <span class="muted mono">{{ info.dir }}</span>
      </div>
    </template>
  </div>
</template>
