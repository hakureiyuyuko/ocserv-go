<script setup>
import { ref, onMounted, inject } from 'vue'
import { api } from '../api'

const say = inject('toast')
const info = ref(null)
const domain = ref('')
const mode = ref('selfsigned')
const upload = ref({ cert: '', key: '' })
const acmeForm = ref({ email: '', provider: 'cloudflare', staging: false })
const busy = ref(false)

const providers = [
  { id: 'cloudflare', label: 'Cloudflare（CF_DNS_API_TOKEN）' },
  { id: 'alidns', label: '阿里云 DNS' },
  { id: 'tencentcloud', label: '腾讯云 DNSPod' },
  { id: 'dnspod', label: 'DNSPod Token' }
]

async function load() {
  try {
    info.value = await api.cert()
    const c = await api.config()
    domain.value = c.domain || ''
  } catch (e) {
    say(e.message, 'err')
  }
}

async function run() {
  busy.value = true
  try {
    if (mode.value === 'selfsigned') {
      await api.selfSigned(domain.value)
      say('已生成自签证书')
    } else if (mode.value === 'upload') {
      await api.uploadCert(domain.value, upload.value.cert, upload.value.key)
      say('已保存上传的证书')
    } else {
      say('正在申请，可能需要 1~2 分钟…', 'warn')
      await api.acme({ domain: domain.value, ...acmeForm.value })
      say('证书已签发')
    }
    await load()
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
    <h2>当前证书</h2>
    <div v-if="!info" class="muted">加载中…</div>
    <template v-else-if="info.exists">
      <div class="kv"><span class="muted">域名</span><span class="mono">{{ info.subject }}</span></div>
      <div class="kv"><span class="muted">签发者</span><span class="mono">{{ info.issuer }}</span></div>
      <div class="kv"><span class="muted">到期</span><span class="mono">{{ info.notAfter }}（剩 {{ info.daysLeft }} 天）</span></div>
      <div class="kv"><span class="muted">密钥类型</span>
        <span class="mono">{{ info.isRsa ? 'RSA（DTLS 可用）' : 'ECDSA（DTLS 会被禁用）' }}</span>
      </div>
      <div class="kv"><span class="muted">SAN</span><span class="mono">{{ (info.san || []).join(', ') || '-' }}</span></div>
    </template>
    <p v-else class="muted">尚未安装证书</p>
  </div>

  <div class="card">
    <h2>更换证书</h2>
    <div class="row" style="margin-bottom:12px">
      <label class="muted">域名</label>
      <input v-model="domain" placeholder="vpn.example.com" style="width:280px" />
    </div>
    <div class="row" style="margin-bottom:12px">
      <label><input type="radio" value="selfsigned" v-model="mode" /> 自签（仅测试）</label>
      <label><input type="radio" value="upload" v-model="mode" /> 上传已有证书</label>
      <label><input type="radio" value="acme" v-model="mode" /> 内置 Let's Encrypt（DNS-01）</label>
    </div>

    <div v-if="mode === 'upload'">
      <textarea v-model="upload.cert" placeholder="fullchain 证书（-----BEGIN CERTIFICATE----- …，可含中间证书）"></textarea>
      <textarea v-model="upload.key" placeholder="私钥（-----BEGIN PRIVATE KEY----- …）" style="margin-top:8px"></textarea>
    </div>

    <div v-if="mode === 'acme'">
      <div class="row" style="margin-bottom:8px">
        <label class="muted" style="width:90px">DNS 服务商</label>
        <select v-model="acmeForm.provider" style="width:280px">
          <option v-for="p in providers" :key="p.id" :value="p.id">{{ p.label }}</option>
        </select>
      </div>
      <div class="row" style="margin-bottom:8px">
        <label class="muted" style="width:90px">账号邮箱</label>
        <input v-model="acmeForm.email" placeholder="可留空" style="width:280px" />
        <label class="muted" style="margin-left:12px"><input type="checkbox" v-model="acmeForm.staging" /> 用 staging 测试</label>
      </div>
      <p class="muted" style="font-size:12px">
        凭据从环境变量读取（如 <span class="mono">CF_DNS_API_TOKEN</span>）；本机没有环境变量时请用「上传已有证书」。
      </p>
    </div>

    <div class="row" style="margin-top:12px">
      <button class="primary" :disabled="busy || !domain" @click="run">{{ busy ? '处理中…' : '应用证书' }}</button>
    </div>
  </div>
</template>
