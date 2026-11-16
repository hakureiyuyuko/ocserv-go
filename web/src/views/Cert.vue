<script setup>
import { ref, computed, onMounted, inject } from 'vue'
import { api } from '../api'

const say = inject('toast')
const info = ref(null)
const domain = ref('')
const mode = ref('selfsigned')
const upload = ref({ cert: '', key: '' })
const providers = ref([])
const acmeForm = ref({ email: '', provider: '', staging: false, creds: {} })
const busy = ref(false)



async function load() {
  try {
    info.value = await api.cert()
    const c = await api.config()
    domain.value = c.domain || ''
    const pv = await api.certProviders()
    providers.value = pv.providers || []
    envFile.value = pv.envFile || ''
    if (!acmeForm.value.provider && providers.value.length) {
      acmeForm.value.provider = providers.value[0].id
      syncCreds()
    }
  } catch (e) {
    say(e.message, 'err')
  }
}

const envFile = ref('')

// 当前选择的服务商需要哪些字段
const curProvider = computed(() => providers.value.find((p) => p.id === acmeForm.value.provider) || null)

// 切换服务商时，清空旧凭据
function syncCreds() {
  const creds = {}
  for (const f of (curProvider.value?.fields || [])) creds[f.k] = ''
  acmeForm.value.creds = creds
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
      const missing = (curProvider.value?.fields || []).filter((f) => !String(acmeForm.value.creds[f.k] || '').trim())
      if (missing.length) return say('请填写：' + missing.map((f) => f.label).join('、'), 'warn')
      await api.acme({
        domain: domain.value,
        email: acmeForm.value.email,
        provider: acmeForm.value.provider,
        staging: acmeForm.value.staging,
        creds: acmeForm.value.creds
      })
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
        <select :value="acmeForm.provider" style="width:280px" @change="acmeForm.provider = $event.target.value; syncCreds()">
          <option v-for="p in providers" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select>
      </div>
      <div class="row" v-for="f in (curProvider ? curProvider.fields : [])" :key="f.k" style="margin-bottom:8px;align-items:flex-start">
        <label class="muted" style="width:90px;padding-top:6px">{{ f.label }}</label>
        <div>
          <input :placeholder="f.k" v-model="acmeForm.creds[f.k]" type="password" style="width:320px" autocomplete="off" />
          <div v-if="f.hint" class="muted" style="font-size:12px;margin-top:2px">{{ f.hint }}</div>
        </div>
      </div>
      <div class="row" style="margin-bottom:8px">
        <label class="muted" style="width:90px">账号邮箱</label>
        <input v-model="acmeForm.email" placeholder="可留空" style="width:280px" />
      </div>
      <div class="row" style="margin-bottom:8px">
        <label class="muted"><input type="checkbox" v-model="acmeForm.staging" /> 用 Let's Encrypt staging 测试</label>
      </div>
      <p class="muted" style="font-size:12px">
        凭据只用于本次签发，并写入 <span class="mono">{{ envFile || '/etc/ocserv-go/acme.env' }}</span>（600）。
        需要 RSA 证书（DTLS 用），签发的是 2048 位。
      </p>
    </div>

    <div class="row" style="margin-top:12px">
      <button class="primary" :disabled="busy || !domain" @click="run">{{ busy ? '处理中…' : '应用证书' }}</button>
    </div>
  </div>
</template>
