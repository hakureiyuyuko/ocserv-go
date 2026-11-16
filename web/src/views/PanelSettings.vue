<script setup>
import { ref, onMounted, inject } from 'vue'
import { api } from '../api'

defineProps({ version: String })
const say = inject('toast')
const info = ref(null)
const pw = ref({ oldPassword: '', newPassword: '', repeat: '' })
const busy = ref(false)

async function load() {
  try {
    info.value = await api.panel()
  } catch (e) {
    say(e.message, 'err')
  }
}

async function change() {
  if (pw.value.newPassword !== pw.value.repeat) return say('两次输入的新密码不一致', 'warn')
  busy.value = true
  try {
    await api.changePassword(pw.value.oldPassword, pw.value.newPassword)
    pw.value = { oldPassword: '', newPassword: '', repeat: '' }
    say('面板密码已更新')
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
    <h2>面板信息</h2>
    <div v-if="!info" class="muted">加载中…</div>
    <template v-else>
      <div class="kv"><span class="muted">版本</span><span class="mono">v{{ info.version }}</span></div>
      <div class="kv"><span class="muted">监听</span><span class="mono">{{ info.listen }}</span></div>
      <div class="kv"><span class="muted">账号</span><span class="mono">{{ (info.users || []).join(', ') }}</span></div>
      <div class="kv"><span class="muted">VPN 用户库</span><span class="mono">{{ info.usersFile }}</span></div>
      <div class="kv"><span class="muted">证书 / 私钥</span><span class="mono">{{ info.certFile }}</span></div>
    </template>
  </div>

  <div class="card">
    <h2>修改面板密码</h2>
    <div class="row" style="margin-bottom:8px">
      <label class="muted" style="width:110px">当前密码</label>
      <input v-model="pw.oldPassword" type="password" style="width:240px" />
    </div>
    <div class="row" style="margin-bottom:8px">
      <label class="muted" style="width:110px">新密码</label>
      <input v-model="pw.newPassword" type="password" style="width:240px" />
    </div>
    <div class="row" style="margin-bottom:12px">
      <label class="muted" style="width:110px">确认新密码</label>
      <input v-model="pw.repeat" type="password" style="width:240px" />
    </div>
    <button class="primary" :disabled="busy" @click="change">保存</button>
  </div>
</template>
