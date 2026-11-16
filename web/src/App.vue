<script setup>
import { ref, onMounted, provide } from 'vue'
import { api } from './api'
import Overview from './views/Overview.vue'
import Users from './views/Users.vue'
import Cert from './views/Cert.vue'
import Settings from './views/Settings.vue'
import Logs from './views/Logs.vue'
import PanelSettings from './views/PanelSettings.vue'
import Assets from './views/Assets.vue'
import Connections from './views/Connections.vue'

const user = ref('')
const title = ref('ocserv-go 管理面板')
const version = ref('')
const view = ref('ov')
const booting = ref(true)
const login = ref({ username: 'admin', password: '' })
const loginErr = ref('')
const loggingIn = ref(false)
const toast = ref(null)

function say(msg, kind = 'ok') {
  toast.value = { msg, kind }
  setTimeout(() => (toast.value = null), 3200)
}
provide('toast', say)

const nav = [
  { id: 'ov', label: '概览' },
  { id: 'us', label: 'VPN 用户' },
  { id: 'ct', label: '证书' },
  { id: 'cf', label: '服务配置' },
  { id: 'as', label: '登录页外观' },
  { id: 'cn', label: '连接日志' },
  { id: 'lg', label: '日志' },
  { id: 'pn', label: '面板设置' }
]

async function boot() {
  try {
    const me = await api.me()
    user.value = me.user
    title.value = me.title || title.value
    version.value = me.version
  } catch (e) {
    user.value = ''
  } finally {
    booting.value = false
  }
}

async function doLogin() {
  loginErr.value = ''
  loggingIn.value = true
  try {
    await api.login(login.value.username, login.value.password)
    login.value.password = ''
    await boot()
  } catch (e) {
    loginErr.value = e.message
  } finally {
    loggingIn.value = false
  }
}

async function doLogout() {
  try {
    await api.logout()
  } catch (e) {}
  user.value = ''
  view.value = 'ov'
}

onMounted(boot)
</script>

<template>
  <div v-if="booting" class="center muted">加载中…</div>

  <div v-else-if="!user" class="login-wrap">
    <form class="card login" @submit.prevent="doLogin">
      <h1>{{ title }}</h1>
      <p class="muted">输入面板账号登录</p>
      <label class="muted">用户名</label>
      <input v-model="login.username" autocomplete="username" />
      <label class="muted" style="margin-top:10px">密码</label>
      <input v-model="login.password" type="password" autocomplete="current-password" />
      <p v-if="loginErr" class="err">{{ loginErr }}</p>
      <button class="primary" style="width:100%;margin-top:14px" :disabled="loggingIn">
        {{ loggingIn ? '登录中…' : '登录' }}
      </button>
    </form>
  </div>

  <div v-else class="layout">
    <header>
      <strong>{{ title }}</strong>
      <span class="muted mono" style="margin-left:8px" v-if="version">v{{ version }}</span>
      <span class="spacer"></span>
      <span class="muted">{{ user }}</span>
      <button @click="doLogout">退出</button>
    </header>

    <div class="body">
      <nav>
        <button
          v-for="n in nav"
          :key="n.id"
          :class="{ on: view === n.id }"
          @click="view = n.id"
        >{{ n.label }}</button>
      </nav>
      <main>
        <Overview v-if="view === 'ov'" @go="view = $event" />
        <Users v-else-if="view === 'us'" />
        <Cert v-else-if="view === 'ct'" :version="version" />
        <Settings v-else-if="view === 'cf'" />
        <Assets v-else-if="view === 'as'" />
        <Connections v-else-if="view === 'cn'" />
        <Logs v-else-if="view === 'lg'" />
        <PanelSettings v-else-if="view === 'pn'" :version="version" />
      </main>
    </div>

    <div v-if="toast" class="toast" :class="toast.kind">{{ toast.msg }}</div>
  </div>
</template>

<style scoped>
.center { padding: 80px; text-align: center; }
.login-wrap { display: flex; justify-content: center; padding: 12vh 16px; }
.login { width: 360px; }
.login h1 { font-size: 18px; margin: 0 0 4px; }
.login p { margin: 0 0 14px; }
.login label { display: block; margin-bottom: 4px; }
.err { color: var(--err); margin: 10px 0 0; }

.layout { min-height: 100vh; display: flex; flex-direction: column; }
header {
  display: flex; align-items: center; gap: 8px;
  padding: 12px 18px; background: #111827; color: #f9fafb;
}
header button { background: transparent; color: #f9fafb; border-color: #374151; }
.spacer { flex: 1; }
.body { display: flex; flex: 1; align-items: stretch; }
nav {
  flex: 0 0 172px; width: 172px; padding: 12px 10px; background: #fff;
  border-right: 1px solid var(--line);
  display: flex; flex-direction: column; gap: 4px;
}
nav button { text-align: left; white-space: nowrap; border: 0; background: transparent; padding: 9px 12px; border-radius: 6px; }
nav button.on { background: #eff6ff; color: var(--primary); font-weight: 600; }
main { flex: 1; min-width: 0; padding: 18px; max-width: 1080px; }
.toast {
  position: fixed; right: 18px; bottom: 18px; padding: 10px 16px; border-radius: 8px;
  background: #111827; color: #fff; box-shadow: 0 6px 24px rgba(0,0,0,.18);
}
.toast.err { background: var(--err); }
.toast.warn { background: var(--warn); }
</style>
