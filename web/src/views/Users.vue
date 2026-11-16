<script setup>
import { ref, onMounted, inject } from 'vue'
import { api } from '../api'

const say = inject('toast')
const users = ref([])
const loading = ref(true)
const newUser = ref({ name: '', password: '' })
const busy = ref(false)

async function load() {
  loading.value = true
  try {
    users.value = (await api.users()).users || []
  } catch (e) {
    say(e.message, 'err')
  } finally {
    loading.value = false
  }
}

async function add() {
  if (!newUser.value.name || !newUser.value.password) return say('请填写用户名和密码', 'warn')
  busy.value = true
  try {
    const r = await api.addUser(newUser.value.name, newUser.value.password)
    users.value = r.users || []
    say('已保存用户 ' + newUser.value.name)
    newUser.value = { name: '', password: '' }
  } catch (e) {
    say(e.message, 'err')
  } finally {
    busy.value = false
  }
}

async function resetpw(name) {
  const pw = prompt(`给 ${name} 设置新密码（至少 6 位）`)
  if (!pw) return
  try {
    const r = await api.passwd(name, pw)
    users.value = r.users || []
    say('密码已更新')
  } catch (e) {
    say(e.message, 'err')
  }
}

async function del(name) {
  if (!confirm(`确认删除用户 ${name}？`)) return
  try {
    const r = await api.delUser(name)
    users.value = r.users || []
    say('已删除')
  } catch (e) {
    say(e.message, 'err')
  }
}

onMounted(load)
</script>

<template>
  <div class="card">
    <h2>新增用户 / 重置密码</h2>
    <div class="row">
      <input v-model="newUser.name" placeholder="用户名（字母/数字/._@-）" style="width:220px" />
      <input v-model="newUser.password" placeholder="密码（≥6 位）" style="width:220px" />
      <button class="primary" :disabled="busy" @click="add">保存</button>
      <span class="muted">已存在则覆盖密码；保存后立即生效（无需重启）</span>
    </div>
  </div>

  <div class="card">
    <h2>用户列表 <span class="muted">（{{ users.length }}）</span></h2>
    <div v-if="loading" class="muted">加载中…</div>
    <table v-else-if="users.length">
      <thead><tr><th>用户名</th><th>组</th><th>状态</th><th style="width:220px">操作</th></tr></thead>
      <tbody>
        <tr v-for="u in users" :key="u.name">
          <td class="mono">{{ u.name }}</td>
          <td class="mono">{{ u.group || '-' }}</td>
          <td><span class="tag" :class="u.hasHash ? 'ok' : 'warn'">{{ u.hasHash ? '已设置密码' : '无密码' }}</span></td>
          <td class="row">
            <button @click="resetpw(u.name)">改密码</button>
            <button class="danger" @click="del(u.name)">删除</button>
          </td>
        </tr>
      </tbody>
    </table>
    <p v-else class="muted">还没有 VPN 用户</p>
  </div>
</template>
