// 统一的 API 封装：所有写操作带 X-Panel 头，401 时由上层跳回登录页。
export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

async function req(method, path, body) {
  const opt = { method, headers: {}, credentials: 'same-origin' }
  if (method !== 'GET') {
    opt.headers['X-Panel'] = '1'
    opt.headers['Content-Type'] = 'application/json'
    if (body !== undefined) opt.body = JSON.stringify(body)
  }
  const r = await fetch(path, opt)
  let data = null
  try {
    data = await r.json()
  } catch (e) {
    data = null
  }
  if (!r.ok) throw new ApiError(r.status, (data && data.error) || `HTTP ${r.status}`)
  return data
}

export const api = {
  login: (username, password) => req('POST', '/api/login', { username, password }),
  logout: () => req('POST', '/api/logout', {}),
  me: () => req('GET', '/api/me'),
  overview: () => req('GET', '/api/overview'),

  users: () => req('GET', '/api/users'),
  addUser: (name, password) => req('POST', '/api/users', { action: 'add', name, password }),
  delUser: (name) => req('POST', '/api/users', { action: 'del', name }),
  passwd: (name, password) => req('POST', '/api/users', { action: 'passwd', name, password }),

  service: (action) => req('POST', '/api/service', { action }),
  logs: (lines = 200) => req('GET', `/api/logs?lines=${lines}`),

  assets: () => req('GET', '/api/assets'),
  clearAssets: () => req('DELETE', '/api/assets'),
  async uploadAssets(file) {
    const fd = new FormData()
    fd.append('file', file)
    const r = await fetch('/api/assets', {
      method: 'POST',
      headers: { 'X-Panel': '1' },
      body: fd,
      credentials: 'same-origin'
    })
    let data = null
    try {
      data = await r.json()
    } catch (e) {}
    if (!r.ok) throw new ApiError(r.status, (data && data.error) || `HTTP ${r.status}`)
    return data
  },

  cert: () => req('GET', '/api/cert'),
  certProviders: () => req('GET', '/api/cert/providers'),
  selfSigned: (domain) => req('POST', '/api/cert', { action: 'selfsigned', domain }),
  uploadCert: (domain, cert, key) => req('POST', '/api/cert', { action: 'upload', domain, cert, key }),
  acme: (payload) => req('POST', '/api/cert', { action: 'acme', ...payload }),

  config: () => req('GET', '/api/config'),
  saveConfig: (payload) => req('POST', '/api/config', payload),

  panel: () => req('GET', '/api/panel'),
  changePassword: (oldPassword, newPassword) =>
    req('POST', '/api/panel/password', { oldPassword, newPassword })
}
