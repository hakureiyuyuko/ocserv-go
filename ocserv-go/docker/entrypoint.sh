#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# ===========================================================================
#  ocserv-go 容器入口
#
#  首次启动（目录是空的）时自动完成：
#    · 生成自签 RSA 证书（内置，不依赖 openssl）
#    · 建一个 VPN 用户（密码随机，打印到日志；也可用 VPN_USER/VPN_PASSWORD）
#    · 写面板配置并建 admin 账号（密码随机打印，或用 PANEL_USER/PANEL_PASSWORD）
#
#  PANEL=1（默认）：面板托管 VPN 子进程（面板里可启动/停止/重启、看日志）
#  PANEL=0       ：只跑 VPN，按环境变量传参（面板不启动）
#
#  参数只在**首次启动**生效（之后请到面板「设置」里改，持久化在 panel.json）。
# ===========================================================================
set -eu

BIN=/usr/local/bin/ocserv-go
DATA=${DATA_DIR:-/etc/ocserv-go}
USERS=${USERS_FILE:-/etc/ocserv/ocpasswd}
DOMAIN=${DOMAIN:-vpn.example.com}
PORT=${VPN_PORT:-443}
NET=${VPN_NET:-10.66.66.0/24}
SRV_IP=${VPN_IP:-}
DNS=${VPN_DNS:-1.1.1.1,8.8.8.8}
MTU=${VPN_MTU:-1400}
CERT=${CERT_FILE:-/etc/ssl/securev/$DOMAIN/fullchain.pem}
KEY=${KEY_FILE:-/etc/ssl/securev/$DOMAIN/privkey.pem}
PANEL=${PANEL:-1}
PANEL_LISTEN=${PANEL_LISTEN:-:19999}
PANEL_USER=${PANEL_USER:-admin}
PANEL_PASSWORD=${PANEL_PASSWORD:-}
VPN_USER=${VPN_USER:-admin}
VPN_PASSWORD=${VPN_PASSWORD:-}

say() { printf '[ocserv-go] %s\n' "$*"; }
die() { printf '[ocserv-go] 错误: %s\n' "$*" >&2; exit 1; }

# 允许 docker run <image> <命令> 直接执行（排错用：-version、panel、hash 等）
if [ "$#" -gt 0 ]; then
  case "$1" in
    -*|panel|hash|self-signed) exec "$BIN" "$@" ;;
    *) exec "$@" ;;
  esac
fi

case "$DOMAIN" in
  ""|*[!A-Za-z0-9._-]*) die "DOMAIN 只能是域名/主机名（字母数字点横线下划线），当前: $DOMAIN" ;;
esac
printf '%s' "$PORT" | grep -qE '^[0-9]+$' || die "VPN_PORT 不是数字: $PORT"

mkdir -p "$DATA" "$DATA/assets" "$(dirname "$USERS")" "$(dirname "$CERT")"
chmod 700 "$DATA" 2>/dev/null || true

# ---------------------------------------------------------------- 证书
if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
  say "没有证书，生成自签证书（CN=$DOMAIN）"
  "$BIN" self-signed -domain "$DOMAIN" -cert "$CERT" -key "$KEY"
else
  say "使用已有证书: $CERT"
fi

# ---------------------------------------------------------------- VPN 用户
if [ ! -s "$USERS" ]; then
  pw="$VPN_PASSWORD"
  if [ -z "$pw" ]; then
    pw=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-16)
  fi
  hash=$("$BIN" hash "$pw")
  printf '%s:*:%s\n' "$VPN_USER" "$hash" > "$USERS"
  chmod 600 "$USERS"
  say "已创建 VPN 用户: $VPN_USER  密码: $pw  （请立即保存）"
  say "  以后加用户用面板「用户管理」，或用 ocserv-go hash 生成哈希后改 $USERS"
else
  say "沿用已有用户库: $USERS"
fi

# ---------------------------------------------------------------- 只跑 VPN
if [ "$PANEL" = "0" ]; then
  say "只启动 VPN（PANEL=0），监听 :$PORT"
  if [ -n "$SRV_IP" ]; then
    set -- -addr ":$PORT" -users "$USERS" -cert "$CERT" -key "$KEY" \
      -net "$NET" -ip "$SRV_IP" -dns "$DNS" -mtu "$MTU" -domain "$DOMAIN"
  else
    set -- -addr ":$PORT" -users "$USERS" -cert "$CERT" -key "$KEY" \
      -net "$NET" -dns "$DNS" -mtu "$MTU" -domain "$DOMAIN"
  fi
  set -- "$@" -assets "$DATA/assets" -conn-log "$DATA/connections.jsonl" \
    -acme-state "$DATA/acme.json" -acme-env "$DATA/acme.env"
  exec "$BIN" "$@"
fi

# ---------------------------------------------------------------- 面板配置
dns_json=""
for d in $(printf '%s' "$DNS" | tr ',' ' '); do
  dns_json="${dns_json:+$dns_json,}\"$d\""
done

if [ ! -f "$DATA/panel.json" ]; then
  say "写面板配置（之后改参数请到面板「设置」，环境变量只在首次生效）"
  cat > "$DATA/panel.json" <<EOF
{
  "title": "ocserv-go 管理面板",
  "listen": "$PANEL_LISTEN",
  "service": "ocserv-go",
  "bin": "$BIN",
  "usersFile": "$USERS",
  "assetsDir": "$DATA/assets",
  "acmeEnv": "$DATA/acme.env",
  "acmeState": "$DATA/acme.json",
  "connLog": "$DATA/connections.jsonl",
  "certFile": "$CERT",
  "keyFile": "$KEY",
  "domain": "$DOMAIN",
  "vpnPort": $PORT,
  "vpnNet": "$NET",
  "vpnMtu": $MTU,
  "vpnDns": [$dns_json]
}
EOF
  if [ -n "$PANEL_PASSWORD" ]; then
    [ ${#PANEL_PASSWORD} -ge 6 ] || die "PANEL_PASSWORD 至少 6 位"
    "$BIN" panel -config "$DATA/panel.json" -set-password "$PANEL_USER:$PANEL_PASSWORD" -init
  else
    # 没指定密码：自动建 admin 并打印随机密码
    "$BIN" panel -config "$DATA/panel.json" -init
  fi
else
  # 已有配置：确保至少有一个面板账号（账号被清空时会补建并打印新密码）
  "$BIN" panel -config "$DATA/panel.json" -init
fi

say "面板登录: http://<主机>:${PANEL_LISTEN##*:}/ （账号见上方输出）"
say "面板托管模式启动，VPN 监听 :$PORT（TCP + UDP/DTLS）"
exec "$BIN" panel -config "$DATA/panel.json" -listen "$PANEL_LISTEN" -supervise
