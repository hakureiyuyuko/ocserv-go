#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# ============================================================================
#  ocserv-go 安装脚本（自适应）
#  · 架构：x86_64(amd64) / aarch64(arm64) / armv7l —— 包内已带对应二进制
#  · 初始化系统：systemd（Debian/Ubuntu）或 OpenRC（Alpine），没有则只装不托管
#  · 用户态网络栈：不需要 tun / NET_ADMIN / iptables
#
#  用法： sudo ./install.sh [选项]
#    --domain D        证书域名（默认 vpn.example.com）
#    --port N          VPN 端口（默认 443，TCP+UDP/DTLS）
#    --cert FILE       TLS 证书（不给则自动生成自签 RSA）
#    --key FILE        私钥
#    --users FILE      用户库（默认 /etc/ocserv/ocpasswd）
#    --net CIDR        客户端网段（默认 10.66.66.0/24）
#    --ip ADDR         隧道内服务端地址（默认 10.66.66.1）
#    --dns LIST        下发 DNS（默认 1.1.1.1，逗号分隔）
#    --user NAME       创建一个 VPN 用户
#    --password PW     该用户的密码（不给则随机生成并打印）
#    --prefix DIR      二进制安装目录（默认 /usr/local/bin）
#    --no-start        只写服务单元，不启动
#    --uninstall       卸载（停服务、删单元与二进制，保留配置/证书/用户）
# ============================================================================
set -eu

VERSION="1.0.0"
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

DOMAIN="vpn.example.com"
PORT=443
NET="10.66.66.0/24"
IP="10.66.66.1"
DNS="1.1.1.1"
MTU="1400"
USERS="/etc/ocserv/ocpasswd"
CERT=""
KEY=""
PREFIX="/usr/local/bin"
VPN_USER=""
VPN_PASS=""
NO_START=0
UNINSTALL=0
SVC="ocserv-go"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# 需要 openssl 生成自签证书/随机密码；尽量自动补上
ensure_openssl() {
  command -v openssl >/dev/null 2>&1 && return 0
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache openssl >/dev/null 2>&1 || true
  elif command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssl >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q openssl >/dev/null 2>&1 || true
  fi
  command -v openssl >/dev/null 2>&1
}

# busybox 的 install 可能不支持全部参数，退回 cp
install_file() {
  if install "$@" 2>/dev/null; then return 0; fi
  src=$1; dst=$2; shift 2
  cp "$src" "$dst"
}
warn() { printf '\033[1;33m[警告] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m错误：%s\033[0m\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain)   DOMAIN="$2"; shift 2 ;;
    --port)     PORT="$2"; shift 2 ;;
    --cert)     CERT="$2"; shift 2 ;;
    --key)      KEY="$2"; shift 2 ;;
    --users)    USERS="$2"; shift 2 ;;
    --net)      NET="$2"; shift 2 ;;
    --ip)       IP="$2"; shift 2 ;;
    --dns)      DNS="$2"; shift 2 ;;
    --user)     VPN_USER="$2"; shift 2 ;;
    --password) VPN_PASS="$2"; shift 2 ;;
    --prefix)   PREFIX="$2"; shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)  sed -n '4,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "请用 root 运行"

# ---------------------------------------------------------------- 初始化系统
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  INIT=systemd
elif command -v rc-service >/dev/null 2>&1; then
  INIT=openrc
else
  INIT=none
fi

# ---------------------------------------------------------------- 卸载
if [ "$UNINSTALL" = 1 ]; then
  say "卸载 ocserv-go"
  case "$INIT" in
    systemd)
      systemctl disable --now "$SVC-panel" >/dev/null 2>&1 || true
      systemctl disable --now "$SVC" >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/$SVC.service" "/etc/systemd/system/$SVC-panel.service"
      systemctl daemon-reload || true ;;
    openrc)
      rc-service "$SVC-panel" stop >/dev/null 2>&1 || true
      rc-service "$SVC" stop >/dev/null 2>&1 || true
      rc-update del "$SVC-panel" default >/dev/null 2>&1 || true
      rc-update del "$SVC" default >/dev/null 2>&1 || true
      rm -f "/etc/init.d/$SVC" "/etc/init.d/$SVC-panel" ;;
  esac
  rm -f "$PREFIX/ocserv-go"
  echo "已移除服务与二进制；配置 /etc/ocserv-go、用户库 $USERS、证书均保留"
  exit 0
fi

# ---------------------------------------------------------------- 架构
MACH=$(uname -m)
case "$MACH" in
  x86_64|amd64)   ARCH=amd64 ;;
  aarch64|arm64)  ARCH=arm64 ;;
  armv7l|armv7*)  ARCH=armv7 ;;
  *) die "不支持的架构: $MACH（包提供 amd64 / arm64 / armv7）" ;;
esac

BIN_SRC="$SRC/bin/ocserv-go"
[ -f "$BIN_SRC" ] || die "包内缺少 bin/ocserv-go"
chmod 755 "$BIN_SRC" 2>/dev/null || true

# 直接执行一次：架构不匹配会以 "Exec format error" 失败，最可靠的校验
if ! "$BIN_SRC" -version >/dev/null 2>&1; then
  die "包内二进制无法在当前架构（$MACH）运行；请下载 ocserv-go-$VERSION-linux-$ARCH 对应的包"
fi
say "环境"
echo "    架构: $MACH ($ARCH)"
echo "    初始化系统: $INIT"
echo "    版本: $("$BIN_SRC" -version)"

# ---------------------------------------------------------------- 安装二进制
say "安装二进制"
mkdir -p "$PREFIX"
install -m 755 "$BIN_SRC" "$PREFIX/ocserv-go"
echo "    $PREFIX/ocserv-go"

# ---------------------------------------------------------------- 证书
say "证书"
if [ -z "$CERT" ]; then
  CERT="/etc/ssl/securev/$DOMAIN/fullchain.pem"
  KEY="/etc/ssl/securev/$DOMAIN/privkey.pem"
fi
if [ -z "$KEY" ]; then
  KEY="$(dirname "$CERT")/privkey.pem"
fi
if [ -s "$CERT" ] && [ -s "$KEY" ]; then
  echo "    使用已有证书: $CERT"
else
  ensure_openssl || die "没有证书且找不到 openssl，无法生成自签"
  mkdir -p "$(dirname "$CERT")"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" \
    -keyout "$KEY" -out "$CERT" >/dev/null 2>&1 \
    || die "自签证书生成失败"
  chmod 600 "$KEY"
  echo "    已生成自签证书（客户端会提示不受信任）: $CERT"
  echo "    之后可用内置 ACME 换正式证书，见文末"
fi

# ---------------------------------------------------------------- 用户
say "用户库"
mkdir -p "$(dirname "$USERS")"
if [ ! -s "$USERS" ]; then
  install -m 600 /dev/null "$USERS"
fi
if [ -n "$VPN_USER" ]; then
  ensure_openssl || true
  [ -n "$VPN_PASS" ] || VPN_PASS=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-16)
  HASH=$("$PREFIX/ocserv-go" hash "$VPN_PASS")
  grep -q "^$VPN_USER:" "$USERS" 2>/dev/null || printf '%s:*:%s\n' "$VPN_USER" "$HASH" >> "$USERS"
  chmod 600 "$USERS"
  echo "    已创建/更新用户: $VPN_USER  密码: $VPN_PASS"
elif [ ! -s "$USERS" ]; then
  VPN_USER=admin
  ensure_openssl || true
  VPN_PASS=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-16)
  HASH=$("$PREFIX/ocserv-go" hash "$VPN_PASS")
  printf '%s:*:%s\n' "$VPN_USER" "$HASH" >> "$USERS"
  chmod 600 "$USERS"
  echo "    用户库为空，已创建用户: $VPN_USER  密码: $VPN_PASS"
else
  echo "    沿用已有用户库: $USERS"
fi

# ---------------------------------------------------------------- 配置目录
mkdir -p /etc/ocserv-go
chmod 700 /etc/ocserv-go

ASSETS=/etc/ocserv-go/assets
ARGS="-addr :$PORT -users $USERS -cert $CERT -key $KEY -net $NET -ip $IP -dns $DNS -mtu $MTU -domain $DOMAIN -assets $ASSETS"

# ---------------------------------------------------------------- 服务单元
say "服务单元"
case "$INIT" in
  systemd)
    cat > "/etc/systemd/system/$SVC.service" <<UNIT
[Unit]
Description=ocserv-go (userspace AnyConnect VPN)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PREFIX/ocserv-go $ARGS
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    echo "    /etc/systemd/system/$SVC.service"
    [ "$NO_START" = 1 ] || { systemctl enable --now "$SVC" >/dev/null 2>&1 || warn "启动失败，看 journalctl -u $SVC"; } ;;
  openrc)
    cat > "/etc/init.d/$SVC" <<UNIT
#!/sbin/openrc-run
description="ocserv-go (userspace AnyConnect VPN)"

command="$PREFIX/ocserv-go"
command_args="$ARGS"
command_background=true
pidfile="/run/$SVC.pid"
output_log="/var/log/$SVC.log"
error_log="/var/log/$SVC.log"

depend() {
    need net
}
UNIT
    chmod 755 "/etc/init.d/$SVC"
    rc-update add "$SVC" default >/dev/null 2>&1 || true
    echo "    /etc/init.d/$SVC（已加入 default 运行级）"
    [ "$NO_START" = 1 ] || { rc-service "$SVC" restart >/dev/null 2>&1 || rc-service "$SVC" start >/dev/null 2>&1 || warn "启动失败，看 /var/log/$SVC.log"; } ;;
  *)
    warn "没有 systemd / OpenRC：只安装了二进制，请手动运行："
    echo "    $PREFIX/ocserv-go $ARGS" ;;
esac

# ---------------------------------------------------------------- 管理面板
say "管理面板（内置在同一个二进制里）"
PANEL_CFG=/etc/ocserv-go/panel.json
PANEL_PORT="${PANEL_PORT:-19999}"
mkdir -p /etc/ocserv-go
if [ ! -f "$PANEL_CFG" ]; then
  PANEL_PW="$(openssl rand -base64 12 2>/dev/null | tr -dc 'A-Za-z0-9' | cut -c1-12 || true)"
  [ -n "$PANEL_PW" ] || PANEL_PW="admin123456"
  cat > "$PANEL_CFG" <<JSON
{
  "title": "ocserv-go 管理面板",
  "listen": ":$PANEL_PORT",
  "service": "$SVC",
  "bin": "$PREFIX/ocserv-go",
  "usersFile": "$USERS",
  "certFile": "$CERT",
  "keyFile": "$KEY",
  "domain": "$DOMAIN",
  "vpnPort": $PORT,
  "vpnNet": "$NET",
  "vpnMtu": $MTU,
  "vpnDns": ["$(printf '%s' "$DNS" | cut -d, -f1)"],
  "assetsDir": "$ASSETS"
}
JSON
  chmod 600 "$PANEL_CFG"
  "$PREFIX/ocserv-go" panel -config "$PANEL_CFG" -set-password "admin:$PANEL_PW" -init >/dev/null 2>&1 \
    || warn "面板配置初始化失败（可手动：ocserv-go panel -config $PANEL_CFG -set-password admin:新密码 -init）"
  echo "    面板账号: admin / $PANEL_PW   （请尽快在面板里修改）"
else
  echo "    已存在 $PANEL_CFG，保留现有配置与账号"
fi

case "$INIT" in
  systemd)
    cat > "/etc/systemd/system/$SVC-panel.service" <<UNIT
[Unit]
Description=ocserv-go panel (built-in)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PREFIX/ocserv-go panel -config $PANEL_CFG
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    echo "    /etc/systemd/system/$SVC-panel.service"
    [ "$NO_START" = 1 ] || { systemctl enable --now "$SVC-panel" >/dev/null 2>&1 || warn "面板启动失败，看 journalctl -u $SVC-panel"; } ;;
  openrc)
    cat > "/etc/init.d/$SVC-panel" <<UNIT
#!/sbin/openrc-run
description="ocserv-go panel (built-in)"

command="$PREFIX/ocserv-go"
command_args="panel -config $PANEL_CFG"
command_background=true
pidfile="/run/$SVC-panel.pid"
output_log="/var/log/$SVC-panel.log"
error_log="/var/log/$SVC-panel.log"

depend() {
    need net
}
UNIT
    chmod 755 "/etc/init.d/$SVC-panel"
    rc-update add "$SVC-panel" default >/dev/null 2>&1 || true
    echo "    /etc/init.d/$SVC-panel（已加入 default 运行级）"
    [ "$NO_START" = 1 ] || { rc-service "$SVC-panel" restart >/dev/null 2>&1 || rc-service "$SVC-panel" start >/dev/null 2>&1 || true; } ;;
  *)
    echo "    手动启动: $PREFIX/ocserv-go panel -config $PANEL_CFG" ;;
esac
echo "    面板地址: http://<本机IP>:$PANEL_PORT/"

# ---------------------------------------------------------------- 汇总
say "完成"
sleep 1
case "$INIT" in
  systemd) ST=$(systemctl is-active "$SVC" 2>/dev/null || true) ;;
  openrc)  ST=$(rc-service "$SVC" status 2>/dev/null | tail -1 || true) ;;
  *)       ST="未托管" ;;
esac
echo "    服务状态: $ST"
echo "    监听: TCP/UDP $PORT  客户端网段 $NET  隧道地址 $IP"
echo "    用户库: $USERS"
echo "    证书:   $CERT"
echo
echo "  客户端连接: 任意 AnyConnect 兼容客户端 → $DOMAIN:$PORT"
echo "  管理面板:   http://<本机IP>:$PANEL_PORT/  (systemctl status $SVC-panel)"
echo
echo "  换正式证书（内置 Let's Encrypt DNS-01，无需 80 端口）:"
echo "    cat > /etc/ocserv-go/acme.env <<'EOF'"
echo "    CF_DNS_API_TOKEN=xxxx        # 或 ALICLOUD_ACCESS_KEY/SECRET、TENCENTCLOUD_SECRET_ID/KEY、DNSPOD_API_KEY"
echo "    EOF"
echo "    chmod 600 /etc/ocserv-go/acme.env"
echo "    $PREFIX/ocserv-go -acme-once -acme-domain $DOMAIN -acme-dns cloudflare \\"
echo "      -acme-env /etc/ocserv-go/acme.env -acme-cache /etc/ocserv-go/acme \\"
echo "      -cert $CERT -key $KEY"
echo "    然后重启服务即可。"
