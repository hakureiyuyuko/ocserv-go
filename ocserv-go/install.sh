#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# ============================================================================
#  ocserv-go 安装脚本（自适应）
#  · 架构：x86_64（amd64 / amd64-v2 / amd64-v3）/ aarch64 / armhf / armel —— 包内已带对应二进制
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
#    --mtu N           隧道 MTU（默认 1400）
#    --from-panel DIR  从老 Node 面板升级（默认自动探测 /opt/ocserv-panel）
#    --no-migrate      不探测/迁移老面板，也不停用老的 C 版 ocserv
#    --no-start        只写服务单元，不启动
#    --uninstall       卸载（停服务、删单元与二进制，保留配置/证书/用户）
# ============================================================================
set -eu

VERSION="1.1.3"
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
PANEL_DIR="/opt/ocserv-panel"   # 老 Node 面板默认位置
MIGRATE=1
FROM_PANEL=""
DOMAIN_SET=0; PORT_SET=0; CERT_SET=0; KEY_SET=0; USERS_SET=0
NET_SET=0; IP_SET=0; DNS_SET=0; MTU_SET=0

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
    --domain)   DOMAIN="$2"; DOMAIN_SET=1; shift 2 ;;
    --port)     PORT="$2"; PORT_SET=1; shift 2 ;;
    --cert)     CERT="$2"; CERT_SET=1; shift 2 ;;
    --key)      KEY="$2"; KEY_SET=1; shift 2 ;;
    --users)    USERS="$2"; USERS_SET=1; shift 2 ;;
    --net)      NET="$2"; NET_SET=1; shift 2 ;;
    --ip)       IP="$2"; IP_SET=1; shift 2 ;;
    --dns)      DNS="$2"; DNS_SET=1; shift 2 ;;
    --mtu)      MTU="$2"; MTU_SET=1; shift 2 ;;
    --user)     VPN_USER="$2"; shift 2 ;;
    --password) VPN_PASS="$2"; shift 2 ;;
    --prefix)   PREFIX="$2"; shift 2 ;;
    --from-panel) FROM_PANEL="$2"; shift 2 ;;
    --no-migrate) MIGRATE=0; shift ;;
    --no-start) NO_START=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)  sed -n '4,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
  armv7l|armv7*|armv8l)
    # armhf 与 armel 的 uname 都是 armv7l，看有没有硬浮点动态加载器来区分
    if [ -e /lib/ld-linux-armhf.so.3 ] || [ -e /lib/ld-musl-armhf.so.1 ] || [ -d /lib/arm-linux-gnueabihf ]; then
      ARCH=armhf
    else
      ARCH=armel
    fi ;;
  armv6l|armv6*|armv5*)
    ARCH=armel ;;
  *) die "不支持的架构: $MACH（包提供 amd64 / amd64-v2 / amd64-v3 / arm64 / armhf / armel）" ;;
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

# ---------------------------------------------------------------- 老面板迁移（探测）
# 老 Node 面板默认装在 /opt/ocserv-panel，配置里有证书/用户库/域名/端口。
# 探测到就按迁移模式安装：沿用这些值、导入老面板账号、迁移 ACME 凭据、停用老服务。
cfg_get() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$OLD_CFG" "$1" <<'PYGET' || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
v = d.get(sys.argv[2], "")
if isinstance(v, (dict, list)):
    v = ""
if isinstance(v, bool):
    v = "true" if v else "false"
print(v)
PYGET
  else
    sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\{0,1\}\([^",}]*\)"\{0,1\}.*/\1/p' "$OLD_CFG" 2>/dev/null | head -1
  fi
}

MIGRATING=0
OLD_CFG=""
if [ "$MIGRATE" = 1 ]; then
  if [ -n "$FROM_PANEL" ]; then
    [ -f "$FROM_PANEL/config.json" ] || die "--from-panel 里没有 config.json: $FROM_PANEL"
    OLD_CFG="$FROM_PANEL/config.json"
  elif [ -f "$PANEL_DIR/config.json" ]; then
    OLD_CFG="$PANEL_DIR/config.json"
  elif [ "$INIT" = systemd ] && [ -f /etc/systemd/system/ocserv-panel.service ]; then
    WD=$(sed -n 's/^WorkingDirectory=//p' /etc/systemd/system/ocserv-panel.service | head -1)
    if [ -n "$WD" ] && [ -f "$WD/config.json" ]; then OLD_CFG="$WD/config.json"; fi
  fi
fi

OLD_DOMAIN=""; OLD_CERT=""; OLD_KEY=""; OLD_USERS=""; OLD_SVC=""
OLD_GOPORT=""; OLD_GONET=""; OLD_GODNS=""; OLD_GOMTU=""; OLD_PPORT=""

if [ -n "$OLD_CFG" ]; then
  MIGRATING=1
  OLD_DOMAIN=$(cfg_get acmeDomain)
  OLD_CERT=$(cfg_get certFile)
  OLD_KEY=$(cfg_get keyFile)
  OLD_USERS=$(cfg_get ocpasswd)
  OLD_SVC=$(cfg_get ocservService)
  OLD_GOPORT=$(cfg_get goPort)
  OLD_GONET=$(cfg_get goNet)
  OLD_GODNS=$(cfg_get goDNS)
  OLD_GOMTU=$(cfg_get goMTU)
  OLD_PPORT=$(cfg_get port)
  [ -n "$OLD_PPORT" ] || OLD_PPORT=19999

  # 用户没显式指定的参数，沿用老面板里的值
  if [ "$DOMAIN_SET" = 0 ] && [ -n "$OLD_DOMAIN" ]; then DOMAIN="$OLD_DOMAIN"; fi
  if [ "$PORT_SET" = 0 ] && [ -n "$OLD_GOPORT" ] && [ "$OLD_GOPORT" != "0" ]; then PORT="$OLD_GOPORT"; fi
  if [ "$NET_SET" = 0 ] && [ -n "$OLD_GONET" ]; then NET="$OLD_GONET"; fi
  if [ "$DNS_SET" = 0 ] && [ -n "$OLD_GODNS" ]; then DNS="$OLD_GODNS"; fi
  if [ "$MTU_SET" = 0 ] && [ -n "$OLD_GOMTU" ] && [ "$OLD_GOMTU" != "0" ]; then MTU="$OLD_GOMTU"; fi

  if [ "$CERT_SET" = 0 ]; then
    if [ -n "$OLD_CERT" ] && [ -s "$OLD_CERT" ]; then
      CERT="$OLD_CERT"
    elif [ -s "/etc/ssl/securev/$DOMAIN/fullchain.pem" ]; then
      CERT="/etc/ssl/securev/$DOMAIN/fullchain.pem"
    fi
  fi
  if [ "$KEY_SET" = 0 ]; then
    if [ -n "$OLD_KEY" ] && [ -s "$OLD_KEY" ]; then
      KEY="$OLD_KEY"
    elif [ -n "$CERT" ] && [ -s "$(dirname "$CERT")/privkey.pem" ]; then
      KEY="$(dirname "$CERT")/privkey.pem"
    fi
  fi

  # 用户库：老面板指向哪个文件就继续用那个文件；不是默认路径时复制过来，方便维护
  if [ "$USERS_SET" = 0 ] && [ -n "$OLD_USERS" ] && [ -s "$OLD_USERS" ] && [ "$OLD_USERS" != "$USERS" ]; then
    mkdir -p "$(dirname "$USERS")"
    if [ ! -s "$USERS" ]; then
      cp -p "$OLD_USERS" "$USERS" 2>/dev/null || true
      if [ -s "$USERS" ]; then echo "    用户库已复制: $OLD_USERS -> $USERS"; fi
    fi
  fi

  say "检测到老面板，按迁移模式安装"
  echo "    老面板配置: $OLD_CFG"
  echo "    沿用域名:   $DOMAIN"
  echo "    沿用端口:   $PORT（面板 $OLD_PPORT）"
  if [ -n "$CERT" ]; then echo "    沿用证书:   $CERT"; else echo "    证书:       老面板没有可用证书，稍后生成自签"; fi
  echo "    沿用用户库: $USERS"
fi

# ---------------------------------------------------------------- 已有面板配置（重装/升级）
# 这台机器以前装过 ocserv-go：端口/网段/证书等可能已经在面板里改过，
# 重跑 install.sh 时沿用 panel.json，避免把参数打回默认值（比如把 8443 改回 443）。
PANEL_CFG=/etc/ocserv-go/panel.json
if [ "$MIGRATING" = 0 ] && [ -f "$PANEL_CFG" ]; then
  OLD_CFG="$PANEL_CFG"
  EX_DOMAIN=$(cfg_get domain)
  EX_PORT=$(cfg_get vpnPort)
  EX_NET=$(cfg_get vpnNet)
  EX_MTU=$(cfg_get vpnMtu)
  EX_CERT=$(cfg_get certFile)
  EX_KEY=$(cfg_get keyFile)
  EX_USERS=$(cfg_get usersFile)
  EX_LISTEN=$(cfg_get listen)
  EX_DNS=$(tr -d '\n' < "$PANEL_CFG" | sed -n 's/.*"vpnDns"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' | tr -d '" ' | sed 's/,$//')
  OLD_CFG=""

  if [ "$DOMAIN_SET" = 0 ] && [ -n "$EX_DOMAIN" ]; then DOMAIN="$EX_DOMAIN"; fi
  if [ "$PORT_SET" = 0 ] && [ -n "$EX_PORT" ] && [ "$EX_PORT" != "0" ]; then PORT="$EX_PORT"; fi
  if [ "$NET_SET" = 0 ] && [ -n "$EX_NET" ]; then NET="$EX_NET"; fi
  if [ "$MTU_SET" = 0 ] && [ -n "$EX_MTU" ] && [ "$EX_MTU" != "0" ]; then MTU="$EX_MTU"; fi
  if [ "$DNS_SET" = 0 ] && [ -n "$EX_DNS" ]; then DNS="$EX_DNS"; fi
  if [ "$CERT_SET" = 0 ] && [ -n "$EX_CERT" ] && [ -s "$EX_CERT" ]; then CERT="$EX_CERT"; fi
  if [ "$KEY_SET" = 0 ] && [ -n "$EX_KEY" ] && [ -s "$EX_KEY" ]; then KEY="$EX_KEY"; fi
  if [ "$USERS_SET" = 0 ] && [ -n "$EX_USERS" ] && [ -s "$EX_USERS" ] && [ "$EX_USERS" != "$USERS" ] && [ ! -s "$USERS" ]; then
    mkdir -p "$(dirname "$USERS")"
    cp -p "$EX_USERS" "$USERS" 2>/dev/null || true
  fi

  say "检测到已有面板配置，沿用其中的参数"
  echo "    $PANEL_CFG"
  echo "    域名/端口: $DOMAIN / $PORT"
  echo "    网段/MTU:  $NET / $MTU"
  [ -n "$EX_LISTEN" ] && echo "    面板监听:  $EX_LISTEN"
fi

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

# 没找到老面板配置但系统里有老 ocserv：只提醒（不动它，避免误伤）
if [ "$MIGRATING" = 0 ]; then
  case "$INIT" in
    systemd)
      if systemctl is-active ocserv >/dev/null 2>&1; then
        warn "检测到老的 ocserv 服务正在运行，可能占用端口；要停用它：systemctl disable --now ocserv ocserv-nat ocserv-panel"
      fi ;;
    openrc)
      if [ -f /etc/init.d/ocserv ] && rc-service ocserv status >/dev/null 2>&1; then
        warn "检测到老的 ocserv 服务正在运行，可能占用端口；要停用它：rc-service ocserv stop && rc-update del ocserv default"
      fi ;;
  esac
fi

# ---------------------------------------------------------------- 停用老服务
# 老面板在跑的话，老 C 版 ocserv 会占着同一个端口，必须先停掉再起新的。
# 只 stop + disable，不删单元/配置，随时可以回滚。
if [ "$MIGRATING" = 1 ]; then
  say "停用老服务（保留文件，可回滚）"
  BK="/var/backups/ocserv-go/migrate-$(date +%s)"
  mkdir -p "$BK"
  [ -f "$OLD_CFG" ] && cp -a "$OLD_CFG" "$BK/old-panel-config.json" 2>/dev/null || true
  for f in /etc/systemd/system/ocserv.service /etc/systemd/system/ocserv-nat.service \
           /etc/systemd/system/ocserv-panel.service /etc/init.d/ocserv /etc/init.d/ocserv-nat \
           /etc/init.d/ocserv-panel /etc/ocserv/ocserv.conf; do
    [ -e "$f" ] && cp -a "$f" "$BK/" 2>/dev/null || true
  done
  echo "    备份: $BK"

  OLD_SERVICES=""
  add_old_svc() {
    case " $OLD_SERVICES " in
      *" $1 "*) ;;
      *) OLD_SERVICES="${OLD_SERVICES:+$OLD_SERVICES }$1" ;;
    esac
  }
  [ -n "$OLD_SVC" ] && add_old_svc "$OLD_SVC"
  add_old_svc ocserv
  add_old_svc ocserv-nat
  add_old_svc ocserv-panel
  for svc in $OLD_SERVICES; do
    case "$INIT" in
      systemd)
        if systemctl cat "$svc" >/dev/null 2>&1 || [ -f "/etc/systemd/system/$svc.service" ]; then
          systemctl disable --now "$svc" >/dev/null 2>&1 || true
          echo "    已停止并禁用: $svc"
        fi ;;
      openrc)
        if [ -f "/etc/init.d/$svc" ]; then
          rc-service "$svc" stop >/dev/null 2>&1 || true
          rc-update del "$svc" default >/dev/null 2>&1 || true
          echo "    已停止并移出 default: $svc"
        fi ;;
    esac
  done
fi

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
  # 迁移时沿用老面板的监听端口（书签/反代不用改）
  if [ "$MIGRATING" = 1 ] && [ -n "$OLD_PPORT" ]; then PANEL_PORT="$OLD_PPORT"; fi
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

  if [ "$MIGRATING" = 1 ]; then
    # -import 会把老面板的账号（scrypt）、证书路径、端口、用户库带过来
    if PANEL_OUT=$("$PREFIX/ocserv-go" panel -config "$PANEL_CFG" -import "$OLD_CFG" -init 2>&1); then
      echo "    已从老面板导入账号与设置（密码沿用老面板的，scrypt 兼容）"
      printf '%s\n' "$PANEL_OUT" | grep '管理员账号' | sed 's/^/    /' || true
    else
      warn "从老面板导入失败（$PANEL_OUT），改为新建 admin"
      "$PREFIX/ocserv-go" panel -config "$PANEL_CFG" -set-password "admin:$PANEL_PW" -init >/dev/null 2>&1 || true
      echo "    面板账号: admin / $PANEL_PW   （请尽快在面板里修改）"
    fi
  else
    "$PREFIX/ocserv-go" panel -config "$PANEL_CFG" -set-password "admin:$PANEL_PW" -init >/dev/null 2>&1 \
      || warn "面板配置初始化失败（可手动：ocserv-go panel -config $PANEL_CFG -set-password admin:新密码 -init）"
    echo "    面板账号: admin / $PANEL_PW   （请尽快在面板里修改）"
  fi
else
  echo "    已存在 $PANEL_CFG，保留现有配置与账号"
fi

# ---------------------------------------------------------------- ACME 凭据迁移
# 老面板用 acme.sh 续期，DNS 服务商 API Key 存在 /root/.acme.sh/account.conf。
# 迁移过来后内置续期循环可以直接接着用（不需要重新填 token）。
if [ "$MIGRATING" = 1 ] && [ ! -f /etc/ocserv-go/acme.json ] && [ -n "$OLD_DOMAIN" ] && [ "$OLD_DOMAIN" = "$DOMAIN" ]; then
  ACC=/root/.acme.sh/account.conf
  if [ -f "$ACC" ]; then
    acme_val() { sed -n "s/^SAVED_$1='\\{0,1\\}\\([^']*\\)'\\{0,1\\}\$/\\1/p" "$ACC" | head -1; }
    CF_T=$(acme_val CF_Token)
    ALI_K=$(acme_val Ali_Key);        ALI_S=$(acme_val Ali_Secret)
    TC_ID=$(acme_val Tencent_SecretId); TC_K=$(acme_val Tencent_SecretKey)
    DP_ID=$(acme_val DP_Id);          DP_K=$(acme_val DP_Key)
    ACME_PROVIDER=""; ACME_ENV=""
    if [ -n "$CF_T" ]; then
      ACME_PROVIDER=cloudflare; ACME_ENV="CF_DNS_API_TOKEN=$CF_T"
    elif [ -n "$ALI_K" ] && [ -n "$ALI_S" ]; then
      ACME_PROVIDER=alidns
      ACME_ENV="ALICLOUD_ACCESS_KEY=$ALI_K
ALICLOUD_SECRET_KEY=$ALI_S"
    elif [ -n "$TC_ID" ] && [ -n "$TC_K" ]; then
      ACME_PROVIDER=tencentcloud
      ACME_ENV="TENCENTCLOUD_SECRET_ID=$TC_ID
TENCENTCLOUD_SECRET_KEY=$TC_K"
    elif [ -n "$DP_ID" ] && [ -n "$DP_K" ]; then
      ACME_PROVIDER=dnspod; ACME_ENV="DNSPOD_API_KEY=$DP_ID,$DP_K"
    fi
    if [ -n "$ACME_PROVIDER" ]; then
      printf '%s\n' "$ACME_ENV" > /etc/ocserv-go/acme.env
      chmod 600 /etc/ocserv-go/acme.env
      cat > /etc/ocserv-go/acme.json <<JSON
{
  "domain": "$DOMAIN",
  "provider": "$ACME_PROVIDER",
  "envFile": "/etc/ocserv-go/acme.env",
  "cacheDir": "/etc/ocserv-go/acme"
}
JSON
      chmod 600 /etc/ocserv-go/acme.json
      echo "    已迁移 ACME 凭据: $ACME_PROVIDER（来自 acme.sh，证书到期前自动续期）"
    else
      echo "    acme.sh 里没有可迁移的 DNS 凭据（可在面板「证书」页重新填写）"
    fi
  fi
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
if [ "$MIGRATING" = 1 ]; then
echo "    迁移:   老面板已导入；老 ocserv / NAT / 面板服务已停用（未删除，可回滚）"
fi
echo
echo "  客户端连接: 任意 AnyConnect 兼容客户端 → $DOMAIN:$PORT"
case "$INIT" in
  systemd) PANEL_STATUS_HINT="systemctl status $SVC-panel" ;;
  openrc)  PANEL_STATUS_HINT="rc-service $SVC-panel status" ;;
  *)       PANEL_STATUS_HINT="面板未托管（手动运行）" ;;
esac
echo "  管理面板:   http://<本机IP>:$PANEL_PORT/  ($PANEL_STATUS_HINT)"
echo
if [ ! -f /etc/ocserv-go/acme.json ]; then
echo "  换正式证书（内置 Let's Encrypt DNS-01，无需 80 端口）:"
echo "    cat > /etc/ocserv-go/acme.env <<'EOF'"
echo "    CF_DNS_API_TOKEN=xxxx        # 或 ALICLOUD_ACCESS_KEY/SECRET、TENCENTCLOUD_SECRET_ID/KEY、DNSPOD_API_KEY"
echo "    EOF"
echo "    chmod 600 /etc/ocserv-go/acme.env"
echo "    $PREFIX/ocserv-go -acme-once -acme-domain $DOMAIN -acme-dns cloudflare \\"
echo "      -acme-env /etc/ocserv-go/acme.env -acme-cache /etc/ocserv-go/acme \\"
echo "      -cert $CERT -key $KEY"
echo "    然后重启服务即可。"
else
echo "  内置 ACME 已配置（$(sed -n 's/.*"provider": *"\([^"]*\)".*/\1/p' /etc/ocserv-go/acme.json | head -1)）：证书到期前会自动续期，凭据在 /etc/ocserv-go/acme.env"
fi
