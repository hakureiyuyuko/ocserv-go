# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# ocserv-go 最小化镜像（Alpine）
#
#   docker build -t ocserv-go ./ocserv-go
#   docker run -d --name ocserv-go --restart unless-stopped \
#     -p 443:443/tcp -p 443:443/udp -p 127.0.0.1:19999:19999 \
#     -v $PWD/data/ocserv-go:/etc/ocserv-go \
#     -v $PWD/data/ocserv:/etc/ocserv \
#     -v $PWD/data/certs:/etc/ssl/securev \
#     ocserv-go
#
# 首次启动会打印 VPN 用户密码和面板 admin 密码；数据都在挂载的三个目录里。
# 见 README「Docker 部署」。
# ---------------------------------------------------------------------------

# ---------- 构建 ----------
# 用构建机自己的架构跑编译器（buildx 多架构时避免 QEMU 慢速编译），再交叉编译到目标架构
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
# 先只拷依赖清单，命中缓存时不用重下模块
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN set -eu; \
    goos="${TARGETOS:-$(go env GOOS)}"; \
    goarch="${TARGETARCH:-$(go env GOARCH)}"; \
    goarm=""; \
    if [ "$goarch" = "arm" ]; then goarm="${TARGETVARIANT#v}"; [ -n "$goarm" ] || goarm=7; fi; \
    echo "构建 $goos/$goarch${goarm:+ GOARM=$goarm}"; \
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" \
      go build -trimpath -ldflags "-s -w" -o /out/ocserv-go .

# ---------- 运行 ----------
FROM alpine:3.24
# ca-certificates：内置 ACME / 连接日志查 IP 归属地都要验证 TLS 证书
# tzdata：日志时间按 TZ 显示
RUN apk add --no-cache ca-certificates tzdata \
 && mkdir -p /etc/ocserv-go/assets /etc/ocserv /etc/ssl/securev

COPY --from=build /out/ocserv-go /usr/local/bin/ocserv-go
COPY docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# 首次启动的参数（之后改「面板 → 设置」里的值，持久化在 /etc/ocserv-go/panel.json）
ENV TZ=Asia/Shanghai \
    DOMAIN=vpn.example.com \
    VPN_PORT=443 \
    VPN_NET=10.66.66.0/24 \
    VPN_DNS=1.1.1.1,8.8.8.8 \
    VPN_MTU=1400 \
    PANEL=1 \
    PANEL_LISTEN=:19999 \
    PANEL_PORT=19999

EXPOSE 443/tcp 443/udp 19999/tcp
VOLUME ["/etc/ocserv-go", "/etc/ocserv", "/etc/ssl/securev"]

# 面板起来了就算健康（PANEL=0 时不做检查）
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD sh -c '[ "${PANEL:-1}" = "0" ] || nc -z 127.0.0.1 "${PANEL_PORT:-19999}"'

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
