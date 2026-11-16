# 无特权可运行：不需要 --privileged / --device / --cap-add
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/ocserv-go .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/ocserv-go /usr/local/bin/ocserv-go
USER 65534:65534
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/ocserv-go"]
