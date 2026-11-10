# Authway Server: build the web UI, then the server with the UI inside, then a small image with the tools it calls.
# The first two stages run on the machine that builds, for any target: Go cross-compiles, only the last stage is of
# the target. docker buildx build --platform linux/amd64,linux/arm64 .
FROM --platform=$BUILDPLATFORM node:22-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS server
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=ui /src/internal/admin/ui/dist ./internal/admin/ui/dist
ARG TARGETOS
ARG TARGETARCH
# empty: the version of the source, in cmd/authway-server/main.go. Set it to tell builds apart: 0.2.0+abc1234
ARG VERSION=
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w ${VERSION:+-X main.version=$VERSION}" -o /out/authway-server ./cmd/authway-server

FROM alpine:3.22
# iproute2 and nftables are needed; conntrack forgets the redirected connections at login; wg is only for looking
# at the tunnels: docker exec authway-server wg show
RUN apk add --no-cache iproute2 nftables conntrack-tools wireguard-tools-wg ca-certificates tzdata
COPY --from=server /out/authway-server /usr/local/bin/authway-server
ENV AUTHWAY_DATA=/data
VOLUME /data
EXPOSE 51820/udp 8443/tcp
# /healthz of the web UI: unhealthy when the configuration isn't applied, WireGuard can't be read, the database
# doesn't answer or the loop of the sessions is stuck. docker ps shows it
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 CMD ["/usr/local/bin/authway-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/authway-server"]
