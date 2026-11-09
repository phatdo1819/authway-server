[Authway Server](../README.md) › Development

# Development

The server is in Go (`cmd/`, `internal/`), the web UI in Vue with Tailwind CSS (`web/`), built into the binary.

```sh
cd web && npm ci && npm run build && cd ..
go test ./...
go build ./cmd/authway-server
```

Without Linux or WireGuard, `-fake-network` changes nothing on the system, to try the web pages:

```sh
authway-server -fake-network -admin-tls=false -admin-listen 127.0.0.1:8443 -data ./data -dev-peer 10.8.0.2
```

`-dev-peer` makes the requests to the login page of this computer (`http://127.0.0.1:8181/`) count as coming from a
peer address. How it works inside: [docs/design.md](design.md).
