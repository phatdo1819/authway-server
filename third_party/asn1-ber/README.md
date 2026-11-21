# asn1-ber v1.5.8, patched for Go 1.27

This is [github.com/go-asn1-ber/asn1-ber](https://github.com/go-asn1-ber/asn1-ber) v1.5.8, the BER encoding that the
LDAP client (github.com/go-ldap/ldap/v3) uses, without its tests. `go.mod` points to it with a `replace` line.

The only change: `ber.go` calls `io.ReadAll` instead of `ioutil.ReadAll`, which does the same thing. Go 1.27 no longer
has `io/ioutil`, and no release of asn1-ber has dropped it yet.

Delete this folder and the `replace` line in `go.mod` once a release of asn1-ber builds with the Go of the Dockerfile.
