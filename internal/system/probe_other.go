//go:build !linux

package system

// systemProbe makes the values up: /proc is only on Linux
func systemProbe(dataDir string) Probe {
	return Simulated()
}
