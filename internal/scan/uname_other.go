//go:build !linux

package scan

// unameMachine is unavailable off Linux; callers fall back to GOARCH.
func unameMachine() string { return "" }
