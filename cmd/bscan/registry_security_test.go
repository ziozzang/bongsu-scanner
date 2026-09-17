package main

import (
	"context"
	"strings"
	"testing"
)

func TestRegistrySecurityRejectedTargetRedaction(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, command := range []string{"scan", "batch"} {
		for _, target := range []string{
			"registry://secret-user:secret-password@registry.example/org/image?secret-query=token",
			"oci://secret-user:secret-password@registry.example/org/image",
			"registry://bad%secret-user:secret-password@registry.example/org/image?secret-query=token",
		} {
			args := []string{command, "--no-sign", target}
			// Duplicate invalid targets used to leak through batch output-name validation too.
			if command == "batch" {
				args = append(args, target)
			}
			stdout, stderr, err := captureCommandStreams(t, func() error { return run(context.Background(), args) })
			if err == nil || !strings.Contains(err.Error(), "invalid registry reference") {
				t.Fatalf("invalid reference: %v", err)
			}
			for _, secret := range []string{"secret-user", "secret-password", "secret-query"} {
				if strings.Contains(stdout+stderr+err.Error(), secret) {
					t.Fatalf("%s leaked %s: %s %s %v", command, secret, stdout, stderr, err)
				}
			}
		}
	}
}
