//go:build linux

package vulndb

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestDatabaseLockReleasedOnProcessDeath(t *testing.T) {
	if dir := os.Getenv("BSCAN_TEST_LOCK_CHILD"); dir != "" {
		unlock, err := lockDatabase(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		fmt.Println("LOCKED")
		time.Sleep(time.Minute)
		return
	}
	dir := filepath.Join(t.TempDir(), "db")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDatabaseLockReleasedOnProcessDeath$")
	cmd.Env = append(os.Environ(), "BSCAN_TEST_LOCK_CHILD="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "LOCKED\n" {
		t.Fatalf("child readiness %q: %v", line, err)
	}
	if unlock, err := lockDatabase(dir); err == nil {
		unlock()
		t.Fatal("second process acquired held lock")
	}
	before, err := os.Stat(dir + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	unlock, err := lockDatabase(dir)
	if err != nil {
		t.Fatalf("dead process left lock held: %v", err)
	}
	unlock()
	unlock() // Cleanup can safely be deferred as well as called explicitly.
	after, err := os.Stat(dir + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("lock inode was removed/recreated")
	}
}

func TestDatabaseLockRejectsSymlink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dir+".lock"); err != nil {
		t.Fatal(err)
	}
	if unlock, err := lockDatabase(dir); err == nil {
		unlock()
		t.Fatal("symlink lock accepted")
	}
}
