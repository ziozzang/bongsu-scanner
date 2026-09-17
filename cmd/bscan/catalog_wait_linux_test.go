//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAcceptanceCatalogLockWait(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "1")
	db := privateCLITestDB(t)
	for _, command := range []string{"export", "status", "verify"} {
		for _, mode := range []int{syscall.LOCK_EX, syscall.LOCK_SH} {
			if mode == syscall.LOCK_SH && command != "export" {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", command, mode), func(t *testing.T) {
				lock, err := os.OpenFile(db+".lock", os.O_CREATE|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				if err := syscall.Flock(int(lock.Fd()), mode|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
				released := make(chan struct{})
				timer := time.AfterFunc(200*time.Millisecond, func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); close(released) })
				defer func() {
					if timer.Stop() {
						_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
					} else {
						<-released
					}
				}()
				args := []string{"db", command, "--db", db}
				output := filepath.Join(t.TempDir(), "catalog.tar.gz")
				if command == "export" {
					args = append(args, output)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				stdout, stderr, err := captureCommandStreams(t, func() error { return run(ctx, args) })
				if err != nil || stdout == "" || strings.Count(stderr, "catalog busy (another bscan process holds the lock); retrying…") != 1 {
					t.Fatalf("err=%v stdout=%s stderr=%s", err, stdout, stderr)
				}
				if command == "export" {
					if st, err := os.Stat(output); err != nil || st.Size() == 0 {
						t.Fatalf("export missing: %v", err)
					}
				}
			})
		}
	}
}

func TestCatalogWaitBoundAndCancellation(t *testing.T) {
	busy := fmt.Errorf("database is locked or unavailable: %w", syscall.EWOULDBLOCK)
	t.Run("bounded", func(t *testing.T) {
		calls := 0
		start := time.Now()
		_, err := captureBatchStderr(t, func() error {
			return waitForCatalog(context.Background(), 20*time.Millisecond, func() error { calls++; return busy })
		})
		if err == nil || !strings.Contains(err.Error(), "catalog busy") || !strings.Contains(err.Error(), "timed out") || calls < 2 || time.Since(start) > time.Second {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	})
	t.Run("canceled while waiting", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		_, err := captureBatchStderr(t, func() error { return waitForCatalog(ctx, time.Second, func() error { calls++; cancel(); return busy }) })
		if !errors.Is(err, context.Canceled) || exitCode(err) != 130 || calls != 1 {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	})
	t.Run("unavailable is not busy", func(t *testing.T) {
		calls := 0
		denied := fmt.Errorf("database lock unavailable: %w", os.ErrPermission)
		err := waitForCatalog(context.Background(), time.Second, func() error { calls++; return denied })
		if !errors.Is(err, os.ErrPermission) || calls != 1 {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	})
}
