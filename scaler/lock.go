package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Lock is an advisory file lock shared by `run` and `deploy`, so the autoscaler never
// changes replica counts in the middle of a rolling deploy (or the other way round).
type Lock struct{ f *os.File }

// TryLock returns (nil, nil) if somebody else holds the lock.
func TryLock(dir string) (*Lock, error) {
	f, err := os.OpenFile(filepath.Join(dir, "xbase-scaler.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, nil
		}
		return nil, fmt.Errorf("flock: %w", err)
	}
	return &Lock{f}, nil
}

func (l *Lock) Unlock() {
	if l != nil && l.f != nil {
		_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
		l.f.Close()
	}
}
