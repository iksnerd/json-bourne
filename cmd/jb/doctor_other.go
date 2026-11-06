//go:build !unix

package main

import "os"

func writableDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o200 == 0 {
		return os.ErrPermission
	}
	return nil
}

func writableFile(p string) error { return writableDir(p) }

func ownerMismatch(os.FileInfo) string { return "" }
