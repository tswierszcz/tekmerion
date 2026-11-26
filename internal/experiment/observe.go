package experiment

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"syscall"
)

// Entry is one filesystem object the worker left behind. Links are never
// followed; special files are recorded by type only.
type Entry struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Mode     string `json:"mode"`
	SHA      string `json:"sha256,omitempty"`
	Link     string `json:"link_target,omitempty"`
	Links    uint64 `json:"hard_links,omitempty"`
	Promoted bool   `json:"promoted"`
}

type Listing struct {
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated"`
}

const (
	maxEntries      = 256
	maxPromotedFile = 1 << 20
	maxPromoted     = 8 << 20
)

func fileType(m fs.FileMode) string {
	switch {
	case m.IsRegular():
		return "file"
	case m.IsDir():
		return "dir"
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m&fs.ModeNamedPipe != 0:
		return "fifo"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeDevice != 0:
		return "device"
	}
	return "other"
}

// Observe walks a directory the terminated worker could write. It must only
// be called after the worker and all its descendants have exited. Reads go
// through an os.Root, use Lstat before Open and compare the opened file with
// the listed one, so a link or a swapped file cannot redirect the host.
// promote receives the bytes of each regular file within the size bounds.
func Observe(dir string, promote func(rel string, b []byte) (string, error)) (Listing, error) {
	l := Listing{Entries: []Entry{}}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return l, err
	}
	defer root.Close()
	var total int64
	var walk func(rel string) error
	walk = func(rel string) error {
		d, err := root.Open(rel)
		if err != nil {
			return err
		}
		names, err := d.Readdirnames(-1)
		d.Close()
		if err != nil {
			return err
		}
		sort.Strings(names)
		for _, name := range names {
			p := path.Join(rel, name)
			if len(l.Entries) >= maxEntries {
				l.Truncated = true
				return nil
			}
			fi, err := root.Lstat(p)
			if err != nil {
				return err
			}
			e := Entry{Path: p, Type: fileType(fi.Mode()), Size: fi.Size(), Mode: fi.Mode().String()}
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && !fi.IsDir() && st.Nlink > 1 {
				e.Links = uint64(st.Nlink)
			}
			switch e.Type {
			case "symlink":
				// Parents are directories listed with Lstat, and the worker
				// has exited, so this path names the listed link itself.
				if t, err := os.Readlink(filepath.Join(dir, filepath.FromSlash(p))); err == nil {
					e.Link = t
				}
			case "file":
				b, err := readRegular(root, p, fi)
				if err != nil {
					return err
				}
				sum := sha256.Sum256(b)
				e.SHA = "sha256:" + hex.EncodeToString(sum[:])
				if promote != nil && e.Size <= maxPromotedFile && total+e.Size <= maxPromoted {
					if _, err := promote(p, b); err != nil {
						return err
					}
					total += e.Size
					e.Promoted = true
				}
			}
			l.Entries = append(l.Entries, e)
			if e.Type == "dir" {
				if err := walk(p); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return l, walk(".")
}

func readRegular(root *os.Root, p string, listed fs.FileInfo) ([]byte, error) {
	f, err := root.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(fi, listed) || fi.Size() != listed.Size() {
		return nil, fmt.Errorf("worker output %s changed during observation", p)
	}
	// File size is bounded by the worker's RLIMIT_FSIZE; read one byte more
	// to detect growth after the listing.
	b, err := io.ReadAll(io.LimitReader(f, fi.Size()+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != fi.Size() {
		return nil, fmt.Errorf("worker output %s changed during observation", p)
	}
	return b, nil
}
