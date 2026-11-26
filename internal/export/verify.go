package export

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tswierszcz/tekmerion/internal/jsonx"
)

var mdLink = regexp.MustCompile(`\]\(([^)\s]+)\)`)

// Verify checks an export directory: report.json parses with its schema,
// every indexed artifact and file matches its hash, and every relative link
// in report.md and reproducer READMEs resolves inside the export.
func Verify(dir string) error {
	read := func(rel string) ([]byte, error) {
		return os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	}
	raw, err := read("evidence/index.json")
	if err != nil {
		return err
	}
	var idx Index
	if err := jsonx.Decode(raw, &idx, false); err != nil || idx.Schema != IndexSchema {
		return fmt.Errorf("evidence index: %v", err)
	}
	for _, e := range idx.Artifacts {
		b, err := read(e.Path)
		if err != nil {
			return err
		}
		if hash(b) != e.SHA || int64(len(b)) != e.Size || e.Path != "evidence/artifacts/"+strings.TrimPrefix(e.SHA, "sha256:") {
			return fmt.Errorf("artifact %s does not match its hash", e.Path)
		}
	}
	for rel, sha := range idx.Files {
		if rel == "evidence/index.json" {
			continue
		}
		b, err := read(rel)
		if err != nil {
			return err
		}
		if hash(b) != sha {
			return fmt.Errorf("file %s does not match its hash", rel)
		}
	}
	raw, err = read("report.json")
	if err != nil {
		return err
	}
	var r Report
	if err := jsonx.Decode(raw, &r, false); err != nil || r.Schema != ReportSchema {
		return fmt.Errorf("report.json: %v", err)
	}
	if md, err := read("report.md"); err != nil || string(md) != Markdown(&r) {
		return fmt.Errorf("report.md does not match report.json")
	}
	for rel := range idx.Files {
		if !strings.HasSuffix(rel, ".md") {
			continue
		}
		b, err := read(rel)
		if err != nil {
			return err
		}
		for _, m := range mdLink.FindAllStringSubmatch(string(b), -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "#") {
				continue
			}
			p := path.Clean(path.Join(path.Dir(rel), target))
			if strings.HasPrefix(p, "../") || p == ".." || path.IsAbs(p) {
				return fmt.Errorf("%s links outside the export: %s", rel, target)
			}
			if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(p))); err != nil {
				return fmt.Errorf("%s has a broken link: %s", rel, target)
			}
		}
	}
	// Every evidence path the report names must exist.
	var paths []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for _, y := range x {
				walk(y)
			}
		case []any:
			for _, y := range x {
				walk(y)
			}
		case string:
			if strings.HasPrefix(x, "evidence/") {
				paths = append(paths, x)
			}
		}
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return err
	}
	walk(generic)
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(p))); err != nil {
			return fmt.Errorf("report names missing evidence %s", p)
		}
	}
	return nil
}
