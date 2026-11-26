package recon

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"encoding/json"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/state"
)

// addDocuments indexes only common documentation/test paths inside the pinned
// exported source. A deterministic cap prevents silently loading a repository.
func addDocuments(ctx context.Context, s *state.Store, v *prepare.Verified, c *Context, limits Limits) error {
	type document struct{ path, kind string }
	docs := []document{}
	err := filepath.WalkDir(filepath.Join(v.Work, "src"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(filepath.Join(v.Work, "src"), path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		lower := strings.ToLower(d.Name())
		kind := ""
		if strings.HasPrefix(lower, "readme") || strings.HasPrefix(lower, "security.") || strings.HasPrefix(lower, "threat-model.") || strings.HasPrefix(rel, "docs/") && strings.HasSuffix(lower, ".md") {
			kind = "documentation"
		}
		if strings.HasSuffix(d.Name(), "Test.java") || strings.Contains(rel, "/test/") && strings.HasSuffix(lower, ".java") {
			kind = "test"
		}
		if kind != "" {
			docs = append(docs, document{rel, kind})
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].path < docs[j].path })
	accepted := 0
	for _, doc := range docs {
		if accepted >= 4 {
			break
		}
		raw, err := prepare.ReadFile(filepath.Join(v.Work, "src"), doc.path, 256<<10)
		if err != nil || !utf8.Valid(raw) {
			c.Gaps = append(c.Gaps, fmt.Sprintf("%s context unavailable: %s", doc.kind, doc.path))
			continue
		}
		lines := strings.Split(string(raw), "\n")
		end := min(len(lines), limits.Lines)
		excerpt := Excerpt{Kind: doc.kind, Citation: Citation{Path: doc.path, SHA: hash(raw), Start: 1, End: end}, Text: strings.Join(lines[:end], "\n")}
		c.Excerpts = append(c.Excerpts, excerpt)
		data, _ := json.Marshal(c)
		if len(data) > limits.MaxBytes-2048 {
			c.Excerpts = c.Excerpts[:len(c.Excerpts)-1]
			c.Gaps = append(c.Gaps, "documentation/test context deferred after byte limit")
			break
		}
		if _, err := s.Put(ctx, raw, "text/plain"); err != nil {
			return err
		}
		accepted++
	}
	if len(docs) == 0 {
		c.Gaps = append(c.Gaps, "no README/security/test documents were available in the exported source")
	}
	if len(docs) > accepted {
		c.Gaps = append(c.Gaps, fmt.Sprintf("documentation/test files not included in context: %d", len(docs)-accepted))
	}
	return nil
}
