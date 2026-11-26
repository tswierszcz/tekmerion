package recon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/prepare"
)

func TestAriadnePreparedControlRecon(t *testing.T) {
	src := os.Getenv("ARIADNE_SRC")
	if src == "" {
		t.Skip("ARIADNE_SRC not set")
	}
	bin := os.Getenv("ARIADNE_BIN")
	if bin == "" {
		bin = filepath.Join(src, "bin/ariadne")
	}
	project, raw, err := manifest.LoadProject("../../testdata/control/project.json")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	work := filepath.Join(root, "prepared")
	result, err := prepare.Prepare(context.Background(), prepare.Options{Project: project, ProjectRaw: raw, Checkout: src, Work: work, Ariadne: bin})
	if err != nil {
		t.Fatal(err)
	}
	if result.Run.Analysis == nil {
		t.Fatal("missing real bundle")
	}
	dir := filepath.Join(root, "recon")
	q := &ariadne.CLI{Binary: bin, Bundle: filepath.Join(work, "bundle"), Evidence: ariadne.Recorder{Root: filepath.Join(dir, "ariadne-invocations")}}
	if err := Start(context.Background(), Options{Work: work, State: dir, Limits: DefaultLimits(), Offline: true, Querier: q}); err != nil {
		t.Fatal(err)
	}
	if err := Resume(context.Background(), dir, nil); err != nil {
		t.Fatal(err)
	}
	s, snap, _, c := load(t, dir)
	if len(c.Entries) == 0 || len(c.Excerpts) == 0 || len(snap.Coverage) == 0 {
		t.Fatalf("no grounded API/source context: %+v", c)
	}
	for _, e := range c.Evidence {
		if e.Provenance != ariadne.ProvenanceAnalysis || e.ValidationScope != "bundle" || e.InvocationSHA == "" {
			t.Fatalf("missing real/static provenance: %+v", e)
		}
	}
	if err := s.Verify(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	t.Logf("prepared %s; API entries %d; excerpts %d; coverage %d; gaps %v", c.PreparedSHA, len(c.Entries), len(c.Excerpts), len(snap.Coverage), c.Gaps)
}
