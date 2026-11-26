package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func limits() Limits {
	return Limits{WallSeconds: 20, CPUSeconds: 10, MemoryBytes: 128 << 20, Tasks: 32, FileSizeBytes: 64 << 10, OpenFiles: 64, OutputBytes: 4 << 10}
}

func needSandbox(t *testing.T) {
	t.Helper()
	if err := Available(); err != nil {
		t.Skip(err)
	}
	// A scope needs a reachable user manager; skip rather than fail on CI hosts without one.
	if err := runQuiet("systemd-run", "--user", "--scope", "--quiet", "--collect", "true"); err != nil {
		t.Skip("systemd user scope unavailable: ", err)
	}
}

func TestLimitsValidate(t *testing.T) {
	if err := limits().Validate(); err != nil {
		t.Fatal(err)
	}
	l := limits()
	l.Tasks = 0
	if l.Validate() == nil {
		t.Fatal("zero limit accepted as unlimited")
	}
}

func TestCommandRejectsUnsafeMounts(t *testing.T) {
	dir := t.TempDir()
	for _, m := range []Mount{{Host: dir, Path: "/usr/x", Writable: true}, {Host: dir, Path: "/"}, {Host: dir, Path: "rel"}, {Host: "rel", Path: "/x"}, {Host: dir, Path: "/x/../usr"}} {
		if _, err := command(Spec{Argv: []string{"true"}, Dir: "/x", Limits: limits(), Mounts: []Mount{m}}, "u"); err == nil {
			t.Fatalf("mount %+v accepted", m)
		}
	}
	if _, err := command(Spec{Argv: []string{"true"}, Dir: "/x", Limits: limits(), Env: map[string]string{"A=B": "x"}}, "u"); err == nil {
		t.Fatal("invalid environment name accepted")
	}
}

func TestProbeEnforcement(t *testing.T) {
	needSandbox(t)
	c, err := Probe(context.Background(), limits(), filepath.Join(t.TempDir(), "probe"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range c.Checks {
		if !v.OK {
			t.Errorf("%s: expected %s, observed %q", v.Name, v.Expected, v.Observed)
		}
	}
	if !c.OK || c.Error != "" || len(c.Checks) < 17 {
		t.Fatalf("capabilities not established: %s / %s", c.Probe.Stdout, c.Probe.Stderr)
	}
}

func TestRunWriteBoundaryTimeoutAndOutputCap(t *testing.T) {
	needSandbox(t)
	ctx := context.Background()
	root := t.TempDir()
	rw, ro := filepath.Join(root, "rw"), filepath.Join(root, "ro")
	os.Mkdir(rw, 0700)
	os.Mkdir(ro, 0700)
	l := limits()
	r, err := Run(ctx, Spec{Argv: []string{"/bin/sh", "-c", "echo ok > /w/a; echo bad > /r/b; echo bad > " + root + "/c; exit 3"}, Dir: "/w", Limits: l,
		Mounts: []Mount{{Host: rw, Path: "/w", Writable: true}, {Host: ro, Path: "/r"}}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != 3 {
		t.Fatalf("exit %d, stderr %s", r.Exit, r.Stderr)
	}
	if _, err := os.Stat(filepath.Join(rw, "a")); err != nil {
		t.Fatal("writable mount not written")
	}
	for _, p := range []string{filepath.Join(ro, "b"), filepath.Join(root, "c")} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("write escaped the boundary: %s", p)
		}
	}
	l.WallSeconds = 1
	r, err = Run(ctx, Spec{Argv: []string{"/bin/sh", "-c", "sleep 30 & sleep 30"}, Dir: "/", Limits: l})
	if err != nil {
		t.Fatal(err)
	}
	if !r.TimedOut || r.DurationMS > 10_000 {
		t.Fatalf("wall limit not enforced: %+v", r)
	}
	l.WallSeconds = 20
	r, err = Run(ctx, Spec{Argv: []string{"/bin/sh", "-c", "head -c 100000 /dev/zero | tr '\\0' x"}, Dir: "/", Limits: l})
	if err != nil {
		t.Fatal(err)
	}
	if !r.StdoutTruncated || int64(len(r.Stdout)) != l.OutputBytes || !strings.HasPrefix(string(r.Stdout), "xxx") {
		t.Fatalf("output cap not applied: %d %t", len(r.Stdout), r.StdoutTruncated)
	}
}

func runQuiet(name string, args ...string) error { return exec.Command(name, args...).Run() }
