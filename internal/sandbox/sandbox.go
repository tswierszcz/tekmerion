// Package sandbox runs one bounded target worker. Isolation is layered: a
// systemd user scope sets cgroup memory and task limits, prlimit sets CPU,
// file-size, open-file and core limits, and bubblewrap gives a read-only
// system view, private /tmp, no network and a cleared environment. Only the
// declared writable mounts can be changed. Missing tools are reported as
// errors and capability gaps, never silently skipped.
package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const Schema = "tekmerion-sandbox-1"

// Limits bound one worker. Every field is required; zero is never "unlimited".
type Limits struct {
	WallSeconds   int64 `json:"wall_seconds"`
	CPUSeconds    int64 `json:"cpu_seconds"`
	MemoryBytes   int64 `json:"memory_bytes"`
	Tasks         int64 `json:"tasks"`
	FileSizeBytes int64 `json:"file_size_bytes"`
	OpenFiles     int64 `json:"open_files"`
	OutputBytes   int64 `json:"output_bytes"`
}

func (l Limits) Validate() error {
	in := func(v, lo, hi int64) bool { return v >= lo && v <= hi }
	if !in(l.WallSeconds, 1, 600) || !in(l.CPUSeconds, 1, 600) || !in(l.MemoryBytes, 64<<20, 8<<30) || !in(l.Tasks, 8, 4096) ||
		!in(l.FileSizeBytes, 1<<10, 1<<30) || !in(l.OpenFiles, 32, 65536) || !in(l.OutputBytes, 1<<10, 16<<20) {
		return fmt.Errorf("sandbox limits out of bounds (wall/cpu 1..600 s, memory 64 MiB..8 GiB, tasks 8..4096, file size 1 KiB..1 GiB, open files 32..65536, output 1 KiB..16 MiB)")
	}
	return nil
}

// Mount exposes one host path at an absolute sandbox path. Mounts are
// read-only unless Writable; system directories are always read-only.
type Mount struct {
	Host     string `json:"host"`
	Path     string `json:"path"`
	Writable bool   `json:"writable"`
}

// Spec describes one worker. Tmp, when set, is a host directory bound at
// /tmp so the host can observe it; otherwise /tmp is a private tmpfs. The
// root and /dev are read-only, so declared writable mounts and /tmp are the
// only places a worker can create files.
type Spec struct {
	Argv   []string
	Env    map[string]string
	Mounts []Mount
	Dir    string
	Tmp    string
	Limits Limits
}

// Result is what the host observed after the whole worker had terminated.
type Result struct {
	Schema          string   `json:"schema_version"`
	Argv            []string `json:"argv"`
	Wrapper         []string `json:"wrapper"`
	Exit            int      `json:"exit_code"`
	Signal          string   `json:"signal,omitempty"`
	TimedOut        bool     `json:"timed_out"`
	DurationMS      int64    `json:"duration_ms"`
	Stdout          []byte   `json:"stdout"`
	Stderr          []byte   `json:"stderr"`
	StdoutTruncated bool     `json:"stdout_truncated"`
	StderrTruncated bool     `json:"stderr_truncated"`
	Limits          Limits   `json:"limits"`
}

const oomPrelude = `echo 500 > /proc/self/oom_score_adj && exec "$@"`

var tools = []string{"systemd-run", "systemctl", "prlimit", "bwrap"}

// Available reports a missing decisive tool.
func Available() error {
	for _, t := range tools {
		if _, err := exec.LookPath(t); err != nil {
			return fmt.Errorf("sandbox tool %s unavailable: %w", t, err)
		}
	}
	return nil
}

var baseEnv = map[string]string{"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp", "LC_ALL": "C", "TZ": "UTC"}

func envName(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// systemMounts gives a read-only system view. Merged-/usr symlinks are
// recreated; a JAVA_HOME outside /usr is bound read-only.
func systemMounts() []string {
	args := []string{"--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc"}
	for _, d := range []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64"} {
		fi, err := os.Lstat(d)
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if t, err := os.Readlink(d); err == nil {
				args = append(args, "--symlink", t, d)
			}
		} else if fi.IsDir() {
			args = append(args, "--ro-bind", d, d)
		}
	}
	if jh := os.Getenv("JAVA_HOME"); jh != "" && filepath.IsAbs(jh) && !strings.HasPrefix(filepath.Clean(jh)+"/", "/usr/") {
		if fi, err := os.Stat(jh); err == nil && fi.IsDir() {
			args = append(args, "--ro-bind", jh, jh)
		}
	}
	return args
}

func reserved(p string) bool {
	for _, r := range []string{"/usr", "/etc", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/proc", "/dev", "/tmp", "/"} {
		if p == r || strings.HasPrefix(p, r+"/") && r != "/" {
			return true
		}
	}
	return false
}

func command(s Spec, unit string) ([]string, error) {
	if err := s.Limits.Validate(); err != nil {
		return nil, err
	}
	if len(s.Argv) == 0 || s.Dir == "" || !filepath.IsAbs(s.Dir) {
		return nil, fmt.Errorf("sandbox needs argv and an absolute working directory")
	}
	l := s.Limits
	w := []string{"systemd-run", "--user", "--scope", "--quiet", "--collect", "--unit=" + unit,
		"-p", "MemoryMax=" + strconv.FormatInt(l.MemoryBytes, 10), "-p", "MemorySwapMax=0", "-p", "OOMPolicy=continue", "-p", "TasksMax=" + strconv.FormatInt(l.Tasks, 10), "--",
		"prlimit", "--cpu=" + strconv.FormatInt(l.CPUSeconds, 10), "--fsize=" + strconv.FormatInt(l.FileSizeBytes, 10), "--nofile=" + strconv.FormatInt(l.OpenFiles, 10), "--core=0", "--",
		"bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"}
	env := map[string]string{}
	for k, v := range baseEnv {
		env[k] = v
	}
	if jh := os.Getenv("JAVA_HOME"); jh != "" && filepath.IsAbs(jh) {
		env["JAVA_HOME"] = jh
	}
	for k, v := range s.Env {
		if !envName(k) || strings.ContainsAny(v, "\x00\n") {
			return nil, fmt.Errorf("invalid sandbox environment entry %q", k)
		}
		env[k] = v
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		w = append(w, "--setenv", k, env[k])
	}
	w = append(w, systemMounts()...)
	w = append(w, "--proc", "/proc", "--dev", "/dev")
	if s.Tmp != "" {
		if !filepath.IsAbs(s.Tmp) {
			return nil, fmt.Errorf("sandbox tmp must be an absolute host directory")
		}
		if fi, err := os.Lstat(s.Tmp); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("sandbox tmp must be an existing directory")
		}
		w = append(w, "--bind", s.Tmp, "/tmp")
	} else {
		w = append(w, "--tmpfs", "/tmp")
	}
	seen := map[string]bool{}
	for _, m := range s.Mounts {
		p := filepath.Clean(m.Path)
		if !filepath.IsAbs(m.Host) || !filepath.IsAbs(p) || p != m.Path || reserved(p) || seen[p] {
			return nil, fmt.Errorf("invalid sandbox mount %q", m.Path)
		}
		seen[p] = true
		if _, err := os.Lstat(m.Host); err != nil {
			return nil, err
		}
		flag := "--ro-bind"
		if m.Writable {
			flag = "--bind"
		}
		w = append(w, flag, m.Host, p)
	}
	// Raise the worker's OOM score so the kernel never picks the wrapper
	// processes (bubblewrap) as the victim inside the memory-limited scope.
	w = append(w, "--remount-ro", "/dev", "--remount-ro", "/", "--chdir", s.Dir, "--", "/bin/sh", "-c", oomPrelude, "worker")
	return append(w, s.Argv...), nil
}

type capped struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.limit - int64(c.buf.Len())
	if room < int64(len(p)) {
		c.truncated = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

func unitName() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "tekmerion-worker-" + hex.EncodeToString(b)
}

// Run executes the worker and returns only after it and its descendants have
// terminated: the wall timer kills the process group, bubblewrap's
// die-with-parent and PID namespace take down the sandbox, and the scope is
// stopped. A non-zero exit is a result, not an error.
func Run(ctx context.Context, s Spec) (*Result, error) {
	return run(ctx, s, unitName(), nil)
}

func run(ctx context.Context, s Spec, unit string, during func(unit string)) (*Result, error) {
	if err := Available(); err != nil {
		return nil, err
	}
	argv, err := command(s, unit)
	if err != nil {
		return nil, err
	}
	r := &Result{Schema: Schema, Argv: s.Argv, Wrapper: argv[:len(argv)-len(s.Argv)], Limits: s.Limits}
	stdout, stderr := &capped{limit: s.Limits.OutputBytes}, &capped{limit: s.Limits.OutputBytes}
	cmd := exec.Command(argv[0], argv[1:]...)
	// The wrapper itself runs with a minimal host environment: systemd-run
	// needs the user bus; bubblewrap then clears everything for the worker.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for _, k := range []string{"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "TEKMERION_PROBE_LEAK"} {
		if v, ok := os.LookupEnv(k); ok {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if during != nil {
		go during(unit)
	}
	timer := time.NewTimer(time.Duration(s.Limits.WallSeconds) * time.Second)
	defer timer.Stop()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-timer.C:
		r.TimedOut = true
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		waitErr = <-done
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		stop(unit)
		return nil, ctx.Err()
	}
	stop(unit)
	r.DurationMS = time.Since(start).Milliseconds()
	r.Stdout, r.Stderr = stdout.buf.Bytes(), stderr.buf.Bytes()
	r.StdoutTruncated, r.StderrTruncated = stdout.truncated, stderr.truncated
	var ee *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &ee) {
		return nil, waitErr
	}
	ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
	switch {
	case ws.Signaled():
		r.Exit, r.Signal = -1, ws.Signal().String()
	default:
		r.Exit = ws.ExitStatus()
		// bubblewrap reports a signalled child as 128+signal.
		if r.Exit > 128 && r.Exit < 128+65 {
			r.Signal = syscall.Signal(r.Exit - 128).String()
		}
	}
	return r, nil
}

// stop makes sure no process of the scope survives; an already collected
// scope is not an error.
func stop(unit string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "systemctl", "--user", "kill", "--signal=SIGKILL", unit+".scope").Run()
	_ = exec.CommandContext(ctx, "systemctl", "--user", "stop", unit+".scope").Run()
}
