// Package prepare is TM1 target preparation: it exports a pinned revision
// from an existing checkout, runs the declared build in a fresh work
// directory, records the artifact and classpath hashes, builds the source
// index, runs `ariadne research index` and writes the run manifest.
//
// Work directory layout (the directory must not exist):
//
//	src/               the exported revision, read-only while the build runs
//	out/               build outputs (${OUT})
//	home/ tmp/         HOME and TMPDIR of the build
//	logs/NN-step.{stdout,stderr}
//	bundle/            the Ariadne research bundle
//	source-index.json
//	run-manifest.json
package prepare

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/sourceindex"
)

// Options configure one preparation.
type Options struct {
	Project    *manifest.Project
	ProjectRaw []byte // the project manifest bytes, recorded verbatim
	Checkout   string // an existing git checkout that contains Target.Revision
	Work       string // fresh work directory; must not exist
	// AllowNetwork must be set for a recipe with network "allowed". A
	// recipe with network "none" is isolated whatever this says.
	AllowNetwork bool
	// Ariadne is the ariadne binary; empty skips indexing.
	Ariadne string
	// Sources passes the app's source root to `research index -sources`:
	// "auto" (when the binary lists the flag), "always" or "never".
	Sources string
	Stderr  io.Writer // progress; nil discards
	Now     func() time.Time
}

// Result is a finished preparation.
type Result struct {
	Run       *manifest.Run
	Index     *sourceindex.Index
	Bundle    *ariadne.Bundle // nil without Ariadne
	Work      string
	SourceDir string
	OutDir    string
}

// Prepare runs target preparation and writes run-manifest.json.
func Prepare(ctx context.Context, o Options) (*Result, error) {
	p := o.Project
	if p == nil {
		return nil, errors.New("prepare: no project")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Build.Network == manifest.NetworkAllowed && !o.AllowNetwork {
		return nil, errors.New("prepare: the recipe needs network access; allow it explicitly")
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	switch o.Sources {
	case "":
		o.Sources = "auto"
	case "auto", "always", "never":
	default:
		return nil, fmt.Errorf("prepare: Sources %q", o.Sources)
	}
	work, err := filepath.Abs(o.Work)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(work, 0o755); err != nil {
		return nil, fmt.Errorf("prepare: work directory: %w", err)
	}
	res := &Result{Work: work, SourceDir: filepath.Join(work, "src"), OutDir: filepath.Join(work, "out")}
	for _, d := range []string{"src", "out", "home", "tmp", "logs"} {
		if err := os.Mkdir(filepath.Join(work, d), 0o755); err != nil {
			return nil, err
		}
	}
	run := &manifest.Run{SchemaVersion: manifest.RunSchema, PreparedAt: o.Now().UTC().Truncate(time.Second),
		Project: append([]byte(nil), o.ProjectRaw...), ProjectSHA256: sha256Hex(o.ProjectRaw)}
	res.Run = run

	fmt.Fprintf(o.Stderr, "prepare: exporting %s from %s\n", p.Target.Revision, o.Checkout)
	if run.Source, err = export(ctx, o.Checkout, p.Target, res.SourceDir); err != nil {
		return res, err
	}
	run.Source.Repository = p.Target.Repository

	if run.Build, err = build(ctx, p, run.Source.CommitTime, work, o.Stderr); err != nil {
		return res, err
	}
	tree, _, err := treeHash(res.SourceDir)
	if err != nil {
		return res, err
	}
	if tree != run.Source.TreeSHA256 {
		return res, errors.New("prepare: the build changed the source tree")
	}

	if run.Artifacts, err = artifacts(res.OutDir, p.Build.Outputs); err != nil {
		return res, err
	}

	ix, err := sourceindex.Build(res.SourceDir, res.OutDir, p.Target.SourceRoots)
	if err != nil {
		return res, fmt.Errorf("prepare: source index: %w", err)
	}
	res.Index = ix
	ixFile := filepath.Join(work, "source-index.json")
	if err := ix.Save(ixFile); err != nil {
		return res, err
	}
	f, err := fileRecord(work, "source-index.json")
	if err != nil {
		return res, err
	}
	run.SourceIndex = manifest.SourceIndex{File: f, Methods: len(ix.Entries)}
	for _, e := range ix.Entries {
		if e.Binding == sourceindex.BindingBuildVerified {
			run.SourceIndex.Located++
		}
	}

	if o.Ariadne != "" {
		if run.Analysis, res.Bundle, err = index(ctx, o, p, res, work); err != nil {
			return res, err
		}
	}
	if err := run.Save(filepath.Join(work, "run-manifest.json")); err != nil {
		return res, err
	}
	return res, nil
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	var out, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// export verifies that the checkout has the revision and extracts the
// revision's selected paths (not the working tree) into dst.
func export(ctx context.Context, checkout string, t manifest.Target, dst string) (manifest.Source, error) {
	var s manifest.Source
	got, err := git(ctx, checkout, "rev-parse", "--verify", "--end-of-options", t.Revision+"^{commit}")
	if err != nil {
		return s, fmt.Errorf("prepare: checkout %s does not have revision %s: %w", checkout, t.Revision, err)
	}
	if got != t.Revision {
		return s, fmt.Errorf("prepare: revision %s resolves to %s", t.Revision, got)
	}
	s.Commit = got
	ct, err := git(ctx, checkout, "show", "-s", "--format=%ct", got)
	if err != nil {
		return s, err
	}
	if s.CommitTime, err = strconv.ParseInt(ct, 10, 64); err != nil {
		return s, fmt.Errorf("prepare: commit time %q", ct)
	}
	s.CheckoutRemote, _ = git(ctx, checkout, "remote", "get-url", "origin")
	paths := t.Paths
	if len(paths) == 0 {
		paths = []string{"."}
	}
	s.GitTrees = map[string]string{}
	for _, x := range paths {
		spec := got + ":"
		if x != "." {
			spec += x
		}
		id, err := git(ctx, checkout, "rev-parse", "--verify", "--end-of-options", spec)
		if err != nil {
			return s, fmt.Errorf("prepare: %s is not in revision %s", x, got)
		}
		s.GitTrees[x] = id
	}
	args := []string{"-C", checkout, "archive", "--format=tar", got}
	if len(t.Paths) > 0 {
		args = append(append(args, "--"), t.Paths...)
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return s, err
	}
	if err := cmd.Start(); err != nil {
		return s, err
	}
	xerr := untar(pipe, dst)
	_, _ = io.Copy(io.Discard, pipe)
	if werr := cmd.Wait(); werr != nil {
		return s, fmt.Errorf("prepare: git archive: %v: %s", werr, strings.TrimSpace(stderr.String()))
	}
	if xerr != nil {
		return s, fmt.Errorf("prepare: extracting revision: %w", xerr)
	}
	if s.TreeSHA256, s.Files, err = treeHash(dst); err != nil {
		return s, err
	}
	return s, nil
}

func untar(r io.Reader, dst string) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := path.Clean(h.Name)
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if name == "." || path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("unsafe archive path %q", h.Name)
		}
		to := filepath.Join(dst, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(to, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if h.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if path.IsAbs(h.Linkname) || strings.HasPrefix(path.Clean(path.Join(path.Dir(name), h.Linkname)), "../") {
				return fmt.Errorf("symlink %q points outside the tree", h.Name)
			}
			if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(h.Linkname, to); err != nil {
				return err
			}
		default:
			return fmt.Errorf("archive entry %q has type %c", h.Name, h.Typeflag)
		}
	}
}

// treeHash hashes a tree as sorted "sha256 mode path" lines (symlinks as
// "link target path").
func treeHash(dir string) (string, int, error) {
	type line struct{ rel, text string }
	var lines []line
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.Type()&fs.ModeSymlink != 0 {
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			lines = append(lines, line{rel, "link " + t + " " + rel})
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		h, err := fileSHA(p)
		if err != nil {
			return err
		}
		mode := "100644"
		if info.Mode()&0o111 != 0 {
			mode = "100755"
		}
		lines = append(lines, line{rel, h + " " + mode + " " + rel})
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].rel < lines[j].rel })
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.text + "\n")
	}
	return sha256Hex([]byte(b.String())), len(lines), nil
}

// setWritable makes the tree writable (on) or read-only (off).
func setWritable(dir string, on bool) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink != 0 {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		m := info.Mode().Perm()
		if on {
			m |= 0o200
		} else {
			m &^= 0o222
		}
		return os.Chmod(p, m)
	})
}

// build runs the recipe's steps with a fixed environment, the source tree
// read-only and, for network "none", in a new empty network namespace.
func build(ctx context.Context, p *manifest.Project, commitTime int64, work string, log io.Writer) (manifest.Build, error) {
	b := manifest.Build{Network: p.Build.Network, NetworkEnforcement: "none"}
	src, out := filepath.Join(work, "src"), filepath.Join(work, "out")
	var wrapper []string
	if p.Build.Network == manifest.NetworkNone {
		wrapper = []string{"unshare", "--user", "--map-current-user", "--net", "--"}
		if err := exec.CommandContext(ctx, wrapper[0], append(wrapper[1:], "true")...).Run(); err != nil {
			return b, fmt.Errorf("prepare: the recipe forbids network access but a network namespace is unavailable (%v)", err)
		}
		b.NetworkEnforcement = "netns"
	}
	env := map[string]string{
		"HOME": filepath.Join(work, "home"), "TMPDIR": filepath.Join(work, "tmp"), "LC_ALL": "C", "TZ": "UTC",
		"SOURCE_DATE_EPOCH": strconv.FormatInt(commitTime, 10),
	}
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		env["JAVA_HOME"] = jh
	}
	for k, v := range p.Build.Env {
		env[k] = v
	}
	b.Env = map[string]string{}
	for k, v := range env {
		b.Env[k] = relArgv([]string{"", v}, work)[1]
	}
	environ := []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range env {
		environ = append(environ, k+"="+v)
	}
	sort.Strings(environ)
	b.Environment = environment(ctx, environ)

	if err := setWritable(src, false); err != nil {
		return b, err
	}
	defer setWritable(src, true)
	vars := map[string]string{"SRC": src, "OUT": out, "WORK": work}
	for i, s := range p.Build.Steps {
		argv := append([]string(nil), wrapper...)
		for _, a := range s.Argv {
			x, err := manifest.Expand(a, vars)
			if err != nil {
				return b, err
			}
			argv = append(argv, x)
		}
		base := filepath.Join(work, "logs", fmt.Sprintf("%02d-%s", i+1, s.Name))
		var stdout, stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = src, environ, &stdout, &stderr
		fmt.Fprintf(log, "prepare: build step %s\n", s.Name)
		started := time.Now()
		err := cmd.Run()
		r := manifest.StepRun{Name: s.Name, Argv: relArgv(argv, work), Duration: time.Since(started).Round(time.Millisecond).String(),
			StdoutSHA256: sha256Hex(stdout.Bytes()), StderrSHA256: sha256Hex(stderr.Bytes())}
		_ = os.WriteFile(base+".stdout", stdout.Bytes(), 0o644)
		_ = os.WriteFile(base+".stderr", stderr.Bytes(), 0o644)
		var ee *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &ee) && ee.Exited():
			r.Exit = ee.ExitCode()
		default:
			r.Exit = -1
		}
		b.Steps = append(b.Steps, r)
		if err != nil {
			return b, fmt.Errorf("prepare: build step %s failed (%v); see %s.stderr", s.Name, err, base)
		}
	}
	return b, nil
}

// environment identifies the OS, kernel and the java on the build's PATH.
func environment(ctx context.Context, environ []string) manifest.Environment {
	e := manifest.Environment{OS: runtime.GOOS, Arch: runtime.GOARCH}
	if k, err := exec.CommandContext(ctx, "uname", "-r").Output(); err == nil {
		e.Kernel = strings.TrimSpace(string(k))
	}
	cmd := exec.CommandContext(ctx, "java", "-XshowSettings:properties", "-version")
	cmd.Env = environ
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	for _, pathDir := range filepath.SplitList(envValue(environ, "PATH")) {
		if j := filepath.Join(pathDir, "java"); isExec(j) {
			if real, err := filepath.EvalSymlinks(j); err == nil {
				e.JavaSHA256, _ = fileSHA(real)
			}
			break
		}
	}
	if cmd.Run() != nil {
		return e
	}
	sc := bufio.NewScanner(&stderr)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " = ")
		if !ok {
			continue
		}
		switch k {
		case "java.version":
			e.JavaVersion = v
		case "java.vendor":
			e.JavaVendor = v
		case "java.vm.version":
			e.JavaVM = v
		case "java.home":
			e.JavaHome = v
		}
	}
	return e
}

func envValue(environ []string, k string) string {
	for _, kv := range environ {
		if strings.HasPrefix(kv, k+"=") {
			return kv[len(k)+1:]
		}
	}
	return ""
}

func isExec(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0
}

// artifacts hashes the outputs. The classpath order is the one Ariadne
// selects in: the app, then the dependency jars by file name.
func artifacts(out string, o manifest.Outputs) (manifest.Artifacts, error) {
	var a manifest.Artifacts
	var err error
	if a.App, err = fileRecord(out, o.App); err != nil {
		return a, fmt.Errorf("prepare: build output app: %w", err)
	}
	a.Classpath = []string{a.App.Path}
	lines := []string{a.App.SHA256 + " " + a.App.Path}
	a.Deps = []manifest.File{}
	if o.Deps != "" {
		ents, err := os.ReadDir(filepath.Join(out, filepath.FromSlash(o.Deps)))
		if err != nil {
			return a, fmt.Errorf("prepare: build output deps: %w", err)
		}
		for _, e := range ents { // ReadDir sorts by file name
			if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".jar") {
				continue
			}
			f, err := fileRecord(out, path.Join(o.Deps, e.Name()))
			if err != nil {
				return a, err
			}
			a.Deps = append(a.Deps, f)
			a.Classpath = append(a.Classpath, f.Path)
			lines = append(lines, f.SHA256+" "+f.Path)
		}
	}
	a.ClasspathSHA256 = sha256Hex([]byte(strings.Join(lines, "\n") + "\n"))
	if o.DepsList != "" {
		f, err := fileRecord(out, o.DepsList)
		if err != nil {
			return a, fmt.Errorf("prepare: build output deps_list: %w", err)
		}
		if err := checkDepsList(filepath.Join(out, filepath.FromSlash(o.DepsList))); err != nil {
			return a, err
		}
		a.DepsList = &f
	}
	return a, nil
}

// checkDepsList accepts `mvn dependency:list` lines
// (group:artifact:type[:classifier]:version:scope, optionally indented or
// with Maven's decorations) and blank lines.
func checkDepsList(file string) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	n := 0
	for i, l := range strings.Split(string(raw), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "The following files have been resolved") || l == "none" {
			continue
		}
		l = strings.TrimSpace(strings.TrimPrefix(l, "[INFO]"))
		if l == "" {
			continue
		}
		f := strings.Split(strings.Fields(l)[0], ":")
		if len(f) < 5 {
			return fmt.Errorf("prepare: deps_list line %d %q is not group:artifact:type:version:scope", i+1, l)
		}
		n++
	}
	if n == 0 {
		return errors.New("prepare: deps_list names no dependency")
	}
	return nil
}

// index runs `ariadne research index` on the artifacts.
func index(ctx context.Context, o Options, p *manifest.Project, res *Result, work string) (*manifest.Analysis, *ariadne.Bundle, error) {
	bin, err := filepath.Abs(o.Ariadne)
	if err != nil {
		return nil, nil, err
	}
	out := res.OutDir
	iopt := ariadne.IndexOptions{App: filepath.Join(out, filepath.FromSlash(p.Build.Outputs.App)), Roots: p.Scenario.Roots,
		Scope: p.Scenario.Scope, Profile: p.Scenario.Profile, Out: filepath.Join(work, "bundle")}
	if p.Build.Outputs.Deps != "" {
		iopt.Deps = filepath.Join(out, filepath.FromSlash(p.Build.Outputs.Deps))
	}
	if p.Build.Outputs.DepsList != "" {
		iopt.DepsList = filepath.Join(out, filepath.FromSlash(p.Build.Outputs.DepsList))
	}
	useSources := o.Sources == "always" || (o.Sources == "auto" && ariadne.IndexHasFlag(ctx, bin, "sources"))
	if useSources {
		for _, r := range p.Target.SourceRoots {
			if r.Artifact == p.Build.Outputs.App {
				iopt.Sources = filepath.Join(res.SourceDir, filepath.FromSlash(r.Path))
				break
			}
		}
	}
	fmt.Fprintf(o.Stderr, "prepare: ariadne research index (sources=%v)\n", useSources)
	ir, err := ariadne.Index(ctx, bin, iopt)
	if ir != nil {
		_ = os.WriteFile(filepath.Join(work, "logs", "ariadne-index.stderr"), ir.Stderr, 0o644)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("prepare: %w", err)
	}
	b := ir.Bundle
	binSHA, err := fileSHA(bin)
	if err != nil {
		return nil, nil, err
	}
	if b.BinarySHA256 != "" && b.BinarySHA256 != binSHA {
		return nil, nil, fmt.Errorf("prepare: bundle names ariadne binary %s, ran %s", b.BinarySHA256, binSHA)
	}
	a := &manifest.Analysis{AnalysisID: b.AnalysisID, Bundle: "bundle", ManifestSHA256: sha256Hex(b.RawManifest),
		IdentitySHA256: sha256Hex(b.RawIdentity), Roots: b.RootsMode, Profile: p.Scenario.Profile, Scope: b.Scope,
		AriadneBinarySHA: binSHA, AriadneToolVersion: b.ToolVersion, SourcesFlag: useSources, Argv: relArgv(ir.Argv, work)}
	return a, b, nil
}

// relArgv writes the work directory as ${WORK} in recorded arguments, so the
// manifests of two preparations compare equal.
func relArgv(argv []string, work string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if i > 0 {
			a = strings.ReplaceAll(a, work, "${WORK}")
		}
		out[i] = a
	}
	return out
}

func fileRecord(dir, rel string) (manifest.File, error) {
	p := filepath.Join(dir, filepath.FromSlash(rel))
	info, err := os.Stat(p)
	if err != nil {
		return manifest.File{}, err
	}
	if !info.Mode().IsRegular() {
		return manifest.File{}, fmt.Errorf("%s is not a regular file", rel)
	}
	h, err := fileSHA(p)
	return manifest.File{Path: rel, SHA256: h, Size: info.Size()}, err
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
