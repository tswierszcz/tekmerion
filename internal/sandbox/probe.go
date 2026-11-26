package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const CapabilitySchema = "tekmerion-sandbox-capabilities-1"

type Check struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	OK       bool   `json:"ok"`
}

// Capabilities records small enforcement tests run through the same wrapper
// as target workers. OK is false when any decisive check failed.
type Capabilities struct {
	Schema string            `json:"schema_version"`
	Limits Limits            `json:"limits"`
	Tools  map[string]string `json:"tools"`
	Checks []Check           `json:"checks"`
	Probe  *Result           `json:"probe,omitempty"`
	Memory *Result           `json:"memory_probe,omitempty"`
	OK     bool              `json:"ok"`
	Error  string            `json:"error,omitempty"`
}

// The probe stresses the limits it can observe from inside: it tries to
// exceed tasks, memory and file size, write to read-only locations and reach
// a network interface. The host also checks the file-size outcome itself.
const probeScript = `
echo "net=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | sort | tr '\n' ',')"
for p in / /dev /dev/shm /usr /etc /ro; do if ( : > "$p/.tekmerion-probe" ) 2>/dev/null; then echo "write:$p=allowed"; else echo "write:$p=denied"; fi; done
if ( : > /case/probe-write ) 2>/dev/null; then echo "write:/case=allowed"; else echo "write:/case=denied"; fi
if ( : > /tmp/probe-write ) 2>/dev/null; then echo "write:/tmp=allowed"; else echo "write:/tmp=denied"; fi
if [ -z "$TEKMERION_PROBE_LEAK" ]; then echo "env_leak=absent"; else echo "env_leak=present"; fi
echo "uid=$(id -u)"
grep -E '^Max (cpu time|file size|open files|core file size) ' /proc/self/limits | awk '{print "limit:" $2 "_" $3 "=" $(NF-2)}'
echo 0 > /case/tasks
( i=0; while [ $i -lt "$1" ]; do sleep 2 & echo $! > /case/lastpid; i=$((i+1)); echo $i > /case/tasks; done ) 2>/dev/null
read n < /case/tasks; read last < /case/lastpid
while [ -e "/proc/$last" ]; do :; done
echo "tasks_started=$n"
( head -c "$2" /dev/zero > /case/fsize ) 2>/dev/null; echo "fsize_status=$?"
echo done=1
`

const memoryScript = `( head -c "$1" /dev/zero | tail -n 1 >/dev/null && echo allocated ) 2>/dev/null; echo "memory_status=$?"`

func version(tool string, args ...string) string {
	out, err := exec.Command(tool, args...).CombinedOutput()
	if err != nil {
		return "unavailable: " + err.Error()
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return line
}

// Probe runs the enforcement tests in a fresh scratch directory that must
// not exist yet. Errors are recorded in the report; it never returns OK on a
// missing tool or an unparsable observation.
func Probe(ctx context.Context, l Limits, scratch string) (*Capabilities, error) {
	c := &Capabilities{Schema: CapabilitySchema, Limits: l, Tools: map[string]string{}, Checks: []Check{}}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	for _, t := range tools {
		c.Tools[t] = version(t, "--version")
	}
	if err := Available(); err != nil {
		c.Error = err.Error()
		return c, nil
	}
	if err := os.Mkdir(scratch, 0700); err != nil {
		return nil, err
	}
	caseDir, roDir := filepath.Join(scratch, "case"), filepath.Join(scratch, "ro")
	for _, d := range []string{caseDir, roDir} {
		if err := os.Mkdir(d, 0700); err != nil {
			return nil, err
		}
	}
	// A host variable the worker must not see; bubblewrap clears it.
	os.Setenv("TEKMERION_PROBE_LEAK", "1")
	defer os.Unsetenv("TEKMERION_PROBE_LEAK")
	spec := Spec{
		Argv:   []string{"/bin/sh", "-c", probeScript, "probe", strconv.FormatInt(l.Tasks+16, 10), strconv.FormatInt(l.FileSizeBytes+4096, 10)},
		Mounts: []Mount{{Host: caseDir, Path: "/case", Writable: true}, {Host: roDir, Path: "/ro"}},
		Dir:    "/case",
		Limits: l,
	}
	r, err := Run(ctx, spec)
	if err != nil {
		c.Error = err.Error()
		return c, nil
	}
	c.Probe = r
	obs := map[string]string{}
	for _, line := range strings.Split(string(r.Stdout), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			obs[k] = v
		}
	}
	add := func(name, expected, observed string, ok bool) {
		c.Checks = append(c.Checks, Check{Name: name, Expected: expected, Observed: observed, OK: ok})
	}
	add("probe completed", "done=1 within wall limit", fmt.Sprintf("done=%s timed_out=%t exit=%d", obs["done"], r.TimedOut, r.Exit), obs["done"] == "1" && !r.TimedOut)
	add("network", "loopback only", obs["net"], obs["net"] == "lo," || obs["net"] == "")
	for _, p := range []string{"/", "/dev", "/dev/shm", "/usr", "/etc", "/ro"} {
		add("write "+p, "denied", obs["write:"+p], obs["write:"+p] == "denied")
	}
	add("write /case", "allowed", obs["write:/case"], obs["write:/case"] == "allowed")
	add("write /tmp (private tmpfs)", "allowed", obs["write:/tmp"], obs["write:/tmp"] == "allowed")
	add("host environment", "cleared", obs["env_leak"], obs["env_leak"] == "absent")
	limit := func(key string, want int64) {
		add("rlimit "+key, strconv.FormatInt(want, 10), obs["limit:"+key], obs["limit:"+key] == strconv.FormatInt(want, 10))
	}
	limit("cpu_time", l.CPUSeconds)
	limit("file_size", l.FileSizeBytes)
	limit("open_files", l.OpenFiles)
	limit("core_file", 0)
	n, err := strconv.ParseInt(obs["tasks_started"], 10, 64)
	add("task limit under fork pressure", "fork refused before "+strconv.FormatInt(l.Tasks, 10)+" concurrent tasks", obs["tasks_started"], err == nil && n > 0 && n < l.Tasks)
	// Memory runs in its own worker: the OOM killer may pick any worker
	// process, so the test asserts only that an allocation above the limit
	// never completes and the worker is killed rather than timing out.
	mem, err := Run(ctx, Spec{Argv: []string{"/bin/sh", "-c", memoryScript, "probe", strconv.FormatInt(l.MemoryBytes+(64<<20), 10)}, Dir: "/", Limits: l})
	if err != nil {
		c.Error = err.Error()
		return c, nil
	}
	c.Memory = mem
	killed := strings.Contains(string(mem.Stdout), "memory_status=137") || mem.Exit == 137 || mem.Signal == "killed"
	add("memory limit", "allocation above limit killed before completion", fmt.Sprintf("%q exit=%d signal=%s", strings.TrimSpace(string(mem.Stdout)), mem.Exit, mem.Signal),
		killed && !mem.TimedOut && !strings.Contains(string(mem.Stdout), "allocated"))
	size := int64(-1)
	if fi, err := os.Lstat(filepath.Join(caseDir, "fsize")); err == nil && fi.Mode().IsRegular() {
		size = fi.Size()
	}
	add("file size limit", "write stopped at <= "+strconv.FormatInt(l.FileSizeBytes, 10)+" bytes", fmt.Sprintf("status=%s size=%d", obs["fsize_status"], size), obs["fsize_status"] != "0" && size >= 0 && size <= l.FileSizeBytes)
	if fi, err := os.Lstat(filepath.Join(roDir, ".tekmerion-probe")); err == nil {
		add("host view of read-only mount", "unchanged", fi.Name(), false)
	}
	c.OK = true
	for _, v := range c.Checks {
		c.OK = c.OK && v.OK
	}
	return c, nil
}
