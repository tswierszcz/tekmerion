package sourceindex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testdata/sourceindex/sample.jar is built from testdata/sourceindex/src
// with Ariadne's scripts/JavaBuild.java (javac defaults: SourceFile and
// LineNumberTable present, -source/-target 11):
//
//	java $ARIADNE_SRC/scripts/JavaBuild.java testdata/sourceindex/src testdata/sourceindex/sample.jar 11
const sampleDir = "../../testdata/sourceindex"

func sampleIndex(t *testing.T) *Index {
	t.Helper()
	ix, err := Build(sampleDir, sampleDir, []Root{{Path: "src", Artifact: "sample.jar"}})
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func TestBuildLinesAndFiles(t *testing.T) {
	ix := sampleIndex(t)
	srcSHA, err := fileSHA256(filepath.Join(sampleDir, "src/ex/pkg/Sample.java"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		class, name, desc string
		lo, hi            int // 0: no lines
	}{
		{"ex.pkg.Sample", "<init>", "(Ljava/lang/String;)V", 8, 10},
		{"ex.pkg.Sample", "greet", "(Ljava/lang/String;)Ljava/lang/String;", 13, 14},
		{"ex.pkg.Sample", "sum", "(JD)J", 18, 18}, // a long constant: two constant pool slots
		{"ex.pkg.Sample", "hook", "()V", 0, 0},    // abstract: no Code
		{"ex.pkg.Sample", "later", "()Ljava/util/function/Supplier;", 24, 24},
		{"ex.pkg.Sample", "lambda$later$0", "()Ljava/lang/String;", 24, 24},
		{"ex.pkg.Sample$Inner", "twice", "(I)I", 29, 29},
		{"ex.pkg.Helper", "run", "()V", 36, 36}, // a second top-level class in Sample.java
	}
	for _, c := range cases {
		e, ok := ix.Lookup(Method{Class: c.class, Name: c.name, Descriptor: c.desc})
		if !ok {
			t.Errorf("%s#%s%s not indexed", c.class, c.name, c.desc)
			continue
		}
		if e.Path == nil || *e.Path != "src/ex/pkg/Sample.java" || e.Binding != BindingBuildVerified || e.SourceSHA256 == nil || *e.SourceSHA256 != srcSHA {
			t.Errorf("%s#%s: file %v %s %v", c.class, c.name, strOrNull(e.Path), e.Binding, e.SourceSHA256)
		}
		got := lines(e.LineStart, e.LineEnd)
		want := "null"
		if c.lo > 0 {
			want = lines(&c.lo, &c.hi)
		}
		if got != want {
			t.Errorf("%s#%s%s lines %s, want %s", c.class, c.name, c.desc, got, want)
		}
		if !strings.HasPrefix(e.ClassSHA256, "sha256:") || e.Artifact != "sample.jar" {
			t.Errorf("%s#%s: class %s artifact %s", c.class, c.name, e.ClassSHA256, e.Artifact)
		}
	}
	// By class hash, the exact copy.
	e, _ := ix.Lookup(Method{Class: "ex.pkg.Sample", Name: "sum", Descriptor: "(JD)J"})
	if _, ok := ix.Lookup(Method{Class: "ex.pkg.Sample", Name: "sum", Descriptor: "(JD)J", ClassSHA256: e.ClassSHA256}); !ok {
		t.Error("lookup by class hash failed")
	}
	if _, ok := ix.Lookup(Method{Class: "ex.pkg.Sample", Name: "sum", Descriptor: "(JD)J", ClassSHA256: "sha256:" + strings.Repeat("0", 64)}); ok {
		t.Error("lookup with another class hash matched")
	}
}

func TestBuildDeterministicAndReload(t *testing.T) {
	a, b := sampleIndex(t), sampleIndex(t)
	dir := t.TempDir()
	if err := a.Save(filepath.Join(dir, "a.json")); err != nil {
		t.Fatal(err)
	}
	if err := b.Save(filepath.Join(dir, "b.json")); err != nil {
		t.Fatal(err)
	}
	ra, _ := os.ReadFile(filepath.Join(dir, "a.json"))
	rb, _ := os.ReadFile(filepath.Join(dir, "b.json"))
	if string(ra) != string(rb) {
		t.Fatal("two builds of the index differ")
	}
	l, err := Load(filepath.Join(dir, "a.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Lookup(Method{Class: "ex.pkg.Sample$Inner", Name: "twice", Descriptor: "(I)I"}); !ok {
		t.Fatal("reloaded index has no lookup")
	}
}

func TestBuildMissingSourceIsDeclared(t *testing.T) {
	// The same artifact against a root that does not hold the file.
	ix, err := Build(sampleDir, sampleDir, []Root{{Path: "nowhere", Artifact: "sample.jar"}})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := ix.Lookup(Method{Class: "ex.pkg.Sample", Name: "greet", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"})
	if e.Binding != BindingDeclared || e.Path == nil || *e.Path != "ex/pkg/Sample.java" || e.SourceSHA256 != nil {
		t.Fatalf("got %s %s %v", e.Binding, strOrNull(e.Path), e.SourceSHA256)
	}
	if _, err := Build(sampleDir, sampleDir, []Root{{Path: "../x", Artifact: "sample.jar"}}); err == nil {
		t.Fatal("root outside the checkout accepted")
	}
}

func ptr[T any](v T) *T { return &v }

func TestResolve(t *testing.T) {
	ix := sampleIndex(t)
	greet := Method{Class: "ex.pkg.Sample", Name: "greet", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"}
	own, _ := ix.Lookup(greet)

	t.Run("index only", func(t *testing.T) {
		l := ix.Resolve(greet, &AriadneSource{Binding: BindingUnavailable})
		if l.Basis != BasisTekmerion || l.Binding != BindingBuildVerified || *l.LineStart != 13 {
			t.Fatalf("%+v", l)
		}
	})
	t.Run("ariadne lines agree", func(t *testing.T) { // Ariadne main: lines, no path
		l := ix.Resolve(greet, &AriadneSource{LineStart: ptr(13), LineEnd: ptr(14), Binding: BindingDeclared})
		if l.Basis != BasisBoth || l.Binding != BindingBuildVerified || len(l.Conflicts) != 0 || *l.Path != "src/ex/pkg/Sample.java" {
			t.Fatalf("%+v", l)
		}
	})
	t.Run("ariadne path and hash agree", func(t *testing.T) { // Ariadne with -sources
		l := ix.Resolve(greet, &AriadneSource{Path: ptr("ex/pkg/Sample.java"), LineStart: ptr(13), LineEnd: ptr(14),
			SourceSHA256: own.SourceSHA256, Binding: BindingBuildVerified})
		if l.Basis != BasisBoth || l.Binding != BindingBuildVerified || len(l.Conflicts) != 0 {
			t.Fatalf("%+v", l)
		}
	})
	t.Run("conflicts", func(t *testing.T) {
		l := ix.Resolve(greet, &AriadneSource{Path: ptr("ex/other/Sample.java"), LineStart: ptr(12), LineEnd: ptr(14),
			SourceSHA256: ptr("sha256:" + strings.Repeat("1", 64)), Binding: BindingBuildVerified})
		if l.Binding != BindingUnavailable || len(l.Conflicts) != 3 {
			t.Fatalf("%+v", l)
		}
	})
	t.Run("ariadne only", func(t *testing.T) {
		m := Method{Class: "ex.pkg.Gone", Name: "f", Descriptor: "()V"}
		l := ix.Resolve(m, &AriadneSource{Path: ptr("ex/pkg/Gone.java"), LineStart: ptr(3), LineEnd: ptr(4), Binding: BindingDeclared})
		if l.Basis != BasisAriadne || l.Binding != BindingDeclared || *l.Path != "ex/pkg/Gone.java" {
			t.Fatalf("%+v", l)
		}
	})
	t.Run("nothing", func(t *testing.T) {
		l := ix.Resolve(Method{Class: "java.nio.file.Files", Name: "write", Descriptor: "()V"}, nil)
		if l.Basis != BasisNone || l.Binding != BindingUnavailable || l.Path != nil {
			t.Fatalf("%+v", l)
		}
	})
}

func TestParseClassRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("PK\x03\x04"), {0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 55, 0, 5, 99}} {
		if _, err := parseClass(b); err == nil {
			t.Errorf("parsed %x", b)
		}
	}
}
