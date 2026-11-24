package sourceindex

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// classInfo is what the source index needs from one class file: its binary
// name, the SourceFile attribute and each method's line table extent.
type classInfo struct {
	Name       string // binary name with dots (fx.research.Extractor$1)
	SourceFile string // "" when the attribute is absent
	Methods    []methodInfo
}

type methodInfo struct {
	Name       string
	Descriptor string
	HasCode    bool
	LineStart  int // 0 when the method has no LineNumberTable
	LineEnd    int
}

type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = errors.New("truncated class file")
		return false
	}
	return true
}

func (r *reader) u1() int {
	if !r.need(1) {
		return 0
	}
	v := r.b[r.off]
	r.off++
	return int(v)
}

func (r *reader) u2() int {
	if !r.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.off:])
	r.off += 2
	return int(v)
}

func (r *reader) u4() int {
	if !r.need(4) {
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return int(v)
}

func (r *reader) bytes(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}

// parseClass reads the parts of a class file (JVMS chapter 4) the index uses.
func parseClass(b []byte) (*classInfo, error) {
	r := &reader{b: b}
	if r.u4() != 0xCAFEBABE {
		return nil, errors.New("not a class file")
	}
	r.u2() // minor
	r.u2() // major
	n := r.u2()
	utf8 := make(map[int]string)
	classIdx := make(map[int]int)
	for i := 1; i < n && r.err == nil; i++ {
		switch tag := r.u1(); tag {
		case 1: // Utf8 (modified UTF-8; identifiers in practice are plain)
			l := r.u2()
			utf8[i] = string(r.bytes(l))
		case 7: // Class
			classIdx[i] = r.u2()
		case 8, 16, 19, 20: // String, MethodType, Module, Package
			r.u2()
		case 3, 4, 9, 10, 11, 12, 17, 18: // Integer, Float, refs, NameAndType, Dynamic, InvokeDynamic
			r.u4()
		case 5, 6: // Long, Double take two slots
			r.bytes(8)
			i++
		case 15: // MethodHandle
			r.u1()
			r.u2()
		default:
			return nil, fmt.Errorf("constant pool tag %d at entry %d", tag, i)
		}
	}
	r.u2() // access
	this := r.u2()
	r.u2() // super
	r.bytes(2 * r.u2())
	name, ok := utf8[classIdx[this]]
	if r.err != nil {
		return nil, r.err
	}
	if !ok {
		return nil, errors.New("this_class does not name a class")
	}
	ci := &classInfo{Name: strings.ReplaceAll(name, "/", ".")}
	// fields
	for f := r.u2(); f > 0 && r.err == nil; f-- {
		r.bytes(6)
		skipAttributes(r)
	}
	for m := r.u2(); m > 0 && r.err == nil; m-- {
		r.u2() // access
		mi := methodInfo{Name: utf8[r.u2()], Descriptor: utf8[r.u2()]}
		for a := r.u2(); a > 0 && r.err == nil; a-- {
			an, l := utf8[r.u2()], r.u4()
			body := r.bytes(l)
			if an == "Code" && body != nil {
				mi.HasCode = true
				mi.LineStart, mi.LineEnd = codeLines(body, utf8)
			}
		}
		ci.Methods = append(ci.Methods, mi)
	}
	for a := r.u2(); a > 0 && r.err == nil; a-- {
		an, l := utf8[r.u2()], r.u4()
		body := r.bytes(l)
		if an == "SourceFile" && len(body) == 2 {
			ci.SourceFile = utf8[int(binary.BigEndian.Uint16(body))]
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	return ci, nil
}

func skipAttributes(r *reader) {
	for a := r.u2(); a > 0 && r.err == nil; a-- {
		r.u2()
		r.bytes(r.u4())
	}
}

// codeLines returns the smallest and largest line in a Code attribute's
// LineNumberTable attributes (0, 0 when there are none).
func codeLines(code []byte, utf8 map[int]string) (lo, hi int) {
	r := &reader{b: code}
	r.u2() // max_stack
	r.u2() // max_locals
	r.bytes(r.u4())
	r.bytes(8 * r.u2()) // exception table
	for a := r.u2(); a > 0 && r.err == nil; a-- {
		an, l := utf8[r.u2()], r.u4()
		body := r.bytes(l)
		if an != "LineNumberTable" {
			continue
		}
		if lines, ok := lineTable(body); ok {
			for _, ln := range lines {
				if lo == 0 || ln < lo {
					lo = ln
				}
				if ln > hi {
					hi = ln
				}
			}
		}
	}
	return lo, hi
}

// lineTable decodes a LineNumberTable: u2 count, count×(u2 pc, u2 line).
func lineTable(body []byte) ([]int, bool) {
	if len(body) < 2 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(body))
	if len(body) != 2+4*n || n == 0 {
		return nil, false
	}
	out := make([]int, n)
	for i := 0; i < n; i++ {
		out[i] = int(binary.BigEndian.Uint16(body[2+4*i+2:]))
	}
	return out, true
}
