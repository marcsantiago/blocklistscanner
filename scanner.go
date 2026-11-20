package blocklist

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
)

const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

// Matcher is a compact, pointer-free, read-only domain blocklist.
// It is safe for concurrent use across goroutines after construction.
type Matcher struct {
	data  []byte   // null-terminated lowercase domains; index 0 is reserved
	slots []uint32 // open-addressed hash table storing offsets into data (0 = empty)
	mask  uint64
	count int
}

// OpenGzip loads and indexes AdBlock-style domain rules (||domain^) from a gzip file.
func OpenGzip(path string) (*Matcher, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()

	return Open(gz)
}

// Open loads and indexes AdBlock-style domain rules (||domain^) from a reader.
func Open(r io.Reader) (*Matcher, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Pre-size the hash table to <= 65% load factor using the line count as an upper bound.
	lineCount := max(bytes.Count(raw, []byte{'\n'})+1, 16)
	tableSize := 16
	for tableSize*13 < lineCount*20 {
		tableSize <<= 1
	}

	slots := make([]uint32, tableSize)
	mask := uint64(tableSize - 1)

	// Reserve offset 0 so 0 in slots unambiguously means empty.
	data := make([]byte, 1, len(raw)+1)
	count := 0

	for lineNum := 1; len(raw) > 0; lineNum++ {
		var line []byte
		if nl := bytes.IndexByte(raw, '\n'); nl >= 0 {
			line = raw[:nl]
			raw = raw[nl+1:]
		} else {
			line = raw
			raw = nil
		}

		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '!' || line[0] == '#' || line[0] == '[' {
			continue
		}

		if len(line) < 4 || line[0] != '|' || line[1] != '|' || line[len(line)-1] != '^' {
			return nil, fmt.Errorf("line %d: invalid rule %q", lineNum, line)
		}

		dom := line[2 : len(line)-1]
		if !normalizeAndValidate(dom) {
			return nil, fmt.Errorf("line %d: invalid domain %q", lineNum, dom)
		}

		h := hashDomainBytes(dom)
		idx := h & mask
		duplicate := false

		for {
			off := slots[idx]
			if off == 0 {
				break
			}
			end := int(off) + len(dom)
			if end < len(data) && data[end] == 0 && bytes.Equal(data[off:end], dom) {
				duplicate = true
				break
			}
			idx = (idx + 1) & mask
		}

		if duplicate {
			continue
		}

		if len(data)+len(dom)+1 > math.MaxUint32 {
			return nil, fmt.Errorf("domain data exceeds 4 GB")
		}

		off := uint32(len(data))
		data = append(data, dom...)
		data = append(data, 0)
		slots[idx] = off
		count++
	}

	return &Matcher{
		data:  bytes.Clone(data), // release unused tail capacity
		slots: slots,
		mask:  mask,
		count: count,
	}, nil
}

// Match reports whether host or any of its parent domains is in the blocklist.
func (m *Matcher) Match(host string) bool {
	for len(host) > 0 && host[len(host)-1] == '.' {
		host = host[:len(host)-1]
	}
	if len(host) == 0 || len(host) > 253 || host[0] == '.' {
		return false
	}

	h := uint64(fnvOffset64)
	for i := len(host) - 1; i >= 0; i-- {
		c := host[i]
		if c == '.' {
			if host[i-1] == '.' {
				return false
			}
			if m.has(h, host[i+1:]) {
				return true
			}
		} else if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}

		h ^= uint64(c)
		h *= fnvPrime64
	}

	return m.has(h, host)
}

// Contains reports whether the exact domain is in the blocklist.
func (m *Matcher) Contains(domain string) bool {
	for len(domain) > 0 && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	if len(domain) == 0 || len(domain) > 253 || domain[0] == '.' {
		return false
	}

	h := uint64(fnvOffset64)
	for i := len(domain) - 1; i >= 0; i-- {
		c := domain[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		h ^= uint64(c)
		h *= fnvPrime64
	}

	return m.has(h, domain)
}

// Size returns the number of unique indexed domains.
func (m *Matcher) Size() int {
	return m.count
}

func (m *Matcher) has(h uint64, candidate string) bool {
	idx := h & m.mask
	for {
		off := m.slots[idx]
		if off == 0 {
			return false
		}
		if m.equals(off, candidate) {
			return true
		}
		idx = (idx + 1) & m.mask
	}
}

func (m *Matcher) equals(off uint32, candidate string) bool {
	end := int(off) + len(candidate)
	if end >= len(m.data) || m.data[end] != 0 {
		return false
	}

	stored := m.data[off:end]
	for i := 0; i < len(candidate); i++ {
		c := candidate[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if stored[i] != c {
			return false
		}
	}
	return true
}

func hashDomainBytes(d []byte) uint64 {
	h := uint64(fnvOffset64)
	for _, v := range slices.Backward(d) {
		h ^= uint64(v)
		h *= fnvPrime64
	}
	return h
}

func normalizeAndValidate(domain []byte) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	labelLen := 0
	for i, c := range domain {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
			domain[i] = c
		}

		if c == '.' {
			if labelLen == 0 || domain[i-1] == '-' {
				return false
			}
			labelLen = 0
			continue
		}

		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
		if labelLen == 0 && c == '-' {
			return false
		}

		labelLen++
		if labelLen > 63 {
			return false
		}
	}

	return labelLen > 0 && domain[len(domain)-1] != '-'
}
