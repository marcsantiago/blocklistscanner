package blocklist

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOpenAndMatch(t *testing.T) {
	rules := strings.Join([]string{
		"! Title: Test Blocklist",
		"# Hash comment",
		"[Adblock Plus 2.0]",
		"   ",
		"||021td.com^",
		"||021TD.COM^", // duplicate (case-insensitive)
		"||sub.example.org^",
		"||tracker-net.io^  ",
		"||a-1.b-2.co.uk^",
	}, "\r\n")

	m, err := Open(strings.NewReader(rules))
	if err != nil {
		t.Fatalf("Open() unexpected error: %v", err)
	}

	if got, want := m.Size(), 4; got != want {
		t.Fatalf("Size() = %d, want %d", got, want)
	}

	tests := []struct {
		host string
		want bool
	}{
		// Exact matches
		{host: "021td.com", want: true},
		{host: "sub.example.org", want: true},
		{host: "tracker-net.io", want: true},
		{host: "a-1.b-2.co.uk", want: true},

		// Subdomain matches
		{host: "v8v1.021td.com", want: true},
		{host: "cdn.v8v1.021td.com", want: true},
		{host: "deep.nested.sub.example.org", want: true},

		// Case-insensitivity & trailing FQDN dots
		{host: "CDN.V8V1.021TD.COM", want: true},
		{host: "021td.com.", want: true},
		{host: "cdn.v8v1.021td.com...", want: true},

		// Parent domain must NOT match when only a subdomain is blocked
		{host: "example.org", want: false},
		{host: "org", want: false},
		{host: "co.uk", want: false},
		{host: "b-2.co.uk", want: false},

		// Suffix boundary safety (must not match partial label suffixes)
		{host: "not021td.com", want: false},
		{host: "fake-sub.example.org", want: false},

		// Unrelated domains
		{host: "google.com", want: false},
		{host: "ads.doubleclick.net", want: false},

		// Malformed / edge-case inputs
		{host: "", want: false},
		{host: ".", want: false},
		{host: "..", want: false},
		{host: ".021td.com", want: false},
		{host: "cdn..021td.com", want: false},
		{host: strings.Repeat("a.", 130) + "com", want: false}, // > 253 chars
	}

	for _, tc := range tests {
		if got := m.Match(tc.host); got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestContains(t *testing.T) {
	m, err := Open(strings.NewReader("||021td.com^\n||sub.example.org^\n"))
	if err != nil {
		t.Fatalf("Open() unexpected error: %v", err)
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{domain: "021td.com", want: true},
		{domain: "021TD.COM.", want: true},
		{domain: "sub.example.org", want: true},
		{domain: "cdn.021td.com", want: false}, // subdomain should not match Contains
		{domain: "example.org", want: false},
		{domain: "", want: false},
		{domain: ".021td.com", want: false},
	}

	for _, tc := range tests {
		if got := m.Contains(tc.domain); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestOpenErrors(t *testing.T) {
	invalidInputs := []struct {
		name  string
		input string
	}{
		{name: "missing prefix", input: "021td.com^"},
		{name: "missing caret", input: "||021td.com"},
		{name: "empty domain", input: "||^"},
		{name: "leading dot", input: "||.021td.com^"},
		{name: "trailing dot", input: "||021td.com.^"},
		{name: "double dot", input: "||021td..com^"},
		{name: "leading hyphen", input: "||-021td.com^"},
		{name: "trailing hyphen", input: "||021td-.com^"},
		{name: "invalid character underscore", input: "||bad_domain.com^"},
		{name: "path included", input: "||021td.com/ads^"},
		{name: "label exceeds 63 chars", input: "||" + strings.Repeat("a", 64) + ".com^"},
		{name: "domain exceeds 253 chars", input: "||" + strings.Repeat("abcde.", 43) + "com^"},
	}

	for _, tc := range invalidInputs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Open(strings.NewReader(tc.input)); err == nil {
				t.Errorf("Open(%q) succeeded, expected error", tc.input)
			}
		})
	}
}

func TestOpenGzip(t *testing.T) {
	dir := t.TempDir()
	gzPath := filepath.Join(dir, "domains.gz")

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write([]byte("||021td.com^\n||adservice.example.net^\n"))
	if err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}

	if err := os.WriteFile(gzPath, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write temp file failed: %v", err)
	}

	m, err := OpenGzip(gzPath)
	if err != nil {
		t.Fatalf("OpenGzip() unexpected error: %v", err)
	}
	if m.Size() != 2 {
		t.Fatalf("Size() = %d, want 2", m.Size())
	}
	if !m.Match("cdn.021td.com") {
		t.Errorf("Match(cdn.021td.com) = false, want true")
	}

	// Non-existent file
	if _, err := OpenGzip(filepath.Join(dir, "missing.gz")); err == nil {
		t.Errorf("OpenGzip(missing) succeeded, expected error")
	}

	// Corrupt gzip file
	badPath := filepath.Join(dir, "bad.gz")
	if err := os.WriteFile(badPath, []byte("not-gzip-data"), 0o600); err != nil {
		t.Fatalf("write bad file failed: %v", err)
	}
	if _, err := OpenGzip(badPath); err == nil {
		t.Errorf("OpenGzip(bad) succeeded, expected error")
	}
}

func TestConcurrentMatch(t *testing.T) {
	m, err := Open(strings.NewReader("||021td.com^\n||blocked.org^\n"))
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				if !m.Match("sub.021td.com") {
					t.Error("expected hit")
				}
				if m.Match("clean.example.com") {
					t.Error("expected miss")
				}
			}
		}()
	}
	wg.Wait()
}

// --- Benchmarks ---

const benchRuleCount = 627_122

var (
	benchOnce    sync.Once
	benchMatcher *Matcher
	benchPayload []byte
)

func getBenchFixture(b *testing.B) (*Matcher, []byte) {
	b.Helper()
	benchOnce.Do(func() {
		tlds := []string{"com", "net", "org", "io", "co.uk", "xyz", "top", "site"}
		var sb strings.Builder
		sb.Grow(benchRuleCount * 22)

		for i := 0; i < benchRuleCount; i++ {
			tld := tlds[i%len(tlds)]
			if i%3 == 0 {
				fmt.Fprintf(&sb, "||v%d.node%d.%s^\n", i%97, i, tld)
			} else {
				fmt.Fprintf(&sb, "||tracker-%d.%s^\n", i, tld)
			}
		}

		benchPayload = []byte(sb.String())
		var err error
		benchMatcher, err = Open(bytes.NewReader(benchPayload))
		if err != nil {
			panic(err)
		}
	})
	return benchMatcher, benchPayload
}

func BenchmarkMatchMiss(b *testing.B) {
	m, _ := getBenchFixture(b)
	hosts := []string{
		"api.segment.io",
		"cdn.jsdelivr.net",
		"static.nytimes.com",
		"assets.bbci.co.uk",
	}

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		if m.Match(hosts[i&3]) {
			b.Fatal("unexpected match")
		}
	}
}

func BenchmarkMatchHitExact(b *testing.B) {
	m, _ := getBenchFixture(b)
	hosts := []string{
		"tracker-1.net",
		"tracker-100001.net",
		"tracker-350002.org",
		"tracker-600001.net",
	}

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		if !m.Match(hosts[i&3]) {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkMatchHitDeepSubdomain(b *testing.B) {
	m, _ := getBenchFixture(b)
	hosts := []string{
		"a.b.c.tracker-1.net",
		"img.cdn.eu.tracker-250001.net",
		"bid.rtb.us-east.tracker-450002.org",
		"sync.pixel.dsp.tracker-620009.net",
	}

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		if !m.Match(hosts[i&3]) {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkMatchParallel(b *testing.B) {
	m, _ := getBenchFixture(b)
	hosts := []string{
		"api.segment.io",             // miss
		"cdn.jsdelivr.net",           // miss
		"bid.rtb.tracker-450002.org", // hit (subdomain)
		"static.nytimes.com",         // miss
		"tracker-100001.net",         // hit (exact)
		"assets.bbci.co.uk",          // miss
		"v3.node3.io",                // hit (exact)
		"edge.cache.fastly.net",      // miss
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = m.Match(hosts[i&7])
			i++
		}
	})
}

func BenchmarkOpen(b *testing.B) {
	_, payload := getBenchFixture(b)

	b.ReportAllocs()

	for b.Loop() {
		m, err := Open(bytes.NewReader(payload))
		if err != nil {
			b.Fatal(err)
		}
		if m.Size() != benchRuleCount {
			b.Fatalf("Size() = %d, want %d", m.Size(), benchRuleCount)
		}
	}
}
