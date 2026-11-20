package blocklist

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// SourceFunc fetches a blocklist stream (plain text or gzipped) from any backend.
type SourceFunc func(ctx context.Context) (io.ReadCloser, error)

// Option configures a Store.
type Option func(*Store)

// WithURL configures the Store to fetch the blocklist over HTTP/HTTPS
// (for example, a public or pre-signed S3 object URL).
func WithURL(rawURL string) Option {
	return func(s *Store) {
		s.url = rawURL
	}
}

// WithHTTPClient sets a custom *http.Client for HTTP/HTTPS fetches.
func WithHTTPClient(client *http.Client) Option {
	return func(s *Store) {
		if client != nil {
			s.client = client
		}
	}
}

// WithHeader adds a custom HTTP header to outgoing fetch requests.
func WithHeader(key, value string) Option {
	return func(s *Store) {
		if s.headers == nil {
			s.headers = make(http.Header)
		}
		s.headers.Add(key, value)
	}
}

// WithSource configures a custom loader (such as an AWS SDK S3 GetObject wrapper)
// instead of an HTTP URL.
func WithSource(fn SourceFunc) Option {
	return func(s *Store) {
		s.source = fn
	}
}

// OpenURL fetches an AdBlock-formatted domain list (plain text or gzipped)
// from rawURL and returns a ready-to-use Matcher.
func OpenURL(ctx context.Context, rawURL string, client *http.Client) (*Matcher, error) {
	if rawURL == "" {
		return nil, errors.New("blocklistscanner: URL must not be empty")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("blocklistscanner: unexpected status %s fetching %s", resp.Status, rawURL)
	}

	return openAuto(resp.Body)
}

// Store holds an atomically swappable Matcher for lock-free reads during updates.
type Store struct {
	current atomic.Pointer[Matcher]
	url     string
	client  *http.Client
	headers http.Header
	source  SourceFunc

	mu           sync.Mutex
	etag         string
	lastModified string
}

// NewStore creates a new Store configured with the provided options.
// Call Reload once at startup to load the initial blocklist.
func NewStore(opts ...Option) *Store {
	s := &Store{
		client: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// Match delegates to the currently active Matcher with zero lock contention.
func (s *Store) Match(host string) bool {
	m := s.current.Load()
	return m != nil && m.Match(host)
}

// Contains delegates to the currently active Matcher with zero lock contention.
func (s *Store) Contains(domain string) bool {
	m := s.current.Load()
	return m != nil && m.Contains(domain)
}

// Size returns the number of domains in the currently active Matcher.
func (s *Store) Size() int {
	m := s.current.Load()
	if m == nil {
		return 0
	}
	return m.Size()
}

// Reload fetches, validates, and atomically swaps in an updated Matcher.
// When using WithURL, conditional HTTP headers (ETag / Last-Modified) are sent
// so unchanged S3/CDN objects return updated=false without re-downloading.
func (s *Store) Reload(ctx context.Context) (updated bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.source != nil {
		rc, err := s.source(ctx)
		if err != nil {
			return false, err
		}
		defer func() { _ = rc.Close() }()

		next, err := openAuto(rc)
		if err != nil {
			return false, err
		}
		s.current.Store(next)
		return true, nil
	}

	if s.url == "" {
		return false, errors.New("blocklistscanner: no URL or custom source configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return false, err
	}
	for k, vals := range s.headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	if s.etag != "" {
		req.Header.Set("If-None-Match", s.etag)
	}
	if s.lastModified != "" {
		req.Header.Set("If-Modified-Since", s.lastModified)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("blocklistscanner: unexpected status %s fetching %s", resp.Status, s.url)
	}

	next, err := openAuto(resp.Body)
	if err != nil {
		return false, err
	}

	s.current.Store(next)
	s.etag = resp.Header.Get("ETag")
	s.lastModified = resp.Header.Get("Last-Modified")
	return true, nil
}

// openAuto transparently decompresses gzip streams (magic bytes 0x1f 0x8b)
// or reads plain text directly.
func openAuto(r io.Reader) (*Matcher, error) {
	br := bufio.NewReader(r)
	hdr, err := br.Peek(2)
	if err == nil && hdr[0] == 0x1f && hdr[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer func() { _ = gz.Close() }()
		return Open(gz)
	}
	return Open(br)
}
