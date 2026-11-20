# blocklistscanner

A high-throughput, zero-allocation, GC-friendly domain blocklist matcher for Go.

`blocklistscanner` is built for latency-sensitive services (such as ad exchanges, DNS resolvers, and HTTP proxies) that perform dozens of domain lookups per request against large blocklists containing hundreds of thousands of rules.

## How It Works

- **Zero GC Overhead:** Indexed domains are stored in a contiguous, null-terminated `[]byte` arena paired with a `[]uint32` open-addressed hash table. Because neither slice contains pointers, Go's garbage collector skips the entire ~18.4 MB structure during mark cycles.
- **Single-Pass Parent Matching:** `Match()` hashes candidate hostnames from right to left (TLD $\rightarrow$ root domain $\rightarrow$ subdomains) using FNV-1a, checking every parent domain level in a single backward scan with zero heap allocations.
- **Subdomain & Exact Semantics:** Matching `||example.com^` blocks `example.com` as well as any nested subdomain (`cdn.v1.example.com`), while rejecting partial label suffixes (`notexample.com`).

## Blocklist Data Source

This package parses AdBlock-style domain rules (`||domain^`) compatible with [HaGeZi's DNS Blocklists](https://github.com/hagezi/dns-blocklists).

To download and compress the default NSFW blocklist for local loading or uploading to S3:

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt
  | gzip -9 > domains.gz
```

Example input format:

```text
! Title: HaGeZi's NSFW DNS Blocklist
||021td.com^
||tracker.example.org^
```

Comments (`!`, `#`, `[`) and blank lines are ignored during parsing. Rules are validated and normalized to lowercase on load.

## Installation

```bash
go get github.com/marcsantiago/blocklistscanner
```

## Usage

### Static File Loading

```go
package main

import (
	"fmt"
	"log"

	"github.com/marcsantiago/blocklistscanner
)

func main() {
	// Load directly from a gzipped AdBlock-formatted list
	matcher, err := blocklistscanner.OpenGzip("domains.gz")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Loaded %d unique domains\n", matcher.Size())

	// Match checks the host and all of its parent domains (case-insensitive)
	fmt.Println(matcher.Match("021td.com"))          // true
	fmt.Println(matcher.Match("cdn.v8v1.021td.com")) // true
	fmt.Println(matcher.Match("not021td.com"))       // false

	// Contains checks only for an exact domain match
	fmt.Println(matcher.Contains("021td.com"))       // true
	fmt.Println(matcher.Contains("cdn.021td.com"))   // false
}
```

### Runtime Hot-Reloading (S3 / HTTP)

`Store` wraps `Matcher` in an `atomic.Pointer` so request goroutines read with zero lock contention while background updates swap in fresh blocklists. Both gzipped and plain-text payloads are detected automatically.

#### From an S3 / HTTPS URL (with `ETag` caching)

```go
store := blocklistscanner.NewStore(
	blocklistscanner.WithURL("https://your-bucket.s3.amazonaws.com/domains.gz"),
)

if _, err := store.Reload(ctx); err != nil {
	log.Fatal(err)
}

// Poll periodically; unchanged S3 objects return HTTP 304 and skip re-indexing
go func() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := store.Reload(ctx); err != nil {
				log.Printf("blocklist reload failed: %v", err)
			}
		}
	}
}()

// Lock-free lookup on the hot path
if store.Match("cdn.v8v1.021td.com") {
	// blocked
}
```

#### From a Private S3 Bucket via AWS SDK

```go
store := blocklistscanner.NewStore(
	blocklistscanner.WithSource(func(ctx context.Context) (io.ReadCloser, error) {
		out, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String("your-bucket"),
			Key:    aws.String("blocklists/domains.gz"),
		})
		if err != nil {
			return nil, err
		}
		return out.Body, nil
	}),
)
```

## Benchmarks

Benchmarked against **627,122 rules** on an **Apple M1 Pro** (`darwin/arm64`, Go `1.27.1`):

| Benchmark                           |  Iterations |         Latency |  Bytes / Op |  Allocs / Op |
| :---------------------------------- | ----------: | --------------: | ----------: | -----------: |
| `BenchmarkMatchMiss`                |  42,428,875 | **28.59 ns/op** |      0 B/op |  0 allocs/op |
| `BenchmarkMatchHitExact`            |  32,754,481 | **36.54 ns/op** |      0 B/op |  0 allocs/op |
| `BenchmarkMatchParallel` (10 cores) | 302,766,974 |  **4.01 ns/op** |      0 B/op |  0 allocs/op |
| `BenchmarkOpen` (cold load & index) |          18 | **70.83 ms/op** | 63.24 MB/op | 36 allocs/op |

_(Steady-state heap footprint after `Open` returns is ~18.4 MB with 0 GC-scanned pointers.)_

### Raw Benchmark Output

```text
goos: darwin
goarch: arm64
pkg: blocklistscanner
cpu: Apple M1 Pro
BenchmarkMatchMiss-10                   42428875                28.61 ns/op            0 B/op          0 allocs/op
BenchmarkMatchMiss-10                   41979264                28.58 ns/op            0 B/op          0 allocs/op
BenchmarkMatchMiss-10                   41943009                28.59 ns/op            0 B/op          0 allocs/op
BenchmarkMatchHitExact-10               32568979                36.60 ns/op            0 B/op          0 allocs/op
BenchmarkMatchHitExact-10               32754481                36.50 ns/op            0 B/op          0 allocs/op
BenchmarkMatchHitExact-10               32710432                36.54 ns/op            0 B/op          0 allocs/op
BenchmarkMatchParallel-10               302766974                3.972 ns/op           0 B/op          0 allocs/op
BenchmarkMatchParallel-10               300845248                4.093 ns/op           0 B/op          0 allocs/op
BenchmarkMatchParallel-10               300254182                3.984 ns/op           0 B/op          0 allocs/op
BenchmarkOpen-10                              18          65321512 ns/op        63242096 B/op         36 allocs/op
BenchmarkOpen-10                              15          73366981 ns/op        63242137 B/op         36 allocs/op
BenchmarkOpen-10                              15          73799969 ns/op        63242096 B/op         36 allocs/op
```

## Development

```bash
# Run unit tests with the race detector
go test -race -v ./...

# Run benchmarks with memory allocation stats
go test -bench=. -benchmem -count=3 ./...
```
