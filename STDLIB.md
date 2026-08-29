# STDLIB.md — Standard Library Substitution Matrix

This document details how ZeroTrust implements all required data structures, algorithms, parsers, and system utilities using **only Go standard library primitives**, replacing 10 third-party packages commonly found in security CLIs.

---

### 1. `github.com/pelletier/go-toml` → `bufio.Scanner` + Hand-Rolled TOML Tokenizer
**Ecosystem context:** In a typical Go security tool auditing `Cargo.toml` dependency manifests, developers import `pelletier/go-toml` or `BurntSushi/toml`.
**What we built:** We implemented a hand-rolled line-by-line TOML tokenizer (`manifest/cargo.go`) that tracks table section headers (`[dependencies]`, `[dev-dependencies]`), parses key-value pairs, strips inline comments, and unwraps inline tables (`tokio = { version = "1.0", features = ["full"] }`).
**Why this is a real substitution, not a toy:** It correctly handles key normalization, dotted table headers, and complex inline table fields without depending on external reflection-heavy parser engines.

---

### 2. `github.com/agnivade/levenshtein` → Dynamic-Programming Matrix in `detect/typosquat.go`
**Ecosystem context:** In CLI security tools checking dependency similarity, developers rely on third-party string distance libraries to detect typosquats.
**What we built:** We built a hand-rolled Levenshtein distance matrix solver using stdlib `[]rune` slices and classic 2D dynamic programming ($O(n \cdot m)$ time and space).
**Why this is a real substitution, not a toy:** It correctly handles multi-byte UTF-8 runes, deletion/insertion/substitution cost matrices, and strictly enforces exact-match exemptions to eliminate false-positive self-flagging.

---

### 3. `github.com/bits-and-blooms/bloom` → Hand-Rolled Bit Array + FNV Double Hashing
**Ecosystem context:** Fast $O(1)$ set membership checks against 10,000+ package names usually require external Bloom filter packages.
**What we built:** We constructed a thread-safe Bloom filter (`bloom/bloom.go`) backed by a `[]uint64` bit array, utilizing standard library `hash/fnv` (FNV-1 and FNV-1a) to implement Kirsch-Mitzenmacher double hashing ($g_i(x) = h_1(x) + i \cdot h_2(x) \pmod m$).
**Why this is a real substitution, not a toy:** It dynamically computes optimal bit array size $m$ and hash function count $k$ based on target false-positive probability bounds ($p < 0.001$).

---

### 4. `github.com/armon/go-radix` → Hand-Rolled Prefix Trie in `trie/trie.go`
**Ecosystem context:** Prefix matching and candidate generation for typosquat edit-distance checks require a Trie or Radix tree structure.
**What we built:** We implemented a concurrent, thread-safe N-ary prefix Trie (`trie/trie.go`) supporting word insertion, exact search, prefix traversal, and candidate list collection.
**Why this is a real substitution, not a toy:** It prunes candidate generation for similarity checks from 15,000 linear comparisons down to a sub-millisecond prefix sub-tree traversal.

---

### 5. `github.com/fatih/color` & `github.com/charmbracelet/lipgloss` → ANSI Escape Sequences in `ui/ansi.go`
**Ecosystem context:** Go CLI tools use `fatih/color` or `lipgloss` for colored terminal output and aligned summary tables.
**What we built:** We hand-rolled ANSI escape sequence wrappers (`ui/ansi.go`), status badges, and an ASCII table formatter that calculates visible rune column widths while stripping ANSI escape codes.
**Why this is a real substitution, not a toy:** It provides clean multi-column table padding and colored severity indicators without introducing external styling frameworks. *(Note: The September 2025 `chalk` account takeover in the npm ecosystem served as the hackathon's motivating incident for eliminating terminal styling dependencies).*

---

### 6. `golang.org/x/time/rate` → Thread-Safe Token Bucket Rate Limiter
**Ecosystem context:** Live HTTP queries to registry APIs require rate limiting to prevent throttling or IP bans, typically using `golang.org/x/time/rate`.
**What we built:** We implemented a thread-safe Token Bucket rate limiter (`registry/ratelimit.go`) using `sync.Mutex`, `time.Now()`, and `time.Sleep()`.
**Why this is a real substitution, not a toy:** It dynamically refills tokens based on elapsed sub-second intervals and blocks callers until capacity becomes available. *(Note: The default rate limit is deliberately kept conservative at 2 requests/second to prevent triggering registry-side IP throttling during live demonstration and evaluation)*.

---

### 7. `github.com/go-resty/resty` → Standard Library `net/http` Client
**Ecosystem context:** Querying remote REST APIs often leads developers to pull in high-level HTTP client libraries like `resty`.
**What we built:** We built an opt-in live registry verification client (`registry/live.go`) using Go's built-in `net/http.Client` with custom timeouts, `User-Agent` headers, and HTTP status code interpretation.
**Why this is a real substitution, not a toy:** It gracefully catches network timeouts and transport errors, falling back to offline Bloom filter findings without crashing the process.

---

### 8. `github.com/syndtr/goleveldb` → Append-Only Line-Formatted KV Disk Store
**Ecosystem context:** Persisting live registry lookup results across runs typically uses an embedded KV database like LevelDB or BoltDB.
**What we built:** We created an append-only file KV store (`cache/kv.go`) using `os.OpenFile` with `O_APPEND`, line-oriented parsing (`bufio.Scanner`), and a 7-day TTL expiration policy.
**Why this is a real substitution, not a toy:** It provides durable disk persistence and fast in-memory lookup caching with zero CGO or external database dependencies.

---

### 9. Shannon Entropy Calculation → `math.Log2` Histogram in `detect/entropy.go`
**Ecosystem context:** Detecting obfuscated binary payloads in source files requires computing Shannon entropy ($H(X) = -\sum P(x_i) \log_2 P(x_i)$), often offloaded to third-party math packages.
**What we built:** We built a byte-frequency histogram calculator (`detect/entropy.go`) over 256-byte sliding windows using `math.Log2`.
**Why this is a real substitution, not a toy:** It scans arbitrary binary/text streams with 50% overlapping windows and filters out legitimate binary formats via an extension allowlist/denylist heuristic.

---

### 10. `github.com/smacker/go-tree-sitter` → Lexical Pattern Tokenizer in `detect/tokens.go`
**Ecosystem context:** Identifying dangerous execution calls (`eval`, `child_process.exec`, `os.system`) often prompts developers to import full AST parsers like Tree-Sitter.
**What we built:** We implemented a fast line-by-line lexical tokenizer (`detect/tokens.go`) scanning source code for high-risk token patterns while ignoring pure comment lines.
**Why this is a real substitution, not a toy:** It delivers immediate pattern detection across JS, TS, Python, and Shell files without the overhead or native build requirements of full language grammars.

---

### 11. `github.com/owenrumney/go-sarif` → Standard Library `encoding/json` SARIF 2.1.0 Subset Emitter
**Ecosystem context:** Exporting structured static-analysis reports for CI/CD integrations or GitHub Security Code Scanning typically requires specialized SARIF reporting libraries.
**What we built:** We built a zero-dependency JSON and SARIF 2.1.0 report formatter (`ui/json.go`) directly using Go's standard library `encoding/json`.
**Why this is a real substitution, not a toy:** It constructs valid SARIF 2.1.0 telemetry documents with tool driver definitions, rule catalogs (`ZT001`–`ZT005`), result locations, and severity levels compatible with GitHub Code Scanning without importing external schema generators. *(Note: Documented as a minimal, best-effort SARIF 2.1.0 subset focusing on rule identifiers, physical artifact locations, and message strings)*.
