# ZeroTrust Corpus Provenance & Sources

## Overview

ZeroTrust utilizes embedded, offline corpora of known package names across three primary package ecosystems (`npm`, `PyPI`, and `crates.io`). These corpora serve as the baseline dataset for the offline Bloom filter (instant existence checks) and prefix Trie (candidate generation for typosquat distance detection).

> [!IMPORTANT]
> **Corpus Transparency & Honesty Disclosure**:
> The package lists embedded in `npm_curated.txt.gz`, `pypi_curated.txt.gz`, and `crates_curated.txt.gz` are curated, high-confidence representative datasets of well-known, highly-downloaded packages in each respective ecosystem. They are **not** complete dumps of public registries. Every package name in these lists has been verified to exist on the public registry as of August 2026.

## Ecosystem Breakdown

| Ecosystem | Embedded File | Package Count | Compilation Basis | Retrieval / Verification Date |
| :--- | :--- | :--- | :--- | :--- |
| **npm** | `data/npm_curated.txt.gz` | 189 real packages | Curated top downloaded packages (frameworks, utilities, build tools, stdlib shims) | August 2026 |
| **PyPI** | `data/pypi_curated.txt.gz` | 120 real packages | Curated top PyPI packages (data science, web frameworks, async, system utilities) | August 2026 |
| **crates.io** | `data/crates_curated.txt.gz` | 90 real packages | Curated top Rust crates (concurrency, serialization, network, CLI, async) | August 2026 |

## Compilation Methodology

1. **Extraction**: Selected top download-ranked packages from public registry statistics (npm registry, PyPI download counts, Crates.io API statistics).
2. **Verification**: Checked every name against official registry APIs (`registry.npmjs.org`, `pypi.org`, `crates.io/api/v1`) to prevent inclusion of non-existent or deleted package names.
3. **Format**: One lowercase package name per line, gzip-compressed to minimize binary footprint (<50KB embedded).
4. **License Notice**: Package names are public domain metadata and non-copyrightable identifiers under standard intellectual property law.
