# LPR Technical Context & Developer Specification

**Version:** 1.4.0
**Attribution:** Made using vibe coding by Sunil Warrier
**License:** MIT OR The Unlicense

---

## 1. Toolchain

- **Host:** macOS aarch64 (Apple Silicon), Rust `stable-aarch64-apple-darwin`
- **Windows cross:** `x86_64-pc-windows-gnu` via `x86_64-w64-mingw32-gcc`/`ar` (see `.cargo/config.toml`, `jobs = 4`)
- **CI:** `.github/workflows/build.yml` (Windows/Linux/macOS)

## 2. Crate Versions (Cargo.toml)

| Crate | Version | Purpose |
|---|---|---|
| arrow | 53 | columnar storage |
| datafusion | 42 | SQL engine |
| rayon | 1.10 | parallel parsing |
| clap | 4.5 | CLI |
| tokio, axum | 1.x/0.7 | async + REST |
| ratatui, crossterm | TUI | |
| tao, wry | gui feature | |
| encoding_rs | | UTF-16/Win-1252 |
| flate2, zstd, zip | | compression |
| evtx | | Windows events |
| calamine | | Excel |
| parquet | | columnar sink |
| serde, serde_json, csv | | serialization |
| ipnet, regex, urlencoding | | UDF support |

## 3. Architecture Flow

```
CLI args ──preprocess_cli_args──> clap Cli ──> Commands::{Query?, Audit, Suggest, Sdk,
                                              Gui, Tui, Mcp, Serve, Fleet, Config}
                                                    │
Query path: extract_into_from_sql → extract_source_from_sql →
  LogEngine::register_source(name, pattern, fmt, checkpoint) →
    parsers::resolve_source_items(pattern) → Vec<LogSourceItem>
      (DiskFile | ZipEntry{archive,index,name,size} | Stdin)
    parsers::detect_format_item → InputFormat
    parsers::parse_* (rayon par_iter across items) → Vec<RecordBatch>
    engine wraps batches in partitioned MemTable → ctx.register_table("logs")
  normalize_sql (brackets→snake_case, TOP→LIMIT, hyphen→_) → ctx.sql()
  → sinks::render(batches, output_fmt, max_width, vertical)
```

## 4. Key Invariants

- **All parsed columns are `Utf8`** — numeric ops require `CAST(col AS BIGINT/FLOAT)`.
- `log_filename`/`log_row` injected per row by every parser.
- Engine never panics on encoding — `decode_line()` handles BOM/UTF-16/Win-1252/lossy.
- `.zip` items parse in parallel via `rayon::par_iter`, one `RecordBatch` per entry → separate MemTable partition → DataFusion parallel exec.
- `FleetScanConfig` merges precedence: CLI arg > saved profile > defaults. `SavedProfile` fields are all `Option<T>` so absent keys mean "not set".
- No secrets ever stored in `lpr.config.json` — only paths/patterns/usernames.

## 5. UDF Registration (`src/udfs.rs`)

`register_all_udfs(ctx)` registers 27 scalar UDFs. Signature note: multi-arg UDFs must expand `ColumnarValue::Scalar` via `s.to_array_of_size(n)` where `n = max(array arg len)` — plain `to_array()` produces length-1 and DataFusion aborts with "UDF returned a different number of rows".

New in 1.4.0: `time_bucket`, `date_diff_days`, `geoip_scope`, `url_path`.

## 6. Adding a New Input Format

1. Add variant to `InputFormat` enum (with `#[value(alias = "...")]`).
2. Add detection heuristics in `detect_format_item` (filename + first-lines sniffing).
3. Write `parse_<fmt>_items(items) → Vec<RecordBatch>`; register in `register_source`.
4. Add audit rules in `src/audit.rs` and intent templates in `src/engine.rs::suggest_queries`.
5. Add a synthetic file under `samples/<fmt>/` and a smoke-test case in `tests/smoke_test.sh`.

## 7. Testing

```bash
bash tests/smoke_test.sh        # 10 suites
cargo check / cargo build       # incremental
./target/release/lpr <cmd>      # manual verify
```

## 8. Git / Release Hygiene

- `.gitignore`: `/target`, `Cargo.lock`, `*.parquet`, `*.checkpoint.json`, `lpr.config.json`, `samples_client_local/`, `*.zip` except `samples/**/*.zip`.
- Never commit `samples_client_local/`, real `lpr.config.json`, or generated `output/` CSVs.
- Commit style: conventional prefix, body explains **why**, footer `Generated with [Devin](https://devin.ai)` + co-author trailer.
