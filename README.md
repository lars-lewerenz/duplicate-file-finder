# duplicate-file-finder

Find duplicate files inside a folder with a fast, size-first scan and SHA256 verification.

## Why

File copies build up quickly across project folders and backups. This tool keeps the workflow simple while still using a reliable hash to confirm duplicates.

## How it works

1. Walk the target directory and group files by size.
2. Hash only the size-matched candidates with SHA256.
3. Print duplicate groups and a timing summary.

## Usage

```sh
cargo run --
cargo run -- /path/to/folder
```

## Output

Duplicates are grouped by file paths, followed by total runtime and processing rates.
