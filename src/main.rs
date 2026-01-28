use anyhow::{Context, Result};
use clap::Parser;
use indicatif::ProgressBar;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use walkdir::WalkDir;

const READ_BUFFER_BYTES: usize = 1024 * 64;
const HASH_UPDATE_EVERY: u64 = 2;
const SCAN_UPDATE_EVERY: u64 = 1;

#[derive(Parser)]
#[command(
    name = "duplicate-file-finder",
    about = "Find duplicate files by SHA256"
)]
struct Args {
    #[arg(default_value = ".")]
    path: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let start = Instant::now();
    let progress = new_progress();
    let (by_size, scanned) = collect_by_size(&args.path, &progress);
    let (by_hash, processed) = hash_candidates(&by_size, &progress);
    progress.finish_with_message(format!("Hashed {processed} files"));
    print_duplicates(&by_hash);
    print_timing(start, scanned, processed);

    Ok(())
}

fn new_progress() -> ProgressBar {
    let progress = ProgressBar::new_spinner();
    progress.enable_steady_tick(Duration::from_millis(100));
    progress.set_message("Scanning files...");
    progress
}

fn collect_by_size(target: &Path, progress: &ProgressBar) -> (HashMap<u64, Vec<PathBuf>>, u64) {
    let mut by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    let mut scanned: u64 = 0;

    for entry in WalkDir::new(target).into_iter() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("Skipping entry due to error: {err}");
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        match entry.metadata() {
            Ok(metadata) => {
                by_size
                    .entry(metadata.len())
                    .or_default()
                    .push(path.to_path_buf());
            }
            Err(err) => {
                eprintln!("Skipping file {}: {err}", path.display());
            }
        }
        scanned += 1;
        if scanned % SCAN_UPDATE_EVERY == 0 {
            progress.set_message(format!("Scanned {scanned} files"));
        }
    }

    (by_size, scanned)
}

fn hash_candidates(
    by_size: &HashMap<u64, Vec<PathBuf>>,
    progress: &ProgressBar,
) -> (HashMap<String, Vec<PathBuf>>, u64) {
    let mut by_hash: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut processed: u64 = 0;
    progress.set_message("Hashing candidates...");

    for paths in by_size.values().filter(|paths| paths.len() > 1) {
        for path in paths {
            match compute_sha256(path) {
                Ok(hash) => {
                    by_hash.entry(hash).or_default().push(path.to_path_buf());
                }
                Err(err) => {
                    eprintln!("Skipping file {}: {err}", path.display());
                }

            }
            processed += 1;
            if processed % HASH_UPDATE_EVERY == 0 {
                progress.set_message(format!("Hashed {processed} files"));
            }
        }
    }

    (by_hash, processed)
}

fn print_duplicates(by_hash: &HashMap<String, Vec<PathBuf>>) {
    let mut groups: Vec<Vec<PathBuf>> = by_hash
        .values()
        .filter(|paths| paths.len() > 1)
        .map(|paths| {
            let mut group = paths.clone();
            group.sort_by(|a, b| a.as_os_str().cmp(b.as_os_str()));
            group
        })
        .collect();
    groups.sort_by(|a, b| a[0].as_os_str().cmp(b[0].as_os_str()));

    if groups.is_empty() {
        println!("No duplicates found.");
        return;
    }

    for paths in groups {
        println!("Duplicate group:");
        for path in paths {
            println!("  {}", path.display());
        }
    }
}

fn print_timing(start: Instant, scanned: u64, processed: u64) {
    let elapsed = start.elapsed().as_secs_f64();
    if elapsed > 0.0 {
        let scanned_rate = scanned as f64 / elapsed;
        let hashed_rate = processed as f64 / elapsed;
        println!(
            "Finished in {:.2}s (scanned {}, hashed {}, {:.1} scanned/s, {:.1} hashed/s)",
            elapsed, scanned, processed, scanned_rate, hashed_rate
        );
    } else {
        println!("Finished instantly (scanned {scanned}, hashed {processed})");
    }
}

fn compute_sha256(path: &Path) -> Result<String> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; READ_BUFFER_BYTES];

    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("Failed to read file {}", path.display()))?;
        if read == 0 {
            break;
        }
        // Chunked reads keep memory usage stable.
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn find_duplicate_groups(root: &Path) -> Vec<Vec<PathBuf>> {
        let progress = ProgressBar::hidden();
        let (by_size, _) = collect_by_size(root, &progress);
        let (by_hash, _) = hash_candidates(&by_size, &progress);
        let mut groups: Vec<Vec<PathBuf>> = by_hash
            .values()
            .filter(|paths| paths.len() > 1)
            .map(|paths| {
                let mut group = paths.clone();
                group.sort();
                group
            })
            .collect();
        groups.sort_by(|a, b| a[0].cmp(&b[0]));
        groups
    }

    #[test]
    fn detects_identical_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let a = temp.path().join("a.txt");
        let b = temp.path().join("b.txt");
        fs::write(&a, b"hello")?;
        fs::write(&b, b"hello")?;

        let groups = find_duplicate_groups(temp.path());
        assert_eq!(groups.len(), 1);
        assert!(groups[0].contains(&a));
        assert!(groups[0].contains(&b));
        Ok(())
    }

    #[test]
    fn ignores_same_size_different_content() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let a = temp.path().join("a.txt");
        let b = temp.path().join("b.txt");
        fs::write(&a, b"ab")?;
        fs::write(&b, b"cd")?;

        let groups = find_duplicate_groups(temp.path());
        assert!(groups.is_empty());
        Ok(())
    }

    #[test]
    fn groups_empty_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let a = temp.path().join("a.txt");
        let b = temp.path().join("b.txt");
        fs::write(&a, b"")?;
        fs::write(&b, b"")?;

        let groups = find_duplicate_groups(temp.path());
        assert_eq!(groups.len(), 1);
        assert!(groups[0].contains(&a));
        assert!(groups[0].contains(&b));
        Ok(())
    }

    #[test]
    fn finds_duplicates_in_nested_dirs() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let nested = temp.path().join("nested");
        fs::create_dir_all(&nested)?;
        let a = temp.path().join("a.txt");
        let b = nested.join("b.txt");
        fs::write(&a, b"nested")?;
        fs::write(&b, b"nested")?;

        let groups = find_duplicate_groups(temp.path());
        assert_eq!(groups.len(), 1);
        assert!(groups[0].contains(&a));
        assert!(groups[0].contains(&b));
        Ok(())
    }
}
