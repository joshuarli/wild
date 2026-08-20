use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use git2::{Repository, Signature};
use serde::Serialize;

#[derive(Parser)]
struct Args {
    /// Create the repository at this path instead of a temporary directory.
    #[arg(long)]
    path: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Serialize)]
struct Summary {
    branch: String,
    commit: String,
    tracked_bytes: usize,
}

fn create_repository(path: &Path) -> Result<Summary, Box<dyn std::error::Error>> {
    fs::create_dir_all(path)?;
    fs::write(path.join("README.md"), b"Wild qualifies real Cargo graphs.\n")?;

    let repository = Repository::init(path)?;
    let signature = Signature::now("Wild Cargo corpus", "wild-corpus@example.invalid")?;
    let mut index = repository.index()?;
    index.add_path(Path::new("README.md"))?;
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repository.find_tree(tree_id)?;
    let commit_id = repository.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "Initial corpus commit",
        &tree,
        &[],
    )?;
    let commit = repository.find_commit(commit_id)?;
    let commit_tree = commit.tree()?;
    let tracked = commit_tree
        .get_name("README.md")
        .ok_or("README.md missing from committed tree")?;
    let blob = repository.find_blob(tracked.id())?;

    Ok(Summary {
        branch: repository
            .head()?
            .shorthand()?
            .to_owned(),
        commit: commit_id.to_string(),
        tracked_bytes: blob.content().len(),
    })
}

fn main() {
    let args = Args::parse();
    let temporary = args.path.is_none();
    let path = args.path.unwrap_or_else(|| {
        std::env::temp_dir().join(format!(
            "wild-cargo-git2-corpus-{}",
            std::process::id()
        ))
    });
    let summary = create_repository(&path).expect("git2 repository operation failed");
    println!("{}", serde_json::to_string(&summary).expect("summary is serializable"));
    if temporary {
        fs::remove_dir_all(path).expect("temporary git2 repository cleanup failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_reads_a_committed_tree() {
        let path = std::env::temp_dir().join(format!(
            "wild-cargo-git2-corpus-test-{}",
            std::process::id()
        ));
        let summary = create_repository(&path).expect("git2 repository operation failed");
        assert_eq!(summary.branch, "master");
        assert_eq!(summary.tracked_bytes, b"Wild qualifies real Cargo graphs.\n".len());
        assert_eq!(summary.commit.len(), 40);
        fs::remove_dir_all(path).expect("temporary git2 repository cleanup failed");
    }
}
