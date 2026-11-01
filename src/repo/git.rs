//! Minimal read-only Git metadata reader.
//!
//! Reads HEAD, refs, and the origin URL directly instead of running `git`, so
//! the fact works before Saltbox configures `safe.directory` and regardless of
//! repository ownership. Only the files-based ref storage is supported.

use std::path::{Component, Path, PathBuf};

const MAX_SYMREF_DEPTH: usize = 5;
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Default, Eq, PartialEq)]
pub struct LocalState {
    /// Checked-out branch; `None` when HEAD is detached.
    pub branch: Option<String>,
    /// HEAD commit; `None` for a branch without commits.
    pub commit: Option<String>,
    pub detached: bool,
    pub origin_url: Option<String>,
}

pub fn read_local(repo: &Path) -> Result<LocalState, String> {
    let git_dir = git_dir(repo)?;
    let common_dir = common_dir(&git_dir)?;
    let config = match read_small(&common_dir.join("config")) {
        Ok(content) => Config::parse(&content),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(error) => return Err(format!("Failed to read Git config: {error}")),
    };
    if config
        .last("extensions", None, "refstorage")
        .is_some_and(|storage| !storage.eq_ignore_ascii_case("files"))
    {
        return Err("Git ref storage other than files (e.g. reftable) is not supported".into());
    }
    let origin_url = config
        .first("remote", Some("origin"), "url")
        .map(str::to_string);

    let head = read_small(&git_dir.join("HEAD"))
        .map_err(|error| format!("Failed to read Git HEAD: {error}"))?;
    let head = head.trim();
    let refs = Refs {
        git_dir: &git_dir,
        common_dir: &common_dir,
    };

    if let Some(reference) = head.strip_prefix("ref:") {
        let reference = reference.trim();
        let branch = reference
            .strip_prefix("refs/heads/")
            .ok_or_else(|| format!("HEAD points outside refs/heads: {reference}"))?;
        Ok(LocalState {
            branch: Some(branch.to_string()),
            commit: refs.resolve(reference)?,
            detached: false,
            origin_url,
        })
    } else if is_object_id(head) {
        Ok(LocalState {
            branch: None,
            commit: Some(head.to_ascii_lowercase()),
            detached: true,
            origin_url,
        })
    } else {
        Err("Git HEAD has an unrecognised format".to_string())
    }
}

fn git_dir(repo: &Path) -> Result<PathBuf, String> {
    let dot_git = repo.join(".git");
    let metadata = std::fs::metadata(&dot_git)
        .map_err(|error| format!("{} is not a Git repository: {error}", repo.display()))?;
    if metadata.is_dir() {
        return Ok(dot_git);
    }
    // Worktrees and submodules use a `.git` file pointing at the real directory.
    let content = read_small(&dot_git)
        .map_err(|error| format!("Failed to read {}: {error}", dot_git.display()))?;
    let target = content
        .trim()
        .strip_prefix("gitdir:")
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .ok_or_else(|| format!("{} has no gitdir line", dot_git.display()))?;
    Ok(repo.join(target))
}

fn common_dir(git_dir: &Path) -> Result<PathBuf, String> {
    match read_small(&git_dir.join("commondir")) {
        Ok(content) => Ok(git_dir.join(content.trim())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(git_dir.to_path_buf()),
        Err(error) => Err(format!("Failed to read Git commondir: {error}")),
    }
}

fn read_small(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut content = String::new();
    file.take(MAX_METADATA_BYTES).read_to_string(&mut content)?;
    Ok(content)
}

struct Refs<'a> {
    git_dir: &'a Path,
    common_dir: &'a Path,
}

impl Refs<'_> {
    /// Resolves a ref to a commit, following symbolic refs. `Ok(None)` means
    /// the ref does not exist yet, e.g. a branch without commits.
    fn resolve(&self, reference: &str) -> Result<Option<String>, String> {
        let mut reference = reference.to_string();
        for _ in 0..MAX_SYMREF_DEPTH {
            if !is_safe_ref_name(&reference) {
                return Err(format!("Refusing unsafe Git ref name: {reference}"));
            }
            let value = match self.loose(&reference)? {
                Some(value) => value,
                None => return self.packed(&reference),
            };
            if let Some(target) = value.strip_prefix("ref:") {
                reference = target.trim().to_string();
            } else if is_object_id(&value) {
                return Ok(Some(value.to_ascii_lowercase()));
            } else {
                return Err(format!("Git ref {reference} has an unrecognised format"));
            }
        }
        Err(format!(
            "Git ref {reference} exceeds {MAX_SYMREF_DEPTH} symbolic levels"
        ))
    }

    fn loose(&self, reference: &str) -> Result<Option<String>, String> {
        // Per-worktree refs live in the worktree's directory, shared refs in
        // the common directory.
        for directory in [self.git_dir, self.common_dir] {
            match read_small(&directory.join(reference)) {
                Ok(value) => return Ok(Some(value.trim().to_string())),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::IsADirectory
                    ) => {}
                Err(error) => return Err(format!("Failed to read Git ref {reference}: {error}")),
            }
        }
        Ok(None)
    }

    fn packed(&self, reference: &str) -> Result<Option<String>, String> {
        let content = match read_small(&self.common_dir.join("packed-refs")) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("Failed to read Git packed-refs: {error}")),
        };
        Ok(content
            .lines()
            .filter(|line| !line.starts_with('#') && !line.starts_with('^'))
            .filter_map(|line| line.split_once(' '))
            .find(|(_, name)| name.trim() == reference)
            .map(|(id, _)| id.trim())
            .filter(|id| is_object_id(id))
            .map(str::to_ascii_lowercase))
    }
}

fn is_safe_ref_name(reference: &str) -> bool {
    reference.starts_with("refs/")
        && Path::new(reference)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// SHA-1 (40) or SHA-256 (64) hexadecimal object IDs.
pub fn is_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Subset of the Git config format: sections, quoted subsections, and
/// key/value lines with quoting, escapes, and comments. Includes are not
/// followed.
#[derive(Debug, Default)]
struct Config {
    entries: Vec<ConfigEntry>,
}

#[derive(Debug)]
struct ConfigEntry {
    section: String,
    subsection: Option<String>,
    key: String,
    value: String,
}

impl Config {
    fn parse(content: &str) -> Self {
        let mut entries = Vec::new();
        let mut section = String::new();
        let mut subsection = None;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(header) = line.strip_prefix('[') {
                if let Some((name, sub)) = parse_section_header(header) {
                    section = name;
                    subsection = sub;
                }
                continue;
            }
            let (key, value) = match line.split_once('=') {
                Some((key, value)) => (key.trim(), parse_value(value)),
                None => (strip_comment(line).trim(), "true".to_string()),
            };
            if key.is_empty() || section.is_empty() {
                continue;
            }
            entries.push(ConfigEntry {
                section: section.clone(),
                subsection: subsection.clone(),
                key: key.to_ascii_lowercase(),
                value,
            });
        }
        Self { entries }
    }

    fn values(&self, section: &str, subsection: Option<&str>, key: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.section == section
                    && entry.subsection.as_deref() == subsection
                    && entry.key == key
            })
            .map(|entry| entry.value.as_str())
            .collect()
    }

    fn first(&self, section: &str, subsection: Option<&str>, key: &str) -> Option<&str> {
        self.values(section, subsection, key).first().copied()
    }

    fn last(&self, section: &str, subsection: Option<&str>, key: &str) -> Option<&str> {
        self.values(section, subsection, key).last().copied()
    }
}

/// Parses `section "subsection"]` or the legacy `section.subsection]`.
/// Section names are case-insensitive; quoted subsections are not.
fn parse_section_header(header: &str) -> Option<(String, Option<String>)> {
    let header = header.trim_start();
    if let Some(quote) = header.find('"') {
        let name = header[..quote].trim().to_ascii_lowercase();
        let mut subsection = String::new();
        let mut chars = header[quote + 1..].chars();
        loop {
            match chars.next()? {
                '\\' => subsection.push(chars.next()?),
                '"' => break,
                character => subsection.push(character),
            }
        }
        chars
            .as_str()
            .trim_start()
            .starts_with(']')
            .then_some((name, Some(subsection)))
    } else {
        let name = header[..header.find(']')?].trim().to_ascii_lowercase();
        match name.split_once('.') {
            Some((section, subsection)) => {
                Some((section.to_string(), Some(subsection.to_string())))
            }
            None => Some((name, None)),
        }
    }
}

fn parse_value(raw: &str) -> String {
    let mut value = String::new();
    let mut quoted = false;
    // Length of `value` up to its last character that must be kept, so
    // unquoted trailing whitespace is dropped.
    let mut keep = 0;
    let mut chars = raw.trim_start().chars();
    while let Some(character) = chars.next() {
        match character {
            '"' => {
                quoted = !quoted;
                keep = value.len();
            }
            '\\' => {
                match chars.next() {
                    Some('n') => value.push('\n'),
                    Some('t') => value.push('\t'),
                    Some('b') => {
                        value.pop();
                    }
                    Some(other) => value.push(other),
                    None => {}
                }
                keep = value.len();
            }
            '#' | ';' if !quoted => break,
            character => {
                value.push(character);
                if quoted || !character.is_whitespace() {
                    keep = value.len();
                }
            }
        }
    }
    value.truncate(keep);
    value
}

fn strip_comment(line: &str) -> &str {
    line.find(['#', ';']).map_or(line, |index| &line[..index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const SHA_A: &str = "1111111111111111111111111111111111111111";
    const SHA_B: &str = "2222222222222222222222222222222222222222";

    fn repo_with(head: &str, files: &[(&str, &str)]) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let git = directory.path().join(".git");
        fs::create_dir_all(git.join("refs/heads")).unwrap();
        fs::write(git.join("HEAD"), head).unwrap();
        for (path, content) in files {
            let path = git.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        directory
    }

    #[test]
    fn reads_a_branch_from_a_loose_ref() {
        let repo = repo_with(
            "ref: refs/heads/master\n",
            &[
                ("refs/heads/master", &format!("{SHA_A}\n")),
                (
                    "config",
                    "[remote \"origin\"]\n\turl = https://github.com/saltyorg/saltbox.git\n",
                ),
            ],
        );
        assert_eq!(
            read_local(repo.path()).unwrap(),
            LocalState {
                branch: Some("master".to_string()),
                commit: Some(SHA_A.to_string()),
                detached: false,
                origin_url: Some("https://github.com/saltyorg/saltbox.git".to_string()),
            }
        );
    }

    #[test]
    fn prefers_loose_refs_over_packed_refs() {
        let packed = format!("# pack-refs with: peeled fully-peeled sorted\n{SHA_B} refs/heads/develop\n^{SHA_A}\n{SHA_B} refs/heads/master\n");
        let repo = repo_with("ref: refs/heads/develop", &[("packed-refs", &packed)]);
        assert_eq!(
            read_local(repo.path()).unwrap().commit.as_deref(),
            Some(SHA_B)
        );

        let repo = repo_with(
            "ref: refs/heads/master",
            &[("packed-refs", &packed), ("refs/heads/master", SHA_A)],
        );
        assert_eq!(
            read_local(repo.path()).unwrap().commit.as_deref(),
            Some(SHA_A)
        );
    }

    #[test]
    fn reports_detached_heads() {
        let repo = repo_with(&format!("{}\n", SHA_A.to_uppercase()), &[]);
        let state = read_local(repo.path()).unwrap();
        assert!(state.detached);
        assert_eq!(state.branch, None);
        assert_eq!(state.commit.as_deref(), Some(SHA_A));
    }

    #[test]
    fn unborn_branches_have_no_commit() {
        let repo = repo_with("ref: refs/heads/main\n", &[]);
        let state = read_local(repo.path()).unwrap();
        assert_eq!(state.branch.as_deref(), Some("main"));
        assert_eq!(state.commit, None);
    }

    #[test]
    fn follows_worktree_gitdir_and_commondir() {
        let main = repo_with(
            "ref: refs/heads/master\n",
            &[
                ("refs/heads/feature", SHA_B),
                (
                    "config",
                    "[remote \"origin\"]\nurl = https://github.com/saltyorg/Saltbox\n",
                ),
                ("worktrees/wt/HEAD", "ref: refs/heads/feature\n"),
                ("worktrees/wt/commondir", "../..\n"),
            ],
        );
        let worktree = tempfile::tempdir().unwrap();
        fs::write(
            worktree.path().join(".git"),
            format!(
                "gitdir: {}\n",
                main.path().join(".git/worktrees/wt").display()
            ),
        )
        .unwrap();
        let state = read_local(worktree.path()).unwrap();
        assert_eq!(state.branch.as_deref(), Some("feature"));
        assert_eq!(state.commit.as_deref(), Some(SHA_B));
        assert_eq!(
            state.origin_url.as_deref(),
            Some("https://github.com/saltyorg/Saltbox")
        );
    }

    #[test]
    fn rejects_reftable_and_unsafe_or_malformed_refs() {
        let repo = repo_with(
            "ref: refs/heads/.invalid\n",
            &[("config", "[extensions]\n\trefStorage = reftable\n")],
        );
        assert!(read_local(repo.path()).unwrap_err().contains("reftable"));

        let repo = repo_with("ref: refs/heads/../../../../etc/passwd\n", &[]);
        assert!(read_local(repo.path()).unwrap_err().contains("unsafe"));

        let repo = repo_with(
            "ref: refs/heads/master\n",
            &[("refs/heads/master", "garbage")],
        );
        assert!(read_local(repo.path())
            .unwrap_err()
            .contains("unrecognised"));

        let repo = repo_with("not a head\n", &[]);
        assert!(read_local(repo.path()).is_err());
    }

    #[test]
    fn follows_symbolic_refs_with_a_depth_limit() {
        let repo = repo_with(
            "ref: refs/heads/alias\n",
            &[
                ("refs/heads/alias", "ref: refs/heads/master"),
                ("refs/heads/master", SHA_A),
            ],
        );
        assert_eq!(
            read_local(repo.path()).unwrap().commit.as_deref(),
            Some(SHA_A)
        );

        let repo = repo_with(
            "ref: refs/heads/loop\n",
            &[("refs/heads/loop", "ref: refs/heads/loop")],
        );
        assert!(read_local(repo.path()).unwrap_err().contains("symbolic"));
    }

    #[test]
    fn missing_repository_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        assert!(read_local(directory.path())
            .unwrap_err()
            .contains("not a Git repository"));
    }

    #[test]
    fn parses_git_config_syntax() {
        let config = Config::parse(
            "# comment\n\
             [core]\n\trepositoryformatversion = 0\n\tbare\n\
             [Remote \"Origin\"]\n\turl = wrong-case-subsection\n\
             [remote \"origin\"] \n\tURL = \"https://example.com/a b.git\" # trailing\n\
             \turl = second\n\
             [remote.legacy]\n\turl = old ; comment\n\
             [branch \"we\\\"ird\"]\n\tremote = origin\n",
        );
        assert_eq!(config.first("core", None, "bare"), Some("true"));
        assert_eq!(
            config.first("remote", Some("origin"), "url"),
            Some("https://example.com/a b.git")
        );
        assert_eq!(config.last("remote", Some("origin"), "url"), Some("second"));
        assert_eq!(
            config.first("remote", Some("Origin"), "url"),
            Some("wrong-case-subsection")
        );
        assert_eq!(config.first("remote", Some("legacy"), "url"), Some("old"));
        assert_eq!(
            config.first("branch", Some("we\"ird"), "remote"),
            Some("origin")
        );
    }

    #[test]
    fn parses_value_escapes_and_whitespace() {
        assert_eq!(parse_value(" plain  "), "plain");
        assert_eq!(parse_value(" \" padded \" "), " padded ");
        assert_eq!(parse_value(r#"a\"b\\c"#), "a\"b\\c");
        assert_eq!(parse_value("value # comment"), "value");
        assert_eq!(parse_value("\"keep # this\""), "keep # this");
    }
}
