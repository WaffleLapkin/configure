use std::{
    collections::BTreeMap,
    fs,
    io::{self},
    mem,
    path::{Path, PathBuf},
    process,
};

use color_eyre::{owo_colors::OwoColorize, Section};
use eyre::{Context as _, OptionExt};
use rkyv::rancor::BoxedError;
use serde_dhall::StaticType;

/// The value that describes what files we need to copy where.
///
/// **This must be in sync with `./configuration.dhall`.** Ideally we'd just
/// serialize the *type*, but that's not something that is supported by
/// `serde_dhall` (because of `serde` limitations, dang it!).
#[derive(
    StaticType,
    serde::Deserialize,
    Debug,
    Default,
    Clone,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[archive(check_bytes)]
struct Configuration {
    // FIXME: use `PathBuf`/`Utf8Path` instead of the string :\
    /// File path, file contents.
    files: Vec<ConfigFile>,
}

impl Configuration {
    fn canonicalize_paths(&mut self) -> eyre::Result<()> {
        self.files
            .iter_mut()
            .try_for_each(|file| file.canonicalize_path())
    }
}

#[derive(
    StaticType,
    serde::Deserialize,
    Debug,
    Default,
    Clone,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[archive(check_bytes)]
struct ConfigFile {
    path: String,
    contents: String,

    // FIXME: actually make files read only lol (and check if the files are currently read only)
    ro: bool,
}

impl ConfigFile {
    // FIXME: this does not necessarily canonicalize path, this should be renamed
    fn canonicalize_path(&mut self) -> eyre::Result<()> {
        let expanded = shellexpand::path::tilde(Path::new(&self.path));
        let mostly_canonical = canonicalize_or_normalize_path(&expanded);
        self.path = mostly_canonical
            .into_os_string()
            .into_string()
            .map_err(|_| eyre::Report::msg("non-utf8 path :("))?;

        Ok(())
    }
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    let opts = parse_args()?;

    let configuration_path = Path::new(&opts.path);
    let cache_path = opts.cache_path.map(PathBuf::from).ok_or(()).or_else(|()| {
        configuration_path
            .parent()
            .ok_or_eyre("configuration path does not have a parent")
            .map(|p| p.join(".configure-cache.rkyv"))
    })?;

    let mut cache = read_cache(&cache_path)?;
    cache.canonicalize_paths()?;

    let mut configuration: Configuration = serde_dhall::from_file(configuration_path)
        .static_type_annotation()
        .parse()?;
    configuration.canonicalize_paths()?;

    let diffs = diffs(cache, configuration.clone())?;

    struct Diffs {
        st: BTreeMap<String, FileDiff>,
    }

    enum FileDiff {
        OutdatedCache {
            cache: String,
            on_disk: io::Result<String>,
        },
        NewDiskConflict {
            new: String,
            on_disk: io::Result<String>,
        },
        NoChange,
        Deleted {
            cache: String,
        },
        // FIXME: distinguish between an actually new file and a file that wasn't tracked before
        New {
            new: String,
        },
        Updated {
            cache: String,
            new: String,
        },
    }

    fn diffs(cache: Configuration, configuration: Configuration) -> eyre::Result<Diffs> {
        let mut map = BTreeMap::default();

        for file in cache.files {
            let on_disk = fs::read_to_string(&file.path);

            let d = if on_disk.as_deref().ok() == Some(&file.contents) {
                FileDiff::Deleted {
                    cache: file.contents,
                }
            } else {
                FileDiff::OutdatedCache {
                    cache: file.contents,
                    on_disk,
                }
            };

            map.insert(file.path, d);
        }

        for file in configuration.files {
            use std::collections::btree_map::Entry;
            match map.entry(file.path) {
                Entry::Vacant(e) => {
                    let on_disk = fs::read_to_string(e.key());

                    let d = if on_disk
                        .as_ref()
                        .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
                        || on_disk.as_ref().is_ok_and(|c| c == &file.contents)
                    {
                        FileDiff::New { new: file.contents }
                    } else {
                        FileDiff::NewDiskConflict {
                            new: file.contents,
                            on_disk,
                        }
                    };

                    e.insert(d);
                }
                Entry::Occupied(mut e) => {
                    let new = match mem::replace(e.get_mut(), FileDiff::NoChange) {
                        FileDiff::Deleted { cache } if cache == file.contents => FileDiff::NoChange,
                        FileDiff::Deleted { cache } => FileDiff::Updated {
                            cache,
                            new: file.contents,
                        },
                        d @ FileDiff::OutdatedCache { .. } => d,
                        FileDiff::NewDiskConflict { .. }
                        | FileDiff::NoChange
                        | FileDiff::New { .. }
                        | FileDiff::Updated { .. } => {
                            return Err(eyre::Report::msg(format!(
                                "multiple entries for `{}` in the new configuration",
                                e.key()
                            )))
                        }
                    };
                    *e.get_mut() = new;
                }
            }
        }

        Ok(Diffs { st: map })
    }

    println!("Changes to be made:");

    let mut errors = 0;
    let mut warnings = 0;
    for (path, diff) in diffs.st.iter() {
        match diff {
            FileDiff::OutdatedCache { cache, on_disk } => match on_disk {
                Ok(on_disk) => {
                    eprintln!(
                        "{path}: cached version is different from on-disk ({error}):",
                        error = "error".red(),
                    );

                    let diff = prettydiff::diff_lines(cache, on_disk).format_with_context(
                        Some(prettydiff::text::ContextConfig {
                            context_size: 2,
                            skipping_marker: "-- skip --",
                        }),
                        true,
                    );
                    eprintln!("{diff}");

                    errors += 1;
                }
                Err(on_disk) => {
                    eprintln!(
                        "{path}: couldn't read previously cached file ({error}):\n\
                     {on_disk}",
                        error = "error".red(),
                    );
                    errors += 1;
                }
            },
            FileDiff::NewDiskConflict { new, on_disk } => {
                // FIXME: this should show diff
                eprintln!(
                    "{path}: new file is different from disk ({error}):",
                    error = "error".red(),
                );

                match on_disk {
                    Ok(on_disk) => {
                        let diff = prettydiff::diff_lines(on_disk, new).format_with_context(
                            Some(prettydiff::text::ContextConfig {
                                context_size: 2,
                                skipping_marker: "-- skip --",
                            }),
                            true,
                        );
                        eprintln!("{diff}");
                    }
                    Err(_) => todo!(),
                }

                errors += 1;
            }
            FileDiff::NoChange => { /* nothing to do c: */ }
            FileDiff::Deleted { cache } => {
                eprintln!(
                    "{path}: previously cached file is no longer present in configuration ({warning})",
                    warning = "warning".yellow(),
                );
                let diff = prettydiff::diff_lines(cache, "").format_with_context(
                    Some(prettydiff::text::ContextConfig {
                        context_size: 2,
                        skipping_marker: "-- skip --",
                    }),
                    true,
                );
                eprintln!("{diff}");

                warnings += 1;
            }
            FileDiff::New { new } => {
                println!("{path}: new file ({ok}):\n{new}", ok = "ok".green());
            }
            FileDiff::Updated { cache, new } => {
                println!("{path}: updated file ({ok})", ok = "ok".green());
                let diff = prettydiff::diff_lines(cache, new).format_with_context(
                    Some(prettydiff::text::ContextConfig {
                        context_size: 2,
                        skipping_marker: "-- skip --",
                    }),
                    true,
                );
                println!("{diff}");
            }
        };
    }

    if opts.execute {
        if errors > 0 {
            eprint!(
                "Aborting due to {errors} previous error{s}",
                s = if errors > 1 { "s" } else { "" }
            );

            process::exit(1)
        }

        if warnings > 0 && !opts.force {
            eprint!(
                "Aborting due to {warnings} previous warning{s} (if you would like to proceed use `--force`)",
                s = if warnings > 1 { "s" } else { "" }
            );

            process::exit(1)
        }

        for (path, diff) in diffs.st.iter() {
            match diff {
                FileDiff::OutdatedCache { .. } | FileDiff::NewDiskConflict { .. } => unreachable!(),
                FileDiff::Deleted { cache: _ } => {
                    // FIXME: save cached version to tmpdir
                    fs::remove_file(path)?;
                }
                FileDiff::NoChange => {}
                FileDiff::New { new } | FileDiff::Updated { cache: _, new } => {
                    let path = Path::new(path);

                    if let Some(dir) = path.parent() {
                        fs::create_dir_all(dir)
                            .with_context(|| format!("creating directory `{}`", dir.display()))?;
                    }

                    fs::write(&path, new.as_bytes())
                        .with_context(|| format!("writing `{}`", path.display()))?;
                }
            }
        }

        write_cache(&cache_path, &configuration)?;
        Ok(())
    } else {
        eprint!("Aborting due to dry run (use `--execute` to actually commit changes)",);

        Ok(())
    }
}

fn read_cache(path: &Path) -> eyre::Result<Configuration> {
    match fs::read(path) {
        Ok(bytes) => {
            // Fixme: figure out zero copy deserialization for fun?
            let cache = rkyv::from_bytes::<_, BoxedError>(&bytes)
                .wrap_err("couldn't deserialize cache")
                .with_section(|| format!("Help: try deleting the `{}` file", path.display()))?;

            Ok(cache)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Configuration::default()),
        Err(err) => Err(err).wrap_err("couldn't read cache file"),
    }
}

#[allow(unused)]
fn write_cache(path: &Path, cache: &Configuration) -> eyre::Result<()> {
    let bytes = rkyv::to_bytes::<_, 256, BoxedError>(cache)?;
    fs::write(path, bytes)?;
    Ok(())
}

struct Args {
    /// Path to the configuration file (`.dhall`).
    path: String,

    cache_path: Option<String>,

    execute: bool,

    force: bool,
}

fn parse_args() -> Result<Args, lexopt::Error> {
    use lexopt::prelude::*;

    let mut path = None;
    let mut cache_path = None;
    let mut execute = false;
    let mut force = false;

    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next()? {
        match arg {
            Long("path") if path.is_none() => {
                path = Some(parser.value()?.parse()?);
            }
            Long("cache-path") if cache_path.is_none() => {
                cache_path = Some(parser.value()?.parse()?);
            }
            Long("execute") => {
                execute = true;
            }
            Long("force") => {
                force = true;
            }
            Long("help") => {
                println!("Usage: configure [--path=PATH] [--execute] [--force]");
                std::process::exit(0);
            }
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(Args {
        path: path.unwrap_or_else(|| "./local.dhall".to_owned()),
        execute,
        cache_path,
        force,
    })
}

fn canonicalize_or_normalize_path(p: &Path) -> PathBuf {
    let (mut mostly_canonical, ancestor) = p
        .ancestors()
        .find_map(|ancestor| fs::canonicalize(ancestor).ok().zip(Some(ancestor)))
        .unwrap_or((PathBuf::new(), p));

    mostly_canonical.push(p.strip_prefix(ancestor).unwrap());
    normalize_path(&mostly_canonical)
}

fn normalize_path(path: &Path) -> PathBuf {
    // https://github.com/rust-lang/cargo/blob/5da28587846d6cb2694e5bb1db1b5ca327285bf7/crates/cargo-util/src/paths.rs#L84
    use std::path::Component;

    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}
