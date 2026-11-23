//! Embeds all bundled Lua analysers and resources in the generated resource table.

use std::{
    env,
    fmt::Write as _,
    fs,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
};

fn collect(root: &Path, directory: &Path, paths: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(root, &path, paths)?;
        } else if path.is_file() {
            paths.push(path.strip_prefix(root).map_err(Error::other)?.to_path_buf());
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("../../analysers");
    println!("cargo:rerun-if-changed={}", source.display());
    let mut paths = Vec::new();
    collect(&source, &source, &mut paths)?;
    paths.sort();

    let mut generated = String::from("const BUNDLED_ANALYSERS: &[(&str, &str)] = &[\n");
    for relative in paths {
        let name = relative.to_str().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "analyser resource path is not UTF-8",
            )
        })?;
        let path = source.join(&relative);
        writeln!(
            generated,
            "    ({name:?}, include_str!({path:?})),",
            path = path.display().to_string(),
        )?;
    }
    generated.push_str("];\n");
    let output = PathBuf::from(env::var("OUT_DIR")?).join("bundled_analysers.rs");
    fs::write(output, generated)?;
    Ok(())
}
