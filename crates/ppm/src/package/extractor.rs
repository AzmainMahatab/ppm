use crate::core::config::{PackageConfig, PackageKind};
use crate::core::relpath::confined;
use crate::package::msi_layout;
use anyhow::{Context, Result, bail};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

const SEVENZ_SIGNATURE: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// The scratch directories one extraction needs.
///
/// Both sit beside the destination rather than inside it, so they share its volume - which is
/// what lets the payload be moved into place by rename instead of copied - and so a staging
/// directory can never be mistaken for part of the payload it is feeding.
pub struct SwapPaths {
    pub staging: PathBuf,
    pub retired: PathBuf,
}

pub fn swap_paths_for(dest_dir: &Path) -> Result<SwapPaths> {
    let parent = dest_dir.parent().with_context(|| {
        format!(
            "Install destination '{}' has no parent directory to stage beside",
            dest_dir.display()
        )
    })?;
    let name = dest_dir
        .file_name()
        .with_context(|| format!("Install destination '{}' has no name", dest_dir.display()))?
        .to_string_lossy()
        .into_owned();

    Ok(SwapPaths {
        staging: parent.join(format!(".{name}.staging")),
        retired: parent.join(format!(".{name}.previous")),
    })
}

/// Removes a directory tree, treating its absence as success.
pub fn remove_tree_if_present(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Failed to remove directory '{}'", path.display())),
    }
}

struct StagingGuard(PathBuf);

impl Drop for StagingGuard {
    fn drop(&mut self) {
        // The staging directory is often already gone by now - it becomes the installation
        // itself when the payload sits at the archive root - so only a real failure is worth
        // reporting.
        if let Err(error) = remove_tree_if_present(&self.0) {
            tracing::warn!("{error:#}");
        }
    }
}

/// Moves the extracted payload into place, replacing any previous installation wholesale.
///
/// # Why a rename rather than a copy
/// Copying the payload over the previous installation left behind every file the new version no
/// longer ships, so an update produced the union of both releases - which is how an application
/// ends up loading a module its own release notes say was removed. Replacing the directory
/// deletes what is gone by construction. The move is also a metadata operation instead of a byte
/// copy of a payload that routinely runs to hundreds of megabytes.
///
/// # Why the previous tree is set aside rather than deleted
/// Deleting first would leave the application missing outright if the new payload then failed to
/// move into place. Retiring it keeps a restore available for exactly that window.
fn install_payload(source_root: &Path, dest_dir: &Path, retired: &Path) -> Result<()> {
    // A retired tree can only be left over from an interrupted run; the current one is about to
    // take its place.
    remove_tree_if_present(retired)?;

    if let Some(parent) = dest_dir.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create the install parent directory '{}'",
                parent.display()
            )
        })?;
    }

    let had_previous = dest_dir.exists();
    if had_previous {
        fs::rename(dest_dir, retired).with_context(|| {
            format!(
                "Failed to set aside the previous installation at '{}' - a file in it is most likely still open",
                dest_dir.display()
            )
        })?;
    }

    if let Err(error) = fs::rename(source_root, dest_dir) {
        if had_previous && let Err(restore) = fs::rename(retired, dest_dir) {
            bail!(
                "Failed to move the new payload into '{}' ({error}), and the previous installation could not be restored from '{}' ({restore}) - the application is left retired at that path",
                dest_dir.display(),
                retired.display()
            );
        }
        return Err(error).with_context(|| {
            format!(
                "Failed to move the extracted payload into '{}'",
                dest_dir.display()
            )
        });
    }

    remove_tree_if_present(retired)
}

fn to_cmd_path(path: &Path) -> String {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let s = abs.to_string_lossy().to_string();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        s
    }
}

pub fn find_7z_offset(path: &Path) -> Result<u64> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut buffer = [0u8; 65536];
    let mut current_offset: u64 = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read < 6 {
            break;
        }

        for i in 0..=(bytes_read - 6) {
            if &buffer[i..i + 6] == SEVENZ_SIGNATURE {
                return Ok(current_offset + i as u64);
            }
        }

        current_offset += (bytes_read - 5) as u64;
        reader.seek(SeekFrom::Start(current_offset))?;
    }

    bail!(
        "Could not find embedded 7-Zip payload header in NSIS installer '{}'",
        path.display()
    )
}

pub fn extract_7z_stream(archive_path: &Path, offset: u64, dest_dir: &Path) -> Result<()> {
    let mut file = File::open(archive_path)?;
    file.seek(SeekFrom::Start(offset))?;

    // Why beside `dest_dir` rather than inside it: the payload extracts into `dest_dir`, and the
    // carved-out archive must neither land in it nor outlive the extraction.
    let scratch_dir = dest_dir.parent().with_context(|| {
        format!(
            "Extraction target '{}' has no parent directory",
            dest_dir.display()
        )
    })?;
    let mut payload = tempfile::Builder::new()
        .suffix(".7z")
        .tempfile_in(scratch_dir)
        .with_context(|| {
            format!(
                "Failed to create a scratch archive in '{}'",
                scratch_dir.display()
            )
        })?;
    std::io::copy(&mut file, &mut payload)
        .context("Failed to carve the 7-Zip payload out of the installer")?;

    sevenz_rust2::decompress_file(payload.path(), dest_dir)
        .with_context(|| format!("7-Zip decompression failed for '{}'", archive_path.display()))
}

// Ex: the first two bytes of every gzip member (RFC 1952 section 2.3.1).
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Extracts a tar archive, gzip-compressed or plain - the magic bytes decide, since release
/// URLs and cache names do not reliably say which.
pub fn extract_tar(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    let mut file = BufReader::new(
        File::open(archive_path).with_context(|| format!("Failed to open '{}'", archive_path.display()))?,
    );
    let is_gzip = file.fill_buf()?.starts_with(&GZIP_MAGIC);
    let reader: Box<dyn Read> = if is_gzip {
        Box::new(flate2::read::GzDecoder::new(file))
    } else {
        Box::new(file)
    };

    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .with_context(|| format!("'{}' is not a readable tar archive", archive_path.display()))?;
    for entry in entries {
        let mut entry = entry.with_context(|| format!("Corrupt entry in '{}'", archive_path.display()))?;
        write_tar_entry(&mut entry, dest_dir)
            .with_context(|| format!("Failed to extract '{}'", archive_path.display()))?;
    }
    Ok(())
}

fn write_tar_entry<R: Read>(entry: &mut tar::Entry<'_, R>, dest_dir: &Path) -> Result<()> {
    let kind = entry.header().entry_type();
    let raw_path = entry.path()?.to_string_lossy().into_owned();

    // Extended headers carry metadata for the entries that follow, not content of their own.
    let is_metadata = kind.is_pax_global_extensions()
        || kind.is_pax_local_extensions()
        || kind.is_gnu_longname()
        || kind.is_gnu_longlink();
    if is_metadata {
        return Ok(());
    }

    let out_path = dest_dir.join(confined(&raw_path)?);
    if kind.is_dir() {
        fs::create_dir_all(&out_path)
            .with_context(|| format!("Failed to create '{}'", out_path.display()))?;
        return Ok(());
    }
    // Why links fail rather than being skipped: a portable install cannot reproduce them without
    // privileges Windows does not grant by default, and dropping them silently leaves an
    // installation missing the files they stood for.
    if !(kind.is_file() || kind.is_contiguous()) {
        bail!("Tar entry '{raw_path}' is a {kind:?}, which a portable install cannot reproduce");
    }

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("Failed to create '{}'", parent.display()))?;
    }
    let mut out_file =
        File::create(&out_path).with_context(|| format!("Failed to create '{}'", out_path.display()))?;
    std::io::copy(entry, &mut out_file)
        .with_context(|| format!("Failed to extract tar entry '{raw_path}'"))?;
    Ok(())
}

pub fn extract_zip(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    let file = File::open(archive_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        // Why an error rather than a skip: an entry that would land outside the destination
        // only exists in a malformed or hostile archive, and installing the rest of it as if
        // nothing happened would hide that.
        let outpath = match entry.enclosed_name() {
            Some(path) => dest_dir.join(path),
            None => bail!(
                "Zip entry '{}' in '{}' would extract outside the install directory",
                String::from_utf8_lossy(entry.name_raw()),
                archive_path.display()
            ),
        };

        if entry.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent()
                && !p.exists()
            {
                fs::create_dir_all(p)?;
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut entry, &mut outfile)?;
        }
    }

    Ok(())
}

pub fn extract_cab(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    fs::create_dir_all(dest_dir)?;

    // Why `expand.exe` first: it is the platform's own decoder and covers every CAB compression
    // method, including Quantum, which the pure-Rust reader does not.
    let expand_failure = match expand_with_platform_tool(archive_path, dest_dir) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };

    let file =
        File::open(archive_path).with_context(|| format!("Failed to open '{}'", archive_path.display()))?;
    let cabinet = cab::Cabinet::new(file).with_context(|| {
        format!(
            "Failed to extract CAB package '{}': expand.exe failed ({expand_failure:#}), and the archive is not readable as a cabinet",
            archive_path.display()
        )
    })?;
    write_cabinet_entries(cabinet, dest_dir, confined).with_context(|| {
        format!(
            "Failed to extract CAB package '{}' (expand.exe had already failed: {expand_failure:#})",
            archive_path.display()
        )
    })
}

// Why: expand.exe prints one line per file - hundreds for a browser runtime - so its output is
//      captured rather than streamed, and only its last lines are kept as the failure's detail.
//      Ten lines hold its summary and error message; raise it if a diagnosis ever needs more.
const EXPAND_FAILURE_TAIL_LINES: usize = 10;

fn expand_with_platform_tool(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    let output = Command::new("expand.exe")
        .arg(to_cmd_path(archive_path))
        .arg("-F:*")
        .arg(to_cmd_path(dest_dir))
        .output()
        .context("expand.exe could not be started")?;
    if !output.status.success() {
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let lines: Vec<&str> = transcript
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        let tail = lines[lines.len().saturating_sub(EXPAND_FAILURE_TAIL_LINES)..].join(" / ");
        bail!("expand.exe exited with status {:?}: {tail}", output.status.code());
    }
    Ok(())
}

/// Writes every entry of `cabinet` beneath `dest_dir`, at the relative path `path_of` assigns
/// to the entry's name.
fn write_cabinet_entries<R: Read + Seek>(
    mut cabinet: cab::Cabinet<R>,
    dest_dir: &Path,
    path_of: impl Fn(&str) -> Result<PathBuf>,
) -> Result<()> {
    let names: Vec<String> = cabinet
        .folder_entries()
        .flat_map(|folder| folder.file_entries().map(|entry| entry.name().to_string()))
        .collect();

    for name in names {
        let out_path = dest_dir.join(path_of(&name)?);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory '{}'", parent.display()))?;
        }
        let mut reader = cabinet
            .read_file(&name)
            .with_context(|| format!("CAB entry '{name}' could not be opened for reading"))?;
        let mut out_file =
            File::create(&out_path).with_context(|| format!("Failed to create '{}'", out_path.display()))?;
        std::io::copy(&mut reader, &mut out_file)
            .with_context(|| format!("Failed to extract CAB entry '{name}'"))?;
    }
    Ok(())
}

/// The tables of an MSI package that decide where its files land.
struct MsiTables {
    directories: Vec<msi_layout::DirectoryRow>,
    components: Vec<msi_layout::ComponentRow>,
    files: Vec<msi_layout::FileRow>,
    media: Vec<msi_layout::MediaRow>,
}

fn string_column(row: &msi::Row, index: usize) -> Option<String> {
    row[index]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn required_column(row: &msi::Row, index: usize, table: &str) -> Result<String> {
    string_column(row, index).with_context(|| format!("MSI {table} row has an empty required column {index}"))
}

fn select<'a>(package: &'a mut msi::Package<File>, table: &str, columns: &[&str]) -> Result<msi::Rows<'a>> {
    package
        .select_rows(msi::Select::table(table).columns(columns))
        .with_context(|| format!("Failed to read the MSI {table} table"))
}

fn read_msi_tables(package: &mut msi::Package<File>) -> Result<MsiTables> {
    if !package.has_table("File") {
        return Ok(MsiTables {
            directories: Vec::new(),
            components: Vec::new(),
            files: Vec::new(),
            media: Vec::new(),
        });
    }

    let directories = select(
        package,
        "Directory",
        &["Directory", "Directory_Parent", "DefaultDir"],
    )?
    .map(|row| {
        Ok(msi_layout::DirectoryRow {
            id: required_column(&row, 0, "Directory")?,
            parent: string_column(&row, 1),
            default_dir: required_column(&row, 2, "Directory")?,
        })
    })
    .collect::<Result<_>>()?;
    let components = select(package, "Component", &["Component", "Directory_"])?
        .map(|row| {
            Ok(msi_layout::ComponentRow {
                id: required_column(&row, 0, "Component")?,
                directory: required_column(&row, 1, "Component")?,
            })
        })
        .collect::<Result<_>>()?;
    let files = select(package, "File", &["File", "Component_", "FileName"])?
        .map(|row| {
            Ok(msi_layout::FileRow {
                key: required_column(&row, 0, "File")?,
                component: required_column(&row, 1, "File")?,
                file_name: required_column(&row, 2, "File")?,
            })
        })
        .collect::<Result<_>>()?;
    let media = select(package, "Media", &["DiskId", "Cabinet"])?
        .map(|row| {
            Ok(msi_layout::MediaRow {
                disk_id: row[0].as_int().context("MSI Media row has no DiskId")?,
                cabinet: string_column(&row, 1),
            })
        })
        .collect::<Result<_>>()?;

    Ok(MsiTables {
        directories,
        components,
        files,
        media,
    })
}

/// Extracts the files an MSI package installs, laid out as an administrative install would.
///
/// # Why the table-driven path comes first, and when `msiexec /a` takes over
/// Reading the package directly needs no elevation, touches no Windows Installer state, and is
/// deterministic. A package that installs no files of its own - an installer wrapping another
/// installer in a custom action, like Microsoft Edge Enterprise - has nothing for that path to
/// extract, and only then does the administrative install run.
pub fn extract_msi(msi_path: &Path, dest_dir: &Path) -> Result<()> {
    let file = File::open(msi_path).with_context(|| format!("Failed to open '{}'", msi_path.display()))?;
    let mut package = msi::Package::open(file)
        .with_context(|| format!("'{}' is not a readable MSI package", msi_path.display()))?;
    let tables = read_msi_tables(&mut package)?;

    if tables.files.is_empty() {
        return extract_msi_with_msiexec(msi_path, dest_dir);
    }

    let paths = msi_layout::file_paths(&tables.directories, &tables.components, &tables.files)?;
    let path_of = |key: &str| {
        paths
            .get(key)
            .cloned()
            .with_context(|| format!("Cabinet entry '{key}' has no row in the MSI File table"))
    };

    for source in msi_layout::cabinets(&tables.media)? {
        match source {
            msi_layout::CabinetSource::Embedded(stream) => {
                let mut bytes = Vec::new();
                package
                    .read_stream(&stream)
                    .and_then(|mut reader| reader.read_to_end(&mut bytes))
                    .with_context(|| format!("Failed to read embedded cabinet '{stream}'"))?;
                let cabinet = cab::Cabinet::new(Cursor::new(bytes))
                    .with_context(|| format!("Embedded cabinet '{stream}' is not a valid CAB"))?;
                write_cabinet_entries(cabinet, dest_dir, path_of)?;
            }
            msi_layout::CabinetSource::External(name) => {
                let cab_path = msi_path
                    .parent()
                    .with_context(|| format!("'{}' has no parent directory", msi_path.display()))?
                    .join(&name);
                let cab_file = File::open(&cab_path)
                    .with_context(|| format!("External cabinet '{}' is missing", cab_path.display()))?;
                let cabinet = cab::Cabinet::new(cab_file)
                    .with_context(|| format!("'{}' is not a valid CAB", cab_path.display()))?;
                write_cabinet_entries(cabinet, dest_dir, path_of)?;
            }
        }
    }
    Ok(())
}

fn extract_msi_with_msiexec(msi_path: &Path, dest_dir: &Path) -> Result<()> {
    let abs_msi = to_cmd_path(msi_path);
    let abs_dest = to_cmd_path(dest_dir);
    fs::create_dir_all(dest_dir)?;

    let status = Command::new("msiexec.exe")
        .arg("/a")
        .arg(&abs_msi)
        .arg("/qn")
        .arg(format!("TARGETDIR={}", abs_dest))
        .status()?;

    if !status.success() {
        bail!("msiexec extraction failed with exit status: {:?}", status.code());
    }

    // Clean up any stray .msi files dropped into dest_dir by msiexec /a
    if let Ok(entries) = fs::read_dir(dest_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("msi"))
                    .unwrap_or(false)
                && let Err(error) = fs::remove_file(&p)
            {
                tracing::warn!("Failed to remove stray msi '{}': {error}", p.display());
            }
        }
    }

    Ok(())
}

pub fn extract_package(archive_path: &Path, package_config: &PackageConfig, dest_dir: &Path) -> Result<()> {
    let swap = swap_paths_for(dest_dir)?;
    // Anything left at these paths is debris from an interrupted run.
    remove_tree_if_present(&swap.staging)?;
    fs::create_dir_all(&swap.staging).with_context(|| {
        format!(
            "Failed to create the staging directory '{}'",
            swap.staging.display()
        )
    })?;

    let stage_dir = swap.staging.clone();
    let _guard = StagingGuard(swap.staging);

    match package_config.kind {
        PackageKind::Nsis7z => {
            let offset = find_7z_offset(archive_path)?;
            extract_7z_stream(archive_path, offset, &stage_dir)?;
        }
        PackageKind::SevenZ => {
            sevenz_rust2::decompress_file(archive_path, &stage_dir)
                .with_context(|| format!("7-Zip decompression failed for '{}'", archive_path.display()))?;
        }
        PackageKind::Zip => extract_zip(archive_path, &stage_dir)?,
        PackageKind::Cab => extract_cab(archive_path, &stage_dir)?,
        PackageKind::Msi => extract_msi(archive_path, &stage_dir)?,
        PackageKind::Tar => extract_tar(archive_path, &stage_dir)?,
        PackageKind::Binary => {
            let file_name = archive_path.file_name().unwrap_or_default();
            let dest_file = stage_dir.join(file_name);
            fs::copy(archive_path, &dest_file)?;
        }
    }

    // `binary` has no archive to descend into, so a subpath cannot apply to it.
    let extract_subpath = match package_config.kind {
        PackageKind::Binary => None,
        _ => package_config.extract_subpath.as_deref(),
    };

    let source_root = match extract_subpath {
        Some(sub) => {
            let declared = stage_dir.join(confined(sub)?);
            if !declared.is_dir() {
                bail!(
                    "extract_subpath '{sub}' does not exist in the extracted payload of '{}'; refusing to install the archive root instead of the declared subdirectory",
                    archive_path.display()
                );
            }
            declared
        }
        None => find_payload_root(&stage_dir),
    };

    install_payload(&source_root, dest_dir, &swap.retired)
}

fn find_payload_root(dir: &Path) -> PathBuf {
    // 1. Explicit app-64 / app-32 / app conventions
    for sub in &["app-64", "app-32", "app"] {
        let p = dir.join(sub);
        if p.is_dir() {
            return p;
        }
    }

    // 2. Standard MSI directory hierarchies: PFiles/<App>/, Program Files/<Vendor>/<App>/
    for prefix in &["PFiles", "Program Files", "Program Files (x86)"] {
        let p = dir.join(prefix);
        if p.is_dir() {
            if let Ok(mut entries) = fs::read_dir(&p)
                && let Some(Ok(child)) = entries.next()
            {
                let child_path = child.path();
                if child_path.is_dir() {
                    return child_path;
                }
            }
            return p;
        }
    }

    // 3. Common enterprise MSI payload subdirectories
    for candidate in &[
        dir.join("Microsoft").join("Edge").join("Application"),
        dir.join("Microsoft").join("Edge Dev").join("Application"),
        dir.join("Microsoft").join("Edge Beta").join("Application"),
    ] {
        if candidate.is_dir() {
            return candidate.clone();
        }
    }

    // 4. Single nested folder flattening
    if let Ok(entries) = fs::read_dir(dir) {
        let items: Vec<_> = entries.flatten().collect();
        if items.len() == 1 && items[0].path().is_dir() {
            return items[0].path();
        }
    }

    dir.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_7z_offset_detection() {
        let mut sample_nsis = Vec::new();
        sample_nsis.extend_from_slice(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00");
        sample_nsis.resize(1024, 0);
        sample_nsis.extend_from_slice(SEVENZ_SIGNATURE);
        sample_nsis.extend_from_slice(b"sample_7z_stream_payload");

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), &sample_nsis).unwrap();

        let offset = find_7z_offset(temp_file.path()).expect("Should detect 7z offset");
        assert_eq!(offset, 1024);
    }
}
