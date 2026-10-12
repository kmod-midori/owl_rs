// SPDX-License-Identifier: GPL-3.0-or-later
//! Disk-backed, bounded DVZip/CPIO. Untrusted CPIO headers are checked before library allocation.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};
use tempfile::NamedTempFile;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Item {
    pub name: String,
    pub size: u64,
    pub directory: bool,
}
pub struct Prepared {
    pub file: NamedTempFile,
    pub items: Vec<Item>,
    pub bytes: u64,
    pub icon: Option<Vec<u8>>,
}
pub fn safe_path(name: &str) -> Result<PathBuf> {
    ensure!(
        !name.contains('\\') && !name.contains('\0') && name.len() <= 4096,
        "invalid archive name"
    );
    let mut path = PathBuf::new();
    for part in Path::new(name).components() {
        match part {
            Component::Normal(s) => path.push(s),
            Component::CurDir => (),
            _ => bail!("unsafe archive path: {name}"),
        }
    }
    ensure!(!path.as_os_str().is_empty(), "empty archive path");
    Ok(path)
}
pub fn prepare(paths: &[PathBuf], limit: u64) -> Result<Prepared> {
    ensure!(!paths.is_empty(), "choose at least one file or directory");
    let cpio = NamedTempFile::new()?;
    let mut builder = cpio_archive::odc::OdcBuilder::new(cpio.reopen()?);
    let mut names = HashSet::new();
    let mut items = Vec::new();
    let mut total = 0u64;
    let mut count = 0;
    for path in paths {
        let root = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("file names must be UTF-8")?;
        safe_path(root)?;
        ensure!(
            names.insert(root.to_string()),
            "duplicate top-level file name: {root}"
        );
        let meta = std::fs::symlink_metadata(path)?;
        ensure!(
            meta.is_file() || meta.is_dir(),
            "only regular files and directories can be sent"
        );
        let mut root_size = 0;
        for entry in walkdir::WalkDir::new(path)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry?;
            let meta = entry.path().symlink_metadata()?;
            ensure!(
                meta.is_file() || meta.is_dir(),
                "symlinks and special files cannot be sent: {}",
                entry.path().display()
            );
            count += 1;
            ensure!(count <= 4096, "archive exceeds 4096 members");
            let rel = entry.path().strip_prefix(path)?;
            let name = if rel.as_os_str().is_empty() {
                PathBuf::from(root)
            } else {
                Path::new(root).join(rel)
            };
            let name = name.to_str().context("file names must be UTF-8")?;
            safe_path(name)?;
            if meta.is_dir() {
                let mut header = builder.next_header();
                header.name = format!("./{name}");
                header.mode = 0o040755;
                header.nlink = 1;
                builder.append_header_with_data(header, [])?;
            } else {
                total = total
                    .checked_add(meta.len())
                    .context("file size overflow")?;
                ensure!(total <= limit, "send exceeds size limit");
                root_size += meta.len();
                let mut header = builder.next_header();
                header.name = format!("./{name}");
                header.mode = 0o100644;
                header.file_size = meta.len();
                header.nlink = 1;
                builder.append_header_with_reader(
                    header,
                    &mut File::open(entry.path())?.take(meta.len()),
                )?;
            }
        }
        items.push(Item {
            name: root.into(),
            size: root_size,
            directory: meta.is_dir(),
        });
    }
    builder.finish()?;
    drop(builder);
    let wire = NamedTempFile::new()?;
    let mut input = cpio.reopen()?;
    let mut output = wire.reopen()?;
    let mut chunk = [0u8; 65536];
    loop {
        let n = input.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let mut zip = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zip.write_all(&chunk[..n])?;
        let data = zip.finish()?;
        if data.len() < n {
            output.write_all(&(data.len() as u32).to_be_bytes())?;
            output.write_all(&data)?;
        } else {
            output.write_all(&((n as u32) | 0x80000000).to_be_bytes())?;
            output.write_all(&chunk[..n])?;
        }
        ensure!(
            output.stream_position()? <= limit.saturating_add(32 * 1024 * 1024),
            "wire archive exceeds size limit"
        );
    }
    output.flush()?;
    let bytes = output.stream_position()?;
    let icon = thumbnail(&paths[0]);
    Ok(Prepared {
        icon,
        file: wire,
        items,
        bytes,
    })
}
fn copy_limited(reader: &mut impl Read, writer: &mut impl Write, left: &mut u64) -> Result<u64> {
    let mut copied = 0;
    let mut buf = [0; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ensure!(n as u64 <= *left, "expanded archive exceeds size limit");
        writer.write_all(&buf[..n])?;
        *left -= n as u64;
        copied += n as u64;
    }
    Ok(copied)
}
pub fn decode(wire: &Path, limit: u64) -> Result<NamedTempFile> {
    let out = NamedTempFile::new()?;
    let mut writer = out.reopen()?;
    let mut input = File::open(wire)?;
    let mut magic = [0; 2];
    input.read_exact(&mut magic)?;
    input.rewind()?;
    let mut left = limit;
    if magic == [0x1f, 0x8b] {
        copy_limited(
            &mut flate2::read::GzDecoder::new(input),
            &mut writer,
            &mut left,
        )?;
    } else {
        loop {
            let mut header = [0; 4];
            let n = input.read(&mut header[..1])?;
            if n == 0 {
                break;
            }
            input.read_exact(&mut header[1..])?;
            let block = u32::from_be_bytes(header);
            let len = (block & 0x7fffffff) as u64;
            ensure!(
                len > 0 && len <= 16 * 1024 * 1024,
                "invalid DVZip block length"
            );
            let mut section = (&mut input).take(len);
            if block & 0x80000000 != 0 {
                ensure!(
                    copy_limited(&mut section, &mut writer, &mut left)? == len,
                    "truncated stored DVZip block"
                );
            } else {
                let mut compressed = Vec::with_capacity(len as usize);
                section.read_to_end(&mut compressed)?;
                ensure!(
                    compressed.len() as u64 == len,
                    "truncated compressed DVZip block"
                );
                let mut zip = flate2::Decompress::new(true);
                let mut buf = [0; 65536];
                loop {
                    let before_in = zip.total_in();
                    let before_out = zip.total_out();
                    let status = zip.decompress(
                        &compressed[before_in as usize..],
                        &mut buf,
                        flate2::FlushDecompress::None,
                    )?;
                    let n = (zip.total_out() - before_out) as usize;
                    ensure!(n as u64 <= left, "expanded archive exceeds size limit");
                    writer.write_all(&buf[..n])?;
                    left -= n as u64;
                    if status == flate2::Status::StreamEnd {
                        ensure!(zip.total_in() == len, "trailing DVZip compressed data");
                        break;
                    }
                    ensure!(
                        zip.total_in() > before_in || n > 0,
                        "truncated DVZip zlib stream"
                    );
                }
            }
            ensure!(section.limit() == 0, "truncated DVZip block");
        }
    }
    writer.flush()?;
    preflight(out.path(), limit)?;
    Ok(out)
}
fn number(bytes: &[u8], radix: u32) -> Result<u64> {
    Ok(u64::from_str_radix(std::str::from_utf8(bytes)?, radix)?)
}
pub fn preflight(path: &Path, limit: u64) -> Result<()> {
    let mut input = File::open(path)?;
    let length = input.metadata()?.len();
    ensure!(length <= limit, "archive exceeds size limit");
    let mut count = 0;
    loop {
        let start = input.stream_position()?;
        let mut magic = [0; 6];
        input
            .read_exact(&mut magic)
            .context("missing CPIO trailer")?;
        let (names, size, header, align) = match &magic {
            b"070707" => {
                let mut rest = [0; 70];
                input.read_exact(&mut rest)?;
                (number(&rest[53..59], 8)?, number(&rest[59..70], 8)?, 76, 1)
            }
            b"070701" => {
                let mut rest = [0; 104];
                input.read_exact(&mut rest)?;
                (
                    number(&rest[88..96], 16)?,
                    number(&rest[48..56], 16)?,
                    110,
                    4,
                )
            }
            _ => bail!("unsupported CPIO format"),
        };
        ensure!((1..=4096).contains(&names), "invalid CPIO name length");
        let mut name = vec![0; names as usize];
        input.read_exact(&mut name)?;
        ensure!(name.last() == Some(&0), "unterminated CPIO name");
        let name = std::str::from_utf8(&name[..name.len() - 1])?;
        let data = (start + header + names).div_ceil(align) * align;
        let end = data
            .checked_add(size)
            .context("CPIO size overflow")?
            .div_ceil(align)
            * align;
        ensure!(end <= length, "truncated CPIO data");
        if name == "TRAILER!!!" {
            ensure!(size == 0, "invalid CPIO trailer");
            ensure!(count > 0, "empty CPIO archive");
            return Ok(());
        }
        if name != "." && name != "./" {
            safe_path(name)?;
        }
        count += 1;
        ensure!(count <= 4096, "too many CPIO members");
        input.seek(SeekFrom::Start(end))?;
    }
}
pub fn extract_checked(
    wire: &Path,
    output: &Path,
    id: &str,
    limit: u64,
    expected: &[Item],
) -> Result<PathBuf> {
    let cpio = decode(wire, limit)?;
    std::fs::create_dir_all(output)?;
    let staging = tempfile::Builder::new()
        .prefix(".owl-rs-")
        .tempdir_in(output)?;
    let mut reader = cpio_archive::reader(cpio.reopen()?)?;
    let mut names = HashSet::new();
    let mut left = limit;
    while let Some(header) = reader.read_next()? {
        if header.name() == "." || header.name() == "./" {
            ensure!(
                header.mode() & 0o170000 == 0o040000 && header.file_size() == 0,
                "invalid root directory"
            );
            continue;
        }
        let path = safe_path(header.name())?;
        ensure!(names.insert(path.clone()), "duplicate archive member");
        let dest = staging.path().join(&path);
        let kind = header.mode() & 0o170000;
        ensure!(
            kind == 0o100000 || kind == 0o040000,
            "archive contains a symlink or special file"
        );
        if kind == 0o040000 {
            ensure!(header.file_size() == 0, "directory contains file data");
            std::fs::create_dir_all(dest)?;
        } else {
            ensure!(header.nlink() <= 1, "archive hard links are not supported");
            std::fs::create_dir_all(dest.parent().context("missing parent")?)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest)?;
            ensure!(
                copy_limited(&mut reader, &mut file, &mut left)? == header.file_size(),
                "truncated CPIO member"
            );
            file.sync_all()?;
        }
    }
    let roots = std::fs::read_dir(staging.path())?.collect::<std::io::Result<Vec<_>>>()?;
    for root in &roots {
        let name = root.file_name();
        let name = name.to_str().context("invalid extracted name")?;
        if expected.iter().any(|i| i.name == name) {
            continue;
        }
        let original = name
            .strip_prefix("._")
            .context("archive includes an unapproved file")?;
        ensure!(
            expected.iter().any(|i| i.name == original),
            "unapproved metadata companion"
        );
        let meta = root.metadata()?;
        ensure!(
            meta.is_file() && (26..=1024 * 1024).contains(&meta.len()),
            "invalid metadata companion"
        );
        let mut header = [0; 8];
        File::open(root.path())?.read_exact(&mut header)?;
        ensure!(
            header == [0, 5, 22, 7, 0, 2, 0, 0],
            "invalid AppleDouble metadata"
        );
    }
    for item in expected {
        let path = safe_path(&item.name)?;
        ensure!(
            path.components().count() == 1,
            "offered name must be a basename"
        );
        let meta =
            std::fs::metadata(staging.path().join(path)).context("approved file is missing")?;
        ensure!(
            meta.is_dir() == item.directory,
            "approved file type changed"
        );
        // FileSize is optional in Apple offers; zero means unspecified.
        if !item.directory && item.size != 0 {
            ensure!(meta.len() == item.size, "approved file size changed");
        }
    }
    let target = output.join(format!("airdrop-{id}"));
    ensure!(!target.exists(), "transfer output already exists");
    std::fs::rename(staging.path(), &target)?;
    Ok(target)
}

fn thumbnail(path: &Path) -> Option<Vec<u8>> {
    if std::fs::metadata(path).ok()?.len() > 64 * 1024 * 1024 {
        return None;
    }
    let mut reader = image::ImageReader::open(path)
        .ok()?
        .with_guessed_format()
        .ok()?;
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let im = reader.decode().ok()?.thumbnail(240, 240).to_rgb8();
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 80)
        .encode_image(&im)
        .ok()?;
    Some(out)
}
