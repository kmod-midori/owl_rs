// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded streaming DVZip/CPIO extraction into private destination staging.
pub use airdrop_client::control::Item;
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, Write},
    path::{Component, Path, PathBuf},
};
use tempfile::NamedTempFile;
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
    prepare_cancellable(paths, limit, &tokio_util::sync::CancellationToken::new())
}
pub(crate) fn prepare_cancellable(
    paths: &[PathBuf],
    limit: u64,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<Prepared> {
    ensure!(!paths.is_empty(), "choose at least one file or directory");
    let cpio = NamedTempFile::new()?;
    let mut builder = cpio_archive::odc::OdcBuilder::new(cpio.reopen()?);
    let mut names = HashSet::new();
    let mut items = Vec::new();
    let mut total = 0u64;
    let mut count = 0;
    for path in paths {
        ensure!(!cancel.is_cancelled(), "archive preparation cancelled");
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
            ensure!(!cancel.is_cancelled(), "archive preparation cancelled");
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
                    &mut Cancellable {
                        input: File::open(entry.path())?.take(meta.len()),
                        cancel,
                    },
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
    let mut input = Cancellable {
        input: cpio.reopen()?,
        cancel,
    };
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
struct Cancellable<'a, R> {
    input: R,
    cancel: &'a tokio_util::sync::CancellationToken,
}
impl<R: Read> Read for Cancellable<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::other("archive preparation cancelled"));
        }
        self.input.read(bytes)
    }
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
// DVZip decoding keeps only a bounded input buffer and zlib state, never a
// complete compressed block. Gzip uses a single-member decoder to finish at
// its checked footer without waiting for HTTP EOF.
enum Block {
    Stored { left: u64 },
    Compressed { left: u64, zip: flate2::Decompress },
}
enum Encoding<R: Read> {
    Dvzip {
        input: BufReader<R>,
        block: Option<Block>,
    },
    Gzip(flate2::bufread::GzDecoder<BufReader<R>>),
}
struct Decoder<R: Read> {
    encoding: Encoding<R>,
    left: u64,
}
fn decoder(mut input: impl Read, limit: u64) -> Result<Decoder<impl Read>> {
    let mut magic = [0; 2];
    input.read_exact(&mut magic)?;
    let input = BufReader::with_capacity(65536, io::Cursor::new(magic).chain(input));
    let encoding = if magic == [0x1f, 0x8b] {
        Encoding::Gzip(flate2::bufread::GzDecoder::new(input))
    } else {
        Encoding::Dvzip { input, block: None }
    };
    Ok(Decoder {
        encoding,
        left: limit,
    })
}
impl<R: Read> Decoder<R> {
    fn read_decoded(&mut self, out: &mut [u8], next_block: bool) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let n = match &mut self.encoding {
            Encoding::Gzip(zip) => zip.read(out)?,
            Encoding::Dvzip { input, block } => loop {
                if block.is_none() {
                    if !next_block {
                        break 0;
                    }
                    let mut header = [0; 4];
                    if input.read(&mut header[..1])? == 0 {
                        break 0;
                    }
                    input.read_exact(&mut header[1..])?;
                    let value = u32::from_be_bytes(header);
                    let left = (value & 0x7fffffff) as u64;
                    ensure!(
                        left > 0 && left <= 16 * 1024 * 1024,
                        "invalid DVZip block length"
                    );
                    *block = Some(if value & 0x80000000 != 0 {
                        Block::Stored { left }
                    } else {
                        Block::Compressed {
                            left,
                            zip: flate2::Decompress::new(true),
                        }
                    });
                }
                match block.as_mut().expect("DVZip block") {
                    Block::Stored { left } => {
                        let count = out.len().min(*left as usize);
                        let n = input.read(&mut out[..count])?;
                        ensure!(n > 0, "truncated stored DVZip block");
                        *left -= n as u64;
                        if *left == 0 {
                            *block = None;
                        }
                        break n;
                    }
                    Block::Compressed { left, zip } => {
                        let data = if *left == 0 {
                            &[][..]
                        } else {
                            input.fill_buf()?
                        };
                        let before_in = zip.total_in();
                        let before_out = zip.total_out();
                        let status = zip.decompress(
                            &data[..data.len().min(*left as usize)],
                            out,
                            flate2::FlushDecompress::None,
                        )?;
                        let consumed = (zip.total_in() - before_in) as usize;
                        let n = (zip.total_out() - before_out) as usize;
                        input.consume(consumed);
                        *left -= consumed as u64;
                        if status == flate2::Status::StreamEnd {
                            ensure!(*left == 0, "trailing DVZip compressed data");
                            *block = None;
                        } else {
                            ensure!(consumed > 0 || n > 0, "truncated DVZip zlib stream");
                        }
                        if n > 0 {
                            break n;
                        }
                    }
                }
            },
        };
        ensure!(n as u64 <= self.left, "expanded archive exceeds size limit");
        self.left -= n as u64;
        Ok(n)
    }
    /// Drain only the enclosing DVZip block or gzip member, verifying its
    /// checksum and padding without waiting for another block or transport EOF.
    fn finish(&mut self) -> Result<()> {
        let mut buf = [0; 65536];
        while self.read_decoded(&mut buf, false)? != 0 {}
        Ok(())
    }
}
impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.read_decoded(out, true).map_err(io::Error::other)
    }
}
fn number(bytes: &[u8], radix: u32) -> Result<u64> {
    Ok(u64::from_str_radix(std::str::from_utf8(bytes)?, radix)?)
}
/// Checked files stay private until the receive task commits them. Dropping a
/// cancelled worker's result removes staging instead of publishing a transfer.
pub struct Validated {
    staging: tempfile::TempDir,
    target: PathBuf,
}
impl Validated {
    pub fn commit(self) -> Result<PathBuf> {
        // Refuse an existing target atomically, including an empty directory.
        nix::fcntl::renameat2(
            nix::fcntl::AT_FDCWD,
            self.staging.path(),
            nix::fcntl::AT_FDCWD,
            &self.target,
            nix::fcntl::RenameFlags::RENAME_NOREPLACE,
        )
        .context("publish received transfer")?;
        Ok(self.target)
    }
}
/// Validate incoming DVZip blocks and CPIO structure without waiting for HTTP EOF.
/// Gzip reception completes after its CRC/footer, rather than transport EOF.
pub fn receive(input: impl Read, output: &Path, id: &str, limit: u64) -> Result<Validated> {
    receive_with_appledouble(input, output, id, limit, true)
}
pub(crate) fn receive_with_appledouble(
    input: impl Read,
    output: &Path,
    id: &str,
    limit: u64,
    parse_appledouble: bool,
) -> Result<Validated> {
    extract_cpio(decoder(input, limit)?, output, id, limit, parse_appledouble)
}
/// Bound untrusted sizes before the archive library allocates its name buffer.
/// Fixed headers and names remain small; member data is consumed separately.
fn checked_header(
    input: &mut impl Read,
    offset: &mut u64,
    limit: u64,
) -> Result<(Box<dyn cpio_archive::CpioHeader>, u64)> {
    let mut raw = [0; 110];
    input.read_exact(&mut raw[..6])?;
    let (length, align) = match &raw[..6] {
        b"070707" => (76, 1u64),
        b"070701" => (110, 4),
        _ => bail!("unsupported CPIO format"),
    };
    input.read_exact(&mut raw[6..length])?;
    let (names, size) = if length == 76 {
        (number(&raw[59..65], 8)?, number(&raw[65..76], 8)?)
    } else {
        (number(&raw[94..102], 16)?, number(&raw[54..62], 16)?)
    };
    ensure!((1..=4096).contains(&names), "invalid CPIO name length");
    let data = (*offset + length as u64 + names).div_ceil(align) * align;
    let end = data
        .checked_add(size)
        .context("CPIO size overflow")?
        .div_ceil(align)
        * align;
    ensure!(end <= limit, "CPIO member exceeds size limit");
    let mut name = vec![0; names as usize];
    input.read_exact(&mut name)?;
    ensure!(name.last() == Some(&0), "unterminated CPIO name");
    std::str::from_utf8(&name[..name.len() - 1])?;
    let mut reader = io::Cursor::new(&raw[6..length])
        .chain(io::Cursor::new(&name))
        .chain(input);
    let header: Box<dyn cpio_archive::CpioHeader> = if length == 76 {
        Box::new(cpio_archive::odc::OdcHeader::from_reader(&mut reader)?)
    } else {
        Box::new(cpio_archive::newc::NewcHeader::from_reader(&mut reader)?)
    };
    *offset = data;
    Ok((header, align))
}
fn extract_cpio<R: Read>(
    mut input: Decoder<R>,
    output: &Path,
    id: &str,
    limit: u64,
    parse_appledouble: bool,
) -> Result<Validated> {
    let target = safe_path(&format!("airdrop-{id}"))?;
    ensure!(target.components().count() == 1, "invalid transfer ID");
    let target = output.join(target);
    std::fs::create_dir_all(output)?;
    let staging = tempfile::Builder::new()
        .prefix(".owl-rs-")
        .tempdir_in(output)?;
    let mut names = HashSet::new();
    let mut metadata = Vec::new();
    let mut left = limit;
    let mut offset = 0u64;
    let mut count = 0;
    let mut format = None;
    loop {
        let (header, align) = checked_header(&mut input, &mut offset, limit)?;
        ensure!(
            format.is_none_or(|value| value == align),
            "CPIO format changed"
        );
        format = Some(align);
        if header.name() == "TRAILER!!!" {
            ensure!(
                header.file_size() == 0 && count > 0,
                "invalid or empty CPIO trailer"
            );
            input.finish()?;
            break;
        }
        count += 1;
        ensure!(count <= 4096, "too many CPIO members");
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
                copy_limited(
                    &mut (&mut input).take(header.file_size()),
                    &mut file,
                    &mut left
                )? == header.file_size(),
                "truncated CPIO member"
            );
            file.sync_all()?;
            if parse_appledouble
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("._"))
            {
                metadata.push(dest);
            }
        }
        let padding = header.file_size().wrapping_neg() % align;
        input.read_exact(&mut [0; 3][..padding as usize])?;
        offset += header.file_size() + padding;
    }
    // Wait for all archive members so generated XML cannot claim a path that
    // the sender also supplied. Metadata conversion never discards originals.
    for path in metadata {
        if let Err(error) = crate::appledouble::export(&path, &mut left) {
            tracing::warn!(%error, "AppleDouble XML export skipped; original preserved");
        }
    }
    Ok(Validated { staging, target })
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
