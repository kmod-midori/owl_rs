// SPDX-License-Identifier: GPL-3.0-or-later
//! AppleDouble v2 metadata exported as an XML plist without applying attributes.
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use std::{
    collections::HashSet,
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::Path,
};

const MAX_BYTES: u64 = 16 * 1024 * 1024;

// Decoding is optional: complex or unsupported values remain opaque data.
const MAX_PLIST_BYTES: usize = 64 * 1024;
const MAX_PLIST_OBJECTS: u64 = 128;

struct PlistReader<'a> {
    cursor: Cursor<&'a [u8]>,
    remaining: usize,
}
impl Read for PlistReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("embedded plist read limit exceeded"));
        }
        let len = buffer.len().min(self.remaining);
        let read = self.cursor.read(&mut buffer[..len])?;
        self.remaining -= read;
        Ok(read)
    }
}
impl Seek for PlistReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.cursor.seek(pos)
    }
}

fn xml_text(text: &str) -> bool {
    text.chars().all(|c| {
        matches!(c,
        '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' |
        '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
    })
}

fn xml_value(value: &Value) -> bool {
    match value {
        Value::Uid(_) => false, // UIDs have no XML plist representation.
        Value::String(text) => xml_text(text),
        Value::Array(values) => values.iter().all(xml_value),
        Value::Dictionary(values) => values.iter().all(|(k, v)| xml_text(k) && xml_value(v)),
        _ => true,
    }
}

fn attribute_value(bytes: &[u8]) -> Value {
    let binary = bytes.starts_with(b"bplist");
    let text = std::str::from_utf8(bytes).ok();
    let xml = text.is_some_and(|text| {
        let text = text.trim_start_matches('\u{feff}').trim_start();
        text.starts_with("<?xml") || text.starts_with("<plist")
    });
    if binary || xml {
        // Bound nesting before recursive Value construction. For binary plists,
        // the trailer's object count bounds depth; the read budget also bounds
        // expansion of shared object references. XML depth is bounded by tags.
        let simple = if binary {
            bytes.len() >= 32
                && u64::from_be_bytes(
                    bytes[bytes.len() - 24..bytes.len() - 16]
                        .try_into()
                        .unwrap(),
                ) <= MAX_PLIST_OBJECTS
        } else {
            bytes.iter().filter(|&&b| b == b'<').count() <= MAX_PLIST_OBJECTS as usize
        };
        if bytes.len() <= MAX_PLIST_BYTES && simple {
            let reader = PlistReader {
                cursor: Cursor::new(bytes),
                remaining: MAX_PLIST_BYTES * 4,
            };
            let parsed = if binary {
                Value::from_reader(reader)
            } else {
                Value::from_reader_xml(reader)
            };
            if let Ok(value) = parsed
                && xml_value(&value)
            {
                return value;
            }
        }
    } else if let Some(text) = text {
        // A single terminating NUL is common in string attributes. Do not
        // interpret private numeric fields or strings containing control bytes.
        let text = text.strip_suffix('\0').unwrap_or(text);
        if !text.is_empty()
            && xml_text(text)
            && text
                .chars()
                .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
        {
            return Value::String(text.into());
        }
    }
    Value::Data(bytes.to_vec())
}

fn range(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .context("AppleDouble offset overflow")?;
    bytes.get(offset..end).context("truncated AppleDouble data")
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(range(bytes, offset, 2)?.try_into()?))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(range(bytes, offset, 4)?.try_into()?))
}
fn attributes(bytes: &[u8], start: usize, end: usize) -> Result<Dictionary> {
    range(bytes, start, 36)?;
    let total = u32_at(bytes, start + 8)? as usize;
    let data_start = u32_at(bytes, start + 12)? as usize;
    let data_length = u32_at(bytes, start + 16)? as usize;
    ensure!(
        start + 36 <= data_start && data_start <= total && total <= end,
        "invalid AppleDouble attribute header"
    );
    ensure!(
        data_length <= total - data_start,
        "invalid AppleDouble attribute data size"
    );
    let count = usize::from(u16_at(bytes, start + 34)?);
    ensure!(count <= 4096, "too many AppleDouble attributes");
    let mut pos = start + 36;
    let mut result = Dictionary::new();
    let mut spans = Vec::new();
    for _ in 0..count {
        ensure!(
            pos + 11 <= data_start,
            "truncated AppleDouble attribute entry"
        );
        let offset = u32_at(bytes, pos)? as usize;
        let length = u32_at(bytes, pos + 4)? as usize;
        let name_length = usize::from(bytes[pos + 10]);
        ensure!(
            name_length > 1 && pos + 11 + name_length <= data_start,
            "invalid AppleDouble attribute name length"
        );
        let name = range(bytes, pos + 11, name_length)?;
        ensure!(
            name.last() == Some(&0),
            "unterminated AppleDouble attribute name"
        );
        let name = std::str::from_utf8(&name[..name.len() - 1])?;
        ensure!(
            xml_text(name) && !name.chars().any(char::is_control),
            "invalid AppleDouble attribute name"
        );
        ensure!(
            offset >= data_start
                && offset <= data_start + data_length
                && length <= data_start + data_length - offset,
            "invalid AppleDouble attribute range"
        );
        ensure!(
            spans
                .iter()
                .all(|&(a, b)| length == 0 || offset >= b || offset + length <= a),
            "overlapping AppleDouble attributes"
        );
        spans.push((offset, offset + length));
        // Raw entry data is retained separately, including original encodings.
        ensure!(
            result
                .insert(name.into(), attribute_value(range(bytes, offset, length)?))
                .is_none(),
            "duplicate AppleDouble attribute name"
        );
        pos = (pos + 11 + name_length + 3) & !3;
        ensure!(pos <= data_start, "invalid AppleDouble attribute alignment");
    }
    Ok(result)
}
fn parse(bytes: &[u8]) -> Result<Value> {
    ensure!(u32_at(bytes, 0)? == 0x00051607, "not an AppleDouble file");
    ensure!(
        u32_at(bytes, 4)? == 0x00020000,
        "unsupported AppleDouble version"
    );
    let count = usize::from(u16_at(bytes, 24)?);
    ensure!(count <= 4096, "too many AppleDouble entries");
    let table_end = 26 + count * 12;
    range(bytes, 0, table_end)?;
    let mut entries = Vec::new();
    let mut ids = HashSet::new();
    let mut spans = Vec::new();
    let mut root = Dictionary::new();
    root.insert("Version".into(), Value::Integer(2.into()));
    for i in 0..count {
        let pos = 26 + i * 12;
        let id = u32_at(bytes, pos)?;
        let offset = u32_at(bytes, pos + 4)? as usize;
        let length = u32_at(bytes, pos + 8)? as usize;
        ensure!(
            id != 0 && ids.insert(id),
            "invalid or duplicate AppleDouble entry ID"
        );
        ensure!(offset >= table_end, "AppleDouble entry overlaps header");
        let data = range(bytes, offset, length)?;
        let end = offset + length;
        ensure!(
            spans
                .iter()
                .all(|&(a, b)| length == 0 || offset >= b || end <= a),
            "overlapping AppleDouble entries"
        );
        spans.push((offset, end));
        let mut entry = Dictionary::new();
        entry.insert("ID".into(), Value::Integer(id.into()));
        entry.insert("Data".into(), Value::Data(data.to_vec()));
        entries.push(Value::Dictionary(entry));
        if id == 9 {
            ensure!(length >= 32, "truncated Finder information");
            root.insert("FinderInfo".into(), Value::Data(data[..32].to_vec()));
            let attr_start = (offset + 32 + 3) & !3;
            if attr_start + 4 <= end && &bytes[attr_start..attr_start + 4] == b"ATTR" {
                ensure!(
                    attr_start + 36 <= end,
                    "truncated AppleDouble attribute header"
                );
                root.insert(
                    "ExtendedAttributes".into(),
                    Value::Dictionary(attributes(bytes, attr_start, end)?),
                );
            }
        }
    }
    root.insert("Entries".into(), Value::Array(entries));
    Ok(Value::Dictionary(root))
}

struct XmlWriter<W> {
    inner: W,
    remaining: u64,
}
impl<W: Write> Write for XmlWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(io::Error::other(
                "AppleDouble XML exceeds receive size limit",
            ));
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn export(path: &Path, budget: &mut u64) -> Result<()> {
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.len() <= MAX_BYTES,
        "AppleDouble metadata exceeds 16 MiB"
    );
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "AppleDouble metadata exceeds 16 MiB"
    );
    let value = parse(&bytes)?;
    let mut name = path
        .file_name()
        .context("missing AppleDouble filename")?
        .to_os_string();
    name.push(".xml");
    let destination = path.with_file_name(name);
    // Publish only complete XML, and never replace another archive member.
    let mut output = tempfile::NamedTempFile::new_in(path.parent().context("missing parent")?)?;
    let mut writer = XmlWriter {
        inner: &mut output,
        remaining: *budget,
    };
    value.to_writer_xml(&mut writer)?;
    let remaining = writer.remaining;
    output.as_file().sync_all()?;
    output.persist_noclobber(destination)?;
    *budget = remaining;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 144];
        for (offset, value) in [
            (0, 0x00051607u32),
            (4, 0x00020000),
            (26, 9),
            (30, 50),
            (34, 94),
            (38, 2),
            (42, 144),
            (84, 0x41545452),
            (92, 144),
            (96, 140),
            (100, 4),
            (120, 140),
            (124, 4),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        bytes[24..26].copy_from_slice(&2u16.to_be_bytes());
        bytes[118..120].copy_from_slice(&1u16.to_be_bytes());
        bytes[130] = 5;
        bytes[131..136].copy_from_slice(b"test\0");
        bytes[140..144].copy_from_slice(&[0, 1, 254, 255]);
        bytes
    }

    #[test]
    fn attributes_decode_plists_and_text_without_guessing_binary_types() {
        let mut dict = Dictionary::new();
        dict.insert(
            "created".into(),
            Value::Date(plist::Date::from_xml_format("2025-11-22T03:04:05Z").unwrap()),
        );
        dict.insert(
            "values".into(),
            Value::Array(vec![
                Value::Boolean(true),
                Value::Integer(42.into()),
                Value::String("照片".into()),
            ]),
        );
        let value = Value::Dictionary(dict);
        let mut binary = Vec::new();
        value.to_writer_binary(&mut binary).unwrap();
        let mut xml = Vec::new();
        value.to_writer_xml(&mut xml).unwrap();
        assert_eq!(attribute_value(&binary), value);
        assert_eq!(attribute_value(&xml), value);
        assert_eq!(
            attribute_value(b"com.light.beautyabroad\0"),
            Value::String("com.light.beautyabroad".into())
        );
        let mut uid = Vec::new();
        Value::Uid(plist::Uid::new(1))
            .to_writer_binary(&mut uid)
            .unwrap();
        let nested = format!(
            "<plist>{}{}{}</plist>",
            "<array>".repeat(128),
            "<true/>",
            "</array>".repeat(128)
        );
        for bytes in [
            b"\0\x01".as_slice(),
            b"bplist00broken",
            b"<plist>broken",
            b"\xef\xbf\xbf",
            uid.as_slice(),
            nested.as_bytes(),
        ] {
            assert_eq!(attribute_value(bytes), Value::Data(bytes.to_vec()));
        }
        let mut too_many = binary.clone();
        let count = too_many.len() - 24;
        too_many[count..count + 8].copy_from_slice(&129u64.to_be_bytes());
        assert_eq!(attribute_value(&too_many), Value::Data(too_many));
    }

    #[test]
    fn metadata_exports_with_archive_without_overwriting_or_losing_sidecars() {
        let bytes = fixture();
        for end in 0..bytes.len() {
            assert!(parse(&bytes[..end]).is_err(), "prefix {end}");
        }
        let mut invalid = bytes.clone();
        invalid[124..128].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse(&invalid).is_err());
        let mut overlap = bytes.clone();
        overlap[42..46].copy_from_slice(&140u32.to_be_bytes());
        overlap[46..50].copy_from_slice(&4u32.to_be_bytes());
        assert!(parse(&overlap).is_err());

        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        std::fs::create_dir(&input).unwrap();
        for (name, data) in [
            ("._photo.jpg", bytes.as_slice()),
            ("._bad", invalid.as_slice()),
            ("._plain", b"ordinary file".as_slice()),
            ("._collision", bytes.as_slice()),
            ("._collision.xml", b"sender supplied".as_slice()),
        ] {
            std::fs::write(input.join(name), data).unwrap();
        }
        let wire = crate::archive::prepare(&[input], 1024 * 1024).unwrap();
        let received = crate::archive::receive(
            File::open(wire.file.path()).unwrap(),
            &temp.path().join("output"),
            "metadata",
            1024 * 1024,
        )
        .unwrap()
        .commit()
        .unwrap()
        .join("input");
        assert_eq!(std::fs::read(received.join("._photo.jpg")).unwrap(), bytes);
        let xml = std::fs::read(received.join("._photo.jpg.xml")).unwrap();
        assert!(xml.starts_with(b"<?xml"));
        let value = Value::from_reader_xml(xml.as_slice()).unwrap();
        let attrs = value.as_dictionary().unwrap()["ExtendedAttributes"]
            .as_dictionary()
            .unwrap();
        assert_eq!(attrs["test"].as_data(), Some(&[0, 1, 254, 255][..]));
        assert!(!received.join("._bad.xml").exists());
        assert!(!received.join("._plain.xml").exists());
        assert_eq!(
            std::fs::read(received.join("._collision.xml")).unwrap(),
            b"sender supplied"
        );
        let raw = crate::archive::receive_with_appledouble(
            File::open(wire.file.path()).unwrap(),
            &temp.path().join("raw"),
            "metadata",
            1024 * 1024,
            false,
        )
        .unwrap()
        .commit()
        .unwrap()
        .join("input");
        assert_eq!(std::fs::read(raw.join("._photo.jpg")).unwrap(), bytes);
        assert!(!raw.join("._photo.jpg.xml").exists());
        let mut budget = 0;
        assert!(export(&received.join("._collision"), &mut budget).is_err());
        assert_eq!(budget, 0);
    }
}
