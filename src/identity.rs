// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::{Context, Result, bail};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    cms::{CMSOptions, CmsContentInfo},
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, X509NameBuilder, store::X509StoreBuilder},
};
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
#[derive(Clone)]
pub struct Identity {
    pub dir: PathBuf,
    pub record: Option<Vec<u8>>,
    pub hashes: [u8; 8],
}
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}
/// Create private directories without changing ownership of existing parents.
pub fn private_directory(path: &Path, owner: Option<(u32, u32)>) -> Result<()> {
    let mut missing = Vec::new();
    let mut parent = path;
    while !parent.as_os_str().is_empty() && !parent.exists() {
        missing.push(parent.to_path_buf());
        parent = parent.parent().context("directory has no parent")?;
    }
    for path in missing.into_iter().rev() {
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {
                if let Some((uid, gid)) = owner {
                    nix::unistd::chown(
                        &path,
                        Some(nix::unistd::Uid::from_raw(uid)),
                        Some(nix::unistd::Gid::from_raw(gid)),
                    )?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => (),
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::ensure!(path.is_dir(), "{} is not a directory", path.display());
    Ok(())
}
impl Identity {
    pub fn load(dir: &Path, name: &str) -> Result<Self> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        if !cert.exists() && !key.exists() {
            let pkey = PKey::from_rsa(Rsa::generate(2048)?)?;
            let mut subject = X509NameBuilder::new()?;
            subject.append_entry_by_text("CN", name)?;
            let subject = subject.build();
            let mut builder = X509::builder()?;
            builder.set_version(2)?;
            let mut serial = BigNum::new()?;
            serial.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
            let serial = Asn1Integer::from_bn(&serial)?;
            builder.set_serial_number(&serial)?;
            builder.set_subject_name(&subject)?;
            builder.set_issuer_name(&subject)?;
            builder.set_pubkey(&pkey)?;
            let before = Asn1Time::days_from_now(0)?;
            let after = Asn1Time::days_from_now(3650)?;
            builder.set_not_before(&before)?;
            builder.set_not_after(&after)?;
            builder.sign(&pkey, MessageDigest::sha256())?;
            write_private(&key, &pkey.private_key_to_pem_pkcs8()?)?;
            if let Err(e) = write_private(&cert, &builder.build().to_pem()?) {
                let _ = std::fs::remove_file(&key);
                return Err(e);
            }
        }
        let certificates = X509::stack_from_pem(&std::fs::read(cert)?)?;
        let leaf = certificates
            .first()
            .context("empty identity certificate chain")?;
        let pkey = PKey::private_key_from_pem(&std::fs::read(key)?)?;
        if !leaf.public_key()?.public_eq(&pkey) {
            bail!("identity certificate and key do not match");
        }
        let record_path = dir.join("validation_record.cms");
        let record = if record_path.exists() {
            Some(std::fs::read(record_path)?)
        } else {
            None
        };
        let mut hashes = [0; 8];
        if let Some(data) = &record {
            if data.len() > 128 * 1024 {
                bail!("validation record exceeds 128 KiB");
            }
            let mut store = X509StoreBuilder::new()?;
            store.add_cert(X509::from_pem(include_bytes!(
                "../assets/apple_root_ca.pem"
            ))?)?;
            let store = store.build();
            let mut chain = openssl::stack::Stack::new()?;
            for cert in certificates.iter().skip(1) {
                chain.push(cert.clone())?;
            }
            let mut verification = openssl::x509::X509StoreContext::new()?;
            if !verification.init(&store, leaf, &chain, |ctx| ctx.verify_cert())? {
                bail!("validation records require a certificate chain issued by Apple");
            }
            let mut cms = CmsContentInfo::from_der(data)?;
            let mut decoded = Vec::new();
            cms.verify(
                None,
                Some(&store),
                None,
                Some(&mut decoded),
                CMSOptions::empty(),
            )
            .context("verify Apple validation record signature")?;
            let plist = plist::Value::from_reader(std::io::Cursor::new(decoded))?;
            let dict = plist
                .as_dictionary()
                .context("record must be a plist dictionary")?;
            let account = dict
                .get("altDsID")
                .and_then(plist::Value::as_string)
                .context("record has no account")?;
            let cn = leaf
                .subject_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .next()
                .context("certificate has no CN")?
                .data()
                .to_string()?;
            if cn != format!("com.apple.idms.appleid.prd.{account}") {
                bail!("certificate does not match the validation record account");
            }
            let mut prefixes = Vec::new();
            for field in ["ValidatedEmailHashes", "ValidatedPhoneHashes"] {
                if let Some(values) = dict.get(field).and_then(plist::Value::as_array) {
                    for value in values {
                        if let Some(h) = value.as_string()
                            && h.len() == 64
                            && h.bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            let a = u8::from_str_radix(&h[..2], 16)?;
                            let b = u8::from_str_radix(&h[2..4], 16)?;
                            prefixes.push([a, b]);
                        }
                    }
                }
            }
            for (slot, prefix) in hashes.chunks_mut(2).zip(prefixes) {
                slot.copy_from_slice(&prefix);
            }
        }
        Ok(Self {
            dir: dir.into(),
            record,
            hashes,
        })
    }
    pub fn acceptor(&self) -> Result<SslAcceptor> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
        builder.set_certificate_chain_file(self.dir.join("cert.pem"))?;
        builder.set_private_key_file(self.dir.join("key.pem"), openssl::ssl::SslFiletype::PEM)?;
        builder.check_private_key()?;
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        Ok(builder.build())
    }
    pub fn connector(&self) -> Result<SslConnector> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_certificate_chain_file(self.dir.join("cert.pem"))?;
        builder.set_private_key_file(self.dir.join("key.pem"), openssl::ssl::SslFiletype::PEM)?;
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        Ok(builder.build())
    }
}
