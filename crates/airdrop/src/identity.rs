// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::{Context, Result, bail};
use fs2::FileExt;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, X509NameBuilder},
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
    let mut file = tempfile::NamedTempFile::new_in(path.parent().context("file has no parent")?)?;
    file.write_all(data)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)?;
    Ok(())
}
/// Create private directories without changing ownership of existing parents.
pub fn private_directory(path: &Path) -> Result<()> {
    let mut missing = Vec::new();
    let mut parent = path;
    while !parent.as_os_str().is_empty() && !parent.exists() {
        missing.push(parent.to_path_buf());
        parent = parent.parent().context("directory has no parent")?;
    }
    for path in missing.into_iter().rev() {
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => (),
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::ensure!(path.is_dir(), "{} is not a directory", path.display());
    Ok(())
}
impl Identity {
    pub fn load(dir: &Path, name: &str) -> Result<Self> {
        private_directory(dir)?;
        // Different run directories may share an identity. Serialize creation so
        // no loader observes a partially published certificate/key pair.
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(dir.join("identity.lock"))?;
        anyhow::ensure!(lock.metadata()?.is_file(), "invalid identity lock file");
        lock.lock_exclusive()?;
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
            let verifier = crate::contacts::Verifier::apple()?;
            let verified = verifier
                .record(data)
                .context("verify local Apple validation record")?;
            let account = verifier.certificate_account(leaf, &certificates[1..])?;
            if account != verified.account {
                bail!("certificate does not match the validation record account");
            }
            for (slot, digest) in hashes.chunks_mut(2).zip(verified.hashes) {
                slot.copy_from_slice(&digest[..2]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, sync::Barrier};

    #[test]
    fn concurrent_loads_share_a_complete_private_identity() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("nested/keys");
        let barrier = Barrier::new(4);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        let identity = Identity::load(&dir, "fixture").unwrap();
                        identity.acceptor().unwrap();
                        std::fs::read(dir.join("cert.pem")).unwrap()
                    })
                })
                .collect();
            let certificates: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert!(certificates.windows(2).all(|pair| pair[0] == pair[1]));
        });
        for name in ["cert.pem", "key.pem", "identity.lock"] {
            let path = dir.join(name);
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let original = std::fs::read(&path).unwrap();
            assert!(write_private(&path, b"replacement").is_err());
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 3);
    }
}
