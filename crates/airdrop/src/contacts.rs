// SPDX-License-Identifier: GPL-3.0-or-later
//! Apple-signed contact policy, following omdrop-plugin's certificate-bound gate.
use anyhow::{Context, Result, ensure};
use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier},
};
use openssl::{
    cms::{CMSOptions, CmsContentInfo},
    sha::sha256,
    ssl::{SslRef, SslVerifyMode},
    stack::Stack,
    x509::{
        X509, X509PurposeId, X509Ref, X509StoreContext,
        store::{X509Store, X509StoreBuilder},
    },
};
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use x509_cert::{
    Certificate as ParsedCertificate,
    der::{Decode, asn1::ObjectIdentifier},
    ext::pkix::SubjectKeyIdentifier,
};

const RECORD_LIMIT: usize = 128 * 1024;
const RECORD_SIGNING_MARKER: &str = "1.2.840.113635.100.6.25";
const SHARING_MARKER: &str = "1.2.840.113635.100.4.7";
const ACCOUNT_PREFIX: &str = "com.apple.idms.appleid.prd.";

pub(crate) struct Record {
    pub account: String,
    pub hashes: Vec<[u8; 32]>,
}
pub(crate) struct Verifier {
    store: X509Store,
    root: X509,
    intermediates: Vec<X509>,
}
impl Verifier {
    pub(crate) fn apple() -> Result<Self> {
        Self::new(
            X509::from_pem(include_bytes!("../../../assets/apple_root_ca.pem"))?,
            vec![
                X509::from_pem(include_bytes!("../../../assets/apple-ca/apple-aai-ca.pem"))?,
                X509::from_pem(include_bytes!("../../../assets/apple-ca/apple-aai2-ca.pem"))?,
            ],
        )
    }
    fn new(root: X509, intermediates: Vec<X509>) -> Result<Self> {
        let mut store = X509StoreBuilder::new()?;
        store.add_cert(root.clone())?;
        // Apple signs identity records with a non-S/MIME certificate. This
        // changes purpose checks, never signature, chain or lifetime validation.
        store.set_purpose(X509PurposeId::ANY)?;
        Ok(Self {
            store: store.build(),
            root,
            intermediates,
        })
    }
    fn chain(&self, peer: &[X509]) -> Result<Stack<X509>> {
        ensure!(
            peer.len() <= 16,
            "certificate chain exceeds 16 certificates"
        );
        let mut chain = Stack::new()?;
        for cert in peer.iter().chain(&self.intermediates) {
            chain.push(cert.clone())?;
        }
        Ok(chain)
    }
    pub(crate) fn record(&self, data: &[u8]) -> Result<Record> {
        ensure!(
            !data.is_empty() && data.len() <= RECORD_LIMIT,
            "invalid validation record size"
        );
        // Apple account holders possess sharing keys, not validation-record
        // signing keys. A root-issued certificate alone cannot vouch for hashes.
        // Apple's live records use BER indefinite lengths. Let OpenSSL decode
        // and canonicalize the envelope before safe DER signer/role inspection;
        // verify the original CMS content and signatures below.
        let mut cms = CmsContentInfo::from_der(data).context("decode validation CMS")?;
        let canonical = cms.to_der().context("canonicalize validation CMS")?;
        ensure!(canonical.len() <= RECORD_LIMIT, "validation CMS too large");
        let envelope = ContentInfo::from_der(&canonical)?;
        ensure!(
            envelope.content_type == ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2"),
            "record is not SignedData"
        );
        let signed: SignedData = envelope.content.decode_as()?;
        ensure!(!signed.signer_infos.0.is_empty(), "record has no signer");
        let certificates = signed
            .certificates
            .as_ref()
            .context("record has no certificates")?;
        for signer in signed.signer_infos.0.iter() {
            let mut candidates = Vec::new();
            for choice in certificates.0.iter() {
                if let CertificateChoices::Certificate(cert) = choice {
                    let matches = match &signer.sid {
                        SignerIdentifier::IssuerAndSerialNumber(id) => {
                            cert.tbs_certificate.issuer == id.issuer
                                && cert.tbs_certificate.serial_number == id.serial_number
                        }
                        SignerIdentifier::SubjectKeyIdentifier(id) => cert
                            .tbs_certificate
                            .get::<SubjectKeyIdentifier>()?
                            .is_some_and(|(_, key)| key == *id),
                    };
                    if matches {
                        candidates.push(cert);
                    }
                }
            }
            ensure!(
                candidates.len() == 1 && has_marker(candidates[0], RECORD_SIGNING_MARKER),
                "record signer lacks Apple's validation-record signing marker"
            );
        }
        let mut decoded = Vec::new();
        let chain = self.chain(&[])?;
        cms.verify(
            Some(&chain),
            Some(&self.store),
            None,
            Some(&mut decoded),
            CMSOptions::BINARY,
        )?;
        ensure!(
            decoded.len() <= RECORD_LIMIT,
            "validation record payload too large"
        );
        let value = plist::Value::from_reader(std::io::Cursor::new(decoded))?;
        let dict = value
            .as_dictionary()
            .context("record must be a dictionary")?;
        let account = dict
            .get("altDsID")
            .and_then(plist::Value::as_string)
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .context("record has no account")?
            .to_owned();
        match (dict.get("ValidAsOf"), dict.get("SuggestValidDuration")) {
            (None, None) => (),
            (Some(date), Some(duration)) => {
                let base: SystemTime = date.as_date().context("invalid record date")?.into();
                let seconds = duration
                    .as_real()
                    .or_else(|| duration.as_unsigned_integer().map(|v| v as f64))
                    .context("invalid record duration")?;
                ensure!(
                    seconds.is_finite() && seconds > 0.0,
                    "invalid record duration"
                );
                let expiry = base
                    .checked_add(Duration::try_from_secs_f64(seconds)?)
                    .context("record expiry overflow")?;
                ensure!(expiry > SystemTime::now(), "validation record expired");
            }
            _ => anyhow::bail!("incomplete record validity"),
        }
        let mut hashes = Vec::new();
        for key in ["ValidatedEmailHashes", "ValidatedPhoneHashes"] {
            if let Some(values) = dict.get(key) {
                let values = values.as_array().context("invalid record hashes")?;
                ensure!(
                    hashes.len() + values.len() <= 4096,
                    "too many record hashes"
                );
                for value in values {
                    if let Some(hash) = value.as_string()
                        && hash.len() == 64
                        && hash.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        let mut digest = [0; 32];
                        for (i, byte) in digest.iter_mut().enumerate() {
                            *byte = u8::from_str_radix(&hash[2 * i..2 * i + 2], 16)?;
                        }
                        hashes.push(digest);
                    }
                }
            }
        }
        Ok(Record { account, hashes })
    }
    pub(crate) fn certificate_account(&self, leaf: &X509Ref, peer: &[X509]) -> Result<String> {
        let parsed = ParsedCertificate::from_der(&leaf.to_der()?)?;
        ensure!(
            has_marker(&parsed, SHARING_MARKER),
            "certificate is not an Apple sharing identity"
        );
        let mut context = X509StoreContext::new()?;
        let chain = self.chain(peer)?;
        ensure!(
            context.init(&self.store, leaf, &chain, |ctx| ctx.verify_cert())?,
            "certificate is not issued by Apple"
        );
        let mut names = leaf
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME);
        let cn = names
            .next()
            .context("certificate has no CN")?
            .data()
            .to_string()?;
        ensure!(names.next().is_none(), "ambiguous certificate CN");
        Ok(cn
            .strip_prefix(ACCOUNT_PREFIX)
            .filter(|s| !s.is_empty())
            .context("certificate has no Apple account")?
            .into())
    }
    pub(crate) fn request_certificate(&self, ssl: &mut SslRef) -> Result<()> {
        let mut names = Stack::new()?;
        for cert in std::iter::once(&self.root).chain(&self.intermediates) {
            names.push(cert.subject_name().to_owned()?)?;
        }
        ssl.set_client_ca_list(names);
        // Discovery may omit a certificate or use an ephemeral identity. Ask
        // performs full verification before approval; handshake success is not authorization.
        ssl.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
        Ok(())
    }
}

fn has_marker(cert: &ParsedCertificate, oid: &str) -> bool {
    cert.tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter(|e| e.extn_id.to_string() == oid)
        .count()
        == 1
}

#[derive(Clone, Default)]
pub(crate) struct PeerCertificate {
    pub leaf: Option<X509>,
    pub chain: Vec<X509>,
}
impl PeerCertificate {
    pub(crate) fn from_tls(ssl: &SslRef) -> Self {
        Self {
            leaf: ssl.peer_certificate(),
            chain: ssl
                .peer_cert_chain()
                .map(|c| c.iter().take(17).map(X509Ref::to_owned).collect())
                .unwrap_or_default(),
        }
    }
}
#[derive(Clone)]
pub(crate) struct Contacts {
    path: PathBuf,
    verifier: Arc<Verifier>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Denied {
    #[error("missing validation record")]
    NoRecord,
    #[error("invalid or expired validation record")]
    BadRecord,
    #[error("missing client certificate")]
    NoCertificate,
    #[error("record is not bound to an Apple-issued client certificate")]
    Unbound,
    #[error("sender is not a known contact")]
    Unknown,
    #[error("contact policy unavailable")]
    Unavailable,
}
impl Contacts {
    pub(crate) fn new(path: PathBuf) -> Result<Self> {
        // Fail before radio setup on unreadable/invalid files; a missing list is empty.
        known_hashes(&path)?;
        Ok(Self {
            path,
            verifier: Arc::new(Verifier::apple()?),
        })
    }
    pub(crate) fn request_certificate(&self, ssl: &mut SslRef) -> Result<()> {
        self.verifier.request_certificate(ssl)
    }
    // Short BLE prefixes only select wake candidates; Ask still verifies the
    // full signed record, TLS identity and complete SHA-256 contact digest.
    pub(crate) fn matches_ble(&self, prefixes: &[u8; 8]) -> Result<bool> {
        Ok(known_hashes(&self.path)?.iter().any(|hash| {
            prefixes
                .as_chunks::<2>()
                .0
                .iter()
                .any(|prefix| prefix == &hash[..2])
        }))
    }
    pub(crate) async fn discover(&self, record: Option<&[u8]>) -> bool {
        self.check(record, None).await.is_ok()
    }
    pub(crate) async fn authorize(
        &self,
        record: Option<&[u8]>,
        peer: &PeerCertificate,
    ) -> std::result::Result<(), Denied> {
        self.check(record, Some(peer)).await
    }
    async fn check(
        &self,
        record: Option<&[u8]>,
        peer: Option<&PeerCertificate>,
    ) -> std::result::Result<(), Denied> {
        let policy = self.clone();
        let record = record.map(<[u8]>::to_vec);
        let peer = peer.cloned();
        tokio::task::spawn_blocking(move || policy.decide(record.as_deref(), peer.as_ref()))
            .await
            .unwrap_or(Err(Denied::Unavailable))
    }
    fn decide(
        &self,
        data: Option<&[u8]>,
        peer: Option<&PeerCertificate>,
    ) -> std::result::Result<(), Denied> {
        // Discovery is best-effort hiding, never an authorization cache.
        let record = match data {
            None if peer.is_none() => return Ok(()),
            None => return Err(Denied::NoRecord),
            Some(data) => match self.verifier.record(data) {
                Ok(record) => record,
                Err(_) if peer.is_none() => return Ok(()),
                Err(_) => return Err(Denied::BadRecord),
            },
        };
        if let Some(peer) = peer {
            let leaf = peer.leaf.as_ref().ok_or(Denied::NoCertificate)?;
            let account = self
                .verifier
                .certificate_account(leaf, &peer.chain)
                .map_err(|_| Denied::Unbound)?;
            if account != record.account {
                return Err(Denied::Unbound);
            }
        }
        let known = known_hashes(&self.path).map_err(|_| Denied::Unavailable)?;
        if record.hashes.iter().any(|hash| known.contains(hash)) {
            Ok(())
        } else {
            Err(Denied::Unknown)
        }
    }
}
fn known_hashes(path: &std::path::Path) -> Result<HashSet<[u8; 32]>> {
    Ok(crate::contact_book::list(path)?
        .into_iter()
        .map(|id| sha256(id.as_bytes()))
        .collect())
}

pub(crate) fn record_data(value: &plist::Value) -> Option<&[u8]> {
    value.as_dictionary()?.get("SenderRecordData")?.as_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::Identity,
        transfer::{Receiver, dict, plist_bytes},
    };
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::{PKey, Private},
        rsa::Rsa,
        x509::{
            X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
        },
    };
    use std::{path::Path, pin::Pin};

    struct Certificate {
        cert: X509,
        key: PKey<Private>,
    }
    fn certificate(
        name: &str,
        issuer: Option<&Certificate>,
        ca: bool,
        signing: bool,
    ) -> Certificate {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial
            .rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&subject).unwrap();
        builder
            .set_issuer_name(issuer.map(|i| i.cert.subject_name()).unwrap_or(&subject))
            .unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        if ca {
            builder
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            builder
                .append_extension(
                    KeyUsage::new()
                        .critical()
                        .key_cert_sign()
                        .crl_sign()
                        .build()
                        .unwrap(),
                )
                .unwrap();
        } else {
            builder
                .append_extension(BasicConstraints::new().critical().build().unwrap())
                .unwrap();
            builder
                .append_extension(
                    KeyUsage::new()
                        .critical()
                        .digital_signature()
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let mut purpose = ExtendedKeyUsage::new();
            if signing {
                purpose.code_signing();
            } else {
                purpose.client_auth();
            }
            builder.append_extension(purpose.build().unwrap()).unwrap();
        }
        let identifier = openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(issuer.map(|i| i.cert.as_ref()), None))
            .unwrap();
        builder.append_extension(identifier).unwrap();
        if !ca {
            let oid = openssl::asn1::Asn1Object::from_str(if signing {
                RECORD_SIGNING_MARKER
            } else {
                SHARING_MARKER
            })
            .unwrap();
            let null = openssl::asn1::Asn1OctetString::new_from_bytes(&[5, 0]).unwrap();
            builder
                .append_extension(
                    openssl::x509::X509Extension::new_from_der(&oid, false, &null).unwrap(),
                )
                .unwrap();
        }
        builder
            .sign(
                issuer.map(|i| &i.key).unwrap_or(&key),
                MessageDigest::sha256(),
            )
            .unwrap();
        Certificate {
            cert: builder.build(),
            key,
        }
    }
    struct Fixture {
        root: Certificate,
        issuer: Certificate,
        signer: Certificate,
        peer: Certificate,
    }
    impl Fixture {
        fn new() -> Self {
            let root = certificate("Fixture root", None, true, false);
            let issuer = certificate("Fixture issuing CA", Some(&root), true, false);
            let signer = certificate("Fixture record signer", Some(&issuer), false, true);
            let peer = certificate(
                &format!("{ACCOUNT_PREFIX}fixture-account"),
                Some(&issuer),
                false,
                false,
            );
            Self {
                root,
                issuer,
                signer,
                peer,
            }
        }
        fn policy(&self, path: PathBuf) -> Contacts {
            Contacts {
                path,
                verifier: Arc::new(
                    Verifier::new(self.root.cert.clone(), vec![self.issuer.cert.clone()]).unwrap(),
                ),
            }
        }
        fn record(&self, identifier: &str, expired: bool) -> Vec<u8> {
            self.record_signed_by(identifier, expired, &self.signer, CMSOptions::BINARY)
        }
        fn record_signed_by(
            &self,
            identifier: &str,
            expired: bool,
            signer: &Certificate,
            flags: CMSOptions,
        ) -> Vec<u8> {
            let digest = sha256(identifier.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let value = dict([
                ("altDsID".into(), "fixture-account".into()),
                (
                    (if identifier.contains('@') {
                        "ValidatedEmailHashes"
                    } else {
                        "ValidatedPhoneHashes"
                    })
                    .into(),
                    plist::Value::Array(vec![digest.into()]),
                ),
                (
                    "ValidAsOf".into(),
                    plist::Value::Date(
                        (if expired {
                            SystemTime::UNIX_EPOCH
                        } else {
                            SystemTime::now()
                        })
                        .into(),
                    ),
                ),
                ("SuggestValidDuration".into(), 3600u64.into()),
            ]);
            let mut chain = Stack::new().unwrap();
            chain.push(self.issuer.cert.clone()).unwrap();
            // A public record-signing cert in the bag must not vouch for a different signer.
            if signer.cert.to_der().unwrap() != self.signer.cert.to_der().unwrap() {
                chain.push(self.signer.cert.clone()).unwrap();
            }
            CmsContentInfo::sign(
                Some(&signer.cert),
                Some(&signer.key),
                Some(&chain),
                Some(&plist_bytes(&value).unwrap()),
                flags,
            )
            .unwrap()
            .to_der()
            .unwrap()
        }
    }
    #[test]
    fn signed_contact_gate_rejects_replay_spoofing_expiry_and_unknown_senders() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contacts");
        std::fs::write(
            &path,
            "# fixtures\n\nFriend@Example.com\n+1 (555) 010-1234\n",
        )
        .unwrap();
        let fx = Fixture::new();
        let policy = fx.policy(path.clone());
        let mut prefixes = [0; 8];
        prefixes[..2].copy_from_slice(&sha256(b"friend@example.com")[..2]);
        assert!(policy.matches_ble(&prefixes).unwrap());
        assert!(!policy.matches_ble(&[0; 8]).unwrap());
        let peer = PeerCertificate {
            leaf: Some(fx.peer.cert.clone()),
            chain: vec![],
        }; // Bare leaf needs the bundled intermediate.
        let record = fx.record("friend@example.com", false);
        // BER may differ in its outer lengths without changing the signed
        // content. Never treat normalization as a substitute for verification.
        let header = if record[1] & 0x80 == 0 {
            2
        } else {
            2 + usize::from(record[1] & 0x7f)
        };
        let mut ber = vec![0x30, 0x80];
        ber.extend_from_slice(&record[header..]);
        ber.extend_from_slice(&[0, 0]);
        assert_eq!(policy.decide(Some(&ber), Some(&peer)), Ok(()));
        let mut tampered_ber = ber;
        tampered_ber[header + 64] ^= 1;
        assert!(policy.decide(Some(&tampered_ber), Some(&peer)).is_err());

        assert_eq!(policy.decide(Some(&record), Some(&peer)), Ok(()));
        let keyed = fx.record_signed_by(
            "friend@example.com",
            false,
            &fx.signer,
            CMSOptions::BINARY | CMSOptions::USE_KEYID,
        );
        assert_eq!(policy.decide(Some(&keyed), Some(&peer)), Ok(()));
        assert_eq!(
            policy.decide(Some(&fx.record("15550101234", false)), Some(&peer)),
            Ok(())
        );
        assert_eq!(policy.decide(None, Some(&peer)), Err(Denied::NoRecord));
        assert_eq!(
            policy.decide(Some(&record), Some(&PeerCertificate::default())),
            Err(Denied::NoCertificate)
        );
        let other = certificate(
            &format!("{ACCOUNT_PREFIX}other-account"),
            Some(&fx.issuer),
            false,
            false,
        );
        assert_eq!(
            policy.decide(
                Some(&record),
                Some(&PeerCertificate {
                    leaf: Some(other.cert),
                    chain: vec![]
                })
            ),
            Err(Denied::Unbound)
        );
        let impostor = Fixture::new(); // Same issuer names, different signing keys.
        assert_eq!(
            policy.decide(
                Some(&record),
                Some(&PeerCertificate {
                    leaf: Some(impostor.peer.cert.clone()),
                    chain: vec![impostor.issuer.cert.clone()]
                })
            ),
            Err(Denied::Unbound)
        );
        assert_eq!(
            policy.decide(
                Some(&impostor.record("friend@example.com", false)),
                Some(&peer)
            ),
            Err(Denied::BadRecord)
        );
        assert_eq!(
            policy.decide(
                Some(&fx.record_signed_by(
                    "friend@example.com",
                    false,
                    &fx.peer,
                    CMSOptions::BINARY
                )),
                Some(&peer)
            ),
            Err(Denied::BadRecord)
        );
        let mut tampered = record.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            policy.decide(Some(&tampered), Some(&peer)),
            Err(Denied::BadRecord)
        );
        assert_eq!(
            policy.decide(Some(&fx.record("friend@example.com", true)), Some(&peer)),
            Err(Denied::BadRecord)
        );
        assert_eq!(
            policy.decide(Some(&fx.record("stranger@example.com", false)), Some(&peer)),
            Err(Denied::Unknown)
        );
        // Discovery can be visible without identity, but cannot grant transfer consent.
        assert_eq!(policy.decide(None, None), Ok(()));
        assert_eq!(policy.decide(Some(b"not a record"), None), Ok(()));
        assert_eq!(
            policy.decide(Some(&fx.record("stranger@example.com", false)), None),
            Err(Denied::Unknown)
        );
        crate::contact_book::Book::new(path.clone())
            .remove(&["FRIEND@example.com".into(), "+1-555-010-1234".into()])
            .unwrap();
        assert_eq!(
            policy.decide(Some(&record), Some(&peer)),
            Err(Denied::Unknown)
        );
        std::fs::remove_file(path).unwrap();
        assert_eq!(
            policy.decide(Some(&record), Some(&peer)),
            Err(Denied::Unknown)
        );
    }

    async fn connect(
        address: std::net::SocketAddr,
        peer: Option<&Certificate>,
    ) -> (
        hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
        tokio::task::JoinHandle<()>,
    ) {
        let mut builder =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        if let Some(peer) = peer {
            builder.set_certificate(&peer.cert).unwrap();
            builder.set_private_key(&peer.key).unwrap();
        }
        let ssl = builder
            .build()
            .configure()
            .unwrap()
            .into_ssl("AirDrop")
            .unwrap();
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut stream = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
        Pin::new(&mut stream).connect().await.unwrap();
        let (client, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .unwrap();
        let task = tokio::spawn(async {
            connection.await.unwrap();
        });
        (client, task)
    }
    async fn post(
        client: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
        path: &str,
        record: Option<Vec<u8>>,
    ) -> hyper::StatusCode {
        use http_body_util::BodyExt;
        let mut value = dict([
            ("TransferID".into(), uuid::Uuid::new_v4().to_string().into()),
            (
                "Files".into(),
                plist::Value::Array(vec![dict([("FileName".into(), "fixture.bin".into())])]),
            ),
        ]);
        if let Some(record) = record {
            value
                .as_dictionary_mut()
                .unwrap()
                .insert("SenderRecordData".into(), plist::Value::Data(record));
        }
        let request = hyper::Request::builder()
            .method("POST")
            .uri(path)
            .body(http_body_util::Full::new(bytes::Bytes::from(
                plist_bytes(&value).unwrap(),
            )))
            .unwrap();
        let reply = client.send_request(request).await.unwrap();
        let status = reply.status();
        reply.into_body().collect().await.unwrap();
        status
    }
    #[tokio::test]
    async fn https_asks_for_certificate_and_checks_every_offer_before_auto_accept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contacts");
        std::fs::write(&path, "friend@example.com\n").unwrap();
        let fx = Fixture::new();
        let identity = Identity::load(&dir.path().join("keys"), "fixture").unwrap();
        let controller;
        let receiver = Receiver::new(
            "fixture".into(),
            identity,
            dir.path().join("output"),
            1024,
            true,
        )
        .with_policy({
            let (tx, rx) = tokio::sync::watch::channel(crate::visibility::Policy {
                mode: crate::visibility::Visibility::Contacts,
                contacts: Some(fx.policy(path.clone())),
                path: path.clone(),
                revision: 0,
            });
            // Keep the controller alive for the connection-policy regression.
            controller = tx;
            rx
        });
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let server = tokio::spawn({
            let receiver = receiver.clone();
            let cancel = cancel.clone();
            async move { receiver.serve(listener, cancel).await }
        });
        let record = fx.record("friend@example.com", false);
        let spoof = certificate(
            &format!("{ACCOUNT_PREFIX}fixture-account"),
            None,
            false,
            false,
        );
        for (peer, route, record, status) in [
            (
                Some(&spoof),
                "/Ask",
                Some(record.clone()),
                hyper::StatusCode::FORBIDDEN,
            ),
            (
                Some(&fx.peer),
                "/Ask",
                Some(fx.record_signed_by(
                    "friend@example.com",
                    false,
                    &fx.peer,
                    CMSOptions::BINARY,
                )),
                hyper::StatusCode::FORBIDDEN,
            ),
            (None, "/Discover", None, hyper::StatusCode::OK),
            (
                None,
                "/Ask",
                Some(record.clone()),
                hyper::StatusCode::FORBIDDEN,
            ),
            (Some(&fx.peer), "/Ask", None, hyper::StatusCode::FORBIDDEN),
            (
                Some(&fx.peer),
                "/Discover",
                Some(fx.record("stranger@example.com", false)),
                hyper::StatusCode::UNAUTHORIZED,
            ),
            (None, "/Upload", None, hyper::StatusCode::FORBIDDEN),
        ] {
            let (mut client, task) = connect(address, peer).await;
            assert_eq!(post(&mut client, route, record).await, status);
            drop(client);
            task.abort();
            let _ = task.await;
        }
        assert!(receiver.transfers().await.is_empty());
        assert!(!Path::new(&dir.path().join("output")).exists());
        let (mut client, task) = connect(address, Some(&fx.peer)).await;
        assert_eq!(
            post(&mut client, "/Ask", Some(record.clone())).await,
            hyper::StatusCode::OK
        );
        assert_eq!(receiver.transfers().await[0].state, "accepted");
        // A mode change applies to an existing TLS connection without restarting HTTPS.
        let contacts = controller.borrow().contacts.clone();
        controller.send_modify(|policy| {
            policy.mode = crate::visibility::Visibility::Everyone;
            policy.contacts = None;
            policy.revision += 1;
        });
        assert_eq!(post(&mut client, "/Ask", None).await, hyper::StatusCode::OK);
        controller.send_modify(|policy| {
            policy.mode = crate::visibility::Visibility::Contacts;
            policy.contacts = contacts;
            policy.revision += 1;
        });
        assert_eq!(
            post(&mut client, "/Ask", Some(record.clone())).await,
            hyper::StatusCode::OK
        );
        // Revocation applies to the next Ask, even on the same TLS connection.
        crate::contact_book::Book::new(path)
            .remove(&["FRIEND@example.com".into()])
            .unwrap();
        assert_eq!(
            post(&mut client, "/Ask", Some(record)).await,
            hyper::StatusCode::FORBIDDEN
        );
        drop(client);
        task.abort();
        let _ = task.await;
        controller.send_modify(|policy| {
            policy.mode = crate::visibility::Visibility::Off;
            policy.contacts = None;
            policy.revision += 1;
        });
        for route in ["/Discover", "/Ask"] {
            let (mut client, task) = connect(address, None).await;
            assert_eq!(
                post(&mut client, route, None).await,
                hyper::StatusCode::FORBIDDEN
            );
            drop(client);
            task.abort();
            let _ = task.await;
        }
        cancel.cancel();
        server.await.unwrap().unwrap();

        // Past watch updates must not decline new manual offers immediately;
        // a subsequent mode change must invalidate an offer still awaiting approval.
        controller.send_modify(|policy| {
            policy.mode = crate::visibility::Visibility::Everyone;
            policy.revision += 1;
        });
        let mut manual = receiver.clone();
        manual.auto_accept = false;
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let server = tokio::spawn({
            let manual = manual.clone();
            let cancel = cancel.clone();
            async move { manual.serve(listener, cancel).await }
        });
        for allow in [true, false] {
            let offer = tokio::spawn(async move {
                let (mut client, task) = connect(address, None).await;
                let status = post(&mut client, "/Ask", None).await;
                drop(client);
                task.abort();
                let _ = task.await;
                status
            });
            tokio::time::timeout(Duration::from_secs(3), async {
                while !manual
                    .transfers()
                    .await
                    .iter()
                    .any(|t| t.state == "pending")
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            if allow {
                assert!(manual.accept_next().await.unwrap().is_some());
            } else {
                controller.send_modify(|policy| {
                    policy.mode = crate::visibility::Visibility::Off;
                    policy.revision += 1;
                });
            }
            assert_eq!(
                offer.await.unwrap(),
                if allow {
                    hyper::StatusCode::OK
                } else {
                    hyper::StatusCode::FORBIDDEN
                }
            );
        }
        drop(controller);
        cancel.cancel();
        server.await.unwrap().unwrap();
        assert!(!dir.path().join("output").exists()); // Metadata only: no file/link transfer.
    }
}
