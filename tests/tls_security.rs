use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use std::{path::Path, sync::Arc, time::Duration};

fn certificates(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem)
        .map(|cert| cert.unwrap())
        .collect()
}

fn root_store(pem: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for cert in certificates(pem) {
        roots.add(cert).unwrap();
    }
    roots
}

#[test]
fn compromised_intermediates_are_rejected_even_with_explicitly_trusted_issuers() {
    let roots = root_store(include_bytes!("data/emudhra/roots.pem"));
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()
    .unwrap();
    let mut checked = 0;
    for entry in
        std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/emudhra")).unwrap()
    {
        let path = entry.unwrap().path();
        let filename = path.file_name().unwrap().to_str().unwrap();
        let Some(hostname) = filename.strip_suffix(".we-have-a-problem.com.pem") else {
            continue;
        };
        let hostname = ServerName::try_from(format!("{hostname}.we-have-a-problem.com")).unwrap();
        let chain = certificates(&std::fs::read(&path).unwrap());
        let error = verifier
            .verify_server_cert(
                &chain[0],
                &chain[1..],
                &hostname,
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(1792713600)),
            )
            .unwrap_err();
        assert!(
            format!("{error:?}").contains("CertDistrusted"),
            "{filename}: {error:?}"
        );
        checked += 1;
    }
    assert_eq!(checked, 12);
}

#[test]
fn bundled_root_stores_exclude_affected_root_keys() {
    let affected = root_store(include_bytes!("data/emudhra/roots.pem"));
    let mut bundled = RootCertStore::empty();
    for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        bundled.add(cert.clone()).unwrap();
    }
    for roots in [webpki_roots::TLS_SERVER_ROOTS, bundled.roots.as_slice()] {
        assert!(roots.len() > 100);
        for root in &affected.roots {
            assert!(
                !roots
                    .iter()
                    .any(|candidate| candidate.subject_public_key_info
                        == root.subject_public_key_info)
            );
        }
    }
}

#[test]
fn legitimate_chain_is_accepted_and_hostname_validation_is_enforced() {
    let roots = root_store(include_bytes!("data/emudhra/control-root.pem"));
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()
    .unwrap();
    let chain = certificates(include_bytes!("data/emudhra/control-leaf.pem"));
    let now = UnixTime::since_unix_epoch(Duration::from_secs(1792713600));
    verifier
        .verify_server_cert(
            &chain[0],
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            now,
        )
        .unwrap();
    assert!(
        verifier
            .verify_server_cert(
                &chain[0],
                &[],
                &ServerName::try_from("wrong.example").unwrap(),
                &[],
                now
            )
            .is_err()
    );
}
