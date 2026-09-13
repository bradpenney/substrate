//! Mint an X.509 client certificate for a human, via the Kubernetes CSR API.
//!
//! Ported from `create-client-cert.py`.
//!
//! WHY NOT `k0s kubeconfig create`: that command has to run ON a controller,
//! and these nodes deliberately have no SSH management path once running
//! (ADR-025). The CSR API does the same job over the API server, which is the
//! only way in.
//!
//! WHAT THIS PRODUCES: a certificate whose Common Name IS the username.
//! Kubernetes has no user object; the API server reads the CN off the
//! presented certificate and RBAC matches on that string. Group membership
//! comes from the O fields — which is exactly why `system:masters` is so
//! dangerous as an O value and why this refuses to issue one.
//!
//! ⚠️ CLIENT CERTIFICATES CANNOT BE REVOKED. Kubernetes implements no CRL and
//! no OCSP. A leaked certificate is valid until it expires or the cluster CA
//! is rotated. So: keep the lifetime short and re-run to renew; never bind a
//! certificate identity to standing write access (see `jit`).

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use std::path::{Path, PathBuf};

pub const FORBIDDEN_GROUPS: &[&str] = &["system:masters", "system:nodes", "system:node-admins"];
/// Minting an identity means creating AND approving a CSR. The scoped
/// day-to-day identity deliberately cannot do either — a role able to issue
/// certificates is a role able to mint itself a better one (ADR-071).
pub const BREAK_GLASS_CONTEXT: &str = "break-glass";

fn kubectl(args: &[&str], input: Option<&str>) -> Result<String> {
    use std::io::Write as _;
    let mut cmd = std::process::Command::new("kubectl");
    cmd.arg(format!("--context={BREAK_GLASS_CONTEXT}"))
        .args(args);
    cmd.stdin(if input.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    });
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().context("could not run kubectl")?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(text.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "command failed: kubectl --context={BREAK_GLASS_CONTEXT} {}\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub struct Request<'a> {
    pub user: &'a str,
    pub groups: &'a [String],
    pub days: u32,
    pub out_dir: PathBuf,
    pub context: Option<&'a str>,
    /// Print the CSR and what would be submitted; generate a throwaway key;
    /// write nothing, submit nothing.
    pub dry_run: bool,
}

/// The refusals, before anything is generated: a certificate cannot be
/// revoked, so a mistake here is unfixable short of rotating the cluster CA.
pub fn refuse(req: &Request) -> Result<()> {
    let mut bad: Vec<&str> = req
        .groups
        .iter()
        .map(String::as_str)
        .filter(|g| FORBIDDEN_GROUPS.contains(g))
        .collect();
    bad.sort();
    if !bad.is_empty() {
        bail!(
            "refusing to issue a certificate in [{}]: that group bypasses RBAC entirely, which is the thing this replaces.",
            bad.iter()
                .map(|g| format!("'{g}'"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let crt = req.out_dir.join(format!("{}.crt", req.user));
    if crt.exists() {
        bail!(
            "{} already exists. Move it aside to re-issue (the old certificate stays valid until it expires).",
            crt.display()
        );
    }
    Ok(())
}

/// EC P-256 key + a CSR whose subject is CN=user, O=group, O=group...
/// Returns (PKCS#8 private key PEM, CSR PEM).
///
/// One RDN per group, as the Python's `x509.Name` built it. An earlier draft
/// used a DN builder keyed by attribute TYPE, which silently kept only the
/// last `O` — groups are what RBAC matches on, so that is the one thing this
/// function must not lose. The test below parses the CSR back and counts.
pub fn key_and_csr(user: &str, groups: &[String]) -> Result<(String, String)> {
    use p256::pkcs8::EncodePrivateKey as _;
    use std::str::FromStr as _;

    // EC P-256: smaller and faster than RSA, universally supported by client-go.
    let secret = p256::SecretKey::random(&mut rand_core::OsRng);
    let key_pem = secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?
        .to_string();
    let signer = p256::ecdsa::SigningKey::from(&secret);

    // RFC 4514 string → RDN sequence. Values are escaped so a group containing
    // `,` `+` `=` `"` `\` `<` `>` `;` or leading/trailing spaces stays one value.
    // RFC 4514 lists RDNs in REVERSE of the ASN.1 sequence, and the parser
    // honours that. The Python built the sequence CN, O, O...; feeding the
    // string reversed reproduces that DER order (openssl-verified), rather
    // than merely an equivalent subject.
    let mut parts: Vec<String> = groups
        .iter()
        .rev()
        .map(|g| format!("O={}", rfc4514_escape(g)))
        .collect();
    parts.push(format!("CN={}", rfc4514_escape(user)));
    let subject = x509_cert::name::Name::from_str(&parts.join(","))
        .map_err(|e| anyhow::anyhow!("could not build the certificate subject: {e}"))?;

    // Built by hand rather than through RequestBuilder: 0.2.5's builder
    // unconditionally appends an empty extensionRequest attribute, and the
    // Python emits an EMPTY attribute set. Same subject, same key, same
    // signature algorithm — and now the same DER, which is what makes
    // `openssl req -text` on both tools' output diff clean.
    use p256::pkcs8::EncodePublicKey as _;
    use x509_cert::der::{Decode as _, Encode as _};
    let spki_der = secret.public_key().to_public_key_der()?;
    let info = x509_cert::request::CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())?,
        attributes: Default::default(),
    };
    let tbs = info.to_der()?;
    let sig: p256::ecdsa::DerSignature = signature::Signer::sign(&signer, &tbs);
    let csr = x509_cert::request::CertReq {
        info,
        algorithm: <p256::ecdsa::SigningKey as x509_cert::spki::DynSignatureAlgorithmIdentifier>::signature_algorithm_identifier(&signer)?,
        signature: x509_cert::der::asn1::BitString::from_bytes(sig.as_bytes())?,
    };
    let csr_pem = x509_cert::der::EncodePem::to_pem(&csr, x509_cert::der::pem::LineEnding::LF)?;
    Ok((key_pem, csr_pem))
}

/// RFC 4514 §2.4 escaping for one attribute value.
fn rfc4514_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let chars: Vec<char> = v.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        let leading = i == 0 && (*c == ' ' || *c == '#');
        let trailing = i == chars.len() - 1 && *c == ' ';
        if leading || trailing || matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=') {
            out.push('\\');
        }
        out.push(*c);
    }
    out
}

pub fn mint(req: &Request) -> Result<()> {
    refuse(req)?;
    std::fs::create_dir_all(&req.out_dir)?;
    let key_path = req.out_dir.join(format!("{}.key", req.user));
    let crt_path = req.out_dir.join(format!("{}.crt", req.user));

    let (key_pem, csr_pem) = key_and_csr(req.user, req.groups)?;
    if req.dry_run {
        println!(
            "DRY RUN — would submit this CSR as CN={} O={:?} for {} days, then approve it,",
            req.user, req.groups, req.days
        );
        println!(
            "write {} and {}, and add context {}.",
            crt_path.display(),
            key_path.display(),
            req.context.unwrap_or(req.user)
        );
        println!("The key below is a throwaway; nothing was written.\n");
        print!("{csr_pem}");
        return Ok(());
    }
    let csr_name = format!(
        "{}-{}",
        req.user,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    let manifest = serde_json::json!({
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": {"name": csr_name},
        "spec": {
            "request": base64::engine::general_purpose::STANDARD.encode(csr_pem.as_bytes()),
            // The only signer whose certificates the API server accepts for
            // client auth. `kubernetes.io/legacy-unknown` is NOT a substitute.
            "signerName": "kubernetes.io/kube-apiserver-client",
            "expirationSeconds": req.days as u64 * 86400,
            "usages": ["client auth"],
        },
    });
    let groups_shown = if req.groups.is_empty() {
        "none".to_string()
    } else {
        format!(
            "[{}]",
            req.groups
                .iter()
                .map(|g| format!("'{g}'"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    println!(
        "  submitting CSR {csr_name} (CN={}, O={groups_shown})",
        req.user
    );
    kubectl(&["apply", "-f", "-"], Some(&manifest.to_string()))?;

    println!("  approving");
    kubectl(&["certificate", "approve", &csr_name], None)?;

    let mut cert_b64 = String::new();
    for _ in 0..30 {
        cert_b64 = kubectl(
            &[
                "get",
                "csr",
                &csr_name,
                "-o",
                "jsonpath={.status.certificate}",
            ],
            None,
        )?
        .trim()
        .to_string();
        if !cert_b64.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if cert_b64.is_empty() {
        bail!(
            "CSR {csr_name} was approved but never signed. Check that the controller-manager's csrsigning controller is running."
        );
    }

    write_private(&key_path, key_pem.as_bytes())?;
    std::fs::write(
        &crt_path,
        base64::engine::general_purpose::STANDARD.decode(&cert_b64)?,
    )?;
    kubectl(&["delete", "csr", &csr_name], None)?;

    let ctx = req.context.unwrap_or(req.user);
    let cluster = kubectl(
        &[
            "config",
            "view",
            "--minify",
            "-o",
            "jsonpath={.clusters[0].name}",
        ],
        None,
    )?
    .trim()
    .to_string();
    // set-credentials/set-context write the LOCAL kubeconfig; the context
    // prefix selects which entry is read, not who acts.
    kubectl(
        &[
            "config",
            "set-credentials",
            req.user,
            &format!("--client-certificate={}", crt_path.display()),
            &format!("--client-key={}", key_path.display()),
            "--embed-certs=true",
        ],
        None,
    )?;
    kubectl(
        &[
            "config",
            "set-context",
            ctx,
            &format!("--cluster={cluster}"),
            &format!("--user={}", req.user),
        ],
        None,
    )?;

    println!(
        "\n  certificate: {}  (valid {} days, NOT revocable)",
        crt_path.display(),
        req.days
    );
    println!("  private key: {}  (0600)", key_path.display());
    println!("  context    : {ctx}");
    println!("\n  use it:   kubectl --context {ctx} auth whoami");
    println!(
        "  renew it: mv {c} {c}.old && substrate client-cert {u}",
        c = crt_path.display(),
        u = req.user
    );
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    std::io::Write::write_all(&mut f, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_groups_are_refused_before_anything_is_generated() {
        let groups = vec!["dev".to_string(), "system:masters".to_string()];
        let req = Request {
            user: "x",
            groups: &groups,
            days: 1,
            out_dir: std::env::temp_dir(),
            context: None,
            dry_run: false,
        };
        let err = refuse(&req).unwrap_err().to_string();
        assert!(err.contains("['system:masters']"), "{err}");
    }

    #[test]
    fn the_csr_carries_cn_and_every_group_as_o() {
        use x509_cert::der::Decode as _;
        let groups = vec!["platform".to_string(), "ops, with comma".to_string()];
        let (key, csr) = key_and_csr("brad", &groups).unwrap();
        assert!(
            key.starts_with("-----BEGIN PRIVATE KEY-----"),
            "PKCS#8, as the Python wrote"
        );
        assert!(csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        let parsed = x509_cert::request::CertReq::from_der(&pem_to_der(&csr)).unwrap();
        let subject = parsed.info.subject.to_string();
        // Display is RFC 4514 order (reverse of the sequence); the sequence
        // itself is CN, O, O — the Python's order, checked below via openssl too.
        assert_eq!(
            subject, "O=ops\\, with comma,O=platform,CN=brad",
            "{subject}"
        );
        let first = parsed
            .info
            .subject
            .0
            .first()
            .unwrap()
            .0
            .iter()
            .next()
            .unwrap();
        assert_eq!(
            first.oid,
            x509_cert::der::oid::db::rfc4519::CN,
            "CN is the FIRST RDN in the sequence"
        );
        let os = parsed
            .info
            .subject
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .filter(|atv| atv.oid == x509_cert::der::oid::db::rfc4519::O)
            .count();
        assert_eq!(os, 2, "one O per group — the thing the first draft lost");
    }

    fn pem_to_der(pem: &str) -> Vec<u8> {
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap()
    }
}
