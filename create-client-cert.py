#!/usr/bin/env python3
"""Mint an X.509 client certificate for a human, via the Kubernetes CSR API.

WHY NOT `k0s kubeconfig create`
That command has to run ON a controller, and these nodes deliberately have no
SSH management path once running (ADR-025). The CSR API does the same job over
the API server, which is the only way in.

WHAT THIS PRODUCES
A certificate whose Common Name IS the username. Kubernetes has no user object:
the API server reads the CN off the presented certificate and RBAC matches on
that string. Group membership, if any, comes from the O (Organization) fields --
which is exactly why `system:masters` is so dangerous as an O value and why this
script refuses to issue one.

⚠️ CLIENT CERTIFICATES CANNOT BE REVOKED. Kubernetes implements no CRL and no
OCSP. A leaked certificate is valid until it expires or the cluster CA is
rotated. Two consequences shape everything here:
  - keep the lifetime short (default 90 days) and re-run this to renew;
  - never bind a certificate identity to standing write access. Read-only is
    permanent, write is a separate expiring grant (see jit-admin.py).
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

FORBIDDEN_GROUPS = {"system:masters", "system:nodes", "system:node-admins"}

# Minting an identity means creating AND approving a CertificateSigningRequest.
# The scoped day-to-day identity deliberately cannot do either -- a role able to
# issue certificates is a role able to mint itself a better one. So this is one
# of the few operations that still reaches for the break-glass certificate, and
# naming the context here makes that explicit rather than implicit (ADR-071).
BREAK_GLASS_CONTEXT = "break-glass"


def sh(args: list[str], **kw) -> str:
    if args and args[0] == "kubectl":
        args = [args[0], f"--context={BREAK_GLASS_CONTEXT}"] + args[1:]
    r = subprocess.run(args, capture_output=True, text=True, **kw)
    if r.returncode:
        sys.exit(f"command failed: {' '.join(args)}\n{r.stderr.strip()}")
    return r.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("user", help="username; becomes the certificate CN")
    ap.add_argument("--groups", nargs="*", default=[],
                    help="O values. system:masters is refused.")
    ap.add_argument("--days", type=int, default=90,
                    help="certificate lifetime (default 90; it cannot be revoked)")
    ap.add_argument("--out-dir", default=str(Path.home() / ".kube" / "certs"))
    ap.add_argument("--context", default=None,
                    help="kubeconfig context to create (default: the username)")
    args = ap.parse_args()

    bad = FORBIDDEN_GROUPS.intersection(args.groups)
    if bad:
        sys.exit(f"refusing to issue a certificate in {sorted(bad)}: that group "
                 f"bypasses RBAC entirely, which is the thing this replaces.")

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    key_path = out / f"{args.user}.key"
    crt_path = out / f"{args.user}.crt"

    if crt_path.exists():
        sys.exit(f"{crt_path} already exists. Move it aside to re-issue "
                 f"(the old certificate stays valid until it expires).")

    # EC P-256: smaller and faster than RSA, universally supported by client-go.
    key = ec.generate_private_key(ec.SECP256R1())
    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, args.user)]
    name_attrs += [x509.NameAttribute(NameOID.ORGANIZATION_NAME, g) for g in args.groups]
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name(name_attrs))
           .sign(key, hashes.SHA256()))
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    csr_name = f"{args.user}-{int(time.time())}"
    manifest = {
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": {"name": csr_name},
        "spec": {
            "request": base64.b64encode(csr_pem).decode(),
            # The only signer whose certificates the API server accepts for
            # client auth. `kubernetes.io/legacy-unknown` is NOT a substitute:
            # it is not auto-signed and its certs are rejected.
            "signerName": "kubernetes.io/kube-apiserver-client",
            "expirationSeconds": args.days * 86400,
            "usages": ["client auth"],
        },
    }
    print(f"  submitting CSR {csr_name} (CN={args.user}, O={args.groups or 'none'})")
    sh(["kubectl", "apply", "-f", "-"], input=json.dumps(manifest))

    print("  approving")
    sh(["kubectl", "certificate", "approve", csr_name])

    cert_b64 = ""
    for _ in range(30):
        cert_b64 = sh(["kubectl", "get", "csr", csr_name,
                       "-o", "jsonpath={.status.certificate}"]).strip()
        if cert_b64:
            break
        time.sleep(1)
    if not cert_b64:
        sys.exit(f"CSR {csr_name} was approved but never signed. Check that the "
                 f"controller-manager's csrsigning controller is running.")

    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    key_path.chmod(0o600)
    crt_path.write_bytes(base64.b64decode(cert_b64))
    sh(["kubectl", "delete", "csr", csr_name])

    ctx = args.context or args.user
    cluster = sh(["kubectl", "config", "view", "--minify",
                  "-o", "jsonpath={.clusters[0].name}"]).strip()
    # NOTE: set-credentials/set-context below write to the LOCAL kubeconfig.
    # They are `kubectl config` operations, not API calls, so the break-glass
    # context prefix is harmless -- it selects which entry is read, not who acts.
    sh(["kubectl", "config", "set-credentials", args.user,
        f"--client-certificate={crt_path}", f"--client-key={key_path}", "--embed-certs=true"])
    sh(["kubectl", "config", "set-context", ctx,
        f"--cluster={cluster}", f"--user={args.user}"])

    print(f"\n  certificate: {crt_path}  (valid {args.days} days, NOT revocable)")
    print(f"  private key: {key_path}  (0600)")
    print(f"  context    : {ctx}")
    print(f"\n  use it:   kubectl --context {ctx} auth whoami")
    print(f"  renew it: mv {crt_path} {crt_path}.old && {sys.argv[0]} {args.user}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
