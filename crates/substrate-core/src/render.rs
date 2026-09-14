//! Build the Kairos cloud-config for one VM.
//!
//! A faithful translation of `provision.py`'s `render_cloud_config`, asserted
//! byte-for-byte against `tests/golden/*.yaml`. Every Kairos trap the Python
//! collected is reproduced here WITH its comment, because ADR-088's first
//! requirement of the port is that the encoded knowledge survives it: 94 ADRs
//! and 35 logged bugs are welded to specific lines, and a port that drops the
//! comments rediscovers all of it the hard way.
//!
//! WHY push_str AND RAW STRINGS RATHER THAN ONE BIG `format!`
//! `format!` treats `{` and `}` as markup, and this document contains literal
//! braces (`- identity: {}`). One missed escape is a silently malformed
//! cloud-config, which is the exact failure class this file is full of
//! warnings about. Raw strings pushed onto a buffer cannot have that bug.
//!
//! WHY NOT A TEMPLATE ENGINE
//! `minijinja` would let this reuse Ansible's Jinja template — and two
//! implementations sharing a template are one implementation (ADR-093).

use crate::config::SiteConfig;
use base64::Engine as _;
use std::collections::BTreeMap;

/// The label that names a node's hypervisor — the cluster's only statement of
/// its two failure domains.
///
/// `kubernetes.io/hostname` is the sole topology label a stock k0s node
/// carries, and spreading on it does NOT spread across machines: s2-vm1 and
/// s2-vm2 are different hostnames on the SAME hypervisor, which is exactly the
/// domain being guarded.
///
/// Kubelet honours `--labels` at node REGISTRATION ONLY, so this reproduces on
/// a rebuild but never on a reboot; a node that joined before this existed
/// needs a one-time `kubectl label node`.
///
/// A custom domain on purpose: NodeRestriction refuses to let a kubelet
/// self-assign `*.kubernetes.io/` labels, so `topology.kubernetes.io/zone`
/// would leave the node silently unlabelled.
///
/// Kept as a constant in one place per implementation because the pending
/// platform rename has to change it in lockstep with substrate_config and with
/// every already-labelled node.
pub const HYPERVISOR_LABEL: &str = "invariant-platform.io/hypervisor";

/// One k0s node, as the renderer needs it.
///
/// Distinct from `config::NodeConfig`: that is what `site.yml` declares, this
/// is what a render call takes. Keeping them separate is what lets the CLI
/// render a hypothetical node that is not in the fleet, which every golden is.
#[derive(Debug, Clone)]
pub struct Vm {
    pub name: String,
    pub static_ip: String,
    /// Which hypervisor carries this VM — the node's FAILURE DOMAIN.
    ///
    /// Rendered into a kubelet `--labels` argument so a rebuilt node declares
    /// which physical machine it sits on without anyone remembering to run
    /// kubectl. See `HYPERVISOR_LABEL`.
    pub hypervisor: String,
    pub bootstrap: bool,
    pub memory_mib: Option<u32>,
    pub vcpu: Option<u32>,
    pub storage_disk_gb: Option<u32>,
}

/// Render the cloud-config for `vm`.
///
/// `join_token` is `None` for the bootstrap controller, which comes up alone.
/// `ssh_key` is passed in rather than read from the environment here: the key
/// lands in the output, and a renderer that reaches for ambient state is not a
/// pure function of its inputs — which is the property the goldens rely on.
pub fn cloud_config(cfg: &SiteConfig, vm: &Vm, join_token: Option<&str>, ssh_key: &str) -> String {
    let mut args: Vec<String> = cfg.k0s.args.clone();

    // --- failure-domain label (ADR-139 follow-up) ---
    //
    // Pushed HERE, after the configured args and before the --config and
    // --token-file pushes below, because the Python and Jinja renderers emit it
    // in exactly that position and all three are compared against the same
    // goldens. Moving this line is a silent divergence.
    args.push(format!("--labels={HYPERVISOR_LABEL}={}", vm.hypervisor));

    let storage_gb = vm.storage_disk_gb.unwrap_or(cfg.defaults.storage_disk_gb);

    // --- API server hardening (ADR-066) ---
    //
    // Two controls that both live on kube-apiserver flags, and both fail
    // SILENTLY when misconfigured: a bad encryption config means Secrets keep
    // being written in plaintext, and a bad audit path means no log appears.
    // Neither surfaces as an error in `kubectl`.
    //
    // BTreeMap, not HashMap: the flags are rendered in key order, and a
    // nondeterministic map would make the output differ run to run — every
    // golden would fail intermittently and the cause would look like a
    // renderer bug rather than an iteration-order bug.
    let mut api_extra_args: BTreeMap<&str, String> = BTreeMap::new();
    let mut hardening_files = String::new();

    let enc_key = cfg
        .api_hardening
        .secrets_encryption_key
        .as_deref()
        .unwrap_or("")
        .trim();
    if !enc_key.is_empty() {
        api_extra_args.insert(
            "encryption-provider-config",
            "/etc/k0s/encryption.yaml".into(),
        );
        // `secretbox` (XSalsa20-Poly1305) rather than aescbc, whose CBC padding
        // makes it the weaker choice, or aesgcm, which requires rotation every
        // ~200k writes to stay safe with a static key.
        //
        // `identity` LAST is what lets the API server still read Secrets that
        // were written before encryption existed. Putting it first would
        // silently disable encryption while looking configured.
        hardening_files.push_str(
            r#"        - path: /etc/k0s/encryption.yaml
          permissions: 0600
          content: |
            apiVersion: apiserver.config.k8s.io/v1
            kind: EncryptionConfiguration
            resources:
              - resources:
                  - secrets
                providers:
                  - secretbox:
                      keys:
                        - name: key1
                          secret: "#,
        );
        hardening_files.push_str(enc_key);
        hardening_files.push_str("\n                  - identity: {}\n");
    }

    let audit_path = cfg
        .api_hardening
        .audit_log_path
        .as_deref()
        .unwrap_or("")
        .trim();
    if !audit_path.is_empty() {
        api_extra_args.insert("audit-policy-file", "/etc/k0s/audit-policy.yaml".into());
        api_extra_args.insert("audit-log-path", audit_path.to_string());
        api_extra_args.insert(
            "audit-log-maxage",
            cfg.api_hardening
                .audit_log_maxage
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "30".to_string()),
        );
        // A FILE, rotated by the apiserver itself, never "-" (stdout): stdout
        // is the k0s supervisor's pipe, and the supervisor buffers what
        // journald does not drain — 11.9 GB of it on one node (bug-150).
        // maxage alone never rotates a file that is still being written.
        if audit_path != "-" {
            api_extra_args.insert("audit-log-maxsize", "100".into());
            api_extra_args.insert("audit-log-maxbackup", "5".into());
        }
        // Levels, from the top down. Order matters: the FIRST matching rule
        // wins, so the noise-suppression rules have to come before the
        // catch-all.
        hardening_files.push_str(
            r#"        - path: /etc/k0s/audit-policy.yaml
          permissions: 0644
          content: |
            apiVersion: audit.k8s.io/v1
            kind: Policy
            # Never log request or response BODIES for these: the body is the
            # secret. Metadata still records who touched what, and when.
            omitStages:
              - RequestReceived
            rules:
              - level: Metadata
                resources:
                  - group: ""
                    resources: ["secrets", "configmaps"]
                  - group: "authentication.k8s.io"
                    resources: ["tokenreviews"]
              # Anything that changes who can do what, in full. This is the
              # record that answers "how did they get that access".
              - level: RequestResponse
                resources:
                  - group: "rbac.authorization.k8s.io"
                    resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
                  - group: "certificates.k8s.io"
                    resources: ["certificatesigningrequests"]
              # Code execution inside the cluster.
              - level: RequestResponse
                resources:
                  - group: ""
                    resources: ["pods/exec", "pods/attach", "pods/portforward"]
              # Drop the constant read chatter from the control plane itself,
              # which would otherwise bury everything above it.
              - level: None
                users: ["system:kube-scheduler", "system:kube-controller-manager", "system:apiserver"]
                verbs: ["get", "list", "watch"]
              - level: None
                userGroups: ["system:nodes"]
                verbs: ["get", "list", "watch"]
              - level: None
                nonResourceURLs: ["/healthz*", "/readyz*", "/livez*", "/version", "/metrics"]
              # Leader-election leases are renewed every few seconds by every
              # controller in the cluster and say nothing about who did what.
              # Logged at RequestResponse they were most of a 40 MB / 10 min
              # audit stream that, piped through the k0s supervisor to a
              # journald that could not keep up, sat in the supervisor's memory
              # until the node OOMed (bug-150). Events are the other half.
              - level: None
                resources:
                  - group: "coordination.k8s.io"
                    resources: ["leases"]
                  - group: ""
                    resources: ["events"]
                  - group: "events.k8s.io"
                    resources: ["events"]
              # Everything that changes state.
              - level: RequestResponse
                verbs: ["create", "update", "patch", "delete", "deletecollection"]
              # Everything else: who, what, when -- but not the payload.
              - level: Metadata
"#,
        );
    }

    let mut extra_args_yaml = String::new();
    if !api_extra_args.is_empty() {
        extra_args_yaml.push_str("\n                extraArgs:");
        for (k, v) in &api_extra_args {
            extra_args_yaml.push_str(&format!("\n                  {k}: \"{v}\""));
        }
    }

    // --- control-plane load balancer (ADR-045) ---
    //
    // `externalAddress` does two load-bearing things: it puts the VIP into the
    // API server certificate's SANs (without which every client hitting the VIP
    // gets a TLS name mismatch), and it makes k0s hand out the VIP — not the
    // generating node's own address — in join tokens and in the konnectivity
    // agent DaemonSet.
    let mut k0s_config_yaml = String::new();
    if let Some(vip) = cfg.control_plane.vip.as_deref().filter(|v| !v.is_empty()) {
        args.push("--config /etc/k0s/k0s.yaml".to_string());
        // UNQUOTED octal permissions — `stages` wants a YAML integer here. The
        // opposite of `write_files`, which wants it quoted. Getting this
        // backwards is a silent no-op, not an error.
        k0s_config_yaml.push_str(
            r#"        - path: /etc/k0s/k0s.yaml
          permissions: 0644
          content: |
            apiVersion: k0s.k0sproject.io/v1beta1
            kind: ClusterConfig
            metadata:
              name: k0s
            spec:
              api:
                externalAddress: "#,
        );
        k0s_config_yaml.push_str(vip);
        k0s_config_yaml.push_str("\n                sans:\n                  - ");
        k0s_config_yaml.push_str(vip);
        k0s_config_yaml.push_str(&extra_args_yaml);
        // --- node resource reservation (ADR-064) ---
        //
        // Every node here is controller AND worker, so kube-apiserver, etcd,
        // the scheduler and the controller-manager all run as HOST PROCESSES.
        // The kubelet does not account for them, so without a reservation the
        // scheduler believes the whole machine is available for pods.
        //
        // Measured on a 3.9Gi node before this existed: 2333Mi node working
        // set against 482Mi of pods — 1850Mi of host processes, against 100Mi
        // reserved. The scheduler saw 3808Mi allocatable on a node with roughly
        // 1958Mi genuinely free. Filling that gap means an OOM, and on this
        // topology etcd competes for the last page: a scheduling decision
        // becomes a quorum event.
        //
        // These are SANE DEFAULTS, not tuned figures. Revisit once metrics are
        // collected and the real high-water mark across all five nodes is known.
        //
        // evictionHard gives the kubelet room to act before the kernel OOM
        // killer does, which picks its victim by score, not by importance.
        k0s_config_yaml.push_str(
            r#"
              # --- node resource reservation (ADR-064) ---
              #
              # Every node here is controller AND worker, so kube-apiserver,
              # etcd, the scheduler and the controller-manager all run as HOST
              # PROCESSES. The kubelet does not account for them, so without a
              # reservation the scheduler believes the whole machine is
              # available for pods.
              #
              # Measured on s2-vm3 (a 3.9Gi node) before this existed:
              #   node working set   2333Mi
              #   sum of pod working sets  482Mi
              #   -> 1850Mi of host processes, against 100Mi reserved.
              #
              # The scheduler saw 3808Mi of allocatable memory on a node with
              # roughly 1958Mi genuinely free. Filling that gap means an OOM,
              # and on this topology etcd is one of the processes competing for
              # the last page — a scheduling decision becomes a quorum event.
              #
              # 2048Mi total reservation, a little above the 1850Mi measured,
              # rounded rather than fitted. These are deliberately SANE
              # DEFAULTS, not tuned figures: revisit once metrics are being
              # collected and the real high-water mark across all five nodes is
              # known, rather than the single sample above.
              #
              # evictionHard gives the kubelet room to act before the kernel
              # OOM killer does, which picks its victim by score, not by
              # importance.
              workerProfiles:
                - name: homelab
                  values:
                    systemReserved:
                      cpu: 200m
                      memory: 768Mi
                    kubeReserved:
                      cpu: 300m
                      memory: 1280Mi
                    evictionHard:
                      memory.available: 300Mi
                      nodefs.available: 10%
"#,
        );
    }

    // --- dedicated Longhorn disk (ADR-050) ---
    //
    // Mounted at /usr/local/longhorn, NOT the upstream default
    // /var/lib/longhorn. On Kairos the rootfs is read-only ext2 and only
    // specific paths are bind-mounted from COS_PERSISTENT; /var/lib is not
    // writable, so the default path would either fail or land somewhere
    // ephemeral and lose every replica on reboot. /usr/local IS persistent.
    //
    // /etc/systemd is persistent too, which is why a .mount unit written here
    // survives reboots on an immutable OS.
    let mut storage_disk_yaml = String::new();
    let mut storage_prepare_yaml = String::new();
    if storage_gb > 0 {
        storage_prepare_yaml.push_str(
            r#"    - name: prepare the Longhorn data disk
      commands:
        - |
          set -e
          /usr/local/bin/prepare-longhorn-disk.sh
"#,
        );
        storage_disk_yaml.push_str(
            r#"        - path: /etc/systemd/system/usr-local-longhorn.mount
          permissions: 0644
          content: |
            [Unit]
            Description=Longhorn data disk
            After=local-fs.target
            [Mount]
            What=/dev/vdb
            Where=/usr/local/longhorn
            Type=ext4
            Options=defaults,noatime
            [Install]
            WantedBy=local-fs.target
        - path: /usr/local/bin/prepare-longhorn-disk.sh
          permissions: 0755
          content: |
            #!/bin/sh
            # Format ONCE. blkid succeeds only if a filesystem already exists,
            # so a reboot preserves data and a rebuild starts clean.
            set -e
            [ -b /dev/vdb ] || exit 0
            if ! blkid /dev/vdb >/dev/null 2>&1; then
                mkfs.ext4 -F -L longhorn /dev/vdb
            fi
            mkdir -p /usr/local/longhorn
            systemctl enable --now usr-local-longhorn.mount
"#,
        );
    }

    // The token is written via a `stages` entry, NOT cloud-init's `write_files`.
    // Load-bearing: Kairos copies the whole cloud-config to /oem/90_custom.yaml
    // on the PERSISTENT partition during install and re-runs its `stages` on
    // every boot. `write_files` is plain cloud-init syntax that Kairos honours
    // only in the live installer environment — a token written that way exists
    // during install and then silently vanishes, leaving the node unable to
    // join. Verified by mounting the installed image offline.
    //
    // UNQUOTED octal, matching the network file. In a `stages` block Kairos
    // wants a YAML integer (it stores 0644 as decimal 420). Quoting it makes
    // the file silently NOT get written, which on the network config manifests
    // as a node with no IP at all. This is the OPPOSITE of `write_files`, where
    // an unquoted value fails the install with
    // `strconv.ParseUint: parsing "384"`. Same-looking field, two parsers,
    // contradictory rules — hence both bugs.
    let mut token_file_yaml = String::new();
    if let Some(token) = join_token {
        args.push("--token-file /etc/k0s/join-token".to_string());
        token_file_yaml.push_str(
            "        - path: /etc/k0s/join-token\n          permissions: 0600\n          content: |\n            ",
        );
        token_file_yaml.push_str(token);
        token_file_yaml.push('\n');
    }

    // --- GitOps bootstrap (ADR-018) ---
    //
    // Two stacks under k0s's OWN manifest deployer (/var/lib/k0s/manifests),
    // which is how k0s installs CoreDNS, kube-router and konnectivity.
    //
    // SEPARATE DIRECTORIES ON PURPOSE: k0s treats each subdirectory as an
    // independent stack and retries it. The FluxInstance references a CRD that
    // does not exist until the operator has been applied, so one directory
    // would make a single apply fail as a unit.
    let flux = &cfg.flux;
    let registry = flux.oci_repository.split('/').next().unwrap_or("");
    let mut pull_secret_yaml = String::new();
    let mut sync_pull_secret = String::new();
    if let Some(token) = flux.ghcr_token.as_deref().filter(|t| !t.is_empty()) {
        // The ONE irreducible bootstrap credential (ADR-019): Flux needs it to
        // pull the private config artifact, before External Secrets exists.
        let user = flux.ghcr_username.as_deref().unwrap_or("");
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}"));
        // Assembled by hand to match Python's `json.dumps` separators — `", "`
        // and `": "` — rather than serde_json's compact form. Both are valid
        // dockerconfigjson and a node would not care, but the golden files are
        // the definition of a correct node and a PORT REPRODUCES RATHER THAN
        // REDEFINES. Regenerating a golden to make a new implementation pass is
        // the rubber-stamp failure ADR-093 exists to prevent.
        //
        // It also keeps three implementations agreeing: the Ansible path gets
        // this value pre-rendered by inventory.py, in Python, for the same
        // reason. Switching to compact JSON is a deliberate change to all three
        // plus a golden regeneration, not a detail of this file.
        //
        // The values still go through serde_json so quoting and escaping are
        // not hand-rolled; only the whitespace between them is.
        let registry_json = serde_json::to_string(registry).unwrap_or_default();
        let auth_json = serde_json::to_string(&auth).unwrap_or_default();
        let docker_cfg = format!("{{\"auths\": {{{registry_json}: {{\"auth\": {auth_json}}}}}}}");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&docker_cfg);
        // 16 spaces: pullSecret is a SIBLING of kind/url/ref/path under `sync:`.
        // At 12 it lands outside the sync block and the FluxInstance is
        // malformed — caught by check_render.py, on the private path only.
        sync_pull_secret.push_str("\n                pullSecret: ghcr-auth");
        pull_secret_yaml.push_str(
            r#"            ---
            apiVersion: v1
            kind: Secret
            metadata:
              name: ghcr-auth
              namespace: flux-system
            type: kubernetes.io/dockerconfigjson
            data:
              .dockerconfigjson: "#,
        );
        pull_secret_yaml.push_str(&b64);
        pull_secret_yaml.push('\n');
    }

    // --- External Secrets bootstrap credential (ADR-055) ---
    //
    // Rendered as a k0s manifest so it lands BEFORE anything needs it, on a
    // freshly rebuilt cluster, with no human step. This is the credential whose
    // absence made two rebuilds silently produce clusters that could not issue
    // certificates or take backups.
    //
    // The namespace is created here too: a Secret cannot be applied into a
    // namespace that does not exist, and k0s applies manifests in filename
    // order within a directory, not dependency order.
    let mut eso_yaml = String::new();
    let eso = &cfg.external_secrets;
    if let (Some(id), Some(secret)) = (
        eso.client_id.as_deref().filter(|s| !s.is_empty()),
        eso.client_secret.as_deref().filter(|s| !s.is_empty()),
    ) {
        eso_yaml.push_str(
            r#"        - path: /var/lib/k0s/manifests/external-secrets-bootstrap/creds.yaml
          permissions: 0600
          content: |
            apiVersion: v1
            kind: Namespace
            metadata:
              name: external-secrets
            ---
            apiVersion: v1
            kind: Secret
            metadata:
              name: infisical-credentials
              namespace: external-secrets
            type: Opaque
            stringData:
              clientId: "#,
        );
        eso_yaml.push_str(id);
        eso_yaml.push_str("\n              clientSecret: ");
        eso_yaml.push_str(secret);
        eso_yaml.push('\n');
    }

    let k0s_args_yaml = args
        .iter()
        .map(|a| format!("    - {a}"))
        .collect::<Vec<_>>()
        .join("\n");
    let dns_yaml = cfg
        .network
        .dns_servers
        .iter()
        .map(|d| format!("            DNS={d}"))
        .collect::<Vec<_>>()
        .join("\n");

    let mut out = String::with_capacity(16 * 1024);
    out.push_str("#cloud-config\nhostname: ");
    out.push_str(&vm.name);
    out.push_str("\nusers:\n- name: ");
    out.push_str(&cfg.admin_user);
    out.push_str("\n  groups:\n    - admin\n  ssh_authorized_keys:\n    - ");
    out.push_str(ssh_key);
    out.push_str(
        r#"
install:
  device: /dev/vda
  reboot: true
  auto: true
k0s:
  enabled: true
  args:
"#,
    );
    out.push_str(&k0s_args_yaml);
    out.push_str(
        r#"
stages:
  initramfs:
    - files:
        - path: /etc/systemd/network/10-static.network
          permissions: 0644
          content: |
            [Match]
            Name="#,
    );
    out.push_str(&cfg.network.primary_nic);
    out.push_str("\n            [Network]\n            Address=");
    out.push_str(&vm.static_ip);
    out.push_str("/24\n            Gateway=");
    out.push_str(&cfg.network.gateway);
    out.push('\n');
    out.push_str(&dns_yaml);
    out.push('\n');
    out.push_str(&k0s_config_yaml);
    out.push_str(&hardening_files);
    out.push_str(&storage_disk_yaml);
    out.push_str(&eso_yaml);
    out.push_str(&token_file_yaml);
    out.push_str(
        r#"        - path: /etc/ssh/sshd_config.d/99-hardening.conf
          permissions: 0644
          content: |
            # Key-only auth. Kairos's example cloud-config sets a guessable
            # password (`passwd: kairos`); this build sets no password at all,
            # and this makes password auth unusable regardless.
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            PermitRootLogin prohibit-password
        - path: /var/lib/k0s/manifests/flux-instance/instance.yaml
          permissions: 0644
          content: |
            ---
            apiVersion: v1
            kind: Namespace
            metadata:
              name: flux-system
"#,
    );
    out.push_str(&pull_secret_yaml);
    out.push_str(
        r#"            ---
            apiVersion: fluxcd.controlplane.io/v1
            kind: FluxInstance
            metadata:
              name: flux
              namespace: flux-system
            spec:
              distribution:
                version: "#,
    );
    out.push_str(flux.distribution_version.as_deref().unwrap_or(""));
    out.push_str(
        r#"
                registry: ghcr.io/fluxcd
              # EXPLICIT component set. Left unset, flux-operator installs its
              # default four, which includes helm-controller.
              #
              # helm-controller is deliberately absent. Nothing here uses Helm
              # at runtime — every component is vendored upstream YAML — so it
              # reconciled nothing (`helmreleases` = 0) while holding
              # cluster-admin through the cluster-reconciler-flux-system
              # binding. Dropping it removes a cluster-admin subject and a
              # running Deployment for no loss of function.
              #
              # notification-controller is kept: flux-operator writes FluxReport
              # through it. It is the next candidate if that stops being true —
              # Alerts, Providers and Receivers are all currently zero.
              components:
                - source-controller
                - kustomize-controller
                - notification-controller
              # flux-operator OWNS the flux-system Namespace and sets only
              # `warn`, never `enforce` -- so after ADR-063 removed our
              # duplicate declaration, the namespace was left with no Pod
              # Security enforcement at all. This patch is how the owner is
              # asked to set it, rather than fighting it for the object.
              kustomize:
                patches:
                  - target:
                      kind: Namespace
                      name: flux-system
                    patch: |
                      apiVersion: v1
                      kind: Namespace
                      metadata:
                        name: flux-system
                        labels:
                          pod-security.kubernetes.io/enforce: baseline
                          pod-security.kubernetes.io/enforce-version: latest
                  # Verify the config artifact's cosign signature before Flux
                  # will reconcile it (ADR-069). `spec.verify` belongs on the
                  # OCIRepository, which flux-operator generates from
                  # `spec.sync` -- and `sync` has no verify field, so it is
                  # patched in here.
                  #
                  # ⚠️ matchOIDCIdentity is the load-bearing part. `provider:
                  # cosign` ALONE accepts any valid Sigstore signature, including
                  # one an attacker produced with their own GitHub account.
                  # Pinning the issuer AND the subject is what ties the artifact
                  # to this repository's workflow on this branch.
                  #
                  # ⚠️ ORDERING ON A REBUILD: this makes Flux refuse an unsigned
                  # artifact. The publish workflow must be signing before a
                  # rebuild runs, or the new cluster will never reconcile
                  # anything and the cause will look like a registry problem.
                  - target:
                      kind: OCIRepository
                      name: flux-system
                    patch: |
                      apiVersion: source.toolkit.fluxcd.io/v1
                      kind: OCIRepository
                      metadata:
                        name: flux-system
                        namespace: flux-system
                      spec:
                        verify:
                          provider: cosign
                          matchOIDCIdentity:
                            - issuer: ""#,
    );
    out.push_str(&flux.cosign_issuer);
    out.push_str("\"\n                              subject: \"");
    out.push_str(flux.cosign_subject.as_deref().unwrap_or(""));
    out.push_str(
        r#""
              sync:
                kind: OCIRepository
                url: oci://"#,
    );
    out.push_str(&flux.oci_repository);
    out.push_str("\n                ref: ");
    out.push_str(&flux.oci_tag);
    out.push_str("\n                path: clusters/homelab");
    out.push_str(&sync_pull_secret);
    out.push_str("\n  network:\n");
    out.push_str(&storage_prepare_yaml);
    out.push_str(
        r#"    - name: fetch the pinned flux-operator manifest
      commands:
        - |
          set -e
          D=/var/lib/k0s/manifests/flux-operator
          # Guard: Kairos re-runs stages on EVERY boot, so without this each
          # reboot would re-download 97KB for no reason.
          [ -f "$D/install.yaml" ] && exit 0
          mkdir -p "$D"
          curl -fsSL -o /tmp/flux-operator.yaml "#,
    );
    out.push_str(flux.operator_url.as_deref().unwrap_or(""));
    out.push_str("\n          echo \"");
    out.push_str(flux.operator_sha256.as_deref().unwrap_or(""));
    out.push_str(
        r#"  /tmp/flux-operator.yaml" | sha256sum -c -
          mv /tmp/flux-operator.yaml "$D/install.yaml"
"#,
    );
    out
}
