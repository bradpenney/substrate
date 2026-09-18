//! Deploy the posture check to every hypervisor (ADR-196).
//!
//! posture-check is the substrate binary asserting substrate's invariants, so
//! its units ship with the release, the way `deploy-updates` ships the
//! nightly-update machinery: one file plan per host, staged unprivileged,
//! unpacked and enabled under a single sudo. Until ADR-196 the units lived in
//! `~/homelab/systemd/` and ran on one hypervisor — the weaker failure domain
//! (ADR-174) — so losing that host lost the monitor and the page with it.
//!
//! WHAT EACH HOST RECEIVES
//! - `/etc/substrate/site.yml` + `versions.yml`: the check reads its
//!   configuration from there (`--repo /etc/substrate`) and needs no
//!   repository checkout. site.yml is 0600 owned by the admin user: it holds
//!   addresses (ADR-012) and the service runs as that user.
//! - the four units, with the admin user, the kubeconfig context and this
//!   host's timer slot substituted in.
//! - `/etc/substrate/publish-status.env.example` with the account and
//!   namespace ids filled in. The installer copies it to
//!   `publish-status.env` ONLY if that file is absent — the token in there was
//!   typed by a human and is never overwritten by a deploy.
//!
//! The timer is enabled only where the scoped kubeconfig context exists for
//! the admin user. Enabling it blind on a host with no identity would page
//! "8 invariants broken" every morning for a tooling gap, which is the false
//! alarm the whole check is designed not to raise.

use crate::config::SiteConfig;
use crate::exec::Host;
use crate::updates::{PlannedFile, apply};
use anyhow::{Context, Result, bail};
use std::path::Path;

/// First slot, then every further hypervisor 30 minutes later, in name
/// order. After the 03:17 etcd snapshot and the 03:00 backup, so a failure
/// in either is already visible when this reports.
pub const FIRST_SLOT: (u32, u32) = (7, 30);
pub const SLOT_MINUTES: u32 = 30;

const UNITS: &[&str] = &[
    "posture-check.service",
    "posture-check.timer",
    "posture-check-notify.service",
    "publish-status.service",
];

/// `HH:MM` for the n-th hypervisor (0-based, by name).
pub fn slot(index: usize) -> String {
    let minutes = FIRST_SLOT.0 * 60 + FIRST_SLOT.1 + SLOT_MINUTES * index as u32;
    format!("{:02}:{:02}", (minutes / 60) % 24, minutes % 60)
}

/// Substitute the placeholders a unit template carries. Every placeholder
/// must be consumed: a `__NAME__` left in an installed unit is a unit that
/// runs as nobody, at no time.
pub fn render_unit(
    template: &str,
    admin_user: &str,
    context: &str,
    on_calendar: &str,
) -> Result<String> {
    let out = template
        .replace("__ADMIN_USER__", admin_user)
        .replace("__POSTURE_CONTEXT__", context)
        .replace("__ON_CALENDAR__", on_calendar);
    if let Some(pos) = out.find("__") {
        let tail: String = out[pos..].chars().take(30).collect();
        bail!("unit template still has a placeholder after rendering: {tail:?}");
    }
    Ok(out)
}

/// The env-file template: ids from site.yml, the token left blank.
pub fn env_template(cfg: &SiteConfig) -> Result<String> {
    let account = cfg
        .posture
        .status_account_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .context("site.yml: posture.status_account_id is not set (the Cloudflare account that owns the KV namespace)")?;
    let ns = cfg
        .posture
        .status_kv_namespace_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .context("site.yml: posture.status_kv_namespace_id is not set")?;
    Ok(format!(
        "# /etc/substrate/publish-status.env -- root:root 0600. Never in git.\n\
         # Installed from this template by `substrate deploy-posture` ONLY when\n\
         # absent; the token below is typed by a human, once, and survives deploys.\n\
         # Scope: Workers KV Storage:Edit on this one namespace, nothing else.\n\
         CLOUDFLARE_ACCOUNT_ID={account}\n\
         CLOUDFLARE_KV_NAMESPACE_ID={ns}\n\
         CLOUDFLARE_KV_TOKEN=\n"
    ))
}

/// The file plan for one hypervisor. `index` is its position among the
/// hypervisors by name, which decides its timer slot.
pub fn plan(repo: &Path, cfg: &SiteConfig, index: usize) -> Result<Vec<PlannedFile>> {
    // Unit templates come from the release payload (ADR-200); `repo` supplies
    // the two configuration files and nothing else.
    let read = |p: &str| -> Result<Vec<u8>> { Ok(crate::payload::bytes(p)?.to_vec()) };
    let site_path = crate::site_file(repo);
    let mut files = vec![
        PlannedFile {
            data: std::fs::read(&site_path)
                .with_context(|| format!("reading {}", site_path.display()))?,
            remote: "etc/substrate/site.yml".into(),
            mode: 0o600,
            owner: Some(cfg.admin_user.clone()),
        },
        PlannedFile {
            data: read("versions.yml")?,
            remote: "etc/substrate/versions.yml".into(),
            mode: 0o644,
            owner: None,
        },
        PlannedFile {
            data: env_template(cfg)?.into_bytes(),
            remote: "etc/substrate/publish-status.env.example".into(),
            mode: 0o600,
            owner: None,
        },
    ];
    let on_calendar = slot(index);
    for unit in UNITS {
        let template = String::from_utf8(read(&format!("systemd/{unit}"))?)
            .with_context(|| format!("systemd/{unit} is not utf-8"))?;
        files.push(PlannedFile {
            data: render_unit(
                &template,
                &cfg.admin_user,
                &cfg.posture.context,
                &on_calendar,
            )?
            .into_bytes(),
            remote: format!("etc/systemd/system/{unit}"),
            mode: 0o644,
            owner: None,
        });
    }
    Ok(files)
}

/// Everything privileged, once. Enables the timer only where the admin user
/// can already reach the cluster as the scoped context.
pub fn installer(cfg: &SiteConfig) -> String {
    let admin = &cfg.admin_user;
    let ctx = &cfg.posture.context;
    format!(
        r#"#!/bin/bash
# Generated by substrate deploy-posture (ADR-196). Everything privileged
# happens here, once.
set -euo pipefail
umask 022
HERE="$(cd "$(dirname "$0")" && pwd)"

install -d -m 0755 /etc/substrate
install -d -m 0755 -o {admin} -g {admin} /var/lib/substrate
tar -xzpf "$HERE/payload.tar.gz" -C /

# The token file is created once and never overwritten: a deploy must not
# blank a token a human typed in.
if [ ! -e /etc/substrate/publish-status.env ]; then
    install -m 0600 -o root -g root /etc/substrate/publish-status.env.example /etc/substrate/publish-status.env
    echo "  publish-status.env: CREATED from template -- add CLOUDFLARE_KV_TOKEN before the next run"
else
    # Kept, but its mode is not negotiable: a token file that arrived by hand
    # arrived 644 once (server2, 2026-09-15) and was readable by every local
    # user. Content is the human's; permissions are the deploy's.
    chown root:root /etc/substrate/publish-status.env
    chmod 0600 /etc/substrate/publish-status.env
    echo "  publish-status.env: kept, mode enforced ($(stat -c '%a %U' /etc/substrate/publish-status.env))"
fi
if ! grep -q '^CLOUDFLARE_KV_TOKEN=.\+' /etc/substrate/publish-status.env; then
    echo "  WARNING: CLOUDFLARE_KV_TOKEN is empty -- publish-status will fail (and be a finding) until it is set"
fi

systemctl daemon-reload

# Enable the timer only where the scoped identity exists. A host with no
# kubeconfig for the context would page "8 invariants broken" every morning
# for a tooling gap, which is the false alarm this check exists not to raise.
if sudo -u {admin} -H env PATH=/usr/local/bin:/usr/bin:/bin kubectl --context {ctx} auth whoami >/dev/null 2>&1; then
    systemctl enable --now posture-check.timer >/dev/null
    echo "  posture-check.timer: enabled ($(systemctl show -p NextElapseUSecRealtime --value posture-check.timer))"
else
    systemctl disable --now posture-check.timer >/dev/null 2>&1 || true
    echo "  posture-check.timer: NOT enabled -- {admin} has no working kubeconfig context '{ctx}' on this host"
    echo "    mint one here: substrate client-cert {ctx}   (needs the break-glass context on this host), then re-run deploy-posture"
fi
echo "  OnSuccess:       $(systemctl show -p OnSuccess --value posture-check.service)"
echo "  OnFailure:       $(systemctl show -p OnFailure --value posture-check.service)"
echo "  notifier:        $(test -x /usr/local/bin/homelab-notify.sh && echo present || echo 'ABSENT - run deploy-updates first')"
"#
    )
}

/// Deploy to every hypervisor, in name order (which is also slot order).
pub fn deploy_all(repo: &Path, cfg: &SiteConfig, dry_run: bool) -> Result<()> {
    let hosts: Vec<Host> = cfg
        .hypervisors
        .iter()
        .map(|(n, hv)| Host::from_config(n, hv))
        .collect();
    for (index, host) in hosts.iter().enumerate() {
        println!("=== {} (timer slot {}) ===", host.name, slot(index));
        let files = plan(repo, cfg, index)?;
        if dry_run {
            println!(
                "[{}] DRY RUN — would install {} file(s):",
                host.name,
                files.len()
            );
            for f in &files {
                println!(
                    "[{}]   /{}  ({:>4o}, {}, {} bytes)",
                    host.name,
                    f.remote,
                    f.mode,
                    f.owner.as_deref().unwrap_or("root"),
                    f.data.len()
                );
            }
            println!(
                "[{}] DRY RUN — would then run the installer under one sudo (timer enabled only if `{}` has context `{}`)",
                host.name, cfg.admin_user, cfg.posture.context
            );
            continue;
        }
        apply(host, &files, &installer(cfg))?;
        println!("[{}] deployed", host.name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_thirty_minutes_apart_in_name_order() {
        assert_eq!(slot(0), "07:30");
        assert_eq!(slot(1), "08:00");
        assert_eq!(slot(2), "08:30");
    }

    #[test]
    fn a_rendered_unit_carries_no_placeholder() {
        let out = render_unit(
            "User=__ADMIN_USER__\nEnvironment=POSTURE_CONTEXT=__POSTURE_CONTEXT__\nOnCalendar=*-*-* __ON_CALENDAR__:00\n",
            "operator",
            "scoped",
            "08:00",
        )
        .unwrap();
        assert_eq!(
            out,
            "User=operator\nEnvironment=POSTURE_CONTEXT=scoped\nOnCalendar=*-*-* 08:00:00\n"
        );
    }

    #[test]
    fn a_placeholder_the_renderer_does_not_know_is_refused() {
        let err = render_unit("User=__ADMIN_USER__\nX=__NOPE__\n", "u", "c", "07:30")
            .unwrap_err()
            .to_string();
        assert!(err.contains("__NOPE__"), "{err}");
    }

    #[test]
    fn every_shipped_unit_template_renders_clean() {
        for unit in UNITS {
            let t = crate::payload::text(&format!("systemd/{unit}")).unwrap();
            let out = render_unit(t, "operator", "scoped", "07:30").unwrap();
            assert!(
                !out.contains("/home/"),
                "{unit} depends on a home directory"
            );
            assert!(
                !out.contains("notes/"),
                "{unit} depends on a repository checkout"
            );
        }
    }

    #[test]
    fn the_service_reads_its_config_from_etc_and_records_the_run() {
        let t = crate::payload::text("systemd/posture-check.service").unwrap();
        let out = render_unit(t, "operator", "scoped", "07:30").unwrap();
        assert!(out.contains("--repo /etc/substrate"));
        assert!(out.contains("--record /var/lib/substrate/posture.json"));
        assert!(out.contains("OnSuccess=publish-status.service"));
        assert!(out.contains("OnFailure=posture-check-notify.service publish-status.service"));
        assert!(out.contains("User=operator"));
        assert!(out.contains("POSTURE_CONTEXT=scoped"));
    }
}
