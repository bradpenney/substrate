//! Reading the CALM architecture model, and rendering it as diagrams.
//!
//! The CALM document is the SINGLE SOURCE OF TRUTH for this platform's
//! architecture. Diagrams are generated from it and are never edited directly —
//! that is the whole mechanism by which documentation cannot drift from the
//! architecture it claims to describe.
//!
//! Output is D2 rather than Mermaid, deliberately. Mermaid cannot nest
//! containers to arbitrary depth, has no real layout control, and produces
//! diagrams that read as generated. D2 has first-class containers (which map
//! exactly onto CALM's `deployed-in` and `composed-of`), orthogonal routing via
//! ELK, and enough styling control to produce something that looks authored.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Deserialize, Clone)]
pub struct Node {
    #[serde(rename = "unique-id")]
    pub unique_id: String,
    #[serde(rename = "node-type")]
    pub node_type: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub metadata: Vec<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    pub controls: BTreeMap<String, serde_json::Value>,
}

impl Node {
    /// The view this node belongs to, from `metadata[0].layer`.
    pub fn layer(&self) -> &str {
        self.metadata
            .first()
            .and_then(|m| m.get("layer"))
            .and_then(|v| v.as_str())
            .unwrap_or("unassigned")
    }
    pub fn detail(&self) -> Option<&str> {
        self.metadata
            .first()
            .and_then(|m| m.get("detail"))
            .and_then(|v| v.as_str())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Relationship {
    #[serde(rename = "unique-id")]
    pub unique_id: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "relationship-type")]
    pub relationship_type: RelationshipType,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub metadata: Vec<BTreeMap<String, serde_json::Value>>,
}

impl Relationship {
    pub fn layer(&self) -> &str {
        self.metadata
            .first()
            .and_then(|m| m.get("layer"))
            .and_then(|v| v.as_str())
            .unwrap_or("unassigned")
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RelationshipType {
    #[serde(default)]
    pub connects: Option<Connects>,
    #[serde(default, rename = "deployed-in")]
    pub deployed_in: Option<Containment>,
    #[serde(default, rename = "composed-of")]
    pub composed_of: Option<Containment>,
    #[serde(default)]
    pub interacts: Option<Interacts>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Connects {
    pub source: Endpoint,
    pub destination: Endpoint,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Endpoint {
    #[serde(default)]
    pub node: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Containment {
    pub container: String,
    pub nodes: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Interacts {
    pub actor: String,
    pub nodes: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Flow {
    #[serde(rename = "unique-id")]
    pub unique_id: String,
    pub name: String,
    pub description: String,
    pub transitions: Vec<Transition>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Transition {
    #[serde(rename = "relationship-unique-id")]
    pub relationship_unique_id: String,
    #[serde(rename = "sequence-number")]
    pub sequence_number: u32,
    pub description: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Architecture {
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub relationships: Vec<Relationship>,
    #[serde(default)]
    pub flows: Vec<Flow>,
    #[serde(default)]
    pub metadata: Vec<BTreeMap<String, serde_json::Value>>,
}

impl Architecture {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read architecture at {}", path.display()))?;
        let arch: Architecture = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a readable CALM document", path.display()))?;
        arch.check_referential_integrity()?;
        Ok(arch)
    }

    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.unique_id == id)
    }

    /// Every id a relationship or flow names must exist.
    ///
    /// The CALM schema does not enforce this — it validates SHAPE, not
    /// reference. A relationship pointing at a node that was renamed or deleted
    /// still validates, and then silently vanishes from every diagram, which is
    /// the failure mode that makes generated documentation untrustworthy.
    pub fn check_referential_integrity(&self) -> Result<()> {
        let ids: BTreeSet<&str> = self.nodes.iter().map(|n| n.unique_id.as_str()).collect();
        let rel_ids: BTreeSet<&str> = self
            .relationships
            .iter()
            .map(|r| r.unique_id.as_str())
            .collect();
        let mut dangling = Vec::new();
        let mut check = |who: &str, what: &str| {
            if !ids.contains(what) {
                dangling.push(format!("{who} -> unknown node '{what}'"));
            }
        };
        for r in &self.relationships {
            let t = &r.relationship_type;
            if let Some(c) = &t.connects {
                if let Some(n) = &c.source.node {
                    check(&r.unique_id, n);
                }
                if let Some(n) = &c.destination.node {
                    check(&r.unique_id, n);
                }
            }
            for cont in [&t.deployed_in, &t.composed_of].into_iter().flatten() {
                check(&r.unique_id, &cont.container);
                for n in &cont.nodes {
                    check(&r.unique_id, n);
                }
            }
            if let Some(i) = &t.interacts {
                check(&r.unique_id, &i.actor);
                for n in &i.nodes {
                    check(&r.unique_id, n);
                }
            }
        }
        for f in &self.flows {
            for tr in &f.transitions {
                if !rel_ids.contains(tr.relationship_unique_id.as_str()) {
                    dangling.push(format!(
                        "flow '{}' -> unknown relationship '{}'",
                        f.unique_id, tr.relationship_unique_id
                    ));
                }
            }
        }
        if !dangling.is_empty() {
            bail!(
                "the architecture references things it does not define:\n  {}",
                dangling.join("\n  ")
            );
        }
        Ok(())
    }

    /// Container -> children, from `deployed-in` and `composed-of`.
    ///
    /// A node claimed by several containers is placed in the FIRST that claims
    /// it, because a diagram cannot draw one box inside two others. The model
    /// may legitimately express both — for example a node both composed into
    /// the cluster and deployed on a hypervisor — so this is a rendering
    /// decision, not a modelling constraint.
    pub fn containment(&self) -> BTreeMap<String, Vec<String>> {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut placed: BTreeSet<String> = BTreeSet::new();
        for r in &self.relationships {
            for cont in [
                &r.relationship_type.deployed_in,
                &r.relationship_type.composed_of,
            ]
            .into_iter()
            .flatten()
            {
                for n in &cont.nodes {
                    if placed.insert(n.clone()) {
                        map.entry(cont.container.clone())
                            .or_default()
                            .push(n.clone());
                    }
                }
            }
        }
        map
    }
}

// --- rendering to D2 -------------------------------------------------------

/// A named subset of the architecture. Views exist because one diagram of 45
/// nodes is not an architecture diagram, it is a hairball — the value of a view
/// is what it LEAVES OUT.
pub struct View {
    pub id: &'static str,
    pub title: &'static str,
    /// Why this view exists and what question it answers.
    pub purpose: &'static str,
    /// Node layers included. Empty means every layer.
    pub node_layers: &'static [&'static str],
    /// Relationship layers drawn. Empty means every layer.
    pub edge_layers: &'static [&'static str],
    /// Collapse these containers to a single box instead of showing children.
    pub collapse: &'static [&'static str],
}

pub const VIEWS: &[View] = &[
    View {
        id: "context",
        title: "System context",
        purpose: "What this estate touches, and what touches it. Everything inside is one box on \
             purpose: at this level the only interesting questions are which external systems \
             are load-bearing and who can reach what.",
        node_layers: &["people", "external", "physical"],
        edge_layers: &[
            "supply-chain",
            "traffic",
            "observability",
            "backup",
            "control",
        ],
        collapse: &["homelab"],
    },
    View {
        id: "fleet",
        title: "Fleet and failure domains",
        purpose: "Where things physically run, and what is lost with each machine. This is the view \
             that makes the invariant visible: three nodes on one hypervisor, two on the other, \
             and a quorum that cannot survive losing the first.",
        node_layers: &["physical", "node", "cluster", "host-tier"],
        edge_layers: &[],
        collapse: &[],
    },
    View {
        id: "platform",
        title: "Platform services",
        purpose: "What the cluster provides to the workloads that run on it, and what each of those \
             services depends on. The tenant boundary is the point: applications consume the \
             platform and hold no privilege over it.",
        node_layers: &["cluster", "platform", "application"],
        edge_layers: &["traffic", "control"],
        collapse: &[],
    },
    View {
        id: "supply-chain",
        title: "How a change reaches the cluster",
        purpose: "The only sanctioned path by which this cluster changes. Worth its own diagram \
             because the most common and most expensive misunderstanding is that pushing to \
             git deployed something.",
        node_layers: &["people", "external", "cluster", "platform"],
        edge_layers: &["supply-chain"],
        collapse: &[],
    },
    View {
        id: "observability",
        title: "How a failure becomes a notification",
        purpose: "Deliberately drawn to show that every step after collection happens OUTSIDE the \
             cluster. A monitor inside the thing it monitors cannot report that the thing is \
             gone — and the failures that matter most here change no HTTP response at all.",
        node_layers: &["cluster", "platform", "host-tier", "external"],
        edge_layers: &["observability", "backup"],
        collapse: &[],
    },
];

/// Sanitise one identifier for D2.
///
/// ⚠️ `.` is NOT sanitised: D2 uses it to address nested shapes, so
/// `k0s-cluster.flux` means "flux inside k0s-cluster". An earlier version
/// replaced it, which silently produced a NEW top-level shape called
/// `k0s-cluster_flux` floating outside the cluster it was supposed to be in —
/// the precise failure `qualified()` warns about, committed by the function
/// meant to support it.
fn d2_id(s: &str) -> String {
    s.replace(['/', ' '], "_")
}

fn d2_quote(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Wrap prose so a node label does not render as one unreadable line.
fn wrap(s: &str, width: usize) -> String {
    let mut out = String::new();
    let mut col = 0;
    for word in s.split_whitespace() {
        if col > 0 && col + 1 + word.len() > width {
            out.push_str("\\n");
            col = 0;
        } else if col > 0 {
            out.push(' ');
            col += 1;
        }
        out.push_str(word);
        col += word.len();
    }
    out
}

/// First sentence only — a diagram label is a caption, not documentation. The
/// full description travels to the generated page beside the diagram.
fn first_sentence(s: &str) -> &str {
    match s.find(". ") {
        Some(i) => &s[..=i],
        None => s,
    }
}

fn shape_for(node_type: &str) -> &'static str {
    match node_type {
        "actor" => "person",
        "database" => "cylinder",
        "network" => "cloud",
        "ecosystem" | "system" => "rectangle",
        _ => "rectangle",
    }
}

/// Amber-on-dark, matching the estate's own pages. Colour carries meaning here:
/// external systems are dimmed because they are not ours to change, and the
/// invariant host is the only thing drawn in warning red.
fn style_for(node: &Node, pad: &str) -> String {
    let (fill, stroke, font) = match node.layer() {
        "people" => ("#1b1815", "#ffb000", "#e8dcc8"),
        "external" => ("#17150f", "#6b6257", "#a99f92"),
        "physical" => ("#191612", "#ffb000", "#ffb000"),
        "node" => ("#1d1a15", "#8a8078", "#e8dcc8"),
        "cluster" => ("#161310", "#ffb000", "#ffb000"),
        "platform" => ("#1b1815", "#c98f10", "#e8dcc8"),
        "host-tier" => ("#1b1712", "#7fb3ff", "#dce8ff"),
        "application" => ("#181a15", "#9ccc65", "#e4f0d5"),
        _ => ("#1b1815", "#8a8078", "#e8dcc8"),
    };
    let invariant = node
        .detail()
        .map(|d| d.contains("failure-prone"))
        .unwrap_or(false);
    let stroke = if invariant { "#ff5c4d" } else { stroke };
    let width = if invariant { 3 } else { 2 };
    // Built with the caller's indent rather than post-processed: replacing
    // every double-space afterwards also mangles the spaces INSIDE the block,
    // which is how the first version produced ragged output that still compiled.
    format!(
        "{pad}  style: {{\n{pad}    fill: \"{fill}\"\n{pad}    stroke: \"{stroke}\"\n\
         {pad}    stroke-width: {width}\n{pad}    font-color: \"{font}\"\n\
         {pad}    border-radius: 6\n{pad}  }}\n"
    )
}

impl Architecture {
    /// Render one view as a D2 source document.
    pub fn render_d2(&self, view: &View) -> String {
        let containment = self.containment();
        let include_layer = |l: &str| view.node_layers.is_empty() || view.node_layers.contains(&l);

        let mut visible: BTreeSet<String> = self
            .nodes
            .iter()
            .filter(|n| include_layer(n.layer()))
            .map(|n| n.unique_id.clone())
            .collect();
        // A collapsed container is drawn, but none of its children are.
        for c in view.collapse {
            if let Some(kids) = containment.get(*c) {
                for k in kids {
                    visible.remove(k);
                }
                // and their descendants
                let mut frontier: Vec<String> = kids.clone();
                while let Some(k) = frontier.pop() {
                    if let Some(gk) = containment.get(&k) {
                        for g in gk {
                            visible.remove(g);
                            frontier.push(g.clone());
                        }
                    }
                }
            }
            visible.insert((*c).to_string());
        }

        // A FOCUSED view (one that names its edge layers) draws only nodes that
        // actually take part. Without this, "how a change reaches the cluster"
        // renders every service in the cluster and stops being a view at all.
        if !view.edge_layers.is_empty() {
            let mut participating: BTreeSet<String> = BTreeSet::new();
            for r in &self.relationships {
                if !view.edge_layers.contains(&r.layer()) {
                    continue;
                }
                if let Some(c) = &r.relationship_type.connects {
                    for e in [&c.source, &c.destination] {
                        if let Some(n) = &e.node {
                            participating.insert(n.clone());
                        }
                    }
                }
            }
            // Keep any container that still has a participating descendant.
            let mut keep = participating.clone();
            loop {
                let before = keep.len();
                for (container, kids) in &containment {
                    if kids.iter().any(|k| keep.contains(k)) {
                        keep.insert(container.clone());
                    }
                }
                if keep.len() == before {
                    break;
                }
            }
            visible.retain(|id| keep.contains(id));
        }

        let mut out = String::new();
        out.push_str(&format!(
            "# GENERATED FROM homelab.arch.json — DO NOT EDIT.\n\
             # Regenerate: substrate architecture render\n\
             # View: {}\n#\n",
            view.id
        ));
        for line in wrap(view.purpose, 76).split("\\n") {
            out.push_str(&format!("# {line}\n"));
        }
        out.push_str(
            "\nvars: {\n  d2-config: {\n    layout-engine: elk\n    dark-theme-id: 200\n  }\n}\n\n",
        );
        out.push_str(&format!(
            "title: |md\n  # {}\n| {{ near: top-center; style.font-color: \"#ffb000\" }}\n\n",
            d2_quote(view.title)
        ));

        // Children are emitted inside their container so D2 nests them.
        let mut emitted: BTreeSet<String> = BTreeSet::new();
        let is_child: BTreeSet<&str> = containment
            .values()
            .flat_map(|v| v.iter().map(|s| s.as_str()))
            .collect();

        for node in &self.nodes {
            if !visible.contains(&node.unique_id) || is_child.contains(node.unique_id.as_str()) {
                continue;
            }
            self.emit_node(&mut out, node, &containment, &visible, &mut emitted, 0);
        }

        for r in &self.relationships {
            if !view.edge_layers.is_empty() && !view.edge_layers.contains(&r.layer()) {
                continue;
            }
            let Some(c) = &r.relationship_type.connects else {
                continue;
            };
            let (Some(src), Some(dst)) = (&c.source.node, &c.destination.node) else {
                continue;
            };
            let (Some(s), Some(d)) = (
                self.visible_ancestor(src, &visible, &containment),
                self.visible_ancestor(dst, &visible, &containment),
            ) else {
                continue;
            };
            // Skip an edge inside a collapsed box, and skip one between a shape
            // and its own ancestor: containment is already drawn as nesting, so
            // such an arrow adds no information and routes out through the
            // container's title.
            if s == d || s.starts_with(&format!("{d}.")) || d.starts_with(&format!("{s}.")) {
                continue;
            }
            let label = r.protocol.clone().unwrap_or_default();
            out.push_str(&format!(
                "{} -> {}: {{ {}\n  style: {{ stroke: \"#c98f10\"; stroke-width: 2 }}\n}}\n",
                d2_id(&s),
                d2_id(&d),
                if label.is_empty() {
                    String::new()
                } else {
                    format!("label: {label}")
                }
            ));
        }
        out
    }

    /// The nearest ancestor that is actually drawn, so an edge into a collapsed
    /// container lands on the container rather than disappearing.
    fn visible_ancestor(
        &self,
        id: &str,
        visible: &BTreeSet<String>,
        containment: &BTreeMap<String, Vec<String>>,
    ) -> Option<String> {
        if visible.contains(id) {
            return Some(self.qualified(id, containment));
        }
        let parent = containment
            .iter()
            .find(|(_, kids)| kids.iter().any(|k| k == id))
            .map(|(c, _)| c.clone())?;
        self.visible_ancestor(&parent, visible, containment)
    }

    /// D2 addresses nested shapes by path, so a child must be referred to as
    /// `container.child` or the edge silently creates a NEW top-level shape.
    fn qualified(&self, id: &str, containment: &BTreeMap<String, Vec<String>>) -> String {
        match containment
            .iter()
            .find(|(_, kids)| kids.iter().any(|k| k == id))
            .map(|(c, _)| c.clone())
        {
            Some(parent) => format!("{}.{}", self.qualified(&parent, containment), id),
            None => id.to_string(),
        }
    }

    fn emit_node(
        &self,
        out: &mut String,
        node: &Node,
        containment: &BTreeMap<String, Vec<String>>,
        visible: &BTreeSet<String>,
        emitted: &mut BTreeSet<String>,
        depth: usize,
    ) {
        if !emitted.insert(node.unique_id.clone()) {
            return;
        }
        let pad = "  ".repeat(depth);
        let kids: Vec<&Node> = containment
            .get(&node.unique_id)
            .map(|ks| {
                ks.iter()
                    .filter(|k| visible.contains(*k))
                    .filter_map(|k| self.node(k))
                    .collect()
            })
            .unwrap_or_default();

        let mut label = wrap(first_sentence(&node.description), 34);
        if let Some(d) = node.detail() {
            label.push_str(&format!("\\n\\n{}", wrap(d, 34)));
        }
        let controls = if node.controls.is_empty() {
            String::new()
        } else {
            format!("\\n\\n⛨ {} control(s)", node.controls.len())
        };

        out.push_str(&format!("{pad}{}: {{\n", d2_id(&node.unique_id)));
        out.push_str(&format!("{pad}  label: \"{}\"\n", d2_quote(&node.name)));
        if kids.is_empty() {
            out.push_str(&format!("{pad}  shape: {}\n", shape_for(&node.node_type)));
            out.push_str(&format!(
                "{pad}  tooltip: \"{}{}\"\n",
                d2_quote(&label.replace("\\n", " ")),
                d2_quote(&controls.replace("\\n", " "))
            ));
        }
        out.push_str(&style_for(node, &pad));
        for kid in kids {
            self.emit_node(out, kid, containment, visible, emitted, depth + 1);
        }
        out.push_str(&format!("{pad}}}\n"));
    }
}

// --- ADD conformance -------------------------------------------------------

/// What the deployed configuration actually declares, discovered from the
/// GitOps repository rather than from anyone's description of it.
#[derive(Debug, Default)]
pub struct DeployedSurface {
    /// Directory names under apps/, infrastructure/ and observability/ — one
    /// per deployable component.
    pub components: BTreeSet<String>,
}

/// Manifests that configure an area rather than deploying a component into it.
const SCAFFOLDING: &[&str] = &[
    "kustomization",
    "namespace",
    "networkpolicy",
    "resourcequota",
    "host-endpoint",
];

/// Read the deployed surface from a substrate_config checkout.
///
/// Directories, not manifests: a component is a thing someone decided to
/// deploy, and that decision shows up as a directory long before it shows up as
/// a running pod. Reading the repository rather than the cluster is also what
/// lets this gate run BEFORE anything is applied, which is the whole point.
pub fn deployed_surface(config_root: &std::path::Path) -> Result<DeployedSurface> {
    let mut surface = DeployedSurface::default();
    // apps/ and infrastructure/ put one component per directory.
    for area in ["apps", "infrastructure"] {
        let dir = config_root.join(area);
        if !dir.is_dir() {
            continue;
        }
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("could not read {}", dir.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                surface
                    .components
                    .insert(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    // observability/ is FLAT — one manifest per file, no directories. Reading
    // only directories there would silently find nothing and report perfect
    // conformance over an area containing real workloads.
    let obs = config_root.join("observability");
    if obs.is_dir() {
        for entry in
            std::fs::read_dir(&obs).with_context(|| format!("could not read {}", obs.display()))?
        {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".yaml") else {
                continue;
            };
            // Scaffolding, not components: these configure the area itself
            // rather than deploying anything into it.
            if SCAFFOLDING
                .iter()
                .any(|s| stem == *s || stem.starts_with(s))
            {
                continue;
            }
            surface.components.insert(stem.to_string());
        }
    }
    Ok(surface)
}

/// The result of checking configuration against architecture.
pub struct Conformance {
    /// Deployed components this architecture does not describe. FATAL — this is
    /// reality leading architecture, which ADD forbids.
    pub undescribed: Vec<String>,
    /// Described components not yet deployed. ALLOWED — a change in flight.
    pub planned: Vec<String>,
    /// Addresses or internal hostnames found in a model meant to be published.
    pub privacy_violations: Vec<String>,
}

impl Conformance {
    pub fn ok(&self) -> bool {
        self.undescribed.is_empty() && self.privacy_violations.is_empty()
    }
}

/// Which architecture nodes correspond to a deployable component directory.
///
/// Explicit rather than inferred from the node id. A silent name-matching rule
/// would let a renamed directory quietly stop being checked, which is exactly
/// the kind of control that evaluates successfully while measuring nothing.
fn component_aliases(node: &Node) -> Vec<String> {
    let mut names = vec![node.unique_id.clone()];
    if let Some(extra) = node
        .metadata
        .first()
        .and_then(|m| m.get("deploys-as"))
        .and_then(|v| v.as_str())
    {
        names.extend(extra.split(',').map(|s| s.trim().to_string()));
    }
    names
}

/// Whether this node is something the GitOps repository deploys.
///
/// Not everything that runs here is declared there: Flux is rendered into the
/// node image and bootstraps itself, etcd and the cluster come from the
/// provisioner, and the nameserver pods are created by an operator rather than
/// declared directly. Checking those against the repository would demand
/// directories that cannot exist. Stating provenance in the MODEL keeps that
/// judgement reviewable instead of buried in the checker.
fn deployed_by_config(node: &Node) -> bool {
    node.metadata
        .first()
        .and_then(|m| m.get("deployed-by"))
        .and_then(|v| v.as_str())
        == Some("substrate_config")
}

/// Enforce Architecture Driven Design.
///
/// THE RULE: architecture may lead reality; reality may NEVER lead
/// architecture. A component in the configuration that the model does not
/// describe is a failure — the model should have been changed first. A
/// component in the model that is not yet deployed is fine; that is a decision
/// taken and not yet implemented, which is precisely the state ADD is meant to
/// make possible.
pub fn check_conformance(arch: &Architecture, surface: &DeployedSurface) -> Conformance {
    let described: BTreeSet<String> = arch
        .nodes
        .iter()
        .filter(|n| deployed_by_config(n))
        .flat_map(component_aliases)
        .collect();

    let undescribed = surface
        .components
        .iter()
        .filter(|c| !described.contains(*c))
        .cloned()
        .collect();

    let planned = arch
        .nodes
        .iter()
        .filter(|n| deployed_by_config(n))
        .filter(|n| {
            !component_aliases(n)
                .iter()
                .any(|a| surface.components.contains(a))
        })
        .map(|n| n.unique_id.clone())
        .collect();

    Conformance {
        undescribed,
        planned,
        privacy_violations: privacy_violations(arch),
    }
}

/// The model is written to be PUBLISHED. Addresses and internal hostnames must
/// never reach it.
///
/// Checked mechanically rather than by care, because this is the kind of thing
/// that survives review a hundred times and then does not once. A published
/// architecture that maps a private network is worth more to an attacker than
/// it is to a reader.
pub fn privacy_violations(arch: &Architecture) -> Vec<String> {
    let text = serde_json::to_string(&serde_json::json!({
        "nodes": arch.nodes.iter().map(|n| format!("{} {} {}", n.unique_id, n.name, n.description)).collect::<Vec<_>>(),
        "relationships": arch.relationships.iter().map(|r| format!("{} {}", r.unique_id, r.description)).collect::<Vec<_>>(),
    }))
    .unwrap_or_default();

    let mut found = Vec::new();
    // RFC1918 and loopback, written out rather than regex-matched so the
    // intent is readable and each prefix is individually justifiable.
    for (needle, why) in [
        ("192.168.", "RFC1918 address"),
        ("10.0.", "RFC1918 address"),
        ("172.16.", "RFC1918 address"),
        ("127.0.0.1", "loopback address"),
        (".local", "internal hostname"),
        (".internal", "internal hostname"),
        ("BEGIN PRIVATE KEY", "private key material"),
        ("password", "credential"),
        ("token=", "credential"),
    ] {
        if text.to_lowercase().contains(&needle.to_lowercase()) {
            found.push(format!(
                "{why} ({needle}) appears in a model meant to be published"
            ));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arch_from(json: serde_json::Value) -> Architecture {
        serde_json::from_value(json).expect("test fixture must deserialise")
    }

    fn node(id: &str, layer: &str, deployed_by: Option<&str>) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("layer".into(), layer.into());
        if let Some(d) = deployed_by {
            m.insert("deployed-by".into(), d.into());
        }
        serde_json::json!({
            "unique-id": id, "node-type": "service", "name": id,
            "description": "a test node.", "metadata": [m]
        })
    }

    #[test]
    fn a_relationship_naming_a_missing_node_is_rejected() {
        // The CALM schema validates SHAPE, not reference. A relationship
        // pointing at a renamed node still validates and then silently vanishes
        // from every diagram — generated docs that quietly lose an edge are
        // worse than no docs.
        let a = arch_from(serde_json::json!({
            "nodes": [node("a", "platform", None)],
            "relationships": [{
                "unique-id": "a-to-ghost", "description": "",
                "relationship-type": {"connects": {
                    "source": {"node": "a"}, "destination": {"node": "ghost"}}}}]
        }));
        let err = a.check_referential_integrity().unwrap_err().to_string();
        assert!(err.contains("unknown node 'ghost'"), "{err}");
    }

    #[test]
    fn a_flow_naming_a_missing_relationship_is_rejected() {
        let a = arch_from(serde_json::json!({
            "nodes": [node("a", "platform", None)],
            "flows": [{"unique-id": "f", "name": "f", "description": "d",
                "transitions": [{"relationship-unique-id": "nope",
                    "sequence-number": 1, "description": "x"}]}]
        }));
        assert!(a.check_referential_integrity().is_err());
    }

    #[test]
    fn deployed_configuration_the_model_does_not_describe_is_a_violation() {
        // THE ADD RULE, in its failing direction.
        let a = arch_from(serde_json::json!({"nodes": [
            node("known", "application", Some("substrate_config"))]}));
        let mut surface = DeployedSurface::default();
        surface.components.insert("known".into());
        surface.components.insert("surprise".into());
        let c = check_conformance(&a, &surface);
        assert_eq!(c.undescribed, vec!["surprise".to_string()]);
        assert!(!c.ok());
    }

    #[test]
    fn a_described_component_not_yet_deployed_is_allowed() {
        // THE ADD RULE, in its passing direction — and the half that makes the
        // rule usable. Architecture is changed FIRST, so between the decision
        // and the implementation the model legitimately describes more than
        // exists. A gate that failed here would forbid the very workflow it is
        // meant to enforce.
        let a = arch_from(serde_json::json!({"nodes": [
            node("planned-thing", "application", Some("substrate_config"))]}));
        let c = check_conformance(&a, &DeployedSurface::default());
        assert_eq!(c.planned, vec!["planned-thing".to_string()]);
        assert!(c.ok(), "architecture is allowed to lead reality");
    }

    #[test]
    fn components_deployed_by_something_other_than_the_config_repo_are_not_checked() {
        // Flux is rendered into the node image and bootstraps itself; demanding
        // a directory for it would make the gate permanently and wrongly red.
        let a = arch_from(serde_json::json!({"nodes": [
            node("flux", "platform", Some("node-image"))]}));
        let c = check_conformance(&a, &DeployedSurface::default());
        assert!(c.planned.is_empty() && c.ok());
    }

    #[test]
    fn an_address_in_a_published_model_is_a_violation() {
        // This model is rendered onto a public website. A published
        // architecture that maps a private network is worth more to an attacker
        // than to a reader, so it is checked mechanically rather than by care.
        let mut n = node("traefik", "platform", Some("substrate_config"));
        n["description"] = "Ingress, reachable at 192.168.2.206.".into();
        let a = arch_from(serde_json::json!({"nodes": [n]}));
        assert!(!privacy_violations(&a).is_empty());
    }

    #[test]
    fn a_clean_model_reports_no_privacy_violations() {
        let a = arch_from(serde_json::json!({"nodes": [
            node("traefik", "platform", Some("substrate_config"))]}));
        assert!(privacy_violations(&a).is_empty());
    }

    #[test]
    fn nested_shapes_are_addressed_by_path_not_by_a_mangled_name() {
        // D2 addresses a child as `container.child`. Sanitising the dot creates
        // a NEW top-level shape floating outside its container — which is
        // exactly what happened, and it rendered as a phantom `k0s-cluster_flux`
        // box beside the cluster it belonged in.
        assert_eq!(d2_id("k0s-cluster.flux"), "k0s-cluster.flux");
        assert_eq!(d2_id("has space/slash"), "has_space_slash");
    }

    #[test]
    fn a_focused_view_drops_nodes_that_take_no_part_in_it() {
        // A view's value is what it leaves out. Without pruning, "how a change
        // reaches the cluster" rendered every service in the cluster.
        let a = arch_from(serde_json::json!({
            "nodes": [node("a", "platform", None), node("b", "platform", None),
                      node("bystander", "platform", None)],
            "relationships": [{
                "unique-id": "a-b", "description": "",
                "metadata": [{"layer": "supply-chain"}],
                "relationship-type": {"connects": {
                    "source": {"node": "a"}, "destination": {"node": "b"}}}}]
        }));
        let view = View {
            id: "t",
            title: "t",
            purpose: "t",
            node_layers: &["platform"],
            edge_layers: &["supply-chain"],
            collapse: &[],
        };
        let d2 = a.render_d2(&view);
        assert!(d2.contains("a: {") && d2.contains("b: {"));
        assert!(
            !d2.contains("bystander"),
            "an unrelated node was drawn anyway"
        );
    }
}
