//! Plain-text graphical rendering of the topology for terminals.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::model::{Link, LinkView, Node, Role, TopologySnapshot};

/// Renders an ASCII tree: the leader at the root, routers as a mesh summary,
/// and children indented under their parent.
pub fn topology_ascii(snapshot: &TopologySnapshot) -> String {
    let mut out = String::new();
    let name = snapshot
        .network
        .network_name
        .clone()
        .unwrap_or_else(|| "Thread network".to_string());
    let _ = writeln!(out, "{name}");
    if let (Some(channel), Some(pan)) = (snapshot.network.channel, &snapshot.network.pan_id) {
        let _ = writeln!(out, "  channel {channel}, pan {pan}");
    }
    let _ = writeln!(out);

    // Index children by parent RLOC16.
    let mut children_by_parent: BTreeMap<String, Vec<&Node>> = BTreeMap::new();
    for node in &snapshot.nodes {
        if node.role == Role::Child {
            if let Some(parent) = &node.parent_rloc16 {
                children_by_parent
                    .entry(parent.clone())
                    .or_default()
                    .push(node);
            }
        }
    }

    let routers: Vec<&Node> = snapshot
        .nodes
        .iter()
        .filter(|node| node.role != Role::Child)
        .collect();

    for (index, router) in routers.iter().enumerate() {
        let last_router = index + 1 == routers.len();
        let marker = if last_router { "└─" } else { "├─" };
        let role = match router.role {
            Role::Leader => "LEADER",
            _ => "router",
        };
        let reachable = match router.discovery {
            crate::model::Discovery::Unreachable => "  (unreachable)",
            _ => "",
        };
        let _ = writeln!(out, "{marker} [{role}] {}{reachable}", router.rloc16);

        let child_indent = if last_router { "   " } else { "│  " };
        let neighbors = mesh_neighbors(snapshot, &router.rloc16);
        if !neighbors.is_empty() {
            let _ = writeln!(out, "{child_indent}· mesh links: {}", neighbors.join(", "));
        }
        if let Some(connectivity) = &router.connectivity {
            let _ = writeln!(
                out,
                "{child_indent}· neighbors lq3/lq2/lq1 = {}/{}/{}, leader cost {}",
                connectivity.link_quality_3_neighbors,
                connectivity.link_quality_2_neighbors,
                connectivity.link_quality_1_neighbors,
                connectivity.leader_cost,
            );
        }

        if let Some(children) = children_by_parent.get(&router.rloc16) {
            for (child_index, child) in children.iter().enumerate() {
                let last_child = child_index + 1 == children.len();
                let child_marker = if last_child { "└─" } else { "├─" };
                let kind = child
                    .mode
                    .map(|mode| {
                        format!(
                            "{} {}",
                            if mode.rx_on_when_idle {
                                "rx-on"
                            } else {
                                "sleepy"
                            },
                            mode.device_type
                        )
                    })
                    .unwrap_or_else(|| "child".to_string());
                let direct = match child.discovery {
                    crate::model::Discovery::DirectQuery => "",
                    _ => " (parent-table only)",
                };
                let _ = writeln!(
                    out,
                    "{child_indent}{child_marker} {} [{kind}]{direct}",
                    child.rloc16
                );
            }
        }
    }

    let _ = writeln!(
        out,
        "\n{} routers, {} children, {} links",
        routers.len(),
        snapshot.nodes.len() - routers.len(),
        snapshot.links.len(),
    );
    out
}

/// RLOC16s of mesh neighbors of `rloc`, with link quality from `rloc`'s own
/// perspective (in = `rloc` hears the neighbor, out = the neighbor hears `rloc`).
fn mesh_neighbors(snapshot: &TopologySnapshot, rloc: &str) -> Vec<String> {
    let mut neighbors = Vec::new();
    for link in &snapshot.links {
        if let Link::Mesh {
            a,
            b,
            a_view,
            b_view,
        } = link
        {
            let (other, view) = if a == rloc {
                (b, own_view(*a_view, *b_view))
            } else if b == rloc {
                (a, own_view(*b_view, *a_view))
            } else {
                continue;
            };
            match view {
                Some(view) => {
                    neighbors.push(format!("{other} (lq {}/{})", view.lq_in, view.lq_out))
                }
                None => neighbors.push(other.clone()),
            }
        }
    }
    neighbors
}

/// Returns the node's own link view, or the peer's view with in/out swapped
/// (a link view is perspective-dependent), preferring the node's own.
fn own_view(own: Option<LinkView>, peer: Option<LinkView>) -> Option<LinkView> {
    own.or_else(|| {
        peer.map(|view| LinkView {
            lq_in: view.lq_out,
            lq_out: view.lq_in,
        })
    })
}
