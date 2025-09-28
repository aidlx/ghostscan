use crate::ScanOutcome;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

pub fn run() -> ScanOutcome {
    let output = Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .map_err(|err| format!("failed to execute nft: {err}"))?;

    if !output.status.success() {
        return Err(format!("nft exited with {}", output.status));
    }

    let json: Nftables = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse nftables JSON: {err}"))?;

    let mut tables: BTreeMap<TableKey, TableInfo> = BTreeMap::new();
    let mut defined_sets: BTreeSet<ScopedName> = BTreeSet::new();

    for entry in json.nftables.into_iter().flatten() {
        match entry {
            NftEntry::Table { table } => {
                tables
                    .entry(TableKey::new(table.family, table.name))
                    .or_default();
            }
            NftEntry::Chain { chain } => {
                tables
                    .entry(TableKey::new(chain.family.clone(), chain.table.clone()))
                    .or_default()
                    .chains
                    .insert(chain.name.clone(), ChainDetails { hook: chain.hook });
            }
            NftEntry::Rule { rule } => {
                tables
                    .entry(TableKey::new(rule.family.clone(), rule.table.clone()))
                    .or_default()
                    .rules
                    .entry(rule.chain.clone())
                    .or_default()
                    .push(rule.expr.unwrap_or(Value::Null));
            }
            NftEntry::Set { set } => {
                defined_sets.insert(ScopedName {
                    family: set.family,
                    table: set.table,
                    name: set.name,
                });
            }
            NftEntry::Flowtable { .. } | NftEntry::Unknown(_) => {}
        }
    }

    let mut findings = Vec::new();

    for (table, info) in &tables {
        for (chain_name, chain) in &info.chains {
            if chain.hook.is_none() {
                findings.push(format!(
                    "family={}, table={}, chain={}, anomaly=orphan_base_chain",
                    table.family, table.table, chain_name
                ));
            }
        }
    }

    for (table, info) in &tables {
        let known_chains: BTreeSet<String> = info.chains.keys().cloned().collect();
        for (chain, exprs) in &info.rules {
            for expr in exprs {
                scan_expr(
                    expr,
                    table,
                    chain,
                    &known_chains,
                    &defined_sets,
                    &mut findings,
                );
            }
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn scan_expr(
    value: &Value,
    table: &TableKey,
    chain: &str,
    known_chains: &BTreeSet<String>,
    defined_sets: &BTreeSet<ScopedName>,
    findings: &mut Vec<String>,
) {
    match value {
        Value::Object(map) => {
            if let Some(verdict) = map
                .get("jump")
                .and_then(|v| v.get("target"))
                .and_then(Value::as_str)
            {
                if !known_chains.contains(verdict) {
                    findings.push(format!(
                        "family={}, table={}, chain={}, anomaly=jump_to_missing_handle, target={}",
                        table.family, table.table, chain, verdict
                    ));
                }
            }
            if let Some(verdict) = map
                .get("goto")
                .and_then(|v| v.get("target"))
                .and_then(Value::as_str)
            {
                if !known_chains.contains(verdict) {
                    findings.push(format!(
                        "family={}, table={}, chain={}, anomaly=jump_to_missing_handle, target={}",
                        table.family, table.table, chain, verdict
                    ));
                }
            }
            if let Some(name) = map
                .get("set")
                .and_then(|v| v.get("name"))
                .and_then(Value::as_str)
            {
                record_set(name, table, chain, defined_sets, findings);
            }
            for value in map.values() {
                scan_expr(value, table, chain, known_chains, defined_sets, findings);
            }
        }
        Value::Array(arr) => {
            for value in arr {
                scan_expr(value, table, chain, known_chains, defined_sets, findings);
            }
        }
        Value::String(s) => {
            record_set(s, table, chain, defined_sets, findings);
        }
        _ => {}
    }
}

fn record_set(
    candidate: &str,
    table: &TableKey,
    chain: &str,
    defined_sets: &BTreeSet<ScopedName>,
    findings: &mut Vec<String>,
) {
    if let Some(name) = candidate.strip_prefix('@') {
        let scoped = ScopedName {
            family: table.family.clone(),
            table: table.table.clone(),
            name: name.to_string(),
        };
        if !defined_sets.contains(&scoped) {
            findings.push(format!(
                "family={}, table={}, chain={}, anomaly=anon_set_unresolved, set={}",
                table.family, table.table, chain, candidate
            ));
        }
    }
}

#[derive(Default)]
struct TableInfo {
    chains: BTreeMap<String, ChainDetails>,
    rules: BTreeMap<String, Vec<Value>>,
}

#[derive(Default)]
struct ChainDetails {
    hook: Option<String>,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
struct TableKey {
    family: String,
    table: String,
}

impl TableKey {
    fn new(family: String, table: String) -> Self {
        Self { family, table }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
struct ScopedName {
    family: String,
    table: String,
    name: String,
}

#[derive(Deserialize)]
struct Nftables {
    #[serde(default)]
    nftables: Vec<Option<NftEntry>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum NftEntry {
    Table {
        table: TableDef,
    },
    Chain {
        chain: ChainContent,
    },
    Rule {
        rule: RuleContent,
    },
    Set {
        set: SetContent,
    },
    Flowtable {
        #[allow(dead_code)]
        flowtable: Value,
    },
    Unknown(#[allow(dead_code)] Value),
}

#[derive(Deserialize)]
struct TableDef {
    family: String,
    name: String,
}

#[derive(Deserialize)]
struct ChainContent {
    family: String,
    table: String,
    name: String,
    #[serde(default)]
    hook: Option<String>,
}

#[derive(Deserialize)]
struct RuleContent {
    family: String,
    table: String,
    chain: String,
    #[serde(default)]
    expr: Option<Value>,
}

#[derive(Deserialize)]
struct SetContent {
    family: String,
    table: String,
    name: String,
}
