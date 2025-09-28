use crate::ScanOutcome;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
};

pub fn run() -> ScanOutcome {
    let output = Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .map_err(|err| format!("failed to execute nft: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "nft exited with {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let json: Nftables = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse nftables JSON: {err}"))?;

    let mut tables: BTreeMap<TableKey, TableInfo> = BTreeMap::new();
    let mut defined_sets: BTreeSet<ScopedName> = BTreeSet::new();

    for entry in json.nftables.into_iter().flatten() {
        match entry {
            NftEntry::Table { table } => {
                tables
                    .entry(TableKey {
                        family: table.family,
                        table: table.name,
                    })
                    .or_default();
            }
            NftEntry::Chain { chain } => {
                let key = TableKey {
                    family: chain.family,
                    table: chain.table,
                };
                let info = tables.entry(key).or_default();
                info.chains.insert(
                    chain.name.clone(),
                    ChainDetails {
                        hook: chain.hook,
                        r#type: chain.r#type,
                    },
                );
            }
            NftEntry::Rule { rule } => {
                let key = TableKey {
                    family: rule.family,
                    table: rule.table,
                };
                let info = tables.entry(key).or_default();
                if let Some(expr) = rule.expr {
                    info.rules.entry(rule.chain).or_default().push(expr);
                }
            }
            NftEntry::Set { set } => {
                defined_sets.insert(ScopedName {
                    family: set.family,
                    table: set.table,
                    name: set.name,
                });
            }
            NftEntry::Flowtable { .. } | NftEntry::Monitor { .. } | NftEntry::Unknown(_) => {}
        }
    }

    let mut findings = Vec::new();

    for (table_key, info) in &tables {
        for (chain_name, chain_details) in &info.chains {
            if chain_details.r#type.is_some() && chain_details.hook.is_none() {
                findings.push(format!(
                    "{},{},{} anomaly=orphan_base_chain",
                    table_key.family, table_key.table, chain_name
                ));
            }
        }
    }

    for (table_key, info) in &tables {
        let known_chains = info.chains.keys().cloned().collect::<BTreeSet<_>>();

        for (chain_name, expressions) in &info.rules {
            for expr in expressions {
                scan_expr(
                    expr,
                    table_key,
                    chain_name,
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
    expr: &Value,
    table_key: &TableKey,
    chain_name: &str,
    known_chains: &BTreeSet<String>,
    defined_sets: &BTreeSet<ScopedName>,
    findings: &mut Vec<String>,
) {
    match expr {
        Value::Object(map) => {
            for (key, value) in map {
                match key.as_str() {
                    "jump" | "goto" => {
                        if let Some(target) = value.get("target").and_then(Value::as_str) {
                            if !known_chains.contains(target) {
                                findings.push(format!(
                                    "{},{},{} anomaly=jump_to_missing_handle target={}",
                                    table_key.family, table_key.table, chain_name, target
                                ));
                            }
                        }
                    }
                    "set" => {
                        if let Some(name) = value.as_str() {
                            record_unresolved_set(
                                name,
                                table_key,
                                chain_name,
                                defined_sets,
                                findings,
                            );
                        } else if let Some(obj_name) = value.get("name").and_then(Value::as_str) {
                            record_unresolved_set(
                                obj_name,
                                table_key,
                                chain_name,
                                defined_sets,
                                findings,
                            );
                        }
                    }
                    _ => {}
                }
                scan_expr(
                    value,
                    table_key,
                    chain_name,
                    known_chains,
                    defined_sets,
                    findings,
                );
            }
        }
        Value::Array(arr) => {
            for value in arr {
                scan_expr(
                    value,
                    table_key,
                    chain_name,
                    known_chains,
                    defined_sets,
                    findings,
                );
            }
        }
        Value::String(string) => {
            record_unresolved_set(string, table_key, chain_name, defined_sets, findings)
        }
        _ => {}
    }
}

fn record_unresolved_set(
    candidate: &str,
    table_key: &TableKey,
    chain_name: &str,
    defined_sets: &BTreeSet<ScopedName>,
    findings: &mut Vec<String>,
) {
    if let Some(name) = candidate.strip_prefix('@') {
        let scoped = ScopedName {
            family: table_key.family.clone(),
            table: table_key.table.clone(),
            name: name.to_string(),
        };
        if !defined_sets.contains(&scoped) {
            findings.push(format!(
                "{},{},{} anomaly=anon_set_unresolved set={}",
                table_key.family, table_key.table, chain_name, candidate
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
    r#type: Option<String>,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
struct TableKey {
    family: String,
    table: String,
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
        #[serde(default)]
        _flowtable: Value,
    },
    Monitor {
        #[serde(default)]
        _monitor: Value,
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
    #[serde(rename = "type")]
    #[serde(default)]
    r#type: Option<String>,
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
