use crate::{error::Result, vm};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

static SOURCES: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../assets/analysis-sources.json"))
        .expect("Reviewed analysis sources")
});

// Entirely embedded metadata: no evidence reads, cache writes, source fetching,
// or analyzed-program execution. The API never accepts a source URL to resolve.
pub(crate) fn catalog() -> Result<Value> {
    let profile = vm::current_profile();
    let mut rules = vm::current_rule_definitions();
    for rule in &mut rules {
        let (sources, limitations) = match rule["scope"].as_str().unwrap() {
            "javascript-structure" => (
                json!(["reb-vm-detector", "javascript-vm-in-go", "web-re-toolkit"]),
                "Name-dependent lexical heuristics over masked approximate function regions; not AST/binding analysis. Regex literals and template interpolation are not fully modeled. Only the highest-ranked region is retained.",
            ),
            "wasm-structure" => (
                json!(["reb-vm-detector", "web-re-toolkit"]),
                "Decoded opcode and section co-occurrence is structural triage, not guest semantics or verified data flow. Only the highest-ranked function is retained; module data/table clues can be added.",
            ),
            "javascript-lexical-relevance" => (
                json!(["reb-vm-detector"]),
                "Text presence is neither an executed API call nor evidence of VM structure, fingerprinting, provider identity, or malicious intent.",
            ),
            "retained-runtime-relevance" => (
                if rule["rule_id"] == "antibot.runtime-web-audio" {
                    json!(["reb-vm-detector", "web-audio-specification"])
                } else {
                    json!(["reb-vm-detector"])
                },
                "Captured API use does not prove successful return, fingerprinting, or causal value flow. Context-only matches are correlated; missing capture is unknown. Audio events contain no sample buffers.",
            ),
            _ => unreachable!("Known VM rule scopes"),
        };
        rule["source_ids"] = sources;
        rule["limitations"] = json!(limitations);
    }
    let mut catalog = json!({
        "contract_version":1,
        "current_producer":vm::current_producer(),
        "current_profile_digest":hex::encode(Sha256::digest(vm::canonical(&profile)?)),
        "current_profile":profile,
        "compatibility":{
            "profile_matching":"exact-producer-and-profile",
            "build_identity":"not-recorded",
            "historical_definitions":"not-included",
            "limitations":"Match a document's producer ID/version and profile_digest before applying current definitions. Build identity is not recorded, so even matching metadata does not prove the same analyzer binary. The v1 document schema accepts older profiles, but their definitions are not supplied or revalidated by this catalog. Read their embedded profile and evidence; never reinterpret them as current."
        },
        "rules":rules,
        "sources":*SOURCES,
        "limitations":[
            "Scope is the current VM detector's structural and relevance rules, not every REB analyzer. Upstream references supply concepts or review context; REB owns its rule definitions and heuristic weights.",
            "Source inspection is distinct from executing or independently reproducing upstream claims. A source revision or digest identifies content; it does not authenticate a source or establish accuracy, causation, or semantic equivalence.",
            "Catalog revisions do not modify evidence or existing analysis documents. Static relevance weights are exposed here but were not part of the historical VM profile digest projection; retain the producer version when comparing results.",
            "Native origin allowlisting, guest opcode recovery, native audio samples, and CPU identification are not implemented by these rules."
        ]
    });
    catalog["catalog_digest"] = json!(hex::encode(Sha256::digest(vm::canonical(&catalog)?)));
    Ok(catalog)
}
