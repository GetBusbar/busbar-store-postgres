// SPDX-License-Identifier: Apache-2.0

#[test]
fn former_store_module_names_are_converted_without_runtime_alias_admission() {
    install();
    let raw = "store: {module: busbar-store-postgres-plugin}\n";
    let out = busbar_migrations::config::normalize_authored(
        raw,
        &busbar_migrations::config::migrate_plugins::NoPlugins,
    )
    .expect("structural conversion");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).unwrap();
    assert_eq!(doc["store"]["module"].as_str(), Some("postgres"));
}
