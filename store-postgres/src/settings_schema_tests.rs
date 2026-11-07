// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn settings_schema_matches_lifecycle_shapes() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("settings.schema.json")).expect("schema JSON");
    let validator = jsonschema::validator_for(&schema).expect("valid settings schema");
    let cases: &[(&str, bool)] = &[
        (r#"{"url":"postgres://schema_user@localhost/busbar"}"#, true),
        (
            r#"{"url":"host=localhost user=schema_user dbname=busbar"}"#,
            true,
        ),
        (r#"{}"#, false),
        (r#"null"#, false),
        (r#"[]"#, false),
        (r#"{"url":null}"#, false),
        (r#"{"url":1}"#, false),
        (r#"{"url":" "}"#, false),
        (
            r#"{"url":"postgres://schema_user@localhost/busbar","unknown":0}"#,
            false,
        ),
    ];
    for &(text, accepted) in cases {
        let value: serde_json::Value = serde_json::from_str(text).expect("case JSON");
        assert_eq!(validator.is_valid(&value), accepted, "schema: {text}");
        assert_eq!(
            crate::settings::parse(text.as_bytes(), &[]).is_ok(),
            accepted,
            "lifecycle: {text}"
        );
    }
    assert!(!crate::settings::parse(b"", &[]).is_ok());
    // The schema describes the settings shape; the lifecycle also judges libpq semantics.
    for settings in [
        &br#"{"url":"postgres://localhost/busbar"}"#[..],
        &br#"{"url":"host=localhost dbname=busbar"}"#[..],
        &br#"{"url":"postgres://schema_user@localhost/busbar?sslmode=bogus"}"#[..],
        &br#"{"url":"not a connection string"}"#[..],
    ] {
        assert!(crate::settings::parse(settings, &[]).is_err());
    }
}

#[test]
fn settings_schema_marks_secret_fields_without_defaults() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("settings.schema.json")).unwrap();
    let field = &schema["properties"]["url"];
    assert_eq!(field["writeOnly"], true);
    assert_eq!(field["x-busbar-secret"], true);
    assert!(field.get("default").is_none());
}
