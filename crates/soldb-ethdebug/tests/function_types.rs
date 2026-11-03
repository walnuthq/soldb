//! Function signature lists in compiler-produced resources and nested schema tuples.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use soldb_ethdebug::{Member, Resources, TypeDocument, TypeReference};

const FIXTURE: &str =
    include_str!("../../../test/fixtures/ethdebug-function-types/ethdebug_resources.json");
const EMPTY_TUPLE: &str = "t_tuple$__$";
const SINGLE_TUPLE: &str = "t_tuple$_t_uint32_$";
const PARAMETER_TUPLE: &str = "t_tuple$_t_uint32_$_t_bool_$_t_address_$";
const RETURN_TUPLE: &str = "t_tuple$_t_bytes4_$_t_int16_$";

fn fixture() -> Resources {
    let document: Value = serde_json::from_str(FIXTURE).unwrap();
    let resources = Resources::parse(&document).unwrap();
    assert!(resources.dangling_references().is_empty());
    resources
}

fn assert_tuple(resources: &Resources, reference: &TypeReference, component_ids: &[&str]) {
    let expected = TypeDocument::Tuple {
        members: component_ids
            .iter()
            .map(|id| Member {
                name: None,
                ty: TypeReference::Id((*id).to_owned()),
            })
            .collect(),
    };
    assert_eq!(resources.resolve(reference).unwrap(), &expected);
}

fn assert_signature(
    resources: &Resources,
    id: &str,
    expected_external: bool,
    expected_parameters: (&str, &[&str]),
    expected_returns: Option<(&str, &[&str])>,
) {
    let TypeDocument::Function {
        external,
        parameters,
        returns,
        definition,
    } = resources.type_document(id).expect("function type")
    else {
        panic!("{id} is not a function type");
    };
    assert_eq!(*external, expected_external, "{id}");
    assert!(definition.is_none(), "{id}");
    assert_eq!(
        parameters.as_ref(),
        &TypeReference::Id(expected_parameters.0.to_owned()),
        "{id}"
    );
    assert_tuple(resources, parameters, expected_parameters.1);
    match (returns.as_deref(), expected_returns) {
        (Some(reference), Some((tuple_id, components))) => {
            assert_eq!(reference, &TypeReference::Id(tuple_id.to_owned()), "{id}");
            assert_tuple(resources, reference, components);
        }
        (None, None) => {}
        _ => panic!("{id}: unexpected return list {returns:?}"),
    }
}

#[test]
fn function_signatures_preserve_empty_single_and_multiple_lists() {
    let resources = fixture();
    for visibility in ["internal", "external"] {
        let external = visibility == "external";
        let id = |signature: &str| format!("t_function_{visibility}_nonpayable{signature}");
        assert_signature(
            &resources,
            &id("$__$returns$__$"),
            external,
            (EMPTY_TUPLE, &[]),
            None,
        );
        assert_signature(
            &resources,
            &id("$_t_uint32_$returns$_t_uint32_$"),
            external,
            (SINGLE_TUPLE, &["t_uint32"]),
            Some((SINGLE_TUPLE, &["t_uint32"])),
        );
        assert_signature(
            &resources,
            &id("$_t_uint32_$_t_bool_$_t_address_$returns$_t_bytes4_$_t_int16_$"),
            external,
            (PARAMETER_TUPLE, &["t_uint32", "t_bool", "t_address"]),
            Some((RETURN_TUPLE, &["t_bytes4", "t_int16"])),
        );
    }
    assert_signature(
        &resources,
        "t_function_external_nonpayable$_t_uint32_$returns$__$",
        true,
        (SINGLE_TUPLE, &["t_uint32"]),
        None,
    );
    assert_signature(
        &resources,
        "t_function_external_nonpayable$__$returns$_t_uint32_$",
        true,
        (EMPTY_TUPLE, &[]),
        Some((SINGLE_TUPLE, &["t_uint32"])),
    );
    assert_eq!(
        resources
            .types
            .values()
            .filter(|document| matches!(document, TypeDocument::Function { .. }))
            .count(),
        8
    );
}

#[test]
fn callable_declarations_add_tuples_without_duplicating_function_type_lists() {
    let resources = fixture();
    let tuple_ids = resources
        .types
        .iter()
        .filter(|(_, document)| matches!(document, TypeDocument::Tuple { .. }))
        .map(|(id, _)| id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        tuple_ids,
        BTreeSet::from([
            EMPTY_TUPLE,
            SINGLE_TUPLE,
            PARAMETER_TUPLE,
            RETURN_TUPLE,
            "t_tuple$_t_uint8_$_t_bool_$",
            "t_tuple$_t_uint80_$",
            "t_tuple$_t_uint64_$",
            "t_tuple$_t_bool_$",
        ])
    );
    for (id, components) in [
        ("t_tuple$_t_uint8_$_t_bool_$", vec!["t_uint8", "t_bool"]),
        ("t_tuple$_t_uint80_$", vec!["t_uint80"]),
        ("t_tuple$_t_uint64_$", vec!["t_uint64"]),
        ("t_tuple$_t_bool_$", vec!["t_bool"]),
    ] {
        assert_tuple(&resources, &TypeReference::Id(id.to_owned()), &components);
    }
    assert!(!resources.types.contains_key("t_uint200"));
    assert!(!resources.types.contains_key("t_uint208"));
}

#[test]
fn tuple_arguments_and_results_are_not_flattened() {
    for inline in [false, true] {
        let pair = json!({"kind": "tuple", "contains": [
            {"type": {"id": "u"}}, {"type": {"id": "b"}}
        ]});
        let outer = json!({"kind": "tuple", "contains": [{"type": {"id": "pair"}}]});
        let pair_specifier = if inline {
            pair.clone()
        } else {
            json!({"id": "pair"})
        };
        let outer_specifier = if inline {
            outer.clone()
        } else {
            json!({"id": "outer"})
        };
        let resources = Resources::parse(&json!({"types": {
            "u": {"kind": "uint", "bits": 32}, "b": {"kind": "bool"},
            "pair": pair, "outer": outer,
            "multiple": {"kind": "function", "internal": true, "contains": {
                "parameters": {"type": pair_specifier}, "returns": {"type": pair_specifier}
            }},
            "nested": {"kind": "function", "internal": true, "contains": {
                "parameters": {"type": outer_specifier}, "returns": {"type": outer_specifier}
            }}
        }}))
        .unwrap();
        assert!(resources.dangling_references().is_empty());
        for (id, components, label) in [
            ("multiple", vec!["u", "b"], "(uint32, bool)"),
            ("nested", vec!["pair"], "((uint32, bool))"),
        ] {
            let TypeDocument::Function {
                parameters,
                returns,
                ..
            } = resources.type_document(id).unwrap()
            else {
                panic!("{id} is not a function type");
            };
            for reference in [parameters.as_ref(), returns.as_deref().unwrap()] {
                assert_tuple(&resources, reference, &components);
                assert_eq!(resources.label(reference), label);
                assert_eq!(matches!(reference, TypeReference::Inline(_)), inline);
            }
        }
    }
}

#[test]
fn missing_references_in_parameter_and_return_lists_are_reported() {
    for missing in [PARAMETER_TUPLE, RETURN_TUPLE, "t_int16"] {
        let mut resources = fixture();
        assert!(resources.types.remove(missing).is_some());
        assert_eq!(resources.dangling_references(), [missing.to_owned()]);
        assert!(resources
            .resolve(&TypeReference::Id(missing.to_owned()))
            .is_err());
    }
}
