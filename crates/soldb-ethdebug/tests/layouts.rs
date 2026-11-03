//! Decode compiler-produced layouts against memory and storage recorded from the same code.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use soldb_core::decode_hex;
use soldb_ethdebug::{parse_word, Location, Machine, Pointer, Resources, TypeReference, Word};

const TABLES: &str =
    include_str!("../../../test/fixtures/ethdebug-layouts/ethdebug_resources.json");
const SNAPSHOT: &str = include_str!("../../../test/fixtures/ethdebug-layouts/snapshot.json");
const ARRAYS: &str = include_str!("../../../test/fixtures/ethdebug-layouts/arrays.json");

struct Snapshot {
    memory: Vec<u8>,
    calldata: Vec<u8>,
    output: Vec<u8>,
    storage: BTreeMap<Word, Word>,
    transient: BTreeMap<Word, Word>,
}

impl Snapshot {
    fn parse(source: &str) -> Self {
        let source: Value = serde_json::from_str(source).unwrap();
        let words = |key: &str| {
            source[key]
                .as_object()
                .unwrap()
                .iter()
                .map(|(slot, value)| {
                    (
                        parse_word(slot).unwrap(),
                        parse_word(value.as_str().unwrap()).unwrap(),
                    )
                })
                .collect()
        };
        Self {
            memory: decode_hex(source["memory"].as_str().unwrap()).unwrap(),
            calldata: decode_hex(source["calldata"].as_str().unwrap()).unwrap(),
            output: decode_hex(source["output"].as_str().unwrap()).unwrap(),
            storage: words("storage"),
            transient: words("transient"),
        }
    }

    fn output_word(&self, index: usize) -> u64 {
        u64::from_be_bytes(
            self.output[index * 32 + 24..(index + 1) * 32]
                .try_into()
                .unwrap(),
        )
    }
}

impl Machine for Snapshot {
    fn word(&self, location: Location, slot: &Word) -> Option<Word> {
        match location {
            Location::Storage => self.storage.get(slot).copied(),
            Location::Transient => self.transient.get(slot).copied(),
            _ => None,
        }
    }

    fn bytes(&self, location: Location, offset: u64, length: u64) -> Option<Vec<u8>> {
        let bytes = match location {
            Location::Memory => &self.memory,
            Location::Calldata => &self.calldata,
            _ => return None,
        };
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(length).ok()?)?;
        bytes.get(start..end).map(<[u8]>::to_vec)
    }
}

fn tables() -> (Value, Resources) {
    let tables: Value = serde_json::from_str(TABLES).unwrap();
    let resources = Resources::parse(&tables).unwrap();
    assert!(resources.dangling_references().is_empty());
    (tables, resources)
}

fn read(
    resources: &Resources,
    snapshot: &Snapshot,
    location: &str,
    type_id: &str,
    arguments: Value,
) -> Vec<(String, String)> {
    let pointer_id = format!("{location}-{type_id}");
    assert!(resources.pointer_template(&pointer_id).is_some());
    assert!(resources.pointer_template(type_id).is_none());
    let pointer =
        Pointer::parse(&json!({"define": arguments, "in": {"template": pointer_id}})).unwrap();
    resources
        .read_variable(&TypeReference::Id(type_id.to_owned()), &pointer, snapshot)
        .unwrap()
        .into_iter()
        .map(|value| {
            assert!(value.available, "{}: {}", value.name, value.display);
            (value.name, value.display)
        })
        .collect()
}

#[test]
fn the_same_record_decodes_from_storage_memory_and_calldata() {
    let (tables, resources) = tables();
    let snapshot = Snapshot::parse(SNAPSHOT);
    let record = tables["types"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, document)| document["definition"]["name"] == "Record")
        .unwrap()
        .0;
    let expected = [
        ("point-x", "7"),
        ("point-y", "-3"),
        ("values-item", "11"),
        ("values-item", "513"),
        ("text", "\"hello\""),
        ("tag", "0x12345678"),
        ("price", "42"),
        ("color", "Color.Green"),
        (
            "callback",
            "0x1111111111111111111111111111111111111111abcdef01",
        ),
    ]
    .map(|(name, display)| (name.to_owned(), display.to_owned()))
    .to_vec();
    for (location, arguments) in [
        ("storage", json!({"slot": 0})),
        ("memory", json!({"offset": snapshot.output_word(0)})),
        ("calldata", json!({"offset": 36})),
    ] {
        assert_eq!(
            read(&resources, &snapshot, location, record, arguments),
            expected,
            "{location}"
        );
    }
}

#[test]
fn value_templates_use_their_layouts_alignment_and_packing() {
    let (_, resources) = tables();
    let snapshot = Snapshot::parse(SNAPSHOT);
    for (location, type_id, arguments, expected) in [
        ("storage", "t_int16", json!({"slot": 0, "offset": 1}), "-3"),
        (
            "transient",
            "t_uint16",
            json!({"slot": 0, "offset": 0}),
            "11",
        ),
        (
            "memory",
            "t_bytes4",
            json!({"offset": snapshot.output_word(0) + 96}),
            "0x12345678",
        ),
        ("calldata", "t_bytes4", json!({"offset": 164}), "0x12345678"),
        ("calldata", "t_int16", json!({"offset": 68}), "-3"),
    ] {
        assert_eq!(
            read(&resources, &snapshot, location, type_id, arguments),
            [(String::new(), expected.to_owned())]
        );
    }
}

#[test]
fn nested_static_and_dynamic_arrays_use_different_head_layouts() {
    let (_, resources) = tables();
    let snapshot = Snapshot::parse(ARRAYS);
    let fixed_id = "t_array$_t_array$_t_uint16_$2_storage_$3_storage";
    let blobs_id = "t_array$_t_array$_t_bytes_storage_$dyn_storage_$2_storage";
    for (location, fixed_offset, blobs_offset) in [
        ("memory", snapshot.output_word(0), snapshot.output_word(1)),
        (
            "calldata",
            4,
            4 + u64::from_be_bytes(snapshot.calldata[220..228].try_into().unwrap()),
        ),
    ] {
        let fixed = read(
            &resources,
            &snapshot,
            location,
            fixed_id,
            json!({"offset": fixed_offset}),
        );
        assert_eq!(
            fixed
                .iter()
                .map(|(_, display)| display.as_str())
                .collect::<Vec<_>>(),
            ["1", "2", "3", "4", "5", "6"]
        );
        assert!(fixed.iter().all(|(name, _)| name == "item-item"));
        let blobs = read(
            &resources,
            &snapshot,
            location,
            blobs_id,
            json!({"offset": blobs_offset}),
        );
        assert_eq!(
            blobs,
            [
                ("item-item".to_owned(), "0x1122".to_owned()),
                ("item-item".to_owned(), "0x".to_owned())
            ]
        );
    }
}

#[test]
fn missing_memory_is_reported_instead_of_read_as_zero() {
    let (_, resources) = tables();
    let mut snapshot = Snapshot::parse(SNAPSHOT);
    snapshot.memory.clear();
    let pointer =
        Pointer::parse(&json!({"define": {"offset": 0}, "in": {"template": "memory-t_uint16"}}))
            .unwrap();
    let values = resources
        .read_variable(
            &TypeReference::Id("t_uint16".to_owned()),
            &pointer,
            &snapshot,
        )
        .unwrap();
    assert_eq!(values.len(), 1);
    assert!(!values[0].available);
}
