//! Finding and loading one contract's debug artifacts from a directory.
//!
//! An output directory holds the global resource file (`ethdebug.json` from older
//! compilers, `ethdebug_resources.json` from modern ones), one program artifact per
//! contract and environment (`<Contract>_ethdebug.json` for creation code,
//! `<Contract>_ethdebug-runtime.json` for runtime code), and, for compilers that predate
//! ETHDebug, a `combined.json` with legacy source maps. [`load_debug_program`] is the one
//! path through all of that: ETHDebug first, the legacy map as a fallback, and the
//! source text read from the compilation record or from disk. The CLI and the DAP server
//! both load through it, so a directory that works in one works in the other.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use soldb_core::{SoldbError, SoldbResult};

use crate::metadata::{read_compilation_source, EthdebugInfo};
use crate::source_map::{load_source_map_program, SourceMapEnvironment};
use crate::storage_layout::StorageLayout;

/// One contract's debug information as loaded from its artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugProgram {
    pub info: EthdebugInfo,
    /// The ETHDebug resources record: the compilation, types, and pointers.
    pub resources: Value,
    /// Source text by source id, for every source that could be read.
    pub source_contents: BTreeMap<u64, String>,
    /// True when the program came from a legacy `srcmap` rather than ETHDebug.
    pub legacy: bool,
    /// The contract's storage layout, when it was compiled with `--storage-layout`.
    pub storage_layout: Option<StorageLayout>,
}

/// The global ETHDebug resource file in `root`, under either of its names.
#[must_use]
pub fn find_ethdebug_metadata(root: &Path) -> Option<PathBuf> {
    // Modern solc (>= ~0.8.32) renamed the global ETHDebug metadata file from
    // `ethdebug.json` to `ethdebug_resources.json`; accept either.
    [
        root.join("ethdebug.json"),
        root.join("ethdebug_resources.json"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

/// The ETHDebug program artifact for one contract and environment.
///
/// Prefers `<Contract><suffix>`; otherwise accepts a unique artifact whose name ends in
/// `_<Contract><suffix>`, or the only artifact with that suffix in the directory, which
/// is how a directory compiled for one contract loads with no name given.
#[must_use]
pub fn find_program_ethdebug(
    root: &Path,
    contract_name: &str,
    environment: SourceMapEnvironment,
) -> Option<PathBuf> {
    let suffix = program_suffix(environment);
    let named = root.join(format!("{contract_name}{suffix}"));
    if !contract_name.is_empty() && named.exists() {
        return Some(named);
    }

    let mut candidates = fs::read_dir(root)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(suffix))
        })
        .collect::<Vec<_>>();
    candidates.sort();

    if !contract_name.is_empty() {
        let contract_suffix = format!("_{contract_name}{suffix}");
        let mut matching = candidates.iter().filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(&contract_suffix))
        });
        let matched = matching.next().cloned();
        if matched.is_some() && matching.next().is_none() {
            return matched;
        }
    }

    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn program_suffix(environment: SourceMapEnvironment) -> &'static str {
    match environment {
        SourceMapEnvironment::Creation => "_ethdebug.json",
        SourceMapEnvironment::Runtime => "_ethdebug-runtime.json",
    }
}

/// The contract name a program artifact's file name carries.
#[must_use]
pub fn contract_name_from_program_path(
    path: &Path,
    environment: SourceMapEnvironment,
) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(program_suffix(environment)))
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

/// Reads a source file named by the compiler, trying it relative to the artifact
/// directory, to that directory's parent, and as given.
#[must_use]
pub fn read_debug_source(root: &Path, source_path: &str) -> Option<String> {
    let source = Path::new(source_path);
    let mut candidates = Vec::new();
    if source.is_absolute() {
        candidates.push(source.to_path_buf());
    } else {
        candidates.push(root.join(source));
        if let Some(parent) = root.parent() {
            candidates.push(parent.join(source));
        }
        candidates.push(source.to_path_buf());
    }

    candidates
        .into_iter()
        .find_map(|candidate| fs::read_to_string(candidate).ok())
}

/// Parses a JSON file, naming the file in the error.
pub fn read_json_file(path: &Path) -> SoldbResult<Value> {
    let content = fs::read_to_string(path).map_err(|error| {
        SoldbError::Message(format!("failed to read `{}`: {error}", path.display()))
    })?;
    serde_json::from_str(&content).map_err(|error| {
        SoldbError::Message(format!("invalid JSON in `{}`: {error}", path.display()))
    })
}

/// The resources record of an ETHDebug metadata file: its `resources` entry when it has
/// one, otherwise one assembled from the compilation, types, and pointers it carries.
pub fn ethdebug_resources_from_metadata(path: &Path, metadata: &Value) -> SoldbResult<Value> {
    if let Some(resources) = metadata.get("resources") {
        return Ok(resources.clone());
    }

    let Some(compilation) = metadata.get("compilation") else {
        return Err(SoldbError::Message(format!(
            "ETHDebug metadata {} does not contain resources or compilation",
            path.display()
        )));
    };

    Ok(json!({
        "compilation": compilation,
        "types": metadata.get("types").cloned().unwrap_or_else(|| json!({})),
        "pointers": metadata.get("pointers").cloned().unwrap_or_else(|| json!({})),
    }))
}

/// Loads a contract's debug program from `root`: the ETHDebug artifacts when present,
/// otherwise the legacy source map in `combined.json`.
///
/// `Ok(None)` means the directory holds neither for this contract. A present but
/// unreadable artifact is an error, so a caller never silently loses source attribution.
/// An empty `contract_name` loads the only program in the directory and takes its name
/// from the file.
pub fn load_debug_program(
    root: &Path,
    contract_name: &str,
    environment: SourceMapEnvironment,
) -> SoldbResult<Option<DebugProgram>> {
    let environment_name = match environment {
        SourceMapEnvironment::Creation => "create",
        SourceMapEnvironment::Runtime => "call",
    };
    if let Some(program_path) = find_program_ethdebug(root, contract_name, environment) {
        let metadata_path = find_ethdebug_metadata(root).ok_or_else(|| {
            SoldbError::Message(format!(
                "No ETHDebug metadata file (ethdebug.json or ethdebug_resources.json) found in {}",
                root.display()
            ))
        })?;
        let metadata = read_json_file(&metadata_path)?;
        let program = read_json_file(&program_path)?;
        let resources = ethdebug_resources_from_metadata(&metadata_path, &metadata)?;
        let name = if contract_name.is_empty() {
            contract_name_from_program_path(&program_path, environment)
                .unwrap_or_else(|| "Contract".to_owned())
        } else {
            contract_name.to_owned()
        };
        let info = EthdebugInfo::from_artifacts(&name, environment_name, &metadata, &program)
            .map_err(|error| SoldbError::Message(format!("{}: {error}", program_path.display())))?;
        let source_contents = read_sources(root, &info, BTreeMap::new());
        let storage_layout = load_storage_layout(root, &info.contract_name)?;
        return Ok(Some(DebugProgram {
            info,
            resources,
            source_contents,
            legacy: false,
            storage_layout,
        }));
    }

    let Some(program) = load_source_map_program(root, contract_name, environment)? else {
        return Ok(None);
    };
    let source_contents = read_sources(root, &program.info, program.source_contents);
    let storage_layout = match program.storage_layout {
        Some(layout) => Some(layout),
        None => load_storage_layout(root, &program.info.contract_name)?,
    };
    Ok(Some(DebugProgram {
        info: program.info,
        resources: program.resources,
        source_contents,
        legacy: true,
        storage_layout,
    }))
}

/// The `<Contract>_storage.json` that `solc --storage-layout -o <root>` writes, when it
/// is there. A missing file is not an error: the layout is optional debug information.
/// An unreadable one is, because the user compiled with it and would otherwise get a
/// silent "no storage layout" that looks identical to never having asked for it.
pub fn load_storage_layout(root: &Path, contract_name: &str) -> SoldbResult<Option<StorageLayout>> {
    let path = root.join(format!("{contract_name}_storage.json"));
    if !path.exists() {
        return Ok(None);
    }
    let value = read_json_file(&path)?;
    StorageLayout::parse(&value)
        .map(Some)
        .map_err(|error| SoldbError::Message(format!("{}: {error}", path.display())))
}

/// Fills in the source text for every source the program names, from the compilation
/// record first and from disk next to the artifacts otherwise.
fn read_sources(
    root: &Path,
    info: &EthdebugInfo,
    mut source_contents: BTreeMap<u64, String>,
) -> BTreeMap<u64, String> {
    for (source_id, source_path) in &info.sources {
        if source_contents.contains_key(source_id) {
            continue;
        }
        if let Some(source) = read_compilation_source(&info.compilation, *source_id)
            .or_else(|| read_debug_source(root, source_path))
        {
            source_contents.insert(*source_id, source);
        }
    }
    source_contents
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::{
        contract_name_from_program_path, ethdebug_resources_from_metadata, find_ethdebug_metadata,
        find_program_ethdebug, load_debug_program, load_storage_layout, read_debug_source,
        read_json_file,
    };
    use crate::source_map::SourceMapEnvironment;

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("soldb-artifacts-{label}-{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn loads_ethdebug_programs_with_their_sources() {
        let dir = temp_dir("ethdebug");
        let source =
            "contract Counter {\n  function set(uint256 x) public {\n    value = x;\n  }\n}\n";
        fs::write(dir.join("Counter.sol"), source).expect("source");
        fs::write(
            dir.join("ethdebug_resources.json"),
            json!({"compilation": {"sources": [{"id": 0, "path": "Counter.sol"}]}}).to_string(),
        )
        .expect("metadata");
        fs::write(
            dir.join("Counter_ethdebug-runtime.json"),
            json!({"instructions": [{
                "offset": 7,
                "operation": {"mnemonic": "STOP"},
                "context": {"code": {"source": {"id": 0}, "range": {"offset": 59, "length": 9}}}
            }]})
            .to_string(),
        )
        .expect("program");

        let program = load_debug_program(&dir, "Counter", SourceMapEnvironment::Runtime)
            .expect("load")
            .expect("present");
        assert!(!program.legacy);
        assert_eq!(program.info.contract_name, "Counter");
        assert_eq!(program.info.environment, "call");
        assert!(program.info.instruction_at_pc(7).is_some());
        assert_eq!(
            program.source_contents.get(&0).map(String::as_str),
            Some(source)
        );
        assert!(program.resources.get("compilation").is_some());
        // No `Counter_storage.json` yet: the layout is optional debug information.
        assert!(program.storage_layout.is_none());

        // No name: the only program in the directory, named after its file.
        let inferred = load_debug_program(&dir, "", SourceMapEnvironment::Runtime)
            .expect("load")
            .expect("present");
        assert_eq!(inferred.info.contract_name, "Counter");
        // Creation code is a different artifact, absent here.
        assert!(
            load_debug_program(&dir, "Counter", SourceMapEnvironment::Creation)
                .expect("load")
                .is_none()
        );
        assert_eq!(
            contract_name_from_program_path(
                &dir.join("Counter_ethdebug-runtime.json"),
                SourceMapEnvironment::Runtime
            )
            .as_deref(),
            Some("Counter")
        );
        assert_eq!(
            find_ethdebug_metadata(&dir),
            Some(dir.join("ethdebug_resources.json"))
        );
        assert_eq!(
            find_program_ethdebug(&dir, "Other", SourceMapEnvironment::Runtime),
            Some(dir.join("Counter_ethdebug-runtime.json")),
            "a single artifact serves any name"
        );
        assert_eq!(
            read_debug_source(&dir, "Counter.sol").as_deref(),
            Some(source)
        );
        assert!(read_debug_source(&dir, "Missing.sol").is_none());

        // `solc --storage-layout -o <dir>` writes one file per contract; the loader picks
        // it up, and a malformed one is an error rather than a silent miss.
        fs::write(
            dir.join("Counter_storage.json"),
            json!({
                "storage": [{
                    "astId": 1,
                    "contract": "Counter.sol:Counter",
                    "label": "value",
                    "offset": 0,
                    "slot": "1",
                    "type": "t_uint256"
                }],
                "types": {"t_uint256": {
                    "encoding": "inplace",
                    "label": "uint256",
                    "numberOfBytes": "32"
                }}
            })
            .to_string(),
        )
        .expect("layout");
        let program = load_debug_program(&dir, "Counter", SourceMapEnvironment::Runtime)
            .expect("load")
            .expect("present");
        let layout = program.storage_layout.as_ref().expect("storage layout");
        assert_eq!(layout.variable("value").expect("value").slot[31], 1);
        assert!(load_storage_layout(&dir, "Missing")
            .expect("absent")
            .is_none());
        fs::write(dir.join("Counter_storage.json"), "{}").expect("layout");
        let error = load_debug_program(&dir, "Counter", SourceMapEnvironment::Runtime)
            .expect_err("a storage layout that cannot be read is reported");
        assert!(
            error.to_string().contains("Counter_storage.json"),
            "{error}"
        );
    }

    #[test]
    fn a_program_without_metadata_is_an_error_not_a_silent_miss() {
        let dir = temp_dir("no-metadata");
        fs::write(dir.join("Counter_ethdebug-runtime.json"), "{}").expect("program");
        let error = load_debug_program(&dir, "Counter", SourceMapEnvironment::Runtime)
            .expect_err("metadata is required");
        assert!(
            error.to_string().contains("No ETHDebug metadata file"),
            "{error}"
        );

        fs::write(dir.join("ethdebug.json"), "{not json").expect("metadata");
        let error = load_debug_program(&dir, "Counter", SourceMapEnvironment::Runtime)
            .expect_err("malformed metadata");
        assert!(error.to_string().contains("invalid JSON"), "{error}");
        assert!(read_json_file(&dir.join("absent.json")).is_err());
    }

    #[test]
    fn falls_back_to_legacy_source_maps() {
        let dir = temp_dir("legacy");
        let source =
            "contract Counter {\n  function set(uint256 x) public {\n    value = x;\n  }\n}\n";
        fs::write(dir.join("Counter.sol"), source).expect("source");
        let offset = source.find("value = x").expect("statement");
        fs::write(
            dir.join("combined.json"),
            json!({
                "sourceList": ["Counter.sol"],
                "contracts": {"Counter.sol:Counter": {
                    "bin-runtime": "60010000",
                    "srcmap-runtime": format!("{offset}:9:0:-:0;{offset}:9:0;{offset}:9:0")
                }}
            })
            .to_string(),
        )
        .expect("combined");

        let program = load_debug_program(&dir, "Counter", SourceMapEnvironment::Runtime)
            .expect("load")
            .expect("present");
        assert!(program.legacy);
        assert_eq!(
            program.source_contents.get(&0).map(String::as_str),
            Some(source)
        );
        assert!(program.info.instruction_at_pc(2).is_some());

        let empty = temp_dir("empty");
        assert!(
            load_debug_program(&empty, "Counter", SourceMapEnvironment::Runtime)
                .expect("load")
                .is_none()
        );
    }

    #[test]
    fn resources_come_from_the_record_or_are_assembled() {
        let path = PathBuf::from("ethdebug.json");
        let explicit = json!({"resources": {"compilation": {}}});
        assert_eq!(
            ethdebug_resources_from_metadata(&path, &explicit).expect("resources"),
            json!({"compilation": {}})
        );
        let assembled = json!({"compilation": {"sources": []}, "types": {"a": 1}});
        assert_eq!(
            ethdebug_resources_from_metadata(&path, &assembled).expect("resources"),
            json!({"compilation": {"sources": []}, "types": {"a": 1}, "pointers": {}})
        );
        let error = ethdebug_resources_from_metadata(&path, &json!({})).expect_err("neither");
        assert!(
            error.to_string().contains("does not contain resources"),
            "{error}"
        );
    }
}
