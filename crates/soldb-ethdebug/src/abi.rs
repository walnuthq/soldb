use serde::{Deserialize, Serialize};
use serde_json::Value;
use soldb_core::{SoldbError, SoldbResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub name: String,
    pub arg_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiInput {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub components: Vec<AbiInput>,
}

pub fn match_abi_types(parsed_types: &[String], abi_types: &[String]) -> bool {
    parsed_types.len() == abi_types.len()
        && parsed_types
            .iter()
            .zip(abi_types)
            .all(|(parsed_type, abi_type)| match_single_type(parsed_type, abi_type))
}

pub fn match_single_type(parsed_type: &str, abi_type: &str) -> bool {
    if parsed_type == abi_type {
        return true;
    }

    if parsed_type.starts_with('(') && parsed_type.ends_with(')') && abi_type == "tuple" {
        return true;
    }

    if let (Some(parsed_base), Some(abi_base)) =
        (parsed_type.strip_suffix("[]"), abi_type.strip_suffix("[]"))
    {
        return match_single_type(parsed_base, abi_base);
    }

    parsed_type.contains('(') && abi_type == "tuple"
}

pub fn parse_signature(signature: &str) -> Option<FunctionSignature> {
    let open = signature.find('(')?;
    if !signature.ends_with(')') {
        return None;
    }

    let name = &signature[..open];
    if name.is_empty() || !name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()) {
        return None;
    }

    let args = &signature[open + 1..signature.len() - 1];
    Some(FunctionSignature {
        name: name.to_owned(),
        arg_types: split_args(args)?,
    })
}

pub fn parse_tuple_arg(value: &Value, abi_input: &AbiInput) -> SoldbResult<Value> {
    let values = value
        .as_array()
        .ok_or_else(|| SoldbError::Message("Tuple argument must be an array".to_owned()))?;

    if values.len() < abi_input.components.len() {
        return Err(SoldbError::Message(format!(
            "Tuple argument has {} values but ABI expects {}",
            values.len(),
            abi_input.components.len()
        )));
    }

    let mut parsed = Vec::with_capacity(abi_input.components.len());
    for (index, component) in abi_input.components.iter().enumerate() {
        let component_value = &values[index];
        if component.ty == "tuple" {
            parsed.push(parse_tuple_arg(component_value, component)?);
        } else if component.ty.starts_with("tuple") && component.ty.ends_with("[]") {
            let tuple_array = component_value.as_array().ok_or_else(|| {
                SoldbError::Message("Tuple array argument must be an array".to_owned())
            })?;

            let parsed_items = tuple_array
                .iter()
                .map(|item| parse_tuple_arg(item, component))
                .collect::<SoldbResult<Vec<_>>>()?;
            parsed.push(Value::Array(parsed_items));
        } else {
            parsed.push(component_value.clone());
        }
    }

    Ok(Value::Array(parsed))
}

fn split_args(input: &str) -> Option<Vec<String>> {
    if input.trim().is_empty() {
        return Some(Vec::new());
    }

    let mut args = Vec::new();
    let mut depth = 0_i64;
    let mut current = String::new();

    for ch in input.chars() {
        match ch {
            ',' if depth == 0 => {
                let arg = current.trim();
                if !arg.is_empty() {
                    args.push(arg.to_owned());
                }
                current.clear();
            }
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
                current.push(ch);
            }
            _ => current.push(ch),
        }
    }

    if depth != 0 {
        return None;
    }

    let arg = current.trim();
    if !arg.is_empty() {
        args.push(arg.to_owned());
    }

    Some(args)
}

#[cfg(test)]
mod tests {
    use super::{match_abi_types, match_single_type, parse_signature, parse_tuple_arg, AbiInput};
    use serde_json::json;

    #[test]
    fn parses_nested_function_signatures() {
        let signature = parse_signature("foo((uint256,address),uint8[])").expect("valid");
        assert_eq!(signature.name, "foo");
        assert_eq!(signature.arg_types, ["(uint256,address)", "uint8[]"]);

        let noop = parse_signature("noop()").expect("valid");
        assert_eq!(noop.name, "noop");
        assert!(noop.arg_types.is_empty());

        assert!(parse_signature("not a signature").is_none());
        assert!(parse_signature("broken(uint256").is_none());
    }

    #[test]
    fn matches_tuple_and_array_types() {
        let parsed = vec![
            "uint256".to_owned(),
            "(address,uint256)".to_owned(),
            "uint256[]".to_owned(),
        ];
        let abi = vec![
            "uint256".to_owned(),
            "tuple".to_owned(),
            "uint256[]".to_owned(),
        ];

        assert!(match_abi_types(&parsed, &abi));
        assert!(match_single_type("tuple(uint256)", "tuple"));
        assert!(!match_single_type("uint8[]", "uint256[]"));
        assert!(!match_abi_types(&["uint256".to_owned()], &abi));
    }

    #[test]
    fn parses_tuple_arguments_recursively() {
        let abi_input: AbiInput = serde_json::from_value(json!({
            "type": "tuple",
            "components": [
                {"type": "uint256"},
                {"type": "tuple", "components": [{"type": "address"}]},
                {"type": "tuple[]", "components": [{"type": "uint256"}]}
            ]
        }))
        .expect("abi input");

        let parsed =
            parse_tuple_arg(&json!([1, ["0xabc"], [[2], [3]]]), &abi_input).expect("tuple parses");
        assert_eq!(parsed, json!([1, ["0xabc"], [[2], [3]]]));

        assert!(parse_tuple_arg(&json!("bad"), &abi_input).is_err());
    }
}
