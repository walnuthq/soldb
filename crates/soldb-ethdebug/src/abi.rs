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

pub fn encode_function_call(signature: &str, args: &[String]) -> SoldbResult<String> {
    let parsed = parse_signature(signature)
        .ok_or_else(|| SoldbError::Message(format!("Invalid function signature: {signature}")))?;
    if parsed.arg_types.len() != args.len() {
        return Err(SoldbError::Message(format!(
            "Wrong argument count for {signature}: expected {}, got {}",
            parsed.arg_types.len(),
            args.len()
        )));
    }

    let selector = function_selector(signature)?;
    let mut encoded = String::with_capacity(2 + 8 + args.len() * 64);
    encoded.push_str("0x");
    encoded.push_str(&bytes_to_hex(&selector));
    for (arg_type, arg_value) in parsed.arg_types.iter().zip(args) {
        encoded.push_str(&encode_static_arg(arg_type, arg_value)?);
    }
    Ok(encoded)
}

pub fn function_selector(signature: &str) -> SoldbResult<[u8; 4]> {
    let parsed = parse_signature(signature)
        .ok_or_else(|| SoldbError::Message(format!("Invalid function signature: {signature}")))?;
    let canonical = format!("{}({})", parsed.name, parsed.arg_types.join(","));
    let hash = keccak256(canonical.as_bytes());
    Ok([hash[0], hash[1], hash[2], hash[3]])
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0_u64; 25];
    let mut chunks = input.chunks_exact(RATE);

    for block in &mut chunks {
        absorb_block(&mut state, block);
        keccak_f1600(&mut state);
    }

    let remainder = chunks.remainder();
    let mut final_block = [0_u8; RATE];
    final_block[..remainder.len()].copy_from_slice(remainder);
    final_block[remainder.len()] ^= 0x01;
    final_block[RATE - 1] ^= 0x80;
    absorb_block(&mut state, &final_block);
    keccak_f1600(&mut state);

    let mut output = [0_u8; 32];
    for (index, chunk) in output.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&state[index].to_le_bytes());
    }
    output
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

fn encode_static_arg(arg_type: &str, value: &str) -> SoldbResult<String> {
    let arg_type = arg_type.trim();
    if arg_type.starts_with("uint") {
        return encode_uint_arg(arg_type, value);
    }
    if arg_type.starts_with("int") {
        return encode_int_arg(arg_type, value);
    }
    if arg_type == "address" {
        return encode_address_arg(value);
    }
    if arg_type == "bool" {
        return encode_bool_arg(value);
    }
    if arg_type == "bytes32" {
        return encode_bytes32_arg(value);
    }

    Err(SoldbError::Message(format!(
        "ABI encoding for type '{arg_type}' is not ported yet"
    )))
}

fn encode_uint_arg(arg_type: &str, value: &str) -> SoldbResult<String> {
    validate_uint_type(arg_type)?;
    let parsed = parse_u128_value(value)?;
    Ok(format!("{parsed:064x}"))
}

fn encode_int_arg(arg_type: &str, value: &str) -> SoldbResult<String> {
    validate_int_type(arg_type)?;
    let parsed = value
        .parse::<i128>()
        .map_err(|error| SoldbError::Message(format!("Invalid int value '{value}': {error}")))?;
    Ok(format!("{:064x}", parsed as u128))
}

fn encode_address_arg(value: &str) -> SoldbResult<String> {
    let address = value.trim_start_matches("0x");
    if address.len() != 40 || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SoldbError::Message(format!(
            "Invalid address value: {value}"
        )));
    }
    Ok(format!("{address:0>64}").to_ascii_lowercase())
}

fn encode_bool_arg(value: &str) -> SoldbResult<String> {
    match value {
        "true" | "1" => Ok(format!("{:064x}", 1)),
        "false" | "0" => Ok(format!("{:064x}", 0)),
        _ => Err(SoldbError::Message(format!("Invalid bool value: {value}"))),
    }
}

fn encode_bytes32_arg(value: &str) -> SoldbResult<String> {
    let bytes = value.trim_start_matches("0x");
    if bytes.len() != 64 || !bytes.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SoldbError::Message(format!(
            "Invalid bytes32 value: {value}"
        )));
    }
    Ok(bytes.to_ascii_lowercase())
}

fn validate_uint_type(arg_type: &str) -> SoldbResult<()> {
    validate_int_bit_width(arg_type.strip_prefix("uint").unwrap_or_default(), "uint")
}

fn validate_int_type(arg_type: &str) -> SoldbResult<()> {
    validate_int_bit_width(arg_type.strip_prefix("int").unwrap_or_default(), "int")
}

fn validate_int_bit_width(width: &str, label: &str) -> SoldbResult<()> {
    if width.is_empty() {
        return Ok(());
    }

    let bits = width.parse::<u16>().map_err(|error| {
        SoldbError::Message(format!("Invalid {label} bit width '{width}': {error}"))
    })?;
    if bits == 0 || bits > 256 || bits % 8 != 0 {
        return Err(SoldbError::Message(format!(
            "Invalid {label} bit width: {bits}"
        )));
    }
    Ok(())
}

fn parse_u128_value(value: &str) -> SoldbResult<u128> {
    if let Some(hex) = value.strip_prefix("0x") {
        u128::from_str_radix(hex, 16)
            .map_err(|error| SoldbError::Message(format!("Invalid uint value '{value}': {error}")))
    } else {
        value
            .parse::<u128>()
            .map_err(|error| SoldbError::Message(format!("Invalid uint value '{value}': {error}")))
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
    for (lane, chunk) in block.chunks_exact(8).enumerate() {
        state[lane] ^= u64::from_le_bytes(chunk.try_into().expect("8-byte lane"));
    }
}

fn keccak_f1600(state: &mut [u64; 25]) {
    const RHO: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
        14,
    ];
    const RC: [u64; 24] = [
        0x0000_0000_0000_0001,
        0x0000_0000_0000_8082,
        0x8000_0000_0000_808a,
        0x8000_0000_8000_8000,
        0x0000_0000_0000_808b,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8009,
        0x0000_0000_0000_008a,
        0x0000_0000_0000_0088,
        0x0000_0000_8000_8009,
        0x0000_0000_8000_000a,
        0x0000_0000_8000_808b,
        0x8000_0000_0000_008b,
        0x8000_0000_0000_8089,
        0x8000_0000_0000_8003,
        0x8000_0000_0000_8002,
        0x8000_0000_0000_0080,
        0x0000_0000_0000_800a,
        0x8000_0000_8000_000a,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8080,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8008,
    ];

    for round_constant in RC {
        let mut c = [0_u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        let mut d = [0_u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        let mut b = [0_u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                let index = x + 5 * y;
                b[y + 5 * ((2 * x + 3 * y) % 5)] = state[index].rotate_left(RHO[index]);
            }
        }

        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
            }
        }

        state[0] ^= round_constant;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        encode_function_call, function_selector, keccak256, match_abi_types, match_single_type,
        parse_signature, parse_tuple_arg, AbiInput,
    };
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

    #[test]
    fn computes_ethereum_keccak256_selectors() {
        assert_eq!(
            hex(keccak256(b"").as_ref()),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex(function_selector("transfer(address,uint256)")
                .expect("selector")
                .as_ref()),
            "a9059cbb"
        );
        assert_eq!(
            hex(function_selector("increment(uint256)")
                .expect("selector")
                .as_ref()),
            "7cf5dab0"
        );
    }

    #[test]
    fn encodes_static_function_calls() {
        assert_eq!(
            encode_function_call("increment(uint256)", &["4".to_owned()]).expect("calldata"),
            "0x7cf5dab00000000000000000000000000000000000000000000000000000000000000004"
        );
        assert_eq!(
            encode_function_call(
                "transfer(address,uint256)",
                &[
                    "0x0000000000000000000000000000000000000002".to_owned(),
                    "0x2a".to_owned(),
                ],
            )
            .expect("calldata"),
            "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000002a"
        );
    }

    #[test]
    fn rejects_unsupported_or_invalid_static_encoding() {
        assert!(encode_function_call("set(string)", &["hi".to_owned()]).is_err());
        assert!(encode_function_call("set(uint256)", &[]).is_err());
        assert!(encode_function_call("set(address)", &["0x1".to_owned()]).is_err());
        assert!(encode_function_call("set(bool)", &["maybe".to_owned()]).is_err());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
