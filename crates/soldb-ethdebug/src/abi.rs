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

pub fn canonical_abi_input_type(input: &AbiInput) -> String {
    if let Some(suffix) = input.ty.strip_prefix("tuple") {
        let components = input
            .components
            .iter()
            .map(canonical_abi_input_type)
            .collect::<Vec<_>>()
            .join(",");
        return format!("({components}){suffix}");
    }
    input.ty.clone()
}

pub fn encode_abi_arguments(arg_types: &[String], args: &[String]) -> SoldbResult<String> {
    if arg_types.len() != args.len() {
        return Err(SoldbError::Message(format!(
            "Wrong argument count: expected {}, got {}",
            arg_types.len(),
            args.len()
        )));
    }

    let encoded_args = arg_types
        .iter()
        .zip(args)
        .map(|(arg_type, arg_value)| encode_arg(arg_type, arg_value))
        .collect::<SoldbResult<Vec<_>>>()?;
    Ok(encode_tuple_payload(encoded_args))
}

pub fn encode_function_call(signature: &str, args: &[String]) -> SoldbResult<String> {
    let parsed = parse_signature(signature)
        .ok_or_else(|| SoldbError::Message(format!("Invalid function signature: {signature}")))?;

    let selector = function_selector(signature)?;
    let payload = encode_abi_arguments(&parsed.arg_types, args).map_err(|error| {
        SoldbError::Message(format!(
            "Failed to encode arguments for {signature}: {error}"
        ))
    })?;

    let mut encoded = String::with_capacity(2 + 8 + payload.len());
    encoded.push_str("0x");
    encoded.push_str(&bytes_to_hex(&selector));
    encoded.push_str(&payload);
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

enum EncodedArg {
    Static(String),
    Dynamic(String),
}

impl EncodedArg {
    fn head_size_bytes(&self) -> usize {
        match self {
            Self::Static(words) => words.len() / 2,
            Self::Dynamic(_) => 32,
        }
    }

    fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic(_))
    }
}

fn encode_arg(arg_type: &str, value: &str) -> SoldbResult<EncodedArg> {
    let arg_type = arg_type.trim();
    if let Some((base_type, fixed_len)) = parse_array_type(arg_type)? {
        return encode_array_arg(base_type, fixed_len, value);
    }
    if let Some(component_types) = parse_tuple_type(arg_type) {
        return encode_tuple_arg(&component_types, value);
    }
    if arg_type == "string" {
        return Ok(EncodedArg::Dynamic(encode_dynamic_bytes(value.as_bytes())));
    }
    if arg_type == "bytes" {
        return Ok(EncodedArg::Dynamic(encode_dynamic_bytes(&parse_hex_bytes(
            value,
        )?)));
    }

    encode_static_arg(arg_type, value).map(EncodedArg::Static)
}

fn encode_tuple_payload(encoded_args: Vec<EncodedArg>) -> String {
    let head_size_bytes = encoded_args
        .iter()
        .map(EncodedArg::head_size_bytes)
        .sum::<usize>();
    let tail_size = encoded_args
        .iter()
        .filter_map(|arg| match arg {
            EncodedArg::Static(_) => None,
            EncodedArg::Dynamic(tail) => Some(tail.len()),
        })
        .sum::<usize>();

    let mut encoded = String::with_capacity(encoded_args.len() * 64 + tail_size);
    let mut tails = String::with_capacity(tail_size);
    let mut dynamic_offset = head_size_bytes;
    for arg in encoded_args {
        match arg {
            EncodedArg::Static(word) => encoded.push_str(&word),
            EncodedArg::Dynamic(tail) => {
                encoded.push_str(&format!("{dynamic_offset:064x}"));
                dynamic_offset += tail.len() / 2;
                tails.push_str(&tail);
            }
        }
    }
    encoded.push_str(&tails);
    encoded
}

fn parse_array_type(arg_type: &str) -> SoldbResult<Option<(&str, Option<usize>)>> {
    if !arg_type.ends_with(']') {
        return Ok(None);
    }
    let Some(open) = arg_type.rfind('[') else {
        return Ok(None);
    };
    let base_type = arg_type[..open].trim();
    if base_type.is_empty() {
        return Err(SoldbError::Message(format!(
            "Invalid array type: {arg_type}"
        )));
    }

    let length = &arg_type[open + 1..arg_type.len() - 1];
    if length.is_empty() {
        return Ok(Some((base_type, None)));
    }
    let length = length.parse::<usize>().map_err(|error| {
        SoldbError::Message(format!("Invalid fixed array length '{length}': {error}"))
    })?;
    Ok(Some((base_type, Some(length))))
}

fn parse_tuple_type(arg_type: &str) -> Option<Vec<String>> {
    let inner = arg_type.strip_prefix('(')?.strip_suffix(')')?;
    split_args(inner)
}

fn encode_tuple_arg(component_types: &[String], value: &str) -> SoldbResult<EncodedArg> {
    let values = parse_json_array_arg(value, "tuple")?;
    if values.len() != component_types.len() {
        return Err(SoldbError::Message(format!(
            "Tuple argument expects {} values, got {}",
            component_types.len(),
            values.len()
        )));
    }

    let encoded_components = component_types
        .iter()
        .zip(&values)
        .map(|(component_type, item)| encode_arg(component_type, &json_value_to_arg_string(item)?))
        .collect::<SoldbResult<Vec<_>>>()?;
    let is_dynamic = encoded_components.iter().any(EncodedArg::is_dynamic);
    let encoded = encode_tuple_payload(encoded_components);
    if is_dynamic {
        Ok(EncodedArg::Dynamic(encoded))
    } else {
        Ok(EncodedArg::Static(encoded))
    }
}

fn encode_array_arg(
    base_type: &str,
    fixed_len: Option<usize>,
    value: &str,
) -> SoldbResult<EncodedArg> {
    let values = parse_json_array_arg(value, &format!("{base_type}[]"))?;
    if let Some(expected) = fixed_len {
        if values.len() != expected {
            return Err(SoldbError::Message(format!(
                "Fixed array argument expects {expected} values, got {}",
                values.len()
            )));
        }
    }

    let encoded_elements = values
        .iter()
        .map(|item| encode_arg(base_type, &json_value_to_arg_string(item)?))
        .collect::<SoldbResult<Vec<_>>>()?;
    let has_dynamic_elements = encoded_elements.iter().any(EncodedArg::is_dynamic);
    let payload = encode_tuple_payload(encoded_elements);

    if fixed_len.is_some() {
        if has_dynamic_elements {
            Ok(EncodedArg::Dynamic(payload))
        } else {
            Ok(EncodedArg::Static(payload))
        }
    } else {
        let mut encoded = format!("{:064x}", values.len());
        encoded.push_str(&payload);
        Ok(EncodedArg::Dynamic(encoded))
    }
}

fn parse_json_array_arg(value: &str, label: &str) -> SoldbResult<Vec<Value>> {
    let values = serde_json::from_str::<Value>(value).map_err(|error| {
        SoldbError::Message(format!(
            "Array argument for type '{label}' must be JSON: {error}"
        ))
    })?;
    values.as_array().cloned().ok_or_else(|| {
        SoldbError::Message(format!(
            "Array argument for type '{label}' must be a JSON array"
        ))
    })
}

fn json_value_to_arg_string(value: &Value) -> SoldbResult<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Array(_) => serde_json::to_string(value)
            .map_err(|error| SoldbError::Message(format!("Invalid array argument: {error}"))),
        Value::Null => Err(SoldbError::Message(
            "Null ABI array values are not supported".to_owned(),
        )),
        Value::Object(_) => Err(SoldbError::Message(
            "Object ABI array values are not supported".to_owned(),
        )),
    }
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
    if let Some(width) = arg_type.strip_prefix("bytes") {
        return encode_fixed_bytes_arg(width, value);
    }

    Err(SoldbError::Message(format!(
        "ABI encoding for type '{arg_type}' is not ported yet"
    )))
}

fn encode_uint_arg(arg_type: &str, value: &str) -> SoldbResult<String> {
    let bits = validate_uint_type(arg_type)?;
    let encoded = parse_uint_word(value)?;
    validate_uint_fits_bits(&encoded, bits, value)?;
    Ok(encoded)
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
    encode_fixed_bytes_arg("32", value)
}

fn encode_fixed_bytes_arg(width: &str, value: &str) -> SoldbResult<String> {
    let width = width.parse::<usize>().map_err(|error| {
        SoldbError::Message(format!("Invalid fixed bytes width '{width}': {error}"))
    })?;
    if !(1..=32).contains(&width) {
        return Err(SoldbError::Message(format!(
            "Invalid fixed bytes width: {width}"
        )));
    }

    let bytes = parse_hex_bytes(value)?;
    if bytes.len() != width {
        return Err(SoldbError::Message(format!(
            "Invalid bytes{width} value: {value}"
        )));
    }
    let mut encoded = bytes_to_hex(&bytes);
    encoded.push_str(&"0".repeat((32 - width) * 2));
    Ok(encoded)
}

fn encode_dynamic_bytes(bytes: &[u8]) -> String {
    let mut encoded = format!("{:064x}", bytes.len());
    encoded.push_str(&bytes_to_hex(bytes));
    let padding_bytes = (32 - bytes.len() % 32) % 32;
    encoded.push_str(&"0".repeat(padding_bytes * 2));
    encoded
}

fn parse_hex_bytes(value: &str) -> SoldbResult<Vec<u8>> {
    let bytes = value.trim_start_matches("0x");
    if !bytes.len().is_multiple_of(2) || !bytes.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SoldbError::Message(format!("Invalid bytes value: {value}")));
    }

    bytes
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let pair = std::str::from_utf8(chunk)
                .map_err(|error| SoldbError::Message(format!("Invalid bytes value: {error}")))?;
            u8::from_str_radix(pair, 16)
                .map_err(|error| SoldbError::Message(format!("Invalid bytes value: {error}")))
        })
        .collect()
}

fn validate_uint_type(arg_type: &str) -> SoldbResult<u16> {
    validate_int_bit_width(arg_type.strip_prefix("uint").unwrap_or_default(), "uint")
}

fn validate_int_type(arg_type: &str) -> SoldbResult<()> {
    validate_int_bit_width(arg_type.strip_prefix("int").unwrap_or_default(), "int")?;
    Ok(())
}

fn validate_int_bit_width(width: &str, label: &str) -> SoldbResult<u16> {
    if width.is_empty() {
        return Ok(256);
    }

    let bits = width.parse::<u16>().map_err(|error| {
        SoldbError::Message(format!("Invalid {label} bit width '{width}': {error}"))
    })?;
    if bits == 0 || bits > 256 || bits % 8 != 0 {
        return Err(SoldbError::Message(format!(
            "Invalid {label} bit width: {bits}"
        )));
    }
    Ok(bits)
}

fn parse_uint_word(value: &str) -> SoldbResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(SoldbError::Message("Invalid uint value: empty".to_owned()));
    }

    if let Some(hex) = value.strip_prefix("0x") {
        if hex.is_empty() || hex.len() > 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(SoldbError::Message(format!("Invalid uint value: {value}")));
        }
        return Ok(format!("{:0>64}", hex.to_ascii_lowercase()));
    }

    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SoldbError::Message(format!("Invalid uint value: {value}")));
    }

    let mut bytes = [0_u8; 32];
    for digit in value.bytes().map(|byte| byte - b'0') {
        let mut carry = u16::from(digit);
        for byte in bytes.iter_mut().rev() {
            let next = u16::from(*byte) * 10 + carry;
            *byte = (next & 0xff) as u8;
            carry = next >> 8;
        }
        if carry != 0 {
            return Err(SoldbError::Message(format!(
                "Uint value exceeds 256 bits: {value}"
            )));
        }
    }
    Ok(bytes_to_hex(&bytes))
}

fn validate_uint_fits_bits(encoded_word: &str, bits: u16, value: &str) -> SoldbResult<()> {
    let unused_hex_digits = usize::from(256 - bits) / 4;
    if encoded_word[..unused_hex_digits]
        .bytes()
        .any(|byte| byte != b'0')
    {
        return Err(SoldbError::Message(format!(
            "Uint value does not fit uint{bits}: {value}"
        )));
    }
    Ok(())
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
        canonical_abi_input_type, encode_abi_arguments, encode_function_call, function_selector,
        keccak256, match_abi_types, match_single_type, parse_signature, parse_tuple_arg, AbiInput,
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
    fn canonicalizes_tuple_abi_input_types() {
        let abi_input: AbiInput = serde_json::from_value(json!({
            "type": "tuple[]",
            "components": [
                {"type": "uint256"},
                {"type": "tuple", "components": [{"type": "address"}]}
            ]
        }))
        .expect("abi input");

        assert_eq!(
            canonical_abi_input_type(&abi_input),
            "(uint256,(address))[]"
        );
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
        assert_eq!(
            encode_function_call(
                "set(uint256)",
                &["1606938044258990275541962092341162602522202993782792835301376".to_owned()],
            )
            .expect("calldata"),
            "0x60fe47b10000000000000100000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn encodes_dynamic_function_calls() {
        let selector = hex(function_selector("set(string)").expect("selector").as_ref());
        assert_eq!(
            encode_function_call("set(string)", &["hi".to_owned()]).expect("calldata"),
            format!(
                "0x{selector}\
                0000000000000000000000000000000000000000000000000000000000000020\
                0000000000000000000000000000000000000000000000000000000000000002\
                6869{}",
                "0".repeat(60)
            )
        );

        let selector = hex(function_selector("processOrder(uint256,string,string)")
            .expect("selector")
            .as_ref());
        assert_eq!(
            encode_function_call(
                "processOrder(uint256,string,string)",
                &[
                    "10".to_owned(),
                    "express".to_owned(),
                    "electronic".to_owned()
                ],
            )
            .expect("calldata"),
            format!(
                "0x{selector}\
                000000000000000000000000000000000000000000000000000000000000000a\
                0000000000000000000000000000000000000000000000000000000000000060\
                00000000000000000000000000000000000000000000000000000000000000a0\
                0000000000000000000000000000000000000000000000000000000000000007\
                65787072657373{}\
                000000000000000000000000000000000000000000000000000000000000000a\
                656c656374726f6e6963{}",
                "0".repeat(50),
                "0".repeat(44)
            )
        );

        let selector = hex(function_selector("set(bytes)").expect("selector").as_ref());
        assert_eq!(
            encode_function_call("set(bytes)", &["0xabcd".to_owned()]).expect("calldata"),
            format!(
                "0x{selector}\
                0000000000000000000000000000000000000000000000000000000000000020\
                0000000000000000000000000000000000000000000000000000000000000002\
                abcd{}",
                "0".repeat(60)
            )
        );
    }

    #[test]
    fn encodes_fixed_bytes_function_calls() {
        let selector = hex(function_selector("set(bytes2)").expect("selector").as_ref());
        assert_eq!(
            encode_function_call("set(bytes2)", &["0xabcd".to_owned()]).expect("calldata"),
            format!("0x{selector}abcd{}", "0".repeat(60))
        );
    }

    #[test]
    fn encodes_abi_argument_payload_without_selector() {
        let arg_types = vec!["uint256".to_owned(), "string".to_owned()];
        let args = vec!["7".to_owned(), "hi".to_owned()];

        assert_eq!(
            encode_abi_arguments(&arg_types, &args).expect("payload"),
            format!(
                "\
                0000000000000000000000000000000000000000000000000000000000000007\
                0000000000000000000000000000000000000000000000000000000000000040\
                0000000000000000000000000000000000000000000000000000000000000002\
                6869{}",
                "0".repeat(60)
            )
        );
    }

    #[test]
    fn encodes_dynamic_array_function_calls() {
        assert_eq!(
            encode_function_call("set(uint256[])", &["[1,2,3]".to_owned()]).expect("calldata"),
            "0x6ea9bfc500000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003"
        );

        assert_eq!(
            encode_function_call("set(string[])", &["[\"a\",\"bb\"]".to_owned()])
                .expect("calldata"),
            "0x52e66db800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001610000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026262000000000000000000000000000000000000000000000000000000000000"
        );

        assert_eq!(
            encode_function_call(
                "mix(uint256[],string)",
                &["[1,2]".to_owned(), "ok".to_owned()],
            )
            .expect("calldata"),
            "0xb613ef8d000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000026f6b000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn encodes_fixed_array_and_tuple_function_calls() {
        assert_eq!(
            encode_function_call("set(uint256[3])", &["[1,2,3]".to_owned()]).expect("calldata"),
            "0xcf1d72d1000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003"
        );

        assert_eq!(
            encode_function_call(
                "mix(uint256[2],string)",
                &["[1,2]".to_owned(), "ok".to_owned()],
            )
            .expect("calldata"),
            "0x48ec1f2c00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000026f6b000000000000000000000000000000000000000000000000000000000000"
        );

        assert_eq!(
            encode_function_call(
                "set((uint256,address))",
                &["[5,\"0x0000000000000000000000000000000000000002\"]".to_owned()],
            )
            .expect("calldata"),
            "0x0193c8b800000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000002"
        );

        assert_eq!(
            encode_function_call("set((uint256,string))", &["[5,\"hi\"]".to_owned()])
                .expect("calldata"),
            "0xa16fc8d400000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000026869000000000000000000000000000000000000000000000000000000000000"
        );

        assert_eq!(
            encode_function_call("set(string[2])", &["[\"a\",\"bb\"]".to_owned()])
                .expect("calldata"),
            "0x74d379540000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001610000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026262000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn rejects_unsupported_or_invalid_encoding() {
        assert!(encode_function_call("set(uint256)", &[]).is_err());
        assert!(encode_function_call("set(uint8)", &["256".to_owned()]).is_err());
        assert!(encode_function_call("set(address)", &["0x1".to_owned()]).is_err());
        assert!(encode_function_call("set(bool)", &["maybe".to_owned()]).is_err());
        assert!(encode_function_call("set(bytes)", &["0xabc".to_owned()]).is_err());
        assert!(encode_function_call("set(bytes)", &["0xzz".to_owned()]).is_err());
        assert!(encode_function_call("set(bytes2)", &["0xab".to_owned()]).is_err());
        assert!(encode_function_call("set(bytes33)", &["0xab".to_owned()]).is_err());
        assert!(encode_function_call("set(uint256[])", &["1,2".to_owned()]).is_err());
        assert!(encode_function_call("set(address[])", &["[\"0x1\"]".to_owned()]).is_err());
        assert!(encode_function_call("set(uint256[2])", &["[1]".to_owned()]).is_err());
        assert!(encode_function_call("set((uint256,bool))", &["[1]".to_owned()]).is_err());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
