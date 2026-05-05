use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthdebugSpec {
    pub address: Option<String>,
    pub name: Option<String>,
    pub path: String,
}

pub fn parse_ethdebug_spec(input: &str) -> EthdebugSpec {
    let parts = input.splitn(3, ':').collect::<Vec<_>>();
    if parts.len() == 3 && parts[0].starts_with("0x") {
        return EthdebugSpec {
            address: Some(parts[0].to_owned()),
            name: Some(parts[1].to_owned()),
            path: parts[2].to_owned(),
        };
    }

    EthdebugSpec {
        address: None,
        name: None,
        path: input.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_ethdebug_spec;

    #[test]
    fn parses_address_name_path_specs() {
        let spec = parse_ethdebug_spec("0xabc:Token:out");
        assert_eq!(spec.address.as_deref(), Some("0xabc"));
        assert_eq!(spec.name.as_deref(), Some("Token"));
        assert_eq!(spec.path, "out");
    }

    #[test]
    fn keeps_plain_paths_as_paths() {
        let spec = parse_ethdebug_spec("out");
        assert_eq!(spec.address, None);
        assert_eq!(spec.name, None);
        assert_eq!(spec.path, "out");
    }
}
