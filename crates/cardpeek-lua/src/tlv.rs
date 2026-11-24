use cardpeek_core::{ByteString, CoreError};
use mlua::{
    AnyUserData, Error as LuaError, Function, Lua, ObjectLike, Result as LuaResult, Table, Value,
};

use crate::{LuaBytes, asn1_split, binary};

const MAX_DEPTH: usize = 64;
const TYPES: [&str; 4] = [
    "TLV (Universal)",
    "TLV (Application-specific)",
    "TLV (Context-specific)",
    "TLV (Private)",
];
const ISO: &[(u32, &str)] = &[
    (0x02, "Integer"),
    (0x03, "Bit String"),
    (0x04, "Octet String"),
    (0x05, "Null"),
    (0x06, "Object identifier"),
    (0x13, "Printable String"),
    (0x14, "T61 String"),
    (0x16, "IA5 String"),
    (0x17, "UTC Time"),
    (0x30, "Sequence"),
    (0x31, "Set"),
    (0x41, "Country authority"),
    (0x42, "Issuer authority"),
    (0x43, "Card service data"),
    (0x44, "Initial access data"),
    (0x45, "Card issuer's data"),
    (0x46, "Pre-issuing data"),
    (0x47, "Card capabilities"),
    (0x48, "Status information"),
    (0x4F, "Application Identifier (AID)"),
    (0x50, "Application Label"),
    (0x51, "Path"),
    (0x52, "Command to perform"),
    (0x53, "Discretionary data"),
    (0x56, "Track 1 Equivalent Data"),
    (0x57, "Track 2 Equivalent Data"),
    (0x58, "Track 3 Equivalent Data"),
    (0x59, "Card expiration date"),
    (0x5A, "Application PAN"),
    (0x5B, "Name"),
    (0x5C, "Tag list"),
    (0x5D, "Tag length list"),
    (0x5E, "Log-in data"),
    (0x5F20, "Cardholder Name"),
    (0x5F21, "Track 1 Data"),
    (0x5F22, "Track 2 Data"),
    (0x5F23, "Track 3 Data"),
    (0x5F24, "Application Expiration Date"),
    (0x5F25, "Application Effective Date"),
    (0x5F26, "Card Effective Date"),
    (0x5F27, "Interchange control"),
    (0x5F28, "Country Code"),
    (0x5F29, "Interchange profile"),
    (0x5F2A, "Currency code"),
    (0x5F2B, "Date of birth"),
    (0x5F2C, "Cardholder nationality"),
    (0x5F2D, "Language Preference"),
    (0x5F2E, "Cardholder biometric data"),
    (0x5F2F, "PIN usage policy"),
    (0x5F30, "Service Code"),
    (0x5F32, "Transaction counter"),
    (0x5F34, "Application PAN Sequence Number"),
    (0x5F50, "Issuer URL"),
    (0x62, "File Control Parameters (FCP) Template"),
    (0x63, "wrapper"),
    (0x64, "File Management Data (FMD) Template"),
    (0x6F, "File Control Information (FCI) Template"),
    (0x72, "Issuer Script Template 2"),
    (0x73, "Discretionary DOs"),
    (0xA5, "FCI Proprietary Template"),
];
const NESTED_ISO: &[(&str, &str)] = &[
    ("62/80", "Data size excluding structural information"),
    ("62/81", "Data size including structural information"),
    ("62/82", "File descriptor"),
    ("62/83", "File identifier"),
    ("62/84", "Dedicated File (DF) Name"),
    ("62/85", "Proprietary information"),
    ("62/86", "Security attributes"),
    ("62/87", "EF containing FCI extension"),
    ("6F/80", "Data size excluding structural information"),
    ("6F/81", "Data size including structural information"),
    ("6F/82", "File descriptor"),
    ("6F/83", "File identifier"),
    ("6F/84", "Dedicated File (DF) Name"),
    ("6F/85", "Proprietary information"),
    ("6F/86", "Security attributes"),
    ("6F/87", "EF containing FCI extension"),
];

pub(crate) fn module(lua: &Lua) -> LuaResult<Table> {
    let module = lua.create_table()?;
    let parsers = lua.create_table()?;
    parsers.set(
        "number",
        lua.create_function(|lua, (node, data): (Table, AnyUserData)| {
            number_parser(lua, &node, &data)
        })?,
    )?;
    parsers.set(
        "printable",
        lua.create_function(|lua, (node, data): (Table, AnyUserData)| {
            printable_parser(lua, &node, &data)
        })?,
    )?;
    parsers.set(
        "date",
        lua.create_function(|lua, (node, data): (Table, AnyUserData)| {
            date_parser(lua, &node, &data)
        })?,
    )?;
    parsers.set(
        "country",
        lua.create_function(|lua, (node, data): (Table, AnyUserData)| {
            country_parser(lua, &node, &data)
        })?,
    )?;
    parsers.set(
        "currency",
        lua.create_function(|lua, (node, data): (Table, AnyUserData)| {
            currency_parser(lua, &node, &data)
        })?,
    )?;
    parsers.set(
        "oid",
        lua.create_function(|lua, (node, data): (Table, AnyUserData)| {
            oid_parser(lua, &node, &data)
        })?,
    )?;
    module.set("parsers", parsers)?;
    module.set(
        "parse",
        lua.create_function(
            |lua, (parent, data, reference): (Table, AnyUserData, Option<Table>)| {
                let reference = empty_table(lua, reference)?;
                let data = data.borrow::<LuaBytes>()?.0.clone();
                parse(lua, &parent, data, &reference, 0, 0)
            },
        )?,
    )?;
    module.set(
        "one",
        lua.create_function(
            |lua, (parent, tag, value, reference): (Table, u32, AnyUserData, Option<Table>)| {
                let reference = empty_table(lua, reference)?;
                let value = value.borrow::<LuaBytes>()?.0.clone();
                one(lua, &parent, tag, &value, &reference, 0, 0)
            },
        )?,
    )?;
    module.set(
        "info",
        lua.create_function(
            |lua, (tag, reference, parent): (u32, Option<Table>, Option<u32>)| {
                let reference = empty_table(lua, reference)?;
                info(lua, tag, &reference, parent.unwrap_or(0))
            },
        )?,
    )?;
    module.set(
        "tag_type",
        lua.create_function(|_lua, tag: u32| Ok(tag_type(tag)))?,
    )?;
    Ok(module)
}

fn empty_table(lua: &Lua, table: Option<Table>) -> LuaResult<Table> {
    table.map_or_else(|| lua.create_table(), Ok)
}

fn info(lua: &Lua, tag: u32, reference: &Table, parent: u32) -> LuaResult<(Value, Value)> {
    let key = format!("{tag:X}");
    let nested = format!("{parent:X}/{key}");
    for key in [&nested, &key] {
        let item: Value = reference.get(key.as_str())?;
        if let Value::Table(item) = item {
            return Ok((item.raw_get(1)?, item.raw_get(2)?));
        }
    }
    if let Some(name) = nested_name(&nested).or_else(|| iso_name(tag)) {
        let name = Value::String(lua.create_string(name)?);
        let parser = iso_parser(lua, tag)?;
        return Ok((name, parser));
    }
    Ok((Value::Nil, Value::Nil))
}

fn nested_name(key: &str) -> Option<&'static str> {
    NESTED_ISO
        .iter()
        .find_map(|(candidate, name)| (*candidate == key).then_some(*name))
}

fn iso_name(tag: u32) -> Option<&'static str> {
    ISO.iter()
        .find_map(|(candidate, name)| (*candidate == tag).then_some(*name))
}

fn iso_parser(lua: &Lua, tag: u32) -> LuaResult<Value> {
    let name = match tag {
        0x06 => Some("oid"),
        0x13 | 0x17 | 0x50 | 0x5B | 0x5F20 | 0x5F2D => Some("printable"),
        0x5F24..=0x5F26 => Some("date"),
        0x5F28 => Some("country"),
        0x5F2A => Some("currency"),
        _ => None,
    };
    let Some(name) = name else {
        return Ok(Value::Nil);
    };
    let cp: Table = lua.globals().get::<Function>("require")?.call("cardpeek")?;
    let tlv: Table = cp.get("tlv")?;
    let parsers: Table = tlv.get("parsers")?;
    parsers.get(name)
}

fn nested_iso_parser(lua: &Lua, tag: u32, parent: u32) -> LuaResult<Value> {
    let key = format!("{parent:X}/{tag:X}");
    let name = match key.as_str() {
        "62/80" | "62/81" | "6F/80" | "6F/81" => Some("number"),
        "62/84" | "6F/84" => Some("printable"),
        _ => None,
    };
    let Some(name) = name else {
        return Ok(Value::Nil);
    };
    let cp: Table = lua.globals().get::<Function>("require")?.call("cardpeek")?;
    let tlv: Table = cp.get("tlv")?;
    let parsers: Table = tlv.get("parsers")?;
    parsers.get(name)
}

fn parse(
    lua: &Lua,
    parent: &Table,
    mut data: ByteString,
    reference: &Table,
    parent_tag: u32,
    depth: usize,
) -> LuaResult<Value> {
    if depth > MAX_DEPTH {
        return Err(invalid("TLV nesting exceeds 64 levels"));
    }
    if data.is_empty() {
        return Ok(Value::Nil);
    }
    loop {
        let Some((tag, value, consumed)) = asn1_split(&data) else {
            let node: Table = parent.call_method("append", ("card", "Unparsed ASN1 data"))?;
            node.call_method::<()>("set", ("value", LuaBytes(data)))?;
            node.call_method::<()>("set", ("alternative", "(error)"))?;
            return Ok(Value::Table(node));
        };
        if tag == 0 {
            let node: Table = parent.call_method("append", ("card", "Unparsed ASN1 data"))?;
            node.call_method::<()>("set", ("value", LuaBytes(data)))?;
            node.call_method::<()>("set", ("alternative", "(error)"))?;
            return Ok(Value::Table(node));
        }
        let last = one(lua, parent, tag, &value, reference, parent_tag, depth)?;
        if matches!(last, Value::Boolean(false)) {
            return Ok(last);
        }
        if consumed == data.len() {
            return Ok(last);
        }
        data = data.slice(consumed, None);
    }
}

fn one(
    lua: &Lua,
    parent: &Table,
    tag: u32,
    value: &ByteString,
    reference: &Table,
    parent_tag: u32,
    depth: usize,
) -> LuaResult<Value> {
    let (name, parser) = info(lua, tag, reference, parent_tag)?;
    let name = match name {
        Value::String(name) => name.to_str()?.to_owned(),
        Value::Nil => tag_type(tag).to_owned(),
        _ => return Err(invalid("TLV names must be text")),
    };
    let node: Table = parent.call_method("append", ("item", name))?;
    node.call_method::<()>("set", ("identifier", format!("{tag:X}")))?;
    if compound(tag) {
        let result = parse(lua, &node, value.clone(), reference, tag, depth + 1)?;
        if matches!(result, Value::Boolean(false)) {
            node.call_method::<()>("remove", ())?;
            return Ok(Value::Boolean(false));
        }
    } else {
        let parser = if matches!(parser, Value::Nil) {
            nested_iso_parser(lua, tag, parent_tag)?
        } else {
            parser
        };
        match parser {
            Value::Function(parser) => {
                let parsed = parser.call::<Value>((node.clone(), LuaBytes(value.clone())))?;
                if matches!(parsed, Value::Boolean(false)) {
                    node.call_method::<()>("remove", ())?;
                    return Ok(Value::Boolean(false));
                }
            }
            Value::Nil => node.call_method::<()>("set", ("value", LuaBytes(value.clone())))?,
            _ => return Err(invalid("TLV value decoders must be functions")),
        }
    }
    Ok(Value::Table(node))
}

fn compound(tag: u32) -> bool {
    let mut first = tag;
    while first > 255 {
        first /= 256;
    }
    first & 0x20 != 0
}

fn tag_type(tag: u32) -> &'static str {
    TYPES[((tag >> 6) & 3) as usize]
}

fn number_parser(_lua: &Lua, node: &Table, data: &AnyUserData) -> LuaResult<bool> {
    let data = data.borrow::<LuaBytes>()?.0.clone();
    let number = binary::number(&data)?.to_string();
    set_value(node, &data, number)
}

fn printable_parser(_lua: &Lua, node: &Table, data: &AnyUserData) -> LuaResult<bool> {
    let data = data.borrow::<LuaBytes>()?.0.clone();
    if data.is_empty() {
        return Ok(false);
    }
    let alternative = if binary::printable(&data) {
        binary::format_bytes(&data, "%P")?
    } else {
        binary::format_bytes(&data, "%P (%D)")?
    };
    set_value(node, &data, alternative)
}

fn date_parser(_lua: &Lua, node: &Table, data: &AnyUserData) -> LuaResult<bool> {
    let data = data.borrow::<LuaBytes>()?.0.clone();
    let text = data.to_hex();
    if text.len() != 6 {
        return Err(invalid("TLV dates require three BCD bytes"));
    }
    let mut year = text[0..2]
        .parse::<i64>()
        .map_err(|_| invalid("invalid TLV year"))?
        + 1900;
    if year < 1980 {
        year += 100;
    }
    set_value(
        node,
        &data,
        format!("{}/{}/{year}", &text[2..4], &text[4..6]),
    )
}

fn country_parser(lua: &Lua, node: &Table, data: &AnyUserData) -> LuaResult<bool> {
    lookup_parser(lua, node, data, "country-codes", "country code")
}

fn currency_parser(lua: &Lua, node: &Table, data: &AnyUserData) -> LuaResult<bool> {
    lookup_parser(lua, node, data, "currency-codes", "currency code")
}

fn lookup_parser(
    lua: &Lua,
    node: &Table,
    data: &AnyUserData,
    module: &str,
    label: &str,
) -> LuaResult<bool> {
    let data = data.borrow::<LuaBytes>()?.0.clone();
    let code = data
        .to_hex()
        .parse::<u32>()
        .map_err(|_| invalid(format!("invalid {label}")))?;
    let require = lua.globals().get::<Function>("require")?;
    let names: Table = require.call(format!("shared.data.{module}"))?;
    let name: String = names.get::<Function>("name")?.call(code)?;
    set_value(node, &data, name)
}

fn oid_parser(_lua: &Lua, node: &Table, data: &AnyUserData) -> LuaResult<bool> {
    let data = data.borrow::<LuaBytes>()?.0.clone();
    if data.is_empty() {
        return Ok(false);
    }
    let first = data.elements()[0];
    let mut output = vec![(first / 40).to_string(), (first % 40).to_string()];
    let mut item = 0_u64;
    for value in data.elements() {
        item = item
            .checked_mul(128)
            .and_then(|item| item.checked_add(u64::from(value & 0x7F)))
            .ok_or_else(|| invalid("object identifier component exceeds 64 bits"))?;
        if *value < 0x80 {
            output.push(item.to_string());
            item = 0;
        }
    }
    set_value(node, &data, format!("{{ {} }}", output.join(" ")))
}

fn set_value(node: &Table, data: &ByteString, alternative: String) -> LuaResult<bool> {
    node.call_method::<()>("set", ("value", LuaBytes(data.clone())))?;
    node.call_method::<()>("set", ("alternative", alternative))?;
    Ok(true)
}

fn invalid(message: impl Into<String>) -> LuaError {
    LuaError::external(CoreError::InvalidDocument(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_compound_tags_and_classes() {
        assert!(compound(0xA5));
        assert!(!compound(0x5F20));
        assert_eq!(tag_type(0x9F4F), "TLV (Application-specific)");
    }
}
