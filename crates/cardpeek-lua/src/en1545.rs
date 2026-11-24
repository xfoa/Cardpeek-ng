use cardpeek_core::{ByteString, CoreError};
use mlua::{
    AnyUserData, Error as LuaError, Function, Lua, MultiValue, ObjectLike, Result as LuaResult,
    Table, Value, Variadic,
};

use crate::{LuaBytes, binary};

const EPOCH: i64 = 852_076_800;
const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const ALPHA: [char; 32] = [
    '-', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
    'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '?', '?', '?', '?', ' ',
];

#[allow(clippy::too_many_lines)]
pub(crate) fn module(lua: &Lua) -> LuaResult<Table> {
    let module = lua.create_table()?;
    module.set("BITMAP", 1)?;
    module.set("REPEAT", 2)?;
    module.set("BITMAP_BE", 3)?;
    add_scalar(lua, &module, "date", |data, reference| {
        let days = binary::number(data)?;
        let seconds = epoch_offset(reference, days, 86_400)?;
        let (year, month, day) = civil_date(seconds);
        let weekday =
            WEEKDAYS[usize::try_from(seconds.div_euclid(86_400).rem_euclid(7)).unwrap_or(0)];
        Ok(format!(
            "{weekday} {month:02}/{day:02}/{:02}",
            year.rem_euclid(100)
        ))
    })?;
    add_scalar(lua, &module, "time", |data, _| {
        let minutes = field_number(data, 11)?;
        Ok(format!("{:02}:{:02}", (minutes / 60) % 24, minutes % 60))
    })?;
    add_scalar(lua, &module, "quarters", |data, _| {
        let value = field_number(data, 7)?;
        if value == 96 {
            return Ok("End of service".into());
        }
        if value == 127 {
            return Ok("Not significant".into());
        }
        let minutes = value * 15;
        Ok(format!("{:02}:{:02}", (minutes / 60) % 24, minutes % 60))
    })?;
    add_scalar(lua, &module, "date_time", |data, reference| {
        let seconds = epoch_offset(reference, binary::number(data)?, 1)?;
        let (year, month, day) = civil_date(seconds);
        let time = seconds.rem_euclid(86_400);
        let weekday =
            WEEKDAYS[usize::try_from(seconds.div_euclid(86_400).rem_euclid(7)).unwrap_or(0)];
        Ok(format!(
            "{weekday} {} {day:2} {:02}:{:02}:{:02} {year}",
            MONTHS[usize::try_from(month - 1).unwrap_or(0)],
            time / 3600,
            (time / 60) % 60,
            time % 60
        ))
    })?;
    add_scalar(lua, &module, "bcd_date", |data, _| {
        let value = data.convert(8).to_hex();
        if value.len() != 8 {
            return Err(invalid("EN 1545 BCD dates require 32 bits"));
        }
        Ok(format!(
            "{}/{}/{}",
            &value[6..8],
            &value[4..6],
            &value[0..4]
        ))
    })?;
    add_scalar(lua, &module, "alpha", |data, _| {
        let mut output = String::new();
        for chunk in data.elements().chunks(5) {
            if chunk.len() != 5 {
                break;
            }
            let value = chunk
                .iter()
                .fold(0_usize, |value, bit| (value << 1) | usize::from(*bit));
            output.push(ALPHA.get(value).copied().unwrap_or('?'));
        }
        Ok(output)
    })?;
    module.set(
        "network_id",
        lua.create_function(|lua, data: AnyUserData| network_id(lua, &data))?,
    )?;
    add_scalar(lua, &module, "number", |data, _| {
        Ok(binary::number(data)?.to_string())
    })?;
    add_scalar(lua, &module, "amount", |data, _| {
        let value = binary::number(data)?;
        Ok(format!("{}.{:02} EUR", value / 100, value % 100))
    })?;
    add_scalar(lua, &module, "zones", |data, _| {
        let mut value = binary::number(data)?;
        let mut maximum = 0;
        let mut minimum = None;
        for zone in (1..=8).rev() {
            let bit = 1_u64 << (zone - 1);
            if value >= bit {
                if maximum == 0 {
                    maximum = zone;
                }
                value -= bit;
                if value == 0 {
                    minimum = Some(zone);
                }
            }
        }
        Ok(format!(
            "{}-{maximum}",
            minimum.map_or_else(|| "nil".into(), |value| value.to_string())
        ))
    })?;
    add_scalar(lua, &module, "undefined", |data, _| {
        Ok(format!("0x{}", data.convert(8).to_hex()))
    })?;
    module.set(
        "is_all",
        lua.create_function(|_lua, (data, expected): (AnyUserData, u8)| {
            let data = data.borrow::<LuaBytes>()?;
            Ok(!data.0.is_empty() && data.0.elements().iter().all(|value| *value == expected))
        })?,
    )?;
    module.set(
        "map",
        lua.create_function(
            |lua, (root, condition, formats): (Table, Value, Variadic<Table>)| {
                map(lua, root, condition, &formats)
            },
        )?,
    )?;
    Ok(module)
}

fn network_id(lua: &Lua, data: &AnyUserData) -> LuaResult<String> {
    let data = data.borrow::<LuaBytes>()?.0.clone();
    if data.len() < 24 {
        return Err(invalid("EN 1545 network identifiers require 24 bits"));
    }
    let country = bcd_number(&data.slice(0, Some(12)));
    let region = bcd_number(&data.slice(12, Some(12)));
    let countries: Table = lua_require(lua, "shared.data.country-codes")?;
    let networks: Table = lua_require(lua, "shared.data.network-codes")?;
    let country_name: String = match country {
        Some(country) => countries.get::<Function>("name")?.call(country)?,
        None => "Unknown country code nil".into(),
    };
    let network_name: String = match region {
        Some(region) => networks
            .get::<Function>("name")?
            .call((country.unwrap_or(0), region))?,
        None => "Unknown network nil/nil".into(),
    };
    Ok(format!("country {country_name} / network {network_name}"))
}

fn add_scalar(
    lua: &Lua,
    module: &Table,
    name: &str,
    decoder: impl Fn(&ByteString, Option<i64>) -> LuaResult<String> + 'static,
) -> LuaResult<()> {
    module.set(
        name,
        lua.create_function(move |_lua, (data, reference): (AnyUserData, Option<i64>)| {
            decoder(&data.borrow::<LuaBytes>()?.0, reference)
        })?,
    )
}

fn lua_require<T: mlua::FromLua>(lua: &Lua, name: &str) -> LuaResult<T> {
    lua.globals().get::<Function>("require")?.call(name)
}

fn field_number(data: &ByteString, length: usize) -> LuaResult<u64> {
    if data.len() < length {
        return Err(invalid(format!("EN 1545 field requires {length} bits")));
    }
    binary::number(&data.slice(0, Some(length)))
}

fn bcd_number(data: &ByteString) -> Option<u32> {
    data.convert(4).to_hex().parse().ok()
}

fn epoch_offset(reference: Option<i64>, value: u64, scale: i64) -> LuaResult<i64> {
    let reference = reference.unwrap_or(EPOCH);
    let value = i64::try_from(value)
        .ok()
        .and_then(|value| value.checked_mul(scale))
        .ok_or_else(|| invalid("EN 1545 date value exceeds the supported range"))?;
    if reference < 0 {
        reference
            .checked_neg()
            .and_then(|value| value.checked_sub(value))
    } else {
        reference.checked_add(value)
    }
    .ok_or_else(|| invalid("EN 1545 date exceeds the supported range"))
}

fn civil_date(seconds: i64) -> (i64, u32, u32) {
    let days = seconds.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

fn invalid(message: impl Into<String>) -> LuaError {
    LuaError::external(CoreError::InvalidDocument(message.into()))
}

fn map(lua: &Lua, root: Table, condition: Value, formats: &[Table]) -> LuaResult<()> {
    let cp: Table = lua.globals().get::<Function>("require")?.call("cardpeek")?;
    let nodes: Table = cp.get("nodes")?;
    let logs: Table = cp.get("log")?;
    let warning = logs.get::<Function>("warning")?;
    let (file_condition, record_condition) = match condition {
        Value::String(value) => {
            let file = lua.create_table()?;
            file.set("label", value)?;
            let record = lua.create_table()?;
            record.set("label", "record")?;
            (file, record)
        }
        Value::Table(condition) => (condition.get("file")?, condition.get("record")?),
        _ => return Err(invalid("EN 1545 map conditions must be text or a table")),
    };
    let find = nodes.get::<Function>("find")?;
    for file in NodeIterator::new(find.call((root, file_condition))?) {
        for record in NodeIterator::new(find.call((file?, record_condition.clone()))?) {
            let record = record?;
            let data: AnyUserData = record.call_method("get", "value")?;
            let bits = data.borrow::<LuaBytes>()?.0.convert(1);
            let mut parsed = 0_usize;
            for format in formats {
                let mut entries = format
                    .clone()
                    .pairs::<i64, Table>()
                    .collect::<LuaResult<Vec<_>>>()?;
                entries.sort_by_key(|(key, _)| *key);
                for (_, format) in entries {
                    let Some(block) =
                        binary::sub(&bits, i64::try_from(parsed).unwrap_or(i64::MAX), None)
                    else {
                        continue;
                    };
                    if !block.0.is_empty() && !block.0.elements().iter().all(|value| *value == 0) {
                        parsed = parsed.saturating_add(parse_format(
                            lua, &record, &format, &block.0, 0, &warning,
                        )?);
                    }
                }
            }
            if let Some(remaining) =
                binary::sub(&bits, i64::try_from(parsed).unwrap_or(i64::MAX), None)
                && remaining.0.elements().iter().any(|value| *value != 0)
            {
                let node = append_item(&record, "(remaining unparsed data)")?;
                node.call_method::<()>("set", ("value", remaining))?;
                node.call_method::<()>("set", ("alternative", "(binary data)"))?;
            }
        }
    }
    Ok(())
}

struct NodeIterator {
    next: Function,
}

impl NodeIterator {
    fn new(next: Function) -> Self {
        Self { next }
    }

    fn next(&mut self) -> LuaResult<Option<Table>> {
        match self.next.call::<Value>(())? {
            Value::Table(node) => Ok(Some(node)),
            Value::Nil => Ok(None),
            _ => Err(invalid("node iterator returned an invalid value")),
        }
    }
}

impl Iterator for NodeIterator {
    type Item = LuaResult<Table>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next().transpose()
    }
}

#[allow(clippy::too_many_lines)]
fn parse_format(
    lua: &Lua,
    parent: &Table,
    format: &Table,
    data: &ByteString,
    mut parsed: usize,
    warning: &Function,
) -> LuaResult<usize> {
    let length: usize = format.raw_get(2)?;
    let label: String = format.raw_get(3)?;
    let position = parsed;
    let item = binary::sub(
        data,
        i64::try_from(position).unwrap_or(i64::MAX),
        Some(i64::try_from(position + length.saturating_sub(1)).unwrap_or(i64::MAX)),
    );
    let node = append_item(parent, &label)?;
    match format.raw_get::<Value>(1)? {
        Value::Integer(kind @ (1 | 3)) => {
            if length > 0 {
                let Some(item) = item else {
                    node.call_method::<()>("remove", ())?;
                    warning.call::<()>(format!("Missing non-empty bitmap {label}"))?;
                    return Ok(0);
                };
                let bitmap_node = append_item(&node, &format!("({label}Bitmap)"))?;
                bitmap_node.call_method::<()>("set", ("value", item.clone()))?;
                let children: Table = format.raw_get(4)?;
                let mut keys = Vec::new();
                for entry in children.clone().pairs::<i64, Value>() {
                    keys.push(entry?.0);
                }
                keys.sort_unstable();
                let head_size = keys.len().saturating_sub(length);
                for key in keys.iter().take(head_size) {
                    let child: Table = children.raw_get(*key)?;
                    parsed = parsed.saturating_add(parse_format(
                        lua,
                        &node,
                        &child,
                        data,
                        position.saturating_add(parsed),
                        warning,
                    )?);
                }
                let ordered = if kind == 1 {
                    binary::reverse(&item.0)
                } else {
                    item.0
                };
                for (index, bit) in ordered.elements().iter().enumerate() {
                    if *bit == 1 {
                        let key = keys[head_size + index];
                        let child: Table = children.raw_get(key)?;
                        parsed = parsed.saturating_add(parse_format(
                            lua,
                            &node,
                            &child,
                            data,
                            position.saturating_add(parsed),
                            warning,
                        )?);
                    }
                }
            } else {
                let children: Table = format.raw_get(4)?;
                for child in children.sequence_values::<Table>() {
                    parsed = parsed.saturating_add(parse_format(
                        lua,
                        &node,
                        &child?,
                        data,
                        position.saturating_add(parsed),
                        warning,
                    )?);
                }
            }
        }
        Value::Integer(2) => {
            let Some(item) = item else {
                node.call_method::<()>("remove", ())?;
                warning.call::<()>(format!("Missing repeat entry {label}"))?;
                return Ok(0);
            };
            node.call_method::<()>("set", ("value", item.clone()))?;
            let count = binary::number(&item.0)?;
            node.call_method::<()>("set", ("alternative", count.to_string()))?;
            let children: Table = format.raw_get(4)?;
            let child: Table = children.raw_get(0)?;
            for _ in 0..count {
                parsed = parsed.saturating_add(parse_format(
                    lua,
                    &node,
                    &child,
                    data,
                    position.saturating_add(parsed),
                    warning,
                )?);
            }
        }
        Value::Function(decoder) => {
            let Some(item) = item else {
                node.call_method::<()>("remove", ())?;
                warning.call::<()>(format!("Missing entry {label}"))?;
                return Ok(0);
            };
            let arguments: Value = format.raw_get(4)?;
            let mut values = MultiValue::new();
            values.push_back(Value::UserData(lua.create_userdata(item.clone())?));
            match arguments {
                Value::Table(arguments) => {
                    for argument in arguments.sequence_values::<Value>() {
                        values.push_back(argument?);
                    }
                }
                Value::Nil => {}
                argument => values.push_back(argument),
            }
            let alternative = decoder.call::<Value>(values)?;
            if matches!(alternative, Value::Nil) {
                node.call_method::<()>("remove", ())?;
            } else {
                node.call_method::<()>("set", ("value", item))?;
                node.call_method::<()>("set", ("alternative", binary::value_string(alternative)?))?;
            }
        }
        _ => return Err(invalid("invalid EN 1545 field decoder")),
    }
    Ok(length)
}

fn append_item(parent: &Table, label: &str) -> LuaResult<Table> {
    parent.call_method("append", ("item", label))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_are_deterministic() {
        assert_eq!(civil_date(EPOCH), (1997, 1, 1));
        assert_eq!(civil_date(951_782_400), (2000, 2, 29));
        assert_eq!(civil_date(0), (1970, 1, 1));
    }
}
