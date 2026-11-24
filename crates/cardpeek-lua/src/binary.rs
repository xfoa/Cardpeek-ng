use std::fmt::Write;

use cardpeek_core::{ByteString, CoreError};
use mlua::{AnyUserData, Error as LuaError, Lua, Result as LuaResult, Table, Value, Variadic};

use crate::LuaBytes;

#[allow(clippy::too_many_lines)]
pub(crate) fn module(lua: &Lua) -> LuaResult<Table> {
    let module = lua.create_table()?;
    module.set(
        "new",
        lua.create_function(|_lua, (width, values): (u8, Vec<u8>)| {
            Ok(LuaBytes::new(
                ByteString::from_elements(width, values).map_err(LuaError::external)?,
            ))
        })?,
    )?;
    module.set(
        "from_hex",
        lua.create_function(|_lua, (input, width): (String, Option<u8>)| {
            Ok(LuaBytes::new(
                ByteString::from_hex(width.unwrap_or(8), &input).map_err(LuaError::external)?,
            ))
        })?,
    )?;
    module.set(
        "from_string",
        lua.create_function(|_lua, input: String| {
            Ok(LuaBytes::new(ByteString::from_bytes(input.into_bytes())))
        })?,
    )?;
    module.set(
        "all",
        lua.create_function(|_lua, (input, expected): (AnyUserData, u8)| {
            let input = input.borrow::<LuaBytes>()?.0.clone();
            Ok(!input.is_empty() && input.elements().iter().all(|value| *value == expected))
        })?,
    )?;
    module.set(
        "pack",
        lua.create_function(|_lua, (width, values): (u8, Variadic<Value>)| {
            let mut elements = Vec::new();
            for value in values {
                append_value(&mut elements, width, value)?;
            }
            Ok(LuaBytes(
                ByteString::from_elements(width, elements).map_err(LuaError::external)?,
            ))
        })?,
    )?;
    module.set(
        "concat",
        lua.create_function(|_lua, values: Variadic<Value>| {
            let mut result = ByteString::new(8);
            let mut initialized = false;
            for value in values {
                let value = match value {
                    Value::UserData(value) => value.borrow::<LuaBytes>()?.0.clone(),
                    value => {
                        let mut elements = Vec::new();
                        append_value(&mut elements, 8, value)?;
                        ByteString::from_elements(8, elements).map_err(LuaError::external)?
                    }
                };
                if initialized {
                    result.append(&value).map_err(LuaError::external)?;
                } else {
                    result = value;
                    initialized = true;
                }
            }
            Ok(LuaBytes(result))
        })?,
    )?;
    module.set(
        "get",
        lua.create_function(|_lua, (data, index): (Option<AnyUserData>, i64)| {
            let Some(data) = data else { return Ok(None) };
            let data = data.borrow::<LuaBytes>()?;
            let index = usize::try_from(index).ok();
            Ok(index.and_then(|index| data.0.elements().get(index).copied()))
        })?,
    )?;
    module.set(
        "sub",
        lua.create_function(
            |_lua, (data, first, last): (Option<AnyUserData>, Option<i64>, Option<i64>)| {
                let Some(data) = data else { return Ok(None) };
                let data = data.borrow::<LuaBytes>()?.0.clone();
                Ok(sub(&data, first.unwrap_or(0), last))
            },
        )?,
    )?;
    module.set(
        "number",
        lua.create_function(|_lua, data: Option<AnyUserData>| {
            let Some(data) = data else {
                return Ok(Value::Integer(0));
            };
            let value = number(&data.borrow::<LuaBytes>()?.0)?;
            Ok(Value::Integer(i64::try_from(value).map_err(|_| {
                LuaError::external(CoreError::InvalidDocument(
                    "byte string integer exceeds Lua's signed integer range".into(),
                ))
            })?))
        })?,
    )?;
    module.set(
        "format",
        lua.create_function(|_lua, (data, format): (AnyUserData, String)| {
            format_bytes(&data.borrow::<LuaBytes>()?.0, &format)
        })?,
    )?;
    module.set(
        "printable",
        lua.create_function(|_lua, data: Option<AnyUserData>| {
            let Some(data) = data else { return Ok(false) };
            Ok(printable(&data.borrow::<LuaBytes>()?.0))
        })?,
    )?;
    module.set(
        "reverse",
        lua.create_function(|_lua, data: AnyUserData| {
            let data = data.borrow::<LuaBytes>()?.0.clone();
            Ok(LuaBytes(reverse(&data)))
        })?,
    )?;
    module.set(
        "pad_left",
        lua.create_function(|_lua, (data, length, value): (AnyUserData, usize, u8)| {
            let data = data.borrow::<LuaBytes>()?.0.clone();
            Ok(LuaBytes(pad(&data, length, value, true)?))
        })?,
    )?;
    module.set(
        "pad_right",
        lua.create_function(|_lua, (data, length, value): (AnyUserData, usize, u8)| {
            let data = data.borrow::<LuaBytes>()?.0.clone();
            Ok(LuaBytes(pad(&data, length, value, false)?))
        })?,
    )?;
    Ok(module)
}

fn append_value(output: &mut Vec<u8>, width: u8, value: Value) -> LuaResult<()> {
    match value {
        Value::String(value) => {
            let parsed = ByteString::from_hex(width, value.to_str()?.as_ref())
                .map_err(LuaError::external)?;
            output.extend_from_slice(parsed.elements());
        }
        Value::UserData(value) => {
            let value = value.borrow::<LuaBytes>()?;
            if value.0.width() != width {
                return Err(LuaError::external(CoreError::InvalidDocument(
                    "byte string widths differ".into(),
                )));
            }
            output.extend_from_slice(value.0.elements());
        }
        Value::Integer(value) => {
            output.push(u8::try_from(value).map_err(|_| {
                LuaError::external(CoreError::InvalidDocument(format!(
                    "integer {value} does not fit in a byte string element"
                )))
            })?);
        }
        Value::Number(value) if value.fract() == 0.0 && (0.0..=255.0).contains(&value) => {
            output.push(
                u8::try_from(value.to_string().parse::<u16>().map_err(|_| {
                    LuaError::external(CoreError::InvalidDocument("invalid integer".into()))
                })?)
                .map_err(LuaError::external)?,
            );
        }
        _ => {
            return Err(LuaError::external(CoreError::InvalidDocument(
                "expected hexadecimal text, a byte string, or an integer".into(),
            )));
        }
    }
    Ok(())
}

pub(crate) fn sub(data: &ByteString, first: i64, last: Option<i64>) -> Option<LuaBytes> {
    let size = i64::try_from(data.len()).ok()?;
    let first = if first < 0 {
        size.checked_add(first)?
    } else {
        first
    };
    let mut last = last.unwrap_or(size - 1);
    if last < 0 {
        last = last.checked_add(size)?;
    }
    if first < 0 || last < first || first >= size {
        return None;
    }
    last = last.min(size - 1);
    let first = usize::try_from(first).ok()?;
    let length = usize::try_from(last)
        .ok()?
        .checked_sub(first)?
        .checked_add(1)?;
    Some(LuaBytes(data.slice(first, Some(length))))
}

pub(crate) fn number(data: &ByteString) -> LuaResult<u64> {
    let coefficient = 1_u64.checked_shl(u32::from(data.width())).ok_or_else(|| {
        LuaError::external(CoreError::InvalidDocument(
            "invalid byte string width".into(),
        ))
    })?;
    data.elements().iter().try_fold(0_u64, |result, value| {
        result
            .checked_mul(coefficient)
            .and_then(|result| result.checked_add(u64::from(*value)))
            .ok_or_else(|| {
                LuaError::external(CoreError::InvalidDocument(
                    "byte string integer exceeds 64 bits".into(),
                ))
            })
    })
}

pub(crate) fn format_bytes(data: &ByteString, format: &str) -> LuaResult<String> {
    let mut result = String::new();
    let mut codes = format.chars();
    while let Some(character) = codes.next() {
        if character != '%' {
            result.push(character);
            continue;
        }
        let Some(code) = codes.next() else {
            return Err(LuaError::external(CoreError::InvalidDocument(
                "incomplete byte format".into(),
            )));
        };
        match code {
            '%' => result.push('%'),
            'D' => result.push_str(&data.to_hex()),
            'S' => {
                write!(result, "{}:{}", data.width(), data.to_hex()).map_err(LuaError::external)?;
            }
            'w' => result.push_str(&data.width().to_string()),
            'l' => result.push_str(&data.len().to_string()),
            'I' => result.push_str(&number(data)?.to_string()),
            'C' => {
                for value in data.elements() {
                    result.push(char::from(*value));
                }
            }
            'P' => {
                for value in data.elements() {
                    result.push(if (32..127).contains(value) {
                        char::from(*value)
                    } else {
                        '.'
                    });
                }
            }
            _ => {
                return Err(LuaError::external(CoreError::InvalidDocument(format!(
                    "unsupported byte format %{code}"
                ))));
            }
        }
    }
    Ok(result)
}

pub(crate) fn printable(data: &ByteString) -> bool {
    !data.is_empty()
        && data
            .elements()
            .iter()
            .all(|value| (32..127).contains(value))
}

pub(crate) fn reverse(data: &ByteString) -> ByteString {
    let mut values = data.elements().to_vec();
    values.reverse();
    ByteString::from_elements(data.width(), values).expect("existing elements remain valid")
}

pub(crate) fn pad(
    data: &ByteString,
    length: usize,
    value: u8,
    left: bool,
) -> LuaResult<ByteString> {
    let mut values = data.elements().to_vec();
    let padding = length.saturating_sub(values.len());
    let additions = std::iter::repeat_n(value, padding);
    if left {
        values.splice(0..0, additions);
    } else {
        values.extend(additions);
    }
    ByteString::from_elements(data.width(), values).map_err(LuaError::external)
}

pub(crate) fn value_string(value: Value) -> LuaResult<Option<String>> {
    match value {
        Value::Nil => Ok(None),
        Value::String(value) => Ok(Some(value.to_str()?.to_owned())),
        Value::Integer(value) => Ok(Some(value.to_string())),
        Value::Number(value) => Ok(Some(value.to_string())),
        Value::Boolean(value) => Ok(Some(value.to_string())),
        _ => Err(LuaError::external(CoreError::InvalidDocument(
            "expected text, a number, a boolean, or nil".into(),
        ))),
    }
}
