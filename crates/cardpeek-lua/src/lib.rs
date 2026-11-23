//! Lua analyser execution and `Cardpeek` NG APIs.

use std::cell::{Cell, RefCell};
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use cardpeek_analyser::{
    Cancellation, CardHost, EventSink, ExecutionRequest, HostError, LogLevel as AnalyserLogLevel,
};
use cardpeek_core::{
    ApduCommand, ByteString, CaptureBundle, CapturedValue, CoreError, NodeId, NodeValue, Protocol,
    Provenance, ResetMode, ResultDocument, ResultNode, TraceRecordId,
};
use mlua::{
    AnyUserData, Error as LuaError, HookTriggers, Lua, MetaMethod, MultiValue, Result as LuaResult,
    Table, UserData, UserDataMethods, Value, VmState,
};
use thiserror::Error;

/// Native Lua runtime error.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Analyser source could not be read.
    #[error("analyser I/O error for {path}: {source}")]
    Io {
        /// Analyser entry point.
        path: PathBuf,
        /// Native I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Lua loading or execution failed.
    #[error("Lua analyser error: {0}")]
    Lua(#[from] LuaError),
    /// Result document validation failed.
    #[error(transparent)]
    Core(#[from] CoreError),
}

/// Result of live collection followed by decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureExecution {
    /// Decoded result document.
    pub document: ResultDocument,
    /// Capture bundle to retain with the live trace.
    pub capture: CaptureBundle,
}

/// Executes one analyser in a fresh Lua state with a fresh result document.
///
/// # Errors
///
/// Returns source, Lua, cancellation, host, or document validation errors.
pub fn execute<H: CardHost, S: EventSink>(
    request: &ExecutionRequest,
    host: &mut H,
    events: &S,
) -> Result<ResultDocument, RuntimeError> {
    let lua = prepare_lua(request, host.cancellation())?;
    let source = read_source(request)?;
    let document = document_handle(request);
    let next_node = Rc::new(Cell::new(1_u64));
    lua.scope(|scope| {
        install_common_modules(&lua, scope, events, &document, &next_node, None)?;
        let module = common_module(&lua)?;
        module.set("card", card_module(&lua, scope, host)?)?;
        lua.load(&source)
            .set_name(request.analyser.path.to_string_lossy())
            .exec()
    })?;
    finish_document(&document)
}

/// Collects analyser values and decodes them in the same fresh Lua state.
///
/// # Errors
///
/// Returns source, Lua, cancellation, host, capture, or document errors.
pub fn execute_with_capture<H: CardHost, S: EventSink>(
    request: &ExecutionRequest,
    host: &mut H,
    events: &S,
    segment: usize,
) -> Result<CaptureExecution, RuntimeError> {
    let lua = prepare_lua(request, host.cancellation())?;
    let source = read_source(request)?;
    let document = document_handle(request);
    let next_node = Rc::new(Cell::new(1_u64));
    let provenance = decoder_provenance(request);
    let mut capture = CaptureBundle::new(
        request.analyser.id.clone(),
        request.analyser.version.clone(),
        request
            .analyser
            .capture_schema
            .clone()
            .ok_or_else(|| invalid("analyser has no capture schema"))?,
        segment,
    );
    lua.scope(|scope| {
        install_common_modules(&lua, scope, events, &document, &next_node, Some(provenance))?;
        let module = common_module(&lua)?;
        module.set("capture_execution", true)?;
        module.set("card", card_module(&lua, scope, host)?)?;
        lua.load(&source)
            .set_name(request.analyser.path.to_string_lossy())
            .exec()?;
        let globals = lua.globals();
        let collect: mlua::Function = globals
            .get("collect")
            .map_err(|_| LuaError::external(invalid("analyser does not define collect(cp)")))?;
        let decode: mlua::Function = globals.get("decode").map_err(|_| {
            LuaError::external(invalid("analyser does not define decode(cp, captured)"))
        })?;
        let collected: Table = collect.call(module.clone())?;
        capture.values = captured_values(&collected)?;
        let captured = captured_table(&lua, &capture.values)?;
        module.set("captured", captured.clone())?;
        module.set("card", Value::Nil)?;
        decode.call::<()>((module, captured))?;
        Ok(())
    })?;
    Ok(CaptureExecution {
        document: finish_document(&document)?,
        capture,
    })
}

/// Decodes one compatible capture bundle without installing a card API.
///
/// # Errors
///
/// Returns source, Lua, cancellation, compatibility, or document errors.
pub fn decode_capture<C: Cancellation, S: EventSink>(
    request: &ExecutionRequest,
    capture: &CaptureBundle,
    cancellation: &C,
    events: &S,
) -> Result<ResultDocument, RuntimeError> {
    validate_capture(request, capture)?;
    let lua = prepare_lua(request, cancellation)?;
    let source = read_source(request)?;
    let document = document_handle(request);
    let next_node = Rc::new(Cell::new(1_u64));
    let provenance = decoder_provenance(request);
    lua.scope(|scope| {
        install_common_modules(&lua, scope, events, &document, &next_node, Some(provenance))?;
        let module = common_module(&lua)?;
        let captured = captured_table(&lua, &capture.values)?;
        module.set("capture_execution", true)?;
        module.set("captured", captured.clone())?;
        lua.load(&source)
            .set_name(request.analyser.path.to_string_lossy())
            .exec()?;
        let decode: mlua::Function = lua.globals().get("decode").map_err(|_| {
            LuaError::external(invalid("analyser does not define decode(cp, captured)"))
        })?;
        decode.call::<()>((module, captured))?;
        Ok(())
    })?;
    finish_document(&document)
}

fn prepare_lua<C: Cancellation>(
    request: &ExecutionRequest,
    cancellation: &C,
) -> Result<Lua, RuntimeError> {
    let lua = Lua::new();
    let cancellation = cancellation.clone();
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(1000),
        move |_lua, _debug| {
            if cancellation.is_cancelled() {
                Err(LuaError::external(HostError::cancelled()))
            } else {
                Ok(VmState::Continue)
            }
        },
    )?;
    configure_module_path(&lua, request.analyser.resource_root())?;
    Ok(lua)
}

fn read_source(request: &ExecutionRequest) -> Result<String, RuntimeError> {
    fs::read_to_string(&request.analyser.path).map_err(|source| RuntimeError::Io {
        path: request.analyser.path.clone(),
        source,
    })
}

fn document_handle(request: &ExecutionRequest) -> Rc<RefCell<ResultDocument>> {
    Rc::new(RefCell::new(ResultDocument::new(
        request.document_id.clone(),
        request.run_id.clone(),
    )))
}

fn finish_document(document: &Rc<RefCell<ResultDocument>>) -> Result<ResultDocument, RuntimeError> {
    let mut result = document.borrow().clone();
    result.publish();
    result.validate()?;
    Ok(result)
}

fn install_common_modules<'scope, 'env: 'scope, S: EventSink>(
    lua: &Lua,
    scope: &'scope mlua::Scope<'scope, 'env>,
    events: &'env S,
    document: &Rc<RefCell<ResultDocument>>,
    next_node: &Rc<Cell<u64>>,
    provenance: Option<(String, String)>,
) -> LuaResult<()> {
    let module = lua.create_table()?;
    module.set("bytes", bytes_module(lua)?)?;
    module.set("nodes", nodes_module(lua, document, next_node, provenance)?)?;
    module.set("log", log_module(lua, scope, events)?)?;
    module.set("ui", ui_module(lua, scope, events)?)?;
    module.set("asn1", asn1_module(lua)?)?;
    module.set("crypto", crypto_module(lua)?)?;
    module.set("encoding", encoding_module(lua)?)?;
    let loaded: Table = lua.globals().get::<Table>("package")?.get("loaded")?;
    loaded.set("cardpeek", module)
}

fn asn1_module(lua: &Lua) -> LuaResult<Table> {
    let module = lua.create_table()?;
    module.set(
        "split",
        lua.create_function(|lua, input: AnyUserData| {
            let input = input.borrow::<LuaBytes>()?.0.clone();
            let Some((tag, value, consumed)) = asn1_split(&input) else {
                return Ok(MultiValue::from_vec(vec![Value::Nil; 3]));
            };
            let tail = (consumed < input.len()).then(|| LuaBytes(input.slice(consumed, None)));
            Ok(MultiValue::from_vec(vec![
                Value::Integer(i64::from(tag)),
                Value::UserData(lua.create_userdata(LuaBytes(value))?),
                tail.map_or(Ok::<Value, LuaError>(Value::Nil), |value| {
                    Ok(Value::UserData(lua.create_userdata(value)?))
                })?,
            ]))
        })?,
    )?;
    module.set(
        "split_tag",
        lua.create_function(|lua, input: AnyUserData| {
            let input = input.borrow::<LuaBytes>()?.0.clone();
            let Some((tag, consumed)) = asn1_tag(&input) else {
                return Ok(MultiValue::from_vec(vec![Value::Nil; 2]));
            };
            let tail = (consumed < input.len()).then(|| LuaBytes(input.slice(consumed, None)));
            Ok(MultiValue::from_vec(vec![
                Value::Integer(i64::from(tag)),
                tail.map_or(Ok::<Value, LuaError>(Value::Nil), |value| {
                    Ok(Value::UserData(lua.create_userdata(value)?))
                })?,
            ]))
        })?,
    )?;
    module.set(
        "split_length",
        lua.create_function(|lua, input: AnyUserData| {
            let input = input.borrow::<LuaBytes>()?.0.clone();
            let Some((length, consumed)) = asn1_length(&input, 0) else {
                return Ok(MultiValue::from_vec(vec![Value::Nil; 2]));
            };
            let tail = (consumed < input.len()).then(|| LuaBytes(input.slice(consumed, None)));
            Ok(MultiValue::from_vec(vec![
                Value::Integer(i64::try_from(length).unwrap_or(i64::MAX)),
                tail.map_or(Ok::<Value, LuaError>(Value::Nil), |value| {
                    Ok(Value::UserData(lua.create_userdata(value)?))
                })?,
            ]))
        })?,
    )?;
    module.set(
        "join",
        lua.create_function(
            |_lua, (tag, value, tail): (u32, AnyUserData, Option<AnyUserData>)| {
                let value = value.borrow::<LuaBytes>()?.0.clone();
                let encoded = asn1_join(tag, &value).map_err(LuaError::external)?;
                if let Some(tail) = tail {
                    let tail = tail.borrow::<LuaBytes>()?.0.clone();
                    let mut encoded = encoded;
                    encoded.append(&tail).map_err(LuaError::external)?;
                    Ok(LuaBytes(encoded))
                } else {
                    Ok(LuaBytes(encoded))
                }
            },
        )?,
    )?;
    Ok(module)
}

fn asn1_element(input: &ByteString, index: usize) -> Option<u8> {
    input.as_bytes()?.get(index).copied()
}

fn asn1_tag(input: &ByteString) -> Option<(u32, usize)> {
    let first = asn1_element(input, 0)?;
    let mut tag = u32::from(first);
    let mut position = 1;
    if first & 0x1F == 0x1F {
        loop {
            let byte = asn1_element(input, position)?;
            tag = tag.checked_mul(256)?.checked_add(u32::from(byte))?;
            position += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    Some((tag, position))
}

fn asn1_length(input: &ByteString, start: usize) -> Option<(usize, usize)> {
    let first = asn1_element(input, start)?;
    if first < 0x80 {
        return Some((usize::from(first), start + 1));
    }
    let count = usize::from(first & 0x7F);
    if count == 0 || count > std::mem::size_of::<usize>() {
        return None;
    }
    let mut length = 0_usize;
    for index in 0..count {
        length = length
            .checked_mul(256)?
            .checked_add(usize::from(asn1_element(input, start + 1 + index)?))?;
    }
    Some((length, start + 1 + count))
}

fn asn1_split(input: &ByteString) -> Option<(u32, ByteString, usize)> {
    let (tag, position) = asn1_tag(input)?;
    let (length, start) = asn1_length(input, position)?;
    let end = start.checked_add(length)?;
    if end > input.len() {
        return None;
    }
    Some((tag, input.slice(start, Some(length)), end))
}

fn asn1_join(tag: u32, value: &ByteString) -> Result<ByteString, CoreError> {
    if value.width() != 8 {
        return Err(CoreError::InvalidDocument(
            "ASN.1 values must use 8-bit elements".into(),
        ));
    }
    let mut bytes = Vec::new();
    if tag <= 0xFF {
        bytes.push(u8::try_from(tag).map_err(|_| {
            CoreError::InvalidDocument("ASN.1 tag is outside the supported range".into())
        })?);
    } else {
        let mut parts = Vec::new();
        let mut remaining = tag;
        while remaining > 0 {
            parts.push((remaining & 0xFF) as u8);
            remaining >>= 8;
        }
        parts.reverse();
        let last = parts.len() - 1;
        for part in &mut parts[..last] {
            *part |= 0x80;
        }
        bytes.extend(parts);
    }
    let length = value.len();
    if length < 0x80 {
        bytes.push(u8::try_from(length).map_err(|_| {
            CoreError::InvalidDocument("ASN.1 length is outside the supported range".into())
        })?);
    } else {
        let mut parts = Vec::new();
        let mut remaining = length;
        while remaining > 0 {
            parts.push(u8::try_from(remaining & 0xFF).map_err(|_| {
                CoreError::InvalidDocument("ASN.1 length is outside the supported range".into())
            })?);
            remaining >>= 8;
        }
        bytes.push(
            0x80 | u8::try_from(parts.len()).map_err(|_| {
                CoreError::InvalidDocument("ASN.1 length is outside the supported range".into())
            })?,
        );
        bytes.extend(parts.into_iter().rev());
    }
    bytes.extend_from_slice(value.elements());
    Ok(ByteString::from_bytes(bytes))
}

fn crypto_module(lua: &Lua) -> LuaResult<Table> {
    let module = lua.create_table()?;
    module.set(
        "sha1",
        lua.create_function(|_lua, input: AnyUserData| {
            use sha1::{Digest, Sha1};
            let input = input.borrow::<LuaBytes>()?.0.clone();
            let bytes = input.as_bytes().ok_or_else(|| {
                LuaError::external(CoreError::InvalidDocument(
                    "SHA-1 input must use 8-bit elements".into(),
                ))
            })?;
            Ok(LuaBytes(ByteString::from_bytes(
                Sha1::digest(bytes).to_vec(),
            )))
        })?,
    )?;
    module.set(
        "des_ede3_cbc",
        lua.create_function(
            |_lua, (encrypt, key, iv, input): (bool, AnyUserData, AnyUserData, AnyUserData)| {
                let key = crypto_bytes(&key, 16)?;
                let iv = crypto_bytes(&iv, 8)?;
                let input = crypto_bytes(&input, 0)?;
                if !input.len().is_multiple_of(8) {
                    return Err(LuaError::external(CoreError::InvalidDocument(
                        "Triple DES input must contain complete blocks".into(),
                    )));
                }
                let mut output = input;
                if encrypt {
                    des_ede3_encrypt(&key, &iv, &mut output);
                } else {
                    des_ede3_decrypt(&key, &iv, &mut output);
                }
                Ok(LuaBytes(ByteString::from_bytes(output)))
            },
        )?,
    )?;
    module.set(
        "iso9797_mac",
        lua.create_function(|_lua, (key, input): (AnyUserData, AnyUserData)| {
            let key = crypto_bytes(&key, 16)?;
            let input = crypto_bytes(&input, 0)?;
            Ok(LuaBytes(ByteString::from_bytes(iso9797_mac(&key, &input))))
        })?,
    )?;
    Ok(module)
}

fn crypto_bytes(input: &AnyUserData, exact: usize) -> LuaResult<Vec<u8>> {
    let input = input.borrow::<LuaBytes>()?.0.clone();
    let bytes = input.as_bytes().ok_or_else(|| {
        LuaError::external(CoreError::InvalidDocument(
            "cryptographic values must use 8-bit elements".into(),
        ))
    })?;
    if exact != 0 && bytes.len() != exact {
        return Err(LuaError::external(CoreError::InvalidDocument(format!(
            "expected {exact} bytes, received {}",
            bytes.len()
        ))));
    }
    Ok(bytes.to_vec())
}

fn des_ede3_encrypt(key: &[u8], iv: &[u8], output: &mut [u8]) {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
    type DesEde3Cbc = cbc::Encryptor<des::TdesEde2>;
    DesEde3Cbc::new_from_slices(key, iv)
        .expect("validated Triple DES key and IV")
        .encrypt_padded_mut::<NoPadding>(output, output.len())
        .expect("complete Triple DES blocks");
}

fn des_ede3_decrypt(key: &[u8], iv: &[u8], output: &mut [u8]) {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
    type DesEde3Cbc = cbc::Decryptor<des::TdesEde2>;
    DesEde3Cbc::new_from_slices(key, iv)
        .expect("validated Triple DES key and IV")
        .decrypt_padded_mut::<NoPadding>(output)
        .expect("complete Triple DES blocks");
}

fn iso9797_mac(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut padded = input.to_vec();
    padded.push(0x80);
    while !padded.len().is_multiple_of(8) {
        padded.push(0);
    }
    let iv = [0_u8; 8];
    let mut encrypted = padded;
    des_ede3_encrypt(key, &iv, &mut encrypted);
    let start = encrypted.len() - 8;
    encrypted[start..].to_vec()
}

fn encoding_module(lua: &Lua) -> LuaResult<Table> {
    let module = lua.create_table()?;
    module.set(
        "decode",
        lua.create_function(|_lua, (name, input): (String, AnyUserData)| {
            let input = crypto_bytes(&input, 0)?;
            let encoding = match name.to_ascii_uppercase().as_str() {
                "TIS-620" | "ISO-8859-11" => encoding_rs::WINDOWS_874,
                "ISO-8859-1" => encoding_rs::WINDOWS_1252,
                "ISO-8859-2" => encoding_rs::ISO_8859_2,
                "ISO-8859-3" => encoding_rs::ISO_8859_3,
                "ISO-8859-4" => encoding_rs::ISO_8859_4,
                "ISO-8859-5" => encoding_rs::ISO_8859_5,
                "ISO-8859-6" => encoding_rs::ISO_8859_6,
                "ISO-8859-7" => encoding_rs::ISO_8859_7,
                "ISO-8859-8" => encoding_rs::ISO_8859_8,
                "ISO-8859-9" => encoding_rs::WINDOWS_1254,
                "ISO-8859-10" => encoding_rs::ISO_8859_10,
                "ISO-8859-13" => encoding_rs::ISO_8859_13,
                "ISO-8859-14" => encoding_rs::ISO_8859_14,
                "ISO-8859-15" => encoding_rs::ISO_8859_15,
                "ISO-8859-16" => encoding_rs::ISO_8859_16,
                "UTF-8" => encoding_rs::UTF_8,
                _ => {
                    return Err(LuaError::external(CoreError::InvalidDocument(format!(
                        "unsupported character encoding {name}"
                    ))));
                }
            };
            let (text, _, errors) = encoding.decode(&input);
            if errors {
                return Err(LuaError::external(CoreError::InvalidDocument(format!(
                    "invalid {name} input"
                ))));
            }
            Ok(text.into_owned())
        })?,
    )?;
    Ok(module)
}

fn common_module(lua: &Lua) -> LuaResult<Table> {
    let package: Table = lua.globals().get("package")?;
    let loaded: Table = package.get("loaded")?;
    loaded.get("cardpeek")
}

fn decoder_provenance(request: &ExecutionRequest) -> (String, String) {
    (
        request.analyser.id.clone(),
        request.analyser.version.clone(),
    )
}

fn validate_capture(
    request: &ExecutionRequest,
    capture: &CaptureBundle,
) -> Result<(), RuntimeError> {
    let compatible = capture.analyser == request.analyser.id
        && capture.analyser_version == request.analyser.version
        && request.analyser.capture_schema.as_ref() == Some(&capture.capture_schema);
    if !request.analyser.capabilities.offline_decoding || !compatible {
        return Err(invalid(format!(
            "capture bundle is incompatible with analyser {} version {} schema {}",
            request.analyser.id,
            request.analyser.version,
            request.analyser.capture_schema.as_deref().unwrap_or("none")
        )));
    }
    Ok(())
}

fn captured_values(collected: &Table) -> LuaResult<Vec<CapturedValue>> {
    let mut values = Vec::new();
    for entry in collected.sequence_values::<Table>() {
        let entry = entry?;
        let name: String = entry.get("name")?;
        let bytes = entry
            .get::<AnyUserData>("bytes")?
            .borrow::<LuaBytes>()?
            .0
            .clone();
        let source: String = entry.get("source")?;
        values.push(CapturedValue {
            name,
            bytes,
            source: TraceRecordId::new(source).map_err(LuaError::external)?,
        });
    }
    Ok(values)
}

fn captured_table(lua: &Lua, values: &[CapturedValue]) -> LuaResult<Table> {
    let captured = lua.create_table()?;
    for value in values {
        let entry = lua.create_table()?;
        entry.set("name", value.name.clone())?;
        entry.set("bytes", LuaBytes(value.bytes.clone()))?;
        entry.set("source", value.source.as_str())?;
        captured.push(entry)?;
    }
    Ok(captured)
}

fn invalid(message: impl Into<String>) -> RuntimeError {
    RuntimeError::Core(CoreError::InvalidDocument(message.into()))
}

fn configure_module_path(lua: &Lua, root: &Path) -> LuaResult<()> {
    let package: Table = lua.globals().get("package")?;
    let path = format!(
        "{}/?.lua;{}/?/init.lua",
        root.to_string_lossy(),
        root.to_string_lossy()
    );
    package.set("path", path)
}

fn bytes_module(lua: &Lua) -> LuaResult<Table> {
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
    Ok(module)
}

#[derive(Clone, Debug)]
struct LuaBytes(ByteString);

impl LuaBytes {
    fn new(value: ByteString) -> Self {
        Self(value)
    }
}

impl UserData for LuaBytes {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("width", |_lua, this, ()| Ok(this.0.width()));
        methods.add_method("len", |_lua, this, ()| Ok(this.0.len()));
        methods.add_method("bit_len", |_lua, this, ()| Ok(this.0.bit_len()));
        methods.add_method("to_hex", |_lua, this, ()| Ok(this.0.to_hex()));
        methods.add_method("to_string", |_lua, this, ()| {
            String::from_utf8(this.0.as_bytes().unwrap_or_default().to_vec())
                .map_err(LuaError::external)
        });
        methods.add_method("elements", |lua, this, ()| {
            lua.create_sequence_from(this.0.elements().iter().copied())
        });
        methods.add_method("convert", |_lua, this, width: u8| {
            if !matches!(width, 1 | 4 | 8) {
                return Err(LuaError::external(CoreError::InvalidDocument(format!(
                    "unsupported element width {width}"
                ))));
            }
            Ok(Self(this.0.convert(width)))
        });
        methods.add_method(
            "slice",
            |_lua, this, (start, length): (usize, Option<usize>)| {
                if start == 0 {
                    return Err(LuaError::external(CoreError::InvalidDocument(
                        "byte indexes start at one".into(),
                    )));
                }
                Ok(Self(this.0.slice(start - 1, length)))
            },
        );
        methods.add_method("iter", |lua, this, ()| {
            let values = this.0.elements().to_vec();
            let mut index = 0;
            lua.create_function_mut(move |_lua, ()| {
                if index == values.len() {
                    return Ok(Value::Nil);
                }
                index += 1;
                Ok(Value::Integer(i64::from(values[index - 1])))
            })
        });
        methods.add_method("ipairs", |lua, this, ()| {
            let values = this.0.elements().to_vec();
            let mut index = 0;
            lua.create_function_mut(move |_lua, ()| {
                if index == values.len() {
                    return Ok(MultiValue::new());
                }
                let value = i64::from(values[index]);
                let result = MultiValue::from_vec(vec![
                    Value::Integer(i64::try_from(index).unwrap_or(i64::MAX)),
                    Value::Integer(value),
                ]);
                index += 1;
                Ok(result)
            })
        });
        methods.add_meta_method(MetaMethod::ToString, |_lua, this, ()| Ok(this.0.to_hex()));
        methods.add_meta_method(MetaMethod::Len, |_lua, this, ()| Ok(this.0.len()));
        methods.add_meta_method(MetaMethod::Index, |_lua, this, index: Value| match index {
            Value::Integer(index) if index > 0 => Ok(this
                .0
                .elements()
                .get(usize::try_from(index).unwrap_or(usize::MAX) - 1)
                .copied()
                .map_or(Value::Nil, |value| Value::Integer(i64::from(value)))),
            _ => Ok(Value::Nil),
        });
        methods.add_meta_method(MetaMethod::Eq, |_lua, this, other: AnyUserData| {
            Ok(other.borrow::<Self>()?.0 == this.0)
        });
        methods.add_meta_method(MetaMethod::Concat, |_lua, this, other: AnyUserData| {
            let mut value = this.0.clone();
            value
                .append(&other.borrow::<Self>()?.0)
                .map_err(LuaError::external)?;
            Ok(Self(value))
        });
    }
}

fn nodes_module(
    lua: &Lua,
    document: &Rc<RefCell<ResultDocument>>,
    next_node: &Rc<Cell<u64>>,
    provenance: Option<(String, String)>,
) -> LuaResult<Table> {
    let module = lua.create_table()?;
    add_root_accessors(lua, &module, document)?;
    let methods = node_methods(lua, document, next_node, provenance)?;
    let metatable = lua.create_table()?;
    metatable.set("__index", methods)?;
    lua.set_named_registry_value("cardpeek.node_metatable", metatable)?;
    module.set("root", lua.create_function(|lua, ()| node_handle(lua, ""))?)?;
    Ok(module)
}

fn add_root_accessors(
    lua: &Lua,
    module: &Table,
    document: &Rc<RefCell<ResultDocument>>,
) -> LuaResult<()> {
    module.set(
        "find",
        lua.create_function({
            let document = document.clone();
            move |lua, (parent, criteria): (Table, Table)| {
                let ids = matching_nodes(&document, &parent, &criteria)?;
                let mut index = 0;
                lua.create_function_mut(move |lua, ()| {
                    if index == ids.len() {
                        return Ok(Value::Nil);
                    }
                    let id = ids[index].clone();
                    index += 1;
                    node_handle(lua, &id)
                })
            }
        })?,
    )?;
    module.set(
        "find_first",
        lua.create_function({
            let document = document.clone();
            move |lua, (parent, criteria): (Table, Table)| {
                let ids = matching_nodes(&document, &parent, &criteria)?;
                ids.first()
                    .map_or(Ok(Value::Nil), |id| node_handle(lua, id))
            }
        })?,
    )?;
    module.set(
        "roots",
        lua.create_function({
            let document = document.clone();
            move |lua, ()| {
                let ids: Vec<String> = document
                    .borrow()
                    .roots
                    .iter()
                    .map(|node| node.id.as_str().to_owned())
                    .collect();
                node_handles(lua, &ids)
            }
        })?,
    )?;
    module.set(
        "get",
        lua.create_function({
            let document = document.clone();
            move |lua, id: String| {
                let exists = document.borrow().find(&node_id(&id)?).is_some();
                if exists {
                    node_handle(lua, &id)
                } else {
                    Ok(Value::Nil)
                }
            }
        })?,
    )?;
    Ok(())
}

fn node_methods(
    lua: &Lua,
    document: &Rc<RefCell<ResultDocument>>,
    next_node: &Rc<Cell<u64>>,
    provenance: Option<(String, String)>,
) -> LuaResult<Table> {
    let methods = lua.create_table()?;
    add_navigation_methods(lua, &methods, document, next_node)?;
    add_attribute_methods(lua, &methods, document, provenance)?;
    Ok(methods)
}

fn add_search_methods(
    lua: &Lua,
    methods: &Table,
    document: &Rc<RefCell<ResultDocument>>,
) -> LuaResult<()> {
    methods.set(
        "find",
        lua.create_function({
            let document = document.clone();
            move |lua, (parent, criteria): (Table, Table)| {
                let ids = matching_nodes(&document, &parent, &criteria)?;
                let mut index = 0;
                lua.create_function_mut(move |lua, ()| {
                    if index == ids.len() {
                        return Ok(Value::Nil);
                    }
                    let id = ids[index].clone();
                    index += 1;
                    node_handle(lua, &id)
                })
            }
        })?,
    )?;
    methods.set(
        "find_first",
        lua.create_function({
            let document = document.clone();
            move |lua, (parent, criteria): (Table, Table)| {
                let ids = matching_nodes(&document, &parent, &criteria)?;
                ids.first()
                    .map_or(Ok(Value::Nil), |id| node_handle(lua, id))
            }
        })?,
    )?;
    methods.set(
        "remove",
        lua.create_function({
            let document = document.clone();
            move |_lua, handle: Table| {
                let Some(id) = handle_id(&handle)? else {
                    return Ok(false);
                };
                let id = node_id(&id)?;
                let mut document = document.borrow_mut();
                Ok(remove_node(&mut document.roots, &id))
            }
        })?,
    )?;
    Ok(())
}

fn add_navigation_methods(
    lua: &Lua,
    methods: &Table,
    document: &Rc<RefCell<ResultDocument>>,
    next_node: &Rc<Cell<u64>>,
) -> LuaResult<()> {
    add_search_methods(lua, methods, document)?;
    methods.set(
        "append",
        lua.create_function({
            let document = document.clone();
            let next_node = next_node.clone();
            move |lua, (parent, class, label): (Table, String, String)| {
                let parent = handle_id(&parent)?;
                let id = NodeId::new(format!("node-{:04}", next_node.get()))
                    .map_err(LuaError::external)?;
                next_node.set(next_node.get() + 1);
                let child = ResultNode::new(id.clone(), class, label);
                let mut document = document.borrow_mut();
                if let Some(parent) = parent {
                    find_node_mut(&mut document.roots, &node_id(&parent)?)
                        .ok_or_else(|| {
                            LuaError::external(CoreError::InvalidDocument(format!(
                                "unknown parent node {parent}"
                            )))
                        })?
                        .append(child);
                } else {
                    document.roots.push(child);
                }
                node_handle(lua, id.as_str())
            }
        })?,
    )?;
    methods.set(
        "parent",
        lua.create_function({
            let document = document.clone();
            move |lua, handle: Table| {
                let Some(id) = handle_id(&handle)? else {
                    return Ok(Value::Nil);
                };
                let document = document.borrow();
                let parent = find_node(&document.roots, &node_id(&id)?)
                    .and_then(|node| node.parent.as_ref())
                    .map(ToString::to_string);
                parent.map_or(Ok(Value::Nil), |id| node_handle(lua, &id))
            }
        })?,
    )?;
    methods.set(
        "children",
        lua.create_function({
            let document = document.clone();
            move |lua, handle: Table| {
                let ids: Vec<String> = match handle_id(&handle)? {
                    Some(id) => {
                        let document = document.borrow();
                        find_node(&document.roots, &node_id(&id)?).map_or_default(|node| {
                            node.children
                                .iter()
                                .map(|child| child.id.as_str().to_owned())
                                .collect()
                        })
                    }
                    None => document
                        .borrow()
                        .roots
                        .iter()
                        .map(|node| node.id.as_str().to_owned())
                        .collect(),
                };
                node_handles(lua, &ids)
            }
        })?,
    )?;
    methods.set(
        "id",
        lua.create_function(|_lua, handle: Table| handle_id(&handle))?,
    )?;
    Ok(())
}

fn add_attribute_methods(
    lua: &Lua,
    methods: &Table,
    document: &Rc<RefCell<ResultDocument>>,
    provenance: Option<(String, String)>,
) -> LuaResult<()> {
    methods.set(
        "get",
        lua.create_function({
            let document = document.clone();
            move |lua, (handle, field): (Table, String)| {
                let Some(id) = handle_id(&handle)? else {
                    return Err(LuaError::external(CoreError::InvalidDocument(
                        "the document root has no attributes".into(),
                    )));
                };
                let document = document.borrow();
                let node = find_node(&document.roots, &node_id(&id)?).ok_or_else(|| {
                    LuaError::external(CoreError::InvalidDocument(format!("unknown node {id}")))
                })?;
                node_field(lua, node, &field)
            }
        })?,
    )?;
    methods.set(
        "set",
        lua.create_function({
            let document = document.clone();
            move |_lua, (handle, field, value): (Table, String, Value)| {
                with_node_mut(&document, &handle, |node| {
                    set_node_field(node, &field, value)
                })
            }
        })?,
    )?;
    methods.set(
        "set_provenance",
        lua.create_function({
            let document = document.clone();
            move |_lua, (handle, record, operation): (Table, String, Option<String>)| {
                with_node_mut(&document, &handle, |node| {
                    node.provenance = Some(Provenance {
                        record: TraceRecordId::new(record).map_err(LuaError::external)?,
                        operation,
                        analyser: provenance.as_ref().map(|value| value.0.clone()),
                        analyser_version: provenance.as_ref().map(|value| value.1.clone()),
                    });
                    Ok(())
                })
            }
        })?,
    )?;
    Ok(())
}

fn node_handles(lua: &Lua, ids: &[String]) -> LuaResult<Table> {
    let handles = lua.create_table()?;
    for id in ids {
        handles.push(node_handle(lua, id)?)?;
    }
    Ok(handles)
}

fn node_handle(lua: &Lua, id: &str) -> LuaResult<Value> {
    let handle = lua.create_table()?;
    if !id.is_empty() {
        handle.set("_node_id", id)?;
    }
    let metatable: Table = lua.named_registry_value("cardpeek.node_metatable")?;
    handle.set_metatable(Some(metatable))?;
    Ok(Value::Table(handle))
}

fn handle_id(handle: &Table) -> LuaResult<Option<String>> {
    handle.get("_node_id")
}

fn node_id(id: &str) -> LuaResult<NodeId> {
    NodeId::new(id).map_err(LuaError::external)
}

fn find_node<'a>(roots: &'a [ResultNode], id: &NodeId) -> Option<&'a ResultNode> {
    roots.iter().find_map(|node| {
        if &node.id == id {
            Some(node)
        } else {
            find_node(&node.children, id)
        }
    })
}

fn find_node_mut<'a>(roots: &'a mut [ResultNode], id: &NodeId) -> Option<&'a mut ResultNode> {
    for node in roots {
        if &node.id == id {
            return Some(node);
        }
        if let Some(found) = find_node_mut(&mut node.children, id) {
            return Some(found);
        }
    }
    None
}

fn with_node_mut<T>(
    document: &Rc<RefCell<ResultDocument>>,
    handle: &Table,
    operation: impl FnOnce(&mut ResultNode) -> LuaResult<T>,
) -> LuaResult<T> {
    let id = handle_id(handle)?.ok_or_else(|| {
        LuaError::external(CoreError::InvalidDocument(
            "the document root has no attributes".into(),
        ))
    })?;
    let mut document = document.borrow_mut();
    let node = find_node_mut(&mut document.roots, &node_id(&id)?).ok_or_else(|| {
        LuaError::external(CoreError::InvalidDocument(format!("unknown node {id}")))
    })?;
    operation(node)
}

fn node_field(lua: &Lua, node: &ResultNode, field: &str) -> LuaResult<Value> {
    match field {
        "class" => Ok(Value::String(lua.create_string(&node.class)?)),
        "label" => Ok(Value::String(lua.create_string(&node.label)?)),
        "identifier" => optional_string(lua, node.identifier.as_deref()),
        "alternative" => optional_string(lua, node.alternative.as_deref()),
        "mime_type" => optional_string(lua, node.mime_type.as_deref()),
        "size_bits" => Ok(node
            .size_bits
            .map_or(Value::Nil, |size| Value::Integer(size.cast_signed()))),
        "value" => match &node.value {
            Some(NodeValue::Text(value)) => Ok(Value::String(lua.create_string(value)?)),
            Some(NodeValue::Bytes(value)) => Ok(Value::UserData(
                lua.create_userdata(LuaBytes(value.clone()))?,
            )),
            None => Ok(Value::Nil),
        },
        _ => Err(LuaError::external(CoreError::InvalidDocument(format!(
            "unknown node field {field}"
        )))),
    }
}

fn optional_string(lua: &Lua, value: Option<&str>) -> LuaResult<Value> {
    value.map_or(Ok(Value::Nil), |value| {
        Ok(Value::String(lua.create_string(value)?))
    })
}

fn matching_nodes(
    document: &Rc<RefCell<ResultDocument>>,
    parent: &Table,
    criteria: &Table,
) -> LuaResult<Vec<String>> {
    let id = handle_id(parent)?;
    let document = document.borrow();
    let roots: Vec<&ResultNode> = if let Some(id) = id {
        let node = find_node(&document.roots, &node_id(&id)?).ok_or_else(|| {
            LuaError::external(CoreError::InvalidDocument("unknown search parent".into()))
        })?;
        vec![node]
    } else {
        document.roots.iter().collect()
    };
    let mut matches = Vec::new();
    collect_matching_nodes(&roots, criteria, &mut matches)?;
    Ok(matches)
}

fn collect_matching_nodes(
    nodes: &[&ResultNode],
    criteria: &Table,
    output: &mut Vec<String>,
) -> LuaResult<()> {
    for node in nodes {
        if node_matches(node, criteria)? {
            output.push(node.id.as_str().to_owned());
        }
        let children = node.children.iter().collect::<Vec<_>>();
        collect_matching_nodes(&children, criteria, output)?;
    }
    Ok(())
}

fn node_matches(node: &ResultNode, criteria: &Table) -> LuaResult<bool> {
    for pair in criteria.clone().pairs::<String, Value>() {
        let (field, expected) = pair?;
        let field = match field.as_str() {
            "class" | "classname" => "class",
            "id" => "identifier",
            "alt" => "alternative",
            "mime-type" => "mime_type",
            "val" => "value",
            other => other,
        };
        let actual = match field {
            "class" => node.class.clone(),
            "label" => node.label.clone(),
            "identifier" => node.identifier.clone().unwrap_or_default(),
            "alternative" => node.alternative.clone().unwrap_or_default(),
            "mime_type" => node.mime_type.clone().unwrap_or_default(),
            _ => continue,
        };
        let expected = match expected {
            Value::String(value) => value.to_str()?.to_owned(),
            Value::Integer(value) => value.to_string(),
            Value::Number(value) if value.fract() == 0.0 => format!("{value:.0}"),
            _ => return Ok(false),
        };
        if actual != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn remove_node(nodes: &mut Vec<ResultNode>, id: &NodeId) -> bool {
    if let Some(index) = nodes.iter().position(|node| &node.id == id) {
        nodes.remove(index);
        return true;
    }
    nodes
        .iter_mut()
        .any(|node| remove_node(&mut node.children, id))
}

fn set_node_field(node: &mut ResultNode, field: &str, value: Value) -> LuaResult<()> {
    match (field, value) {
        ("class", Value::String(value)) => value.to_str()?.clone_into(&mut node.class),
        ("label", Value::String(value)) => value.to_str()?.clone_into(&mut node.label),
        ("identifier", value) => node.identifier = display_string(value)?,
        ("alternative", value) => node.alternative = display_string(value)?,
        ("mime_type", value) => node.mime_type = nullable_string(value)?,
        ("value", Value::String(value)) => {
            node.set_value(NodeValue::Text(value.to_str()?.to_owned()));
        }
        ("value", Value::UserData(value)) => {
            node.set_value(NodeValue::Bytes(value.borrow::<LuaBytes>()?.0.clone()));
        }
        ("value", Value::Nil) => {
            node.value = None;
            node.size_bits = None;
        }
        (field, _) => {
            return Err(LuaError::external(CoreError::InvalidDocument(format!(
                "invalid value for node field {field}"
            ))));
        }
    }
    Ok(())
}

fn display_string(value: Value) -> LuaResult<Option<String>> {
    match value {
        Value::Nil => Ok(None),
        Value::String(value) => Ok(Some(value.to_str()?.to_owned())),
        Value::Integer(value) => Ok(Some(value.to_string())),
        Value::Number(value) => Ok(Some(value.to_string())),
        _ => Err(LuaError::external(CoreError::InvalidDocument(
            "expected text, a number, or nil".into(),
        ))),
    }
}

fn nullable_string(value: Value) -> LuaResult<Option<String>> {
    match value {
        Value::Nil => Ok(None),
        Value::String(value) => Ok(Some(value.to_str()?.to_owned())),
        _ => Err(LuaError::external(CoreError::InvalidDocument(
            "expected text or nil".into(),
        ))),
    }
}

fn log_module<'scope, 'env: 'scope, S: EventSink>(
    lua: &Lua,
    scope: &'scope mlua::Scope<'scope, 'env>,
    events: &'env S,
) -> LuaResult<Table> {
    let module = lua.create_table()?;
    for (name, level) in [
        ("debug", AnalyserLogLevel::Debug),
        ("info", AnalyserLogLevel::Info),
        ("warning", AnalyserLogLevel::Warning),
        ("error", AnalyserLogLevel::Error),
    ] {
        module.set(
            name,
            scope.create_function(move |_lua, message: String| {
                events.log(level, &message);
                Ok(())
            })?,
        )?;
    }
    Ok(module)
}

fn ui_module<'scope, 'env: 'scope, S: EventSink>(
    lua: &Lua,
    scope: &'scope mlua::Scope<'scope, 'env>,
    events: &'env S,
) -> LuaResult<Table> {
    let module = lua.create_table()?;
    module.set(
        "question",
        scope.create_function(move |_lua, prompt: String| {
            match events.interact(cardpeek_analyser::InteractionKind::Question, &prompt) {
                Ok(cardpeek_analyser::InteractionResponse::Bool(value)) => Ok(value),
                Ok(_) => Err(LuaError::external(HostError::new(
                    "interaction response type mismatch",
                ))),
                Err(error) => Err(LuaError::external(error)),
            }
        })?,
    )?;
    module.set(
        "notice",
        scope.create_function(move |_lua, prompt: String| {
            match events.interact(cardpeek_analyser::InteractionKind::Notice, &prompt) {
                Ok(cardpeek_analyser::InteractionResponse::Acknowledged) => Ok(()),
                Ok(_) => Err(LuaError::external(HostError::new(
                    "interaction response type mismatch",
                ))),
                Err(error) => Err(LuaError::external(error)),
            }
        })?,
    )?;
    module.set(
        "secret",
        scope.create_function(move |_lua, prompt: String| {
            match events.interact(cardpeek_analyser::InteractionKind::Secret, &prompt) {
                Ok(cardpeek_analyser::InteractionResponse::Secret(value)) => Ok(Some(value)),
                Ok(_) => Err(LuaError::external(HostError::new(
                    "interaction response type mismatch",
                ))),
                Err(error) => Err(LuaError::external(error)),
            }
        })?,
    )?;
    module.set(
        "text",
        scope.create_function(
            move |_lua, (prompt, default): (String, Option<String>)| match events.interact(
                cardpeek_analyser::InteractionKind::Text { default },
                &prompt,
            ) {
                Ok(cardpeek_analyser::InteractionResponse::Text(value)) => Ok(Some(value)),
                Ok(_) => Err(LuaError::external(HostError::new(
                    "interaction response type mismatch",
                ))),
                Err(error) => Err(LuaError::external(error)),
            },
        )?,
    )?;
    module.set(
        "file",
        scope.create_function(move |_lua, (prompt, must_exist): (String, bool)| {
            match events.interact(
                cardpeek_analyser::InteractionKind::File { must_exist },
                &prompt,
            ) {
                Ok(cardpeek_analyser::InteractionResponse::File(value)) => {
                    Ok(Some(value.to_string_lossy().into_owned()))
                }
                Ok(_) => Err(LuaError::external(HostError::new(
                    "interaction response type mismatch",
                ))),
                Err(error) => Err(LuaError::external(error)),
            }
        })?,
    )?;
    Ok(module)
}

fn card_module<'scope, 'env: 'scope, H: CardHost>(
    lua: &Lua,
    scope: &'scope mlua::Scope<'scope, 'env>,
    host: &'env mut H,
) -> LuaResult<Table> {
    let module = lua.create_table()?;
    let host = Rc::new(RefCell::new(host));
    let protocol = protocol_name(host.borrow().protocol());
    let capabilities = lua.create_table()?;
    capabilities.set(
        "extended_apdus",
        host.borrow().capabilities().extended_apdus,
    )?;
    module.set("protocol", protocol)?;
    module.set("capabilities", capabilities)?;
    module.set(
        "info",
        lua.create_function({
            let protocol = protocol.to_owned();
            move |lua, ()| {
                let info = lua.create_table()?;
                info.set("protocol", protocol.clone())?;
                Ok(info)
            }
        })?,
    )?;
    let callback_host = host.clone();
    module.set(
        "atr",
        scope.create_function(move |lua, ()| {
            let mut host = callback_host.borrow_mut();
            let record = host
                .current_atr_record()
                .map(|record| record.as_str().to_owned());
            match host.atr() {
                Ok(atr) => {
                    let value = lua.create_table()?;
                    value.set("bytes", LuaBytes(atr.as_byte_string().clone()))?;
                    if let Some(record) = record {
                        value.set("record", record)?;
                    }
                    Ok(MultiValue::from_vec(vec![Value::Table(value), Value::Nil]))
                }
                Err(error) => host_failure(lua, &error),
            }
        })?,
    )?;
    let callback_host = host.clone();
    module.set(
        "reset",
        scope.create_function(move |lua, mode: String| {
            let mode = match mode.as_str() {
                "cold" => ResetMode::Cold,
                "warm" => ResetMode::Warm,
                _ => {
                    return Err(LuaError::external(CoreError::InvalidDocument(format!(
                        "unsupported reset mode {mode}"
                    ))));
                }
            };
            let mut host = callback_host.borrow_mut();
            match host.reset(mode) {
                Ok(atr) => {
                    let record = host
                        .current_atr_record()
                        .map(|record| record.as_str().to_owned());
                    let value = lua.create_table()?;
                    value.set("bytes", LuaBytes(atr.as_byte_string().clone()))?;
                    if let Some(record) = record {
                        value.set("record", record)?;
                    }
                    Ok(MultiValue::from_vec(vec![Value::Table(value), Value::Nil]))
                }
                Err(error) => host_failure(lua, &error),
            }
        })?,
    )?;
    let callback_host = host.clone();
    module.set(
        "transmit",
        scope.create_function(move |lua, command: AnyUserData| {
            let command = command.borrow::<LuaBytes>()?.0.clone();
            let Some(bytes) = command.as_bytes() else {
                return Err(LuaError::external(CoreError::InvalidApdu(
                    "APDU commands must use 8-bit elements".into(),
                )));
            };
            ApduCommand::parse(bytes).map_err(LuaError::external)?;
            match callback_host.borrow_mut().transmit(bytes) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("data", LuaBytes(ByteString::from_bytes(response.data)))?;
                    result.set("status", response.status.value())?;
                    result.set("sw1", response.status.sw1())?;
                    result.set("sw2", response.status.sw2())?;
                    result.set("description", response.status.description())?;
                    Ok(MultiValue::from_vec(vec![Value::Table(result), Value::Nil]))
                }
                Err(error) => host_failure(lua, &error),
            }
        })?,
    )?;
    Ok(module)
}

fn host_failure(lua: &Lua, error: &HostError) -> LuaResult<MultiValue> {
    let table = lua.create_table()?;
    table.set("message", error.to_string())?;
    table.set("cancelled", error.is_cancelled())?;
    Ok(MultiValue::from_vec(vec![Value::Nil, Value::Table(table)]))
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::T0 => "t0",
        Protocol::T1 => "t1",
        Protocol::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardpeek_analyser::{AnalyserCapabilities, AnalyserMetadata};
    use cardpeek_core::{ApduResponse, Atr, DocumentId, RunId, StatusWord};
    use cardpeek_transport::SessionCapabilities;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Host;

    impl CardHost for Host {
        type Cancellation = ();

        fn cancellation(&self) -> &Self::Cancellation {
            &()
        }

        fn protocol(&self) -> Protocol {
            Protocol::T1
        }

        fn capabilities(&self) -> SessionCapabilities {
            SessionCapabilities {
                extended_apdus: true,
            }
        }

        fn atr(&mut self) -> Result<Atr, HostError> {
            Ok(Atr::new(vec![0x3b, 0]))
        }

        fn current_atr_record(&self) -> Option<TraceRecordId> {
            Some(TraceRecordId::new("record-0001").unwrap())
        }

        fn reset(&mut self, _mode: ResetMode) -> Result<Atr, HostError> {
            self.atr()
        }

        fn transmit(&mut self, _command: &[u8]) -> Result<ApduResponse, HostError> {
            Ok(ApduResponse::new(vec![1], StatusWord::NORMAL_PROCESSING))
        }
    }

    fn request(source: &str) -> (ExecutionRequest, PathBuf) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("cardpeek-lua-{}-{unique}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("test.lua");
        fs::write(&path, source).unwrap();
        (
            ExecutionRequest {
                analyser: AnalyserMetadata {
                    id: "test".into(),
                    title: "Test".into(),
                    description: "Test".into(),
                    version: "1".into(),
                    capabilities: AnalyserCapabilities::default(),
                    capture_schema: None,
                    path,
                },
                run_id: RunId::new("run-test").unwrap(),
                document_id: DocumentId::new("doc-test").unwrap(),
            },
            root,
        )
    }

    #[test]
    fn native_modules_create_typed_documents_and_do_not_install_legacy_globals() {
        let (request, root) = request(
            r#"
            local cp = require("cardpeek")
            assert(card == nil and bytes == nil and ui == nil)
            local atr = cp.bytes.from_hex("3B00")
            assert(#atr == 2 and atr[1] == 0x3B and atr:to_hex() == "3B00")
            assert(atr:convert(4):to_hex() == "3B00")
            assert((atr .. cp.bytes.from_hex("90")):to_hex() == "3B0090")
            assert(atr:slice(2, 1):to_hex() == "00")
            local response, failure = cp.card.transmit(cp.bytes.from_hex("00A4040000"))
            assert(failure == nil and response.status == 0x9000 and response.data:to_hex() == "01")
            local root = cp.nodes.root()
            local card = root:append("card", "Card")
            local value = card:append("atr", "ATR")
            value:set("value", atr)
            value:set("identifier", "atr")
            value:set_provenance("record-0001", "Cold reset")
            assert(#root:children() == 1 and value:parent():id() == card:id())
            cp.log.info("native module test")
            "#,
        );
        let document = execute(&request, &mut Host, &()).unwrap();
        assert_eq!(document.node_count(), 2);
        assert_eq!(document.revision, 1);
        let value = document.find(&NodeId::new("node-0002").unwrap()).unwrap();
        assert_eq!(
            value.value,
            Some(NodeValue::Bytes(ByteString::from_hex(8, "3B00").unwrap()))
        );
        assert_eq!(
            value.provenance.as_ref().unwrap().record.as_str(),
            "record-0001"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn capture_collection_and_standalone_decode_match_without_card_access() {
        let source = r#"
            function collect(cp)
                local atr, failure = cp.card.atr()
                assert(failure == nil)
                return {{ name = "atr", bytes = atr.bytes, source = atr.record }}
            end
            function decode(cp, captured)
                assert(cp.card == nil)
                local card = cp.nodes.root():append("card", "Synthetic card")
                local atr = card:append("atr", "Answer to Reset")
                atr:set("value", captured[1].bytes)
                atr:set_provenance(captured[1].source, "Cold reset")
                cp.log.info("Read " .. tostring(#captured[1].bytes) .. " ATR bytes")
            end
        "#;
        let (mut live, root) = request(source);
        live.analyser.id = "atr".into();
        live.analyser.capabilities.offline_decoding = true;
        live.analyser.capture_schema = Some("atr/v1".into());
        let collected = execute_with_capture(&live, &mut Host, &(), 0).unwrap();
        let offline = decode_capture(&live, &collected.capture, &(), &()).unwrap();
        assert_eq!(collected.document, offline);
        assert_eq!(collected.capture.values[0].name, "atr");
        assert_eq!(
            collected.document.roots[0].children[0]
                .provenance
                .as_ref()
                .unwrap()
                .analyser
                .as_deref(),
            Some("atr")
        );
        let mut incompatible = collected.capture.clone();
        incompatible.capture_schema = "other/v1".into();
        assert!(decode_capture(&live, &incompatible, &(), &()).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn extended_native_modules_support_ported_analysers() {
        let source = r"
            local cp = require('cardpeek')
            local encoded = cp.asn1.join(0x9F4F, cp.bytes.from_hex('9F02065F2A02'))
            local tag, value, tail = cp.asn1.split(encoded)
            assert(tag == 0x9F4F and value:to_hex() == '9F02065F2A02' and tail == nil)
            assert(cp.bytes.all(cp.bytes.from_hex('0000'), 0))
            local root = cp.nodes.root():append('card', 'Card')
            local child = root:append('item', 'Test')
            child:set('identifier', '42')
            assert(cp.nodes.find_first(root, { id = 42 }):id() == child:id())
            local decoded = cp.encoding.decode('ISO-8859-1', cp.bytes.from_hex('41E9'))
            assert(decoded:byte(1) == 65 and decoded:byte(2) == 195 and decoded:byte(3) == 169)
            assert(#cp.crypto.sha1(cp.bytes.from_string('abc')) == 20)
            assert(#cp.crypto.des_ede3_cbc(true, cp.bytes.from_hex('0123456789ABCDEFFEDCBA9876543210'), cp.bytes.from_hex('0000000000000000'), cp.bytes.from_hex('0000000000000000')) == 8)
            assert(#cp.crypto.iso9797_mac(cp.bytes.from_hex('0123456789ABCDEFFEDCBA9876543210'), cp.bytes.from_hex('00')) == 8)
            assert(child:remove() and #root:children() == 0)
        ";
        let (request, root) = request(source);
        execute(&request, &mut Host, &()).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn each_run_has_fresh_state_and_nodes() {
        let source = r#"
            local cp = require("cardpeek")
            assert(previous_global == nil)
            previous_global = true
            cp.nodes.root():append("card", "Card")
        "#;
        let (first, root) = request(source);
        let first_document = execute(&first, &mut Host, &()).unwrap();
        assert_eq!(first_document.roots[0].id.as_str(), "node-0001");
        let (second, second_root) = request(source);
        let second_document = execute(&second, &mut Host, &()).unwrap();
        assert_eq!(second_document.roots[0].id.as_str(), "node-0001");
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(second_root);
    }
}
