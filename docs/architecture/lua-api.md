# Lua API contract

The runtime provides native `cardpeek.bytes`, `cardpeek.card`, `cardpeek.nodes`,
`cardpeek.log`, `cardpeek.ui`, `cardpeek.asn1`, `cardpeek.tlv`, `cardpeek.en1545`,
`cardpeek.crypto`, and `cardpeek.encoding` modules.
It does not install legacy Cardpeek globals.
Ported analysers use these modules directly and keep shared code in native Lua modules.

For authoring instructions and examples, see [Write analyser scripts](../analysers.md).

## Runtime and startup

The runtime loads each analyser with `require("cardpeek")`.
The module exposes the Cardpeek-ng API through one namespace.
It does not install Cardpeek globals or emulate Cardpeek Lua behaviour.

Analyser discovery does not execute the analyser.
Metadata headers contain `@id`, `@title`, `@description`, and `@version` in leading Lua line comments.
All four fields are required.
Optional `@capabilities` values are `live`, `decode`, and `replay`.
The default capability list is `live, replay`.
A decoder also declares `@capture-schema`.
Discovery records these capabilities without executing Lua.
Analyser entry points are directly inside the library's `cards/` directory.
The library root is the Lua module and data-file root.
Shared modules, card-family modules, and data files stay below `shared/`.
The runtime replaces the Lua module search path with `?.lua` and `?/init.lua` below that root.
The runtime does not provide `dofile` compatibility behaviour.
Each run receives fresh Lua state, fresh document identifiers, and stable sequential node identifiers.
The `cardpeek.card.atr()` and `cardpeek.card.reset()` calls return an ATR result and an error value.
The ATR result contains typed `bytes` and an optional source `record` identifier.
`cardpeek.card.transmit()` returns response data, status components, and a description.
Native failures use the separate error result.

## Collection and decoding

A live-only analyser uses the top-level execution path.
A capture-capable analyser defines `collect(cardpeek)` and `decode(cardpeek, captured)`.
The runtime always executes the script at top level before it calls these functions.
Collection can use `cardpeek.card`.
It returns captured values with native bytes and source record identifiers.
The runtime stores those values in a capture bundle before decoding.
The runtime removes `cardpeek.card` before it calls the decoder during collection.
Standalone decoding receives the selected bundle and exposes the common modules and captured data.
It does not install `cardpeek.card`.
The runtime sets `cardpeek.capture_execution` and `cardpeek.captured` in both modes.
Live collection and offline decoding therefore share the same decoder without sharing card access.
The CLI and desktop replay path execute only the top-level script.
A capture-capable analyser needs a guarded top-level fallback for these paths.

## API areas

| Module | Required behaviour | Initial validation |
| --- | --- | --- |
| `cardpeek.bytes` | Constructors, explicit widths, indexing, iteration, slices, concatenation, comparison, conversion, checked integers, padding, and formatting | Focused unit tests and ATR fixtures |
| `cardpeek.asn1` | BER-TLV tags, definite lengths, values, tails, and encoding | Focused unit tests and replay document fixtures |
| `cardpeek.tlv` | BER-TLV traversal, bounded nesting, tag metadata, and standard value decoders | Focused unit tests and replay document fixtures |
| `cardpeek.en1545` | Deterministic scalar decoding and bitmap-driven record mapping | Focused unit tests and Calypso replay document fixtures |
| `cardpeek.crypto` | Hashing, symmetric encryption, message authentication, and PACE secure messaging | Focused unit tests and replay document fixtures |
| `cardpeek.encoding` | Strict conversion of supported 8-bit character encodings | Focused unit tests and replay document fixtures |
| `cardpeek.card` | Session information, reset, ATR access, explicit APDU transmission, protocol, and capabilities | Replay integration tests |
| `cardpeek.nodes` | Root access, append, search, removal, navigation, attributes, typed values, and provenance | Document conformance tests |
| `cardpeek.log` | Structured levels and messages | Bounded event tests |
| `cardpeek.ui` | Questions, notices, text input, secret input, and file selection | Broker integration tests |

The runtime does not expose a Lua progress module.
The application supplies operation progress independently.

The card API returns structured success and error values.
It does not perform implicit retries after status 6C.
It does not issue implicit GET RESPONSE commands after status 61.
Analysers may implement those operations explicitly.

Binary values cross the Lua boundary as typed native values.
Legacy `1:`, `4:`, and `8:` prefixes remain confined to XML conversion.

Each bundled analyser has replay fixtures and expected result documents.

## Function reference

A byte string is a native value with 1-bit, 4-bit, or 8-bit elements.
The width is part of the value.
An index in a byte-string method is one-based unless its description states otherwise.
An invalid argument type or value raises a Lua error unless its description states otherwise.

### Byte strings

#### Constructors and functions

| Function | Behaviour |
| --- | --- |
| `cardpeek.bytes.new(width, values)` | Return a byte string from an array of integers. The width must be 1, 4, or 8. Each integer must fit the width. |
| `cardpeek.bytes.from_hex(text, width)` | Return a byte string from hexadecimal text. The width defaults to 8. Spaces, colons, hyphens, and underscores are ignored. |
| `cardpeek.bytes.from_string(text)` | Return an 8-bit byte string from the bytes of a Lua string. |
| `cardpeek.bytes.all(data, expected)` | Return whether a nonempty byte string contains only the selected element. |
| `cardpeek.bytes.pack(width, ...)` | Pack integers, hexadecimal strings, and byte strings into one value. Every byte string must have the selected width. |
| `cardpeek.bytes.concat(...)` | Concatenate values. A non-byte-string argument is converted to 8-bit elements. The first byte string sets the width. An empty argument list returns an empty 8-bit value. |
| `cardpeek.bytes.get(data, index)` | Return the element at a zero-based index. Return `nil` for a `nil` input, a negative index, or an index after the value. |
| `cardpeek.bytes.sub(data, first, last)` | Return an inclusive zero-based range. The first index defaults to zero. The last index defaults to the end. Negative indices count from the end. Return `nil` for a `nil` input or an invalid range. |
| `cardpeek.bytes.number(data)` | Return the unsigned big-endian integer value. Return zero for `nil`. Reject values above the signed Lua integer range. |
| `cardpeek.bytes.format(data, format)` | Return formatted text. Supported codes are `%D` for hexadecimal, `%S` for width and hexadecimal, `%w` for width, `%l` for element count, `%I` for an integer, `%C` for direct characters, `%P` for printable characters, and `%%` for a percent sign. |
| `cardpeek.bytes.printable(data)` | Return whether a nonempty value contains only ASCII elements from 32 through 126. |
| `cardpeek.bytes.reverse(data)` | Return a value with the element order reversed. |
| `cardpeek.bytes.pad_left(data, length, value)` | Add elements on the left until the value has the selected length. Do not truncate a longer value. |
| `cardpeek.bytes.pad_right(data, length, value)` | Add elements on the right until the value has the selected length. Do not truncate a longer value. |

Hexadecimal input needs two digits for an 8-bit element.
It needs one digit for a 4-bit element.
A 1-bit value accepts only `0` and `1`.

#### Methods

| Method | Behaviour |
| --- | --- |
| `data:width()` | Return the element width in bits. |
| `data:len()` | Return the number of elements. |
| `data:bit_len()` | Return the total size in bits. |
| `data:to_hex()` | Return uppercase hexadecimal text. |
| `data:to_string()` | Decode an 8-bit value as UTF-8. Raise an error for invalid UTF-8. Return empty text for another width. |
| `data:elements()` | Return the elements as a new Lua array. |
| `data:convert(width)` | Convert the value to width 1, 4, or 8. Conversion to a wider width left-aligns an incomplete final element. |
| `data:slice(start, length)` | Return a copy that starts at a one-based index. The length is optional. Stop at the end of the value. A start index of zero raises an error. |
| `data:iter()` | Return an iterator that yields each element value. |
| `data:ipairs()` | Return an iterator that yields zero-based index and element value pairs. |

#### Operators

| Expression | Behaviour |
| --- | --- |
| `#data` | Return the number of elements. |
| `data[index]` | Return the element at a positive one-based index. Return `nil` for other indices. |
| `left == right` | Compare the width and every element. |
| `left .. right` | Concatenate two byte strings with the same width. |
| `tostring(data)` | Return uppercase hexadecimal text. |

### Card access

The runtime installs `cardpeek.card` for live execution and replay.
It does not install this module for standalone decoding.
It removes this module before the decoder runs during capture execution.

| Function or field | Behaviour |
| --- | --- |
| `cardpeek.card.protocol` | Contain `t0`, `t1`, or `other`. |
| `cardpeek.card.capabilities.extended_apdus` | Report whether the transport supports extended APDUs. |
| `cardpeek.card.info()` | Return a table with the `protocol` field. |
| `cardpeek.card.atr()` | Return the current ATR result and `nil`. On failure, return `nil` and a failure table. |
| `cardpeek.card.reset(mode)` | Reset the card with mode `cold` or `warm`. Return the new ATR result and `nil`. On failure, return `nil` and a failure table. |
| `cardpeek.card.transmit(command)` | Transmit one complete 8-bit APDU. Return a response table and `nil`. On failure, return `nil` and a failure table. |

An ATR result contains `bytes` and an optional source `record`.
A response contains `data`, `status`, `sw1`, `sw2`, and `description`.
A failure contains `message` and `cancelled`.
A non-success status word is a valid response.
The runtime does not retry after status `6Cxx`.
It does not send GET RESPONSE after status `61xx`.

### Result documents

A node handle refers to a result node.
The document root has no attributes.
Its `id()` and `parent()` methods return `nil`.
Its `children()` method returns the top-level nodes.

| Function | Behaviour |
| --- | --- |
| `cardpeek.nodes.root()` | Return the document root handle. |
| `cardpeek.nodes.roots()` | Return the top-level nodes as an array. |
| `cardpeek.nodes.get(id)` | Return the node with the selected runtime identifier. Return `nil` when it does not exist. |
| `cardpeek.nodes.find(parent, criteria)` | Return an iterator over recursive matches in document order. Include the parent when it matches. |
| `cardpeek.nodes.find_first(parent, criteria)` | Return the first recursive match or `nil`. |

| Method | Behaviour |
| --- | --- |
| `node:append(class, label)` | Append a child with a new sequential runtime identifier. Return its handle. |
| `node:parent()` | Return the parent handle. Return `nil` for the document root or a top-level node. |
| `node:children()` | Return the ordered children as an array. |
| `node:id()` | Return the stable runtime identifier. Return `nil` for the document root. |
| `node:get(field)` | Return an attribute value. Raise an error for the document root or an unknown field. |
| `node:set(field, value)` | Set an attribute. Return no value. |
| `node:set_provenance(record, operation)` | Set the source trace record and optional operation text. Return no value. |
| `node:find(criteria)` | Return an iterator over recursive matches. Include the receiver when it matches. |
| `node:find_first(criteria)` | Return the first recursive match or `nil`. |
| `node:remove()` | Remove the node and its descendants. Return whether the runtime removed the node. |

Search criteria support `class`, `label`, `identifier`, `alternative`, and `mime_type`.
The aliases `classname`, `id`, `alt`, and `mime-type` are accepted.
String and integer criteria are compared as text.

Node attributes are `class`, `label`, `identifier`, `alternative`, `mime_type`, `value`, and `size_bits`.
The `class` and `label` attributes require text.
The `identifier` and `alternative` attributes accept text, numbers, or `nil`.
The `mime_type` attribute accepts text or `nil`.
The `value` attribute accepts text, a byte string, or `nil`.
The `size_bits` attribute is read-only.
Setting `value` derives `size_bits`.

### Logs

Each log function emits one message and returns no value.

| Function | Severity |
| --- | --- |
| `cardpeek.log.debug(message)` | Debug |
| `cardpeek.log.info(message)` | Information |
| `cardpeek.log.warning(message)` | Warning |
| `cardpeek.log.error(message)` | Error |

### User interaction

| Function | Behaviour |
| --- | --- |
| `cardpeek.ui.question(prompt)` | Request a yes or no answer. Return a boolean. |
| `cardpeek.ui.notice(prompt)` | Request acknowledgement. Return no value. |
| `cardpeek.ui.secret(prompt)` | Request secret text. Return the text. |
| `cardpeek.ui.text(prompt, default)` | Request visible text. The default text is optional. Return the text. |
| `cardpeek.ui.file(prompt, must_exist)` | Request a file path. Require an existing path when `must_exist` is true. Return the path as text. |

These functions require an interactive frontend.
An unavailable interaction, a response mismatch, a timeout, or cancellation raises an error.
Replay and standalone decoding do not provide interaction.

### ASN.1

These functions process BER tags and definite lengths.
Indefinite lengths are not supported.
A tag uses the packed numeric representation returned by the parser.

| Function | Behaviour |
| --- | --- |
| `cardpeek.asn1.split(data)` | Return the tag, value, and remaining bytes. Return three `nil` values for malformed or incomplete input. |
| `cardpeek.asn1.split_tag(data)` | Return the tag and remaining bytes. Return two `nil` values for malformed or incomplete input. |
| `cardpeek.asn1.split_length(data)` | Return the definite length and remaining bytes. Return two `nil` values for malformed or incomplete input. |
| `cardpeek.asn1.join(tag, value, tail)` | Encode the tag and 8-bit value. Append the optional tail. Return the encoded byte string. |

The remaining bytes are `nil` when no bytes remain.

### TLV trees

A reference maps a hexadecimal tag to a `{ label, decoder }` entry.
A nested key has the form `PARENT/TAG`.
Tags use uppercase hexadecimal without a prefix.
A decoder receives a result node and a byte string.
It can return `false` to remove the new node.

| Function | Behaviour |
| --- | --- |
| `cardpeek.tlv.parse(parent, data, reference)` | Parse a sequence below a parent node. Return the last new node. Return an error node for malformed data. Return `nil` for empty data. The reference is optional. |
| `cardpeek.tlv.one(parent, tag, value, reference)` | Decode one tag and value below a parent node. Return the new node or `false` when its decoder removes it. The reference is optional. |
| `cardpeek.tlv.info(tag, reference, parent)` | Return the label and decoder for a tag. The reference and numeric parent tag are optional. Return `nil` values when no entry exists. |
| `cardpeek.tlv.tag_type(tag)` | Return `TLV (Universal)`, `TLV (Application-specific)`, `TLV (Context-specific)`, or `TLV (Private)`. |

Constructed values are parsed recursively.
Nesting is limited to 64 levels.
Malformed input produces an `Unparsed ASN1 data` node.

| Parser callback | Behaviour |
| --- | --- |
| `cardpeek.tlv.parsers.number(node, data)` | Store the bytes and a big-endian unsigned integer as display text. |
| `cardpeek.tlv.parsers.printable(node, data)` | Store the bytes and printable display text. Include hexadecimal text for non-printable values. Return `false` for empty data. |
| `cardpeek.tlv.parsers.date(node, data)` | Decode three BCD bytes as MM/DD/YYYY. Years below 1980 use the 2000s. |
| `cardpeek.tlv.parsers.country(node, data)` | Decode a numeric country code through `shared.data.country-codes`. |
| `cardpeek.tlv.parsers.currency(node, data)` | Decode a numeric currency code through `shared.data.currency-codes`. |
| `cardpeek.tlv.parsers.oid(node, data)` | Store the bytes and an object identifier in brace notation. Return `false` for empty data. |

### EN 1545

| Function | Behaviour |
| --- | --- |
| `cardpeek.en1545.date(data, reference)` | Decode a day count as `Www MM/DD/YY`. The reference is a Unix timestamp. The default reference is 1997-01-01 UTC. |
| `cardpeek.en1545.time(data)` | Decode the first 11 bits as minutes after midnight. Return `HH:MM`. |
| `cardpeek.en1545.quarters(data)` | Decode the first 7 bits as 15-minute units. Return `HH:MM`, `End of service`, or `Not significant`. |
| `cardpeek.en1545.date_time(data, reference)` | Decode a second count as `Www Mon D HH:MM:SS YYYY`. The reference is a Unix timestamp. The default reference is 1997-01-01 UTC. |
| `cardpeek.en1545.bcd_date(data)` | Decode 32 BCD bits as `DD/MM/YYYY`. |
| `cardpeek.en1545.alpha(data)` | Decode complete 5-bit groups with the EN 1545 alphabet. Ignore an incomplete final group. |
| `cardpeek.en1545.network_id(data)` | Decode 12-bit BCD country and network codes. Require at least 24 bits. Return the country and network names. |
| `cardpeek.en1545.number(data)` | Return the unsigned big-endian integer as display text. |
| `cardpeek.en1545.amount(data)` | Return an amount in euros with two decimal places. |
| `cardpeek.en1545.zones(data)` | Decode an 8-bit zone bitmap as a minimum and maximum range. |
| `cardpeek.en1545.undefined(data)` | Return the value as `0x` followed by uppercase hexadecimal text. |
| `cardpeek.en1545.is_all(data, expected)` | Return whether a nonempty byte string contains only the selected element. |
| `cardpeek.en1545.map(root, condition, ...)` | Apply one or more format tables to matching records. Return no value. |

A negative date reference selects subtraction.
A string map condition selects a file by label and records with the label `record`.
A table condition supplies separate `file` and `record` criteria.
Each format field is `{ decoder, bitLength, label, arguments }`.
The constants `BITMAP`, `REPEAT`, and `BITMAP_BE` select structural fields.
`BITMAP` selects the least significant bit first.
`BITMAP_BE` selects the most significant bit first.
`REPEAT` uses its first child as the repeated field.
A custom scalar decoder receives a byte string and its optional arguments.
It returns display text or `nil` to omit the field.

### Cryptography

Every key and data argument is an 8-bit byte string.

| Function | Behaviour |
| --- | --- |
| `cardpeek.crypto.sha1(data)` | Return a 20-byte SHA-1 digest. |
| `cardpeek.crypto.sha256(data)` | Return a 32-byte SHA-256 digest. |
| `cardpeek.crypto.aes_cbc(encrypt, key, iv, data)` | Encrypt or decrypt complete 16-byte blocks with AES-256-CBC. Require a 32-byte key and a 16-byte initialisation vector. Do not apply padding. |
| `cardpeek.crypto.aes_cmac(key, data)` | Return a 16-byte AES-CMAC. Require a 32-byte key. |
| `cardpeek.crypto.des_ede3_cbc(encrypt, key, iv, data)` | Encrypt or decrypt complete 8-byte blocks with two-key Triple DES CBC. Require a 16-byte key and an 8-byte initialisation vector. Do not apply padding. |
| `cardpeek.crypto.iso9797_mac(key, data)` | Return an 8-byte ISO/IEC 9797-1 MAC with padding method 2 and MAC algorithm 3. Require a 16-byte key. |
| `cardpeek.crypto.pace_new(credential, secret, mapping_scalar, ephemeral_scalar)` | Create a PACE session. The credential is `mrz`, `can`, `pin`, or `puk`. The optional fixed scalars each contain 48 bytes. Return a session object. |
| `cardpeek.crypto.pace_handshake(session, response)` | Start or continue the PACE handshake. Return the next complete APDU or `nil` after authentication. The optional response contains `data` and `status`. |
| `cardpeek.crypto.pace_protect(session, command)` | Protect one short APDU with PACE secure messaging. Return the protected command. |
| `cardpeek.crypto.pace_unprotect(session, response)` | Validate and decrypt protected response bytes with their final status. Return a table with `data` and `status`. |

PACE uses ECDH generic mapping with Brainpool P-384r1 and AES-256-CBC-CMAC.
Fixed scalars are for deterministic tests.
Do not use them for live analysis.
The PACE profile supports short APDUs only.

### Character encodings

| Function | Behaviour |
| --- | --- |
| `cardpeek.encoding.decode(name, data)` | Decode an 8-bit byte string as UTF-8 text. Raise an error for an unsupported encoding or invalid input. |

Supported names are `UTF-8`, `TIS-620`, and `ISO-8859-1` through `ISO-8859-16` except `ISO-8859-12`.
Names are not case-sensitive.
The decoder maps ISO-8859-1 to Windows-1252, ISO-8859-9 to Windows-1254, and TIS-620 to Windows-874.

### Capture runtime fields

| Field | Behaviour |
| --- | --- |
| `cardpeek.capture_execution` | Equal `true` during capture execution and standalone decoding. It is absent during top-level live execution and replay. |
| `cardpeek.captured` | Contain the captured array after collection and during standalone decoding. Each entry contains `name`, `bytes`, and `source`. |

The runtime sets `cardpeek.captured` only after `collect` returns.
It sets `cardpeek.capture_execution` before top-level execution in both capture modes.
A CLI fallback can use these fields to avoid duplicate collection or decoding.

## Shared Lua helpers

The bundled library provides two reusable Lua modules.
They use the native API.
They do not add global functions.
Load them from the analyser library root:

```lua
local apdu = require("shared.lib.apdu")
local util = require("shared.lib.util")
```

The APDU helpers return response tables from `cardpeek.card.transmit`.
A non-success status word does not raise an error.
The caller must check the response status.
Most arguments have default values.

### APDU helpers

| Function | Behaviour |
| --- | --- |
| `apdu.start(title)` | Read the current ATR. Append a `card` node with the selected title. Append its `atr` child. Set ATR provenance when a source record exists. Return the card node. Raise an error on a native failure. |
| `apdu.select(path, return_what, length, cla)` | Call `util.select` with the same arguments. |
| `apdu.read_record(sfi, record, length, cla)` | Call `util.read_record` with the same arguments. |
| `apdu.read_binary(offset, length, cla)` | Call `util.read_binary` with the same arguments. |
| `apdu.get_data(tag, length, cla)` | Call `util.get_data` with the same arguments. |
| `apdu.verify(pin, p1, p2)` | Send a VERIFY command with the PIN string as command data. The reference values default to zero. Return the response. Do not log or store the PIN. |

### General helpers

| Function | Behaviour |
| --- | --- |
| `util.transmit(command)` | Transmit one complete APDU. Raise an error on a native failure. Return the response table. |
| `util.select(path, return_what, length, cla)` | Send a SELECT command for a path accepted by `util.file_path`. The control value defaults to zero. A `nil` length sends `Le = 0`. The class defaults to zero. Return the response. Return status `6F00` without card access for an invalid path. |
| `util.file_path(path)` | Convert a path to its file identifier and SELECT control value. Return two values. Return `nil, nil` for an invalid path. |
| `util.read_record(sfi, record, length, cla)` | Send READ RECORD with the selected short file identifier and record number. The short file identifier and length default to zero. The class defaults to zero. Use `sfi = "."` for the current file. Return the response. |
| `util.read_binary(offset, length, cla)` | Send READ BINARY at the selected offset. The offset and length default to zero. The class defaults to zero. Return the response. |
| `util.get_data(tag, length, cla)` | Send GET DATA for a 16-bit tag. The length defaults to zero. The class defaults to zero. Return the response. |
| `util.node(parent, class, label, value, alternative, identifier)` | Append a result node. Set only non-`nil` optional attributes. Convert non-byte-string values and display text with `tostring`. Return the node. |
| `util.success(response)` | Return whether `response.status` equals `9000`. |

### File path syntax

A byte-string path selects that value with control `0`.
Text paths use these forms:

| Form | Selection |
| --- | --- |
| `#XXXX` | Select by four hexadecimal digits. Use control `0` for two bytes and control `4` for other lengths. |
| `.XXXX` | Select a file below the current directory with control `2`. |
| `.XXXX/` | Select a directory below the current directory with control `1`. |
| `..` | Select the parent directory with control `3`. Send an empty file identifier. |
| `./PATH` | Select a path below the current directory with control `9`. Remove the leading `./`. |
| `/PATH` | Select an absolute path with control `8`. Remove every slash before hexadecimal conversion. |

The helper does not check that a command length or file identifier fits one APDU.
The caller must supply valid values.
