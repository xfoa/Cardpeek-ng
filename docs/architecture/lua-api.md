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
