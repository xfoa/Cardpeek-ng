#![allow(missing_docs)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelpEntry {
    pub title: &'static str,
    pub explanation: &'static str,
}

#[must_use]
pub const fn entry(title: &'static str, explanation: &'static str) -> HelpEntry {
    HelpEntry { title, explanation }
}

pub const PCSC: HelpEntry = entry(
    "PC/SC",
    "The standard interface that applications use to access smart-card readers.",
);
pub const ATR: HelpEntry = entry(
    "Answer to Reset (ATR)",
    "The identification bytes that a card sends after a reset. The ATR describes communication parameters.",
);
pub const CARD_TYPE: HelpEntry = entry(
    "Card type hint",
    "The ATR reference list supplies this possible card type. It is not proof of a card application.",
);
pub const PROTOCOL: HelpEntry = entry(
    "Card protocol",
    "The rules for card communication. T=0 is byte-oriented. T=1 is block-oriented.",
);
pub const APDU: HelpEntry = entry(
    "Application Protocol Data Unit (APDU)",
    "A command sent to a card or a response returned by the card.",
);
pub const TX: HelpEntry = entry(
    "TX: transmitted",
    "The exact command bytes sent from Cardpeek-ng to the card.",
);
pub const RX: HelpEntry = entry(
    "RX: received",
    "The response data returned by the card. The status word is shown separately.",
);
pub const STATUS_WORD: HelpEntry = entry(
    "Status word",
    "Two response bytes that report the command result. 9000 usually means success.",
);
pub const RESET: HelpEntry = entry(
    "Card reset",
    "Restart card communication and obtain a new Answer to Reset. A reset can change the selected application.",
);
pub const SESSION: HelpEntry = entry(
    "Card session",
    "One exclusive connection to a reader. Its exchanges and captured data stay together.",
);
pub const TRACE: HelpEntry = entry(
    "Trace",
    "An ordered record of resets, commands, and responses. A saved trace supports inspection and replay.",
);
pub const LOAD_CURRENT_SESSION: HelpEntry = entry(
    "Load current session",
    "Open the current card session as a trace. This uses recorded exchanges and does not contact the card.",
);
pub const SEGMENT: HelpEntry = entry(
    "Trace segment",
    "A part of a trace between card resets. Commands before the first reset belong to segment 1.",
);
pub const CAPTURE_BUNDLE: HelpEntry = entry(
    "Capture bundle",
    "Values saved by an analyser for offline decoding. The bundle includes the analyser version and capture schema.",
);
pub const ANALYSER: HelpEntry = entry(
    "Analyser",
    "A trusted Lua script that reads card data and builds a result document.",
);
pub const ANALYSER_VERSION: HelpEntry = entry(
    "Analyser version",
    "The release of an analyser. Offline decoding requires the version used to create the capture bundle.",
);
pub const CAPTURE_SCHEMA: HelpEntry = entry(
    "Capture schema",
    "The versioned layout of values in a capture bundle. The decoder must support this layout.",
);
pub const LIVE: HelpEntry = entry(
    "Live analysis",
    "Read data from a connected physical card. Analyser commands can change card state.",
);
pub const DECODE: HelpEntry = entry(
    "Offline decoding",
    "Build a result from saved capture values without accessing a card or replaying commands.",
);
pub const REPLAY: HelpEntry = entry(
    "Trace replay",
    "Run an analyser against recorded exchanges. Commands go to the recording instead of a physical card.",
);
pub const RESULT_DOCUMENT: HelpEntry = entry(
    "Result document",
    "The decoded output of an analyser. Ordered nodes contain labels, values, and source references.",
);
pub const NODE_ID: HelpEntry = entry(
    "Node identifier",
    "A stable identifier for a result node within one analysis run.",
);
pub const VALUE_CLASS: HelpEntry = entry(
    "Value class",
    "The analyser-defined type of a result node, such as card, file, record, or item.",
);
pub const MIME_TYPE: HelpEntry = entry(
    "MIME type",
    "The declared format of a node value. It helps other applications interpret exported data.",
);
pub const SOURCE_RECORD: HelpEntry = entry(
    "Source record",
    "The trace record that supplied the decoded value. This link supports data verification.",
);
pub const LUA: HelpEntry = entry(
    "Lua analyser",
    "A script in the Lua language. Cardpeek-ng runs analysers as trusted code without a security sandbox.",
);
pub const TELEMETRY: HelpEntry = entry(
    "No telemetry",
    "Cardpeek-ng does not send usage data to a remote service. Exported files still require your review.",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_entries_have_clear_titles_and_explanations() {
        let entries = [
            PCSC,
            ATR,
            CARD_TYPE,
            PROTOCOL,
            APDU,
            TX,
            RX,
            STATUS_WORD,
            RESET,
            SESSION,
            TRACE,
            LOAD_CURRENT_SESSION,
            SEGMENT,
            CAPTURE_BUNDLE,
            ANALYSER,
            ANALYSER_VERSION,
            CAPTURE_SCHEMA,
            LIVE,
            DECODE,
            REPLAY,
            RESULT_DOCUMENT,
            NODE_ID,
            VALUE_CLASS,
            MIME_TYPE,
            SOURCE_RECORD,
            LUA,
            TELEMETRY,
        ];
        for item in entries {
            assert_ne!(item.title.trim(), "");
            assert_ne!(item.explanation.trim(), "");
            assert!(item.explanation.ends_with('.'));
            assert!(item.title.is_ascii());
            assert!(item.explanation.is_ascii());
        }
    }
}
