//! Card-type hints from the bundled ATR reference list.

use cardpeek_core::Atr;

const CARD_LIST: &str = include_str!("../../../analysers/shared/data/smartcard_list.txt");

#[derive(Clone, Copy)]
struct BytePattern {
    high: NibblePattern,
    low: NibblePattern,
}

#[derive(Clone, Copy)]
enum NibblePattern {
    Any,
    Exact(u8),
    OneOf(u16),
}

impl NibblePattern {
    fn parse(input: &str) -> Option<Self> {
        if input == "." {
            return Some(Self::Any);
        }
        if input.len() == 1 && input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return u8::from_str_radix(input, 16).ok().map(Self::Exact);
        }
        let values = input.strip_prefix('[')?.strip_suffix(']')?;
        let mut mask = 0_u16;
        for value in values.split(',') {
            if let Some((start, end)) = value.split_once('-') {
                let start = u8::from_str_radix(start, 16).ok()?;
                let end = u8::from_str_radix(end, 16).ok()?;
                if start > 0x0f || end > 0x0f || start > end {
                    return None;
                }
                for nibble in start..=end {
                    mask |= 1 << nibble;
                }
            } else {
                for value in value.bytes() {
                    let nibble = u8::try_from((value as char).to_digit(16)?).ok()?;
                    mask |= 1 << nibble;
                }
            }
        }
        Some(Self::OneOf(mask))
    }

    fn matches(self, value: u8) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => value == expected,
            Self::OneOf(mask) => mask & (1 << value) != 0,
        }
    }

    const fn specificity(self) -> usize {
        match self {
            Self::Any => 0,
            Self::Exact(_) => 2,
            Self::OneOf(_) => 1,
        }
    }
}

impl BytePattern {
    fn parse(input: &str) -> Option<Self> {
        if input == ".." {
            return Some(Self {
                high: NibblePattern::Any,
                low: NibblePattern::Any,
            });
        }
        let high_length = if input.starts_with('[') {
            input.find(']')? + 1
        } else {
            1
        };
        let (high, low) = input.split_at(high_length);
        Some(Self {
            high: NibblePattern::parse(high)?,
            low: NibblePattern::parse(low)?,
        })
    }

    fn matches(self, value: u8) -> bool {
        self.high.matches(value >> 4) && self.low.matches(value & 0x0f)
    }

    const fn specificity(self) -> usize {
        self.high.specificity() + self.low.specificity()
    }
}

/// Returns the first description from the most specific matching ATR entry.
#[must_use]
pub fn identify(atr: &Atr) -> Option<&'static str> {
    static ENTRIES: std::sync::OnceLock<std::collections::HashMap<usize, Vec<Entry<'static>>>> =
        std::sync::OnceLock::new();
    identify_entries(
        ENTRIES
            .get_or_init(|| index_entries(CARD_LIST))
            .get(&atr.as_bytes().len())?,
        atr.as_bytes(),
    )
}

struct Entry<'a> {
    pattern: Vec<BytePattern>,
    description: &'a str,
    specificity: usize,
}

fn index_entries(source: &str) -> std::collections::HashMap<usize, Vec<Entry<'_>>> {
    let mut indexed = std::collections::HashMap::<usize, Vec<Entry<'_>>>::new();
    for (pattern, description) in entries(source) {
        let entry = Entry {
            specificity: pattern.iter().map(|byte| byte.specificity()).sum(),
            description,
            pattern,
        };
        indexed.entry(entry.pattern.len()).or_default().push(entry);
    }
    indexed
}

fn identify_in<'a>(source: &'a str, atr: &[u8]) -> Option<&'a str> {
    identify_entries(index_entries(source).get(&atr.len())?, atr)
}

fn identify_entries<'a>(entries: &[Entry<'a>], atr: &[u8]) -> Option<&'a str> {
    let mut best = None;
    let mut best_specificity = 0;
    for entry in entries {
        if entry
            .pattern
            .iter()
            .zip(atr)
            .all(|(pattern, value)| pattern.matches(*value))
            && entry.specificity > best_specificity
        {
            best = Some(entry.description);
            best_specificity = entry.specificity;
        }
    }
    best
}

fn entries(source: &str) -> impl Iterator<Item = (Vec<BytePattern>, &str)> {
    source.split("\n\n").filter_map(|record| {
        let mut lines = record.lines();
        let pattern_line = loop {
            let line = lines.next()?;
            if !line.is_empty() && !line.starts_with('#') {
                break line;
            }
        };
        if pattern_line.starts_with(char::is_whitespace) {
            return None;
        }
        let pattern = pattern_line
            .split_whitespace()
            .map(BytePattern::parse)
            .collect::<Option<Vec<_>>>()?;
        let description = lines.find_map(|line| line.strip_prefix('\t'))?;
        Some((pattern, description))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_exact_wildcard_nibble_and_set_patterns() {
        let source = "3B 00\n\tExact card\n\n3B ..\n\tWildcard card\n\n3B 1.\n\tNibble card\n\n3B 0[0-1]\n\tSet card\n";
        assert_eq!(identify_in(source, &[0x3b, 0]), Some("Exact card"));
        assert_eq!(identify_in(source, &[0x3b, 1]), Some("Set card"));
        assert_eq!(identify_in(source, &[0x3b, 0x12]), Some("Nibble card"));
        assert_eq!(identify_in(source, &[0x3b, 0x20]), Some("Wildcard card"));
        assert_eq!(identify_in(source, &[0x3b]), None);
        assert_eq!(
            identify_in("3B ..\n\tGeneric\n\n3B [0,1]0\n\tSpecific\n", &[0x3b, 0x10]),
            Some("Specific")
        );
        assert_eq!(
            identify_in("3B 0[1-5]\n\tRange\n", &[0x3b, 3]),
            Some("Range")
        );
    }

    #[test]
    fn parses_compact_nibble_sets_from_the_updated_list() {
        assert_eq!(
            identify_in("3B 3[13]\n\tSOMA card\n", &[0x3b, 0x31]),
            Some("SOMA card")
        );
        assert_eq!(
            identify_in("3B 3[13]\n\tSOMA card\n", &[0x3b, 0x33]),
            Some("SOMA card")
        );
        assert_eq!(identify_in("3B 3[13]\n\tSOMA card\n", &[0x3b, 0x32]), None);
    }

    #[test]
    fn uses_bundled_reference_entries() {
        assert_eq!(
            identify(&Atr::from_hex("3B021450").unwrap()),
            Some("Schlumberger Multiflex 3k")
        );
        assert_eq!(
            identify(&Atr::from_hex("3B06010210010203").unwrap()),
            Some("ISOProx II Card:")
        );
        assert_eq!(
            identify(&Atr::from_hex("3B391900534F4D414453333033").unwrap()),
            Some("Identity card of the Republic of Kazakhstan (passport)")
        );
        assert_eq!(identify(&Atr::from_hex("3B00").unwrap()), None);
    }
}
