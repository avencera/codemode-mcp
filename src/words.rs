//! Codes a person compares by eye, as BIP39 English words
//!
//! Words are easier to read aloud, remember across two screens and tell
//! apart than hex, and each of the 2048 carries 11 bits. The list is the
//! standard one (`bitcoin/bips` `bip-0039/english.txt`), kept here rather
//! than taken from a crate, so this needs no dependency

use std::sync::LazyLock;

/// The list, one word per line, in its standard order
static WORDS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| include_str!("words/bip39-english.txt").lines().collect());

/// `count` words spelling the leading bits of `bytes`, 11 bits each,
/// joined by spaces; `bytes` must hold at least `count * 11` bits
pub fn words(bytes: &[u8], count: usize) -> String {
    debug_assert!(
        bytes.len() * 8 >= count * 11,
        "too few bits for {count} words"
    );
    let bit = |index: usize| {
        bytes
            .get(index / 8)
            .is_some_and(|byte| byte >> (7 - index % 8) & 1 == 1)
    };

    (0..count)
        .map(|word| {
            let index = (0..11).fold(0, |index, offset| {
                index << 1 | usize::from(bit(word * 11 + offset))
            });

            WORDS[index]
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_the_standard_one() {
        assert_eq!(WORDS.len(), 2048);
        // the BIP39 test vector: 16 zero bytes start with eleven "abandon"s
        // and all-ones bytes with "zoo"
        assert_eq!(words(&[0; 16], 2), "abandon abandon");
        assert_eq!(words(&[0xff; 16], 2), "zoo zoo");
        // 0x7f7f… gives the vector's "legal winner thank year wave sausage"
        assert_eq!(
            words(&[0x7f; 16], 6),
            "legal winner thank year wave sausage"
        );
    }
}
