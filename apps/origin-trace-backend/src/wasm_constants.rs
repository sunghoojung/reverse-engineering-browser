//! Known cryptographic, checksum, encoding and mixing constants, and the
//! bounded scans that find them in a captured module's data segments and in
//! its constant immediates.
//!
//! A match names a constant set and where its values occur. It is evidence
//! that the bytes are present, never that an algorithm runs: a table can be
//! dead data, and a single immediate can coincide with an unrelated value.
//! Every match therefore reports how many of the set's values matched, so a
//! partial table stays partial. Generated tables (AES, CRC) are computed from
//! their definitions; the SHA-2 and MD5 tables are checked in the tests below
//! by recomputing digests against the sha2 crate and known MD5 vectors.
use std::{collections::HashMap, sync::OnceLock};

/// What one element of a constant set is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Width {
    Byte,
    Word32,
    Word64,
}

pub(crate) struct ConstantSet {
    pub id: &'static str,
    pub label: &'static str,
    pub family: &'static str,
    pub width: Width,
    /// Elements, widened to u64 so one comparison serves every width.
    pub values: Vec<u64>,
    /// Consecutive elements a data run needs before it is reported. Zero
    /// means the set is not looked for in data.
    pub data_min_run: usize,
    /// Distinct elements one function's immediates need before they are
    /// reported. Zero means the set is not looked for in immediates: a lone
    /// CRC table entry as an immediate says nothing.
    pub immediate_min: usize,
}

impl ConstantSet {
    pub fn total(&self) -> usize {
        self.values.len()
    }
}

/// How a data run stores its elements.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Encoding {
    Bytes,
    U32Le,
    U32Be,
    U64Le,
    U64Be,
    /// A 64-bit table kept as two 32-bit little-endian words, high word
    /// first, as 32-bit implementations of SHA-512 store it.
    U64HighLow,
}

impl Encoding {
    pub fn name(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::U32Le => "u32_le",
            Self::U32Be => "u32_be",
            Self::U64Le => "u64_le",
            Self::U64Be => "u64_be",
            Self::U64HighLow => "u32_pairs_high_first",
        }
    }
    fn stride(self) -> usize {
        match self {
            Self::Bytes => 1,
            Self::U32Le | Self::U32Be => 4,
            _ => 8,
        }
    }
    fn matches(self, value: u64, bytes: &[u8]) -> bool {
        match self {
            Self::Bytes => bytes[0] as u64 == value,
            Self::U32Le => bytes[..4] == (value as u32).to_le_bytes(),
            Self::U32Be => bytes[..4] == (value as u32).to_be_bytes(),
            Self::U64Le => bytes[..8] == value.to_le_bytes(),
            Self::U64Be => bytes[..8] == value.to_be_bytes(),
            Self::U64HighLow => {
                bytes[..4] == ((value >> 32) as u32).to_le_bytes()
                    && bytes[4..8] == (value as u32).to_le_bytes()
            }
        }
    }
}

fn words32(values: &[u32]) -> Vec<u64> {
    values.iter().map(|value| u64::from(*value)).collect()
}

fn bytes(values: &[u8]) -> Vec<u64> {
    values.iter().map(|value| u64::from(*value)).collect()
}

/// Multiplication in GF(2^8) with the AES polynomial.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

/// The AES S-box from its definition: the multiplicative inverse in GF(2^8)
/// followed by the affine transform.
pub(crate) fn aes_sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];
    for (x, entry) in sbox.iter_mut().enumerate() {
        let inverse = if x == 0 {
            0
        } else {
            (1..=255u8).find(|y| gf_mul(x as u8, *y) == 1).unwrap_or(0)
        };
        let mut value = inverse;
        for shift in 1..5 {
            value ^= inverse.rotate_left(shift);
        }
        *entry = value ^ 0x63;
    }
    sbox
}

/// Te0..Te3 and Td0..Td3 as the reference implementation spells them: one
/// MixColumns column per entry, the first byte most significant.
fn aes_tables(sbox: &[u8; 256], inverse: &[u8; 256]) -> [Vec<u32>; 8] {
    let column = |a: u8, b: u8, c: u8, d: u8| u32::from_be_bytes([a, b, c, d]);
    let te0 = (0..256)
        .map(|x| {
            let s = sbox[x];
            column(gf_mul(s, 2), s, s, gf_mul(s, 3))
        })
        .collect::<Vec<_>>();
    let td0 = (0..256)
        .map(|x| {
            let s = inverse[x];
            column(gf_mul(s, 14), gf_mul(s, 9), gf_mul(s, 13), gf_mul(s, 11))
        })
        .collect::<Vec<_>>();
    let rotated = |table: &[u32], bits: u32| {
        table
            .iter()
            .map(|value| value.rotate_right(bits))
            .collect::<Vec<_>>()
    };
    [
        te0.clone(),
        rotated(&te0, 8),
        rotated(&te0, 16),
        rotated(&te0, 24),
        td0.clone(),
        rotated(&td0, 8),
        rotated(&td0, 16),
        rotated(&td0, 24),
    ]
}

/// A byte-at-a-time CRC-32 table: `reflected` for the LSB-first form.
pub(crate) fn crc_table(polynomial: u32, reflected: bool) -> Vec<u32> {
    (0..256u32)
        .map(|byte| {
            let mut value = if reflected { byte } else { byte << 24 };
            for _ in 0..8 {
                value = if reflected {
                    if value & 1 != 0 {
                        (value >> 1) ^ polynomial
                    } else {
                        value >> 1
                    }
                } else if value & 0x8000_0000 != 0 {
                    (value << 1) ^ polynomial
                } else {
                    value << 1
                };
            }
            value
        })
        .collect()
}

struct Spec {
    id: &'static str,
    label: &'static str,
    family: &'static str,
    width: Width,
    values: Vec<u64>,
    data: usize,
    immediates: usize,
}

fn set(spec: Spec) -> ConstantSet {
    ConstantSet {
        id: spec.id,
        label: spec.label,
        family: spec.family,
        width: spec.width,
        values: spec.values,
        data_min_run: spec.data,
        immediate_min: spec.immediates,
    }
}

/// The catalog, built once. Labels name every algorithm that shares a set,
/// so a match is never narrower than its evidence.
pub(crate) fn catalog() -> &'static [ConstantSet] {
    static CATALOG: OnceLock<Vec<ConstantSet>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        use Width::{Byte, Word32, Word64};
        let sbox = aes_sbox();
        let mut inverse = [0u8; 256];
        for (index, value) in sbox.iter().enumerate() {
            inverse[*value as usize] = index as u8;
        }
        let aes = aes_tables(&sbox, &inverse);
        let w32 = |id, label, family, values: &[u32], data, immediates| Spec {
            id,
            label,
            family,
            width: Word32,
            values: words32(values),
            data,
            immediates,
        };
        let w64 = |id, label, family, values: &[u64], data, immediates| Spec {
            id,
            label,
            family,
            width: Word64,
            values: values.to_vec(),
            data,
            immediates,
        };
        let text = |id, label, family, values: &[u8], data| Spec {
            id,
            label,
            family,
            width: Byte,
            values: bytes(values),
            data,
            immediates: 0,
        };
        let aes_labels = [
            ("aes_te0", "AES encryption T-table Te0"),
            ("aes_te1", "AES encryption T-table Te1"),
            ("aes_te2", "AES encryption T-table Te2"),
            ("aes_te3", "AES encryption T-table Te3"),
            ("aes_td0", "AES decryption T-table Td0"),
            ("aes_td1", "AES decryption T-table Td1"),
            ("aes_td2", "AES decryption T-table Td2"),
            ("aes_td3", "AES decryption T-table Td3"),
        ];
        let mut specs = vec![
            w32(
                "sha256_k",
                "SHA-256 round constants (also SHA-224)",
                "sha2",
                &SHA256_K,
                4,
                2,
            ),
            w32(
                "sha256_h",
                "SHA-256 initial hash value (also the BLAKE2s IV)",
                "sha2",
                &SHA256_H,
                4,
                2,
            ),
            w32(
                "sha224_h",
                "SHA-224 initial hash value",
                "sha2",
                &SHA224_H,
                4,
                2,
            ),
            w64(
                "sha512_k",
                "SHA-512 round constants (also SHA-384)",
                "sha2",
                &SHA512_K,
                4,
                2,
            ),
            w64(
                "sha512_h",
                "SHA-512 initial hash value (also the BLAKE2b IV)",
                "sha2",
                &SHA512_H,
                4,
                2,
            ),
            w64(
                "sha384_h",
                "SHA-384 initial hash value",
                "sha2",
                &SHA384_H,
                4,
                2,
            ),
            w32(
                "sha1_h",
                "SHA-1 initial hash value (also RIPEMD-160)",
                "sha1",
                &[
                    0x6745_2301,
                    0xefcd_ab89,
                    0x98ba_dcfe,
                    0x1032_5476,
                    0xc3d2_e1f0,
                ],
                5,
                2,
            ),
            w32(
                "md5_h",
                "MD5 or MD4 initial state (the first four SHA-1 words)",
                "md5",
                &[0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
                4,
                2,
            ),
            w32(
                "sha1_k",
                "SHA-1 round constants",
                "sha1",
                &[0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6],
                4,
                2,
            ),
            w32("md5_t", "MD5 sine table", "md5", &MD5_T, 4, 2),
            text("aes_sbox", "AES S-box", "aes", &sbox, 16),
            text("aes_inv_sbox", "AES inverse S-box", "aes", &inverse, 16),
            w32(
                "crc32_table",
                "CRC-32 table (reflected polynomial 0xEDB88320)",
                "crc32",
                &crc_table(0xedb8_8320, true),
                8,
                0,
            ),
            w32(
                "crc32c_table",
                "CRC-32C table (reflected polynomial 0x82F63B78)",
                "crc32",
                &crc_table(0x82f6_3b78, true),
                8,
                0,
            ),
            w32(
                "crc32_msb_table",
                "CRC-32 table (MSB-first polynomial 0x04C11DB7)",
                "crc32",
                &crc_table(0x04c1_1db7, false),
                8,
                0,
            ),
            w32(
                "crc32_polynomial",
                "CRC-32 reflected polynomial",
                "crc32",
                &[0xedb8_8320],
                0,
                1,
            ),
            w32(
                "crc32c_polynomial",
                "CRC-32C reflected polynomial",
                "crc32",
                &[0x82f6_3b78],
                0,
                1,
            ),
            w32(
                "chacha_sigma",
                "ChaCha/Salsa20 constant \"expand 32-byte k\"",
                "chacha",
                &[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574],
                4,
                2,
            ),
            w32(
                "salsa_tau",
                "Salsa20/ChaCha constant \"expand 16-byte k\"",
                "chacha",
                &[0x6170_7865, 0x3120_646e, 0x7962_2d36, 0x6b20_6574],
                4,
                2,
            ),
            text(
                "base64_standard",
                "Base64 alphabet",
                "encoding",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                63,
            ),
            text(
                "base64_url",
                "Base64 URL-safe alphabet",
                "encoding",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
                63,
            ),
            text(
                "base62_alphanumeric",
                "Alphanumeric alphabet (Base62, or a Base64 prefix)",
                "encoding",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                62,
            ),
            text(
                "base32_rfc4648",
                "Base32 alphabet (RFC 4648)",
                "encoding",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                32,
            ),
            w32(
                "fnv1_32",
                "FNV-1/FNV-1a 32-bit offset basis and prime",
                "hash_mix",
                &[0x811c_9dc5, 0x0100_0193],
                0,
                1,
            ),
            w64(
                "fnv1_64",
                "FNV-1/FNV-1a 64-bit offset basis and prime",
                "hash_mix",
                &[0xcbf2_9ce4_8422_2325, 0x0000_0100_0000_01b3],
                0,
                1,
            ),
            w32(
                "murmur3_32",
                "MurmurHash3 32-bit constants",
                "hash_mix",
                &[
                    0xcc9e_2d51,
                    0x1b87_3593,
                    0xe654_6b64,
                    0x85eb_ca6b,
                    0xc2b2_ae35,
                ],
                0,
                2,
            ),
            w64(
                "murmur3_64",
                "MurmurHash3 x64 constants",
                "hash_mix",
                &[
                    0x87c3_7b91_1142_53d5,
                    0x4cf5_ad43_2745_937f,
                    0xff51_afd7_ed55_8ccd,
                    0xc4ce_b9fe_1a85_ec53,
                ],
                0,
                2,
            ),
            w32(
                "xxhash32_primes",
                "xxHash32 primes",
                "hash_mix",
                &[
                    0x9e37_79b1,
                    0x85eb_ca77,
                    0xc2b2_ae3d,
                    0x27d4_eb2f,
                    0x1656_67b1,
                ],
                0,
                2,
            ),
            w64(
                "xxhash64_primes",
                "xxHash64 primes (also XXH3)",
                "hash_mix",
                &[
                    0x9e37_79b1_85eb_ca87,
                    0xc2b2_ae3d_27d4_eb4f,
                    0x1656_67b1_9e37_79f9,
                    0x85eb_ca77_c2b2_ae63,
                    0x27d4_eb2f_1656_67c5,
                ],
                0,
                2,
            ),
            w64(
                "siphash_init",
                "SipHash initialization constants (\"somepseudorandomlygeneratedbytes\")",
                "hash_mix",
                &[
                    0x736f_6d65_7073_6575,
                    0x646f_7261_6e64_6f6d,
                    0x6c79_6765_6e65_7261,
                    0x7465_6462_7974_6573,
                ],
                4,
                2,
            ),
            w64(
                "pcg_lcg",
                "PCG / Knuth MMIX LCG multiplier and increment",
                "prng",
                &[0x5851_f42d_4c95_7f2d, 0x1405_7b7e_f767_814f],
                0,
                1,
            ),
            w64(
                "xorshift64star",
                "xorshift64* multiplier",
                "prng",
                &[0x2545_f491_4f6c_dd1d],
                0,
                1,
            ),
            w64(
                "splitmix64",
                "SplitMix64 constants (the first is the 64-bit golden ratio)",
                "prng",
                &[
                    0x9e37_79b9_7f4a_7c15,
                    0xbf58_476d_1ce4_e5b9,
                    0x94d0_49bb_1331_11eb,
                ],
                0,
                1,
            ),
            w32(
                "golden_ratio_32",
                "32-bit golden ratio (TEA/XTEA delta, hash mixing)",
                "hash_mix",
                &[0x9e37_79b9],
                0,
                1,
            ),
            w32(
                "mt19937",
                "MT19937 constants",
                "prng",
                &[0x6c07_8965, 0x9908_b0df, 0x9d2c_5680, 0xefc6_0000],
                0,
                2,
            ),
        ];
        for (index, (id, label)) in aes_labels.into_iter().enumerate() {
            specs.push(w32(id, label, "aes", &aes[index], 8, 0));
        }
        specs.into_iter().map(set).collect()
    })
}

/// A word can start a data run only when it is unlikely to occur by chance.
/// Zeros, small integers and all-ones words still join a run that a
/// distinctive neighbour started.
fn distinctive(width: Width, value: u64) -> bool {
    match width {
        Width::Byte => true,
        Width::Word32 => {
            let value = value as u32;
            (6..=26).contains(&value.count_ones()) && value > 0xffff && value < 0xffff_0000
        }
        Width::Word64 => (12..=52).contains(&value.count_ones()),
    }
}

#[derive(Clone, Copy)]
struct Seed {
    set: u16,
    index: u32,
    encoding: Encoding,
}

/// One prefilter bit per hashed key keeps the common miss to a load and a
/// shift instead of a map lookup per data byte.
const FILTER_BITS: u32 = 20;

struct Seeds {
    four: HashMap<u32, Vec<Seed>>,
    eight: HashMap<u64, Vec<Seed>>,
    filter_four: Vec<u64>,
    filter_eight: Vec<u64>,
}

fn filter_slot(key: u64) -> usize {
    (key.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - FILTER_BITS)) as usize
}

fn mark(filter: &mut [u64], key: u64) {
    let slot = filter_slot(key);
    filter[slot / 64] |= 1 << (slot % 64);
}

fn maybe(filter: &[u64], key: u64) -> bool {
    let slot = filter_slot(key);
    filter[slot / 64] & (1 << (slot % 64)) != 0
}

fn seeds() -> &'static Seeds {
    static SEEDS: OnceLock<Seeds> = OnceLock::new();
    SEEDS.get_or_init(|| {
        let mut seeds = Seeds {
            four: HashMap::new(),
            eight: HashMap::new(),
            filter_four: vec![0; (1 << FILTER_BITS) / 64],
            filter_eight: vec![0; (1 << FILTER_BITS) / 64],
        };
        for (number, set) in catalog().iter().enumerate() {
            if set.data_min_run == 0 {
                continue;
            }
            let set_index = number as u16;
            match set.width {
                Width::Byte => {
                    for (index, window) in set.values.windows(4).enumerate() {
                        let key = u32::from_le_bytes([
                            window[0] as u8,
                            window[1] as u8,
                            window[2] as u8,
                            window[3] as u8,
                        ]);
                        let seed = Seed {
                            set: set_index,
                            index: index as u32,
                            encoding: Encoding::Bytes,
                        };
                        seeds.four.entry(key).or_default().push(seed);
                        mark(&mut seeds.filter_four, u64::from(key));
                    }
                }
                Width::Word32 => {
                    for (index, value) in set.values.iter().enumerate() {
                        if !distinctive(set.width, *value) {
                            continue;
                        }
                        let value = *value as u32;
                        for (key, encoding) in [
                            (value, Encoding::U32Le),
                            (value.swap_bytes(), Encoding::U32Be),
                        ] {
                            seeds.four.entry(key).or_default().push(Seed {
                                set: set_index,
                                index: index as u32,
                                encoding,
                            });
                            mark(&mut seeds.filter_four, u64::from(key));
                        }
                    }
                }
                Width::Word64 => {
                    for (index, value) in set.values.iter().enumerate() {
                        if !distinctive(set.width, *value) {
                            continue;
                        }
                        for (key, encoding) in [
                            (*value, Encoding::U64Le),
                            (value.swap_bytes(), Encoding::U64Be),
                            (value.rotate_left(32), Encoding::U64HighLow),
                        ] {
                            seeds.eight.entry(key).or_default().push(Seed {
                                set: set_index,
                                index: index as u32,
                                encoding,
                            });
                            mark(&mut seeds.filter_eight, key);
                        }
                    }
                }
            }
        }
        seeds
    })
}

/// One run of consecutive set elements in one data segment.
#[derive(Clone, Debug)]
pub(crate) struct Run {
    pub set: usize,
    pub encoding: Encoding,
    pub first: usize,
    pub end_index: usize,
    /// Positions inside the segment's bytes.
    pub start: usize,
    pub end: usize,
}

/// Why a scan stopped early, if it did.
pub(crate) enum Stop {
    Deadline,
}

/// Finds every run of at least `data_min_run` consecutive elements in
/// `data`. `expired` is polled every 64 KiB.
pub(crate) fn scan_data(
    data: &[u8],
    expired: &mut dyn FnMut() -> bool,
) -> (Vec<Run>, usize, Option<Stop>) {
    let seeds = seeds();
    let catalog = catalog();
    let mut runs = Vec::new();
    // The last run found per set and encoding: a later position inside it at
    // the same phase would only rediscover it.
    let mut last: HashMap<(usize, Encoding), (usize, usize)> = HashMap::new();
    let mut extend = |seed: &Seed, position: usize, runs: &mut Vec<Run>| {
        let set_number = seed.set as usize;
        let set = &catalog[set_number];
        let stride = seed.encoding.stride();
        if let Some((start, end)) = last.get(&(set_number, seed.encoding))
            && position >= *start
            && position < *end
            && (position - start).is_multiple_of(stride)
        {
            return;
        }
        let element = |index: usize, at: usize| {
            at + stride <= data.len() && seed.encoding.matches(set.values[index], &data[at..])
        };
        let mut first = seed.index as usize;
        let mut start = position;
        while first > 0 && start >= stride && element(first - 1, start - stride) {
            first -= 1;
            start -= stride;
        }
        let mut end_index = seed.index as usize;
        let mut end = position;
        while end_index < set.total() && element(end_index, end) {
            end_index += 1;
            end += stride;
        }
        last.insert((set_number, seed.encoding), (start, end));
        if end_index - first >= set.data_min_run {
            runs.push(Run {
                set: set_number,
                encoding: seed.encoding,
                first,
                end_index,
                start,
                end,
            });
        }
    };
    for position in 0..data.len() {
        if position.is_multiple_of(65_536) && expired() {
            return (runs, position, Some(Stop::Deadline));
        }
        if position + 4 <= data.len() {
            let key = u32::from_le_bytes(data[position..position + 4].try_into().expect("4 bytes"));
            if maybe(&seeds.filter_four, u64::from(key))
                && let Some(found) = seeds.four.get(&key)
            {
                for seed in found {
                    extend(seed, position, &mut runs);
                }
            }
        }
        if position + 8 <= data.len() {
            let key = u64::from_le_bytes(data[position..position + 8].try_into().expect("8 bytes"));
            if maybe(&seeds.filter_eight, key)
                && let Some(found) = seeds.eight.get(&key)
            {
                for seed in found {
                    extend(seed, position, &mut runs);
                }
            }
        }
    }
    (runs, data.len(), None)
}

/// Immediate lookup: every element of every set that immediates can match,
/// keyed by its value at its width.
pub(crate) struct Immediates {
    pub four: HashMap<u32, Vec<(u16, u32)>>,
    pub eight: HashMap<u64, Vec<(u16, u32)>>,
}

pub(crate) fn immediates() -> &'static Immediates {
    static IMMEDIATES: OnceLock<Immediates> = OnceLock::new();
    IMMEDIATES.get_or_init(|| {
        let mut table = Immediates {
            four: HashMap::new(),
            eight: HashMap::new(),
        };
        for (number, set) in catalog().iter().enumerate() {
            if set.immediate_min == 0 {
                continue;
            }
            for (index, value) in set.values.iter().enumerate() {
                let entry = (number as u16, index as u32);
                match set.width {
                    Width::Word32 => table.four.entry(*value as u32).or_default().push(entry),
                    Width::Word64 => table.eight.entry(*value).or_default().push(entry),
                    Width::Byte => {}
                }
            }
        }
        table
    })
}

// Generated from the sha2 0.10.9 crate constants and a high-precision MD5 sine
// table; the tests recompute each digest against the sha2 crate.
pub(crate) const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub(crate) const SHA224_H: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

pub(crate) const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub(crate) const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub(crate) const SHA384_H: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

pub(crate) const SHA512_H: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

pub(crate) const MD5_T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];
