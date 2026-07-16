use std::fs::File;
use std::io::prelude::*;
use std::io::Cursor;
use std::path::PathBuf;

use aes::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub fn read_test_file(name: &str) -> Vec<u8> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("tests");
    dir.push("files");
    dir.push(name);
    let mut f = File::open(dir).unwrap();
    let mut data: Vec<u8> = Vec::new();
    f.read_to_end(&mut data).unwrap();

    data
}

/// Wrap the two OOXML encryption streams in an OLE compound file.
pub fn build_ole(encryption_info: &[u8], encrypted_package: &[u8]) -> Vec<u8> {
    let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    comp.create_stream("EncryptionInfo")
        .unwrap()
        .write_all(encryption_info)
        .unwrap();
    comp.create_stream("EncryptedPackage")
        .unwrap()
        .write_all(encrypted_package)
        .unwrap();
    comp.flush().unwrap();
    comp.into_inner().into_inner()
}

/// The `EncryptionInfo` and `EncryptedPackage` streams of an OLE-wrapped Office file.
pub fn read_ole_streams(raw: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut comp = cfb::CompoundFile::open(Cursor::new(raw)).unwrap();
    let mut encryption_info = Vec::new();
    comp.open_stream("EncryptionInfo")
        .unwrap()
        .read_to_end(&mut encryption_info)
        .unwrap();
    let mut encrypted_package = Vec::new();
    comp.open_stream("EncryptedPackage")
        .unwrap()
        .read_to_end(&mut encrypted_package)
        .unwrap();

    (encryption_info, encrypted_package)
}

// A minimal ECMA-376 agile *encryptor*, used to generate test fixtures for hash algorithms and
// key sizes that Office itself rarely produces (e.g. Apache POI's SHA1 + AES128 default).
// Fixtures generated with it are cross-validated against Python msoffcrypto-tool (the reference
// implementation this crate is ported from) before being committed.

const BLOCK_VERIFIER_HASH_INPUT: [u8; 8] = [0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79];
const BLOCK_VERIFIER_HASH_VALUE: [u8; 8] = [0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E];
const BLOCK_ENCRYPTED_KEY_VALUE: [u8; 8] = [0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6];
const BLOCK_DATA_INTEGRITY_1: [u8; 8] = [0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6];
const BLOCK_DATA_INTEGRITY_2: [u8; 8] = [0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33];

const SEGMENT_LENGTH: usize = 4096;
const AES_BLOCK_SIZE: usize = 16;

pub struct AgileParams {
    pub hash: &'static str,
    pub key_bits: usize,
    pub spin_count: u32,
}

fn digest(hash: &str, data: &[u8]) -> Vec<u8> {
    match hash {
        "SHA1" => Sha1::digest(data).to_vec(),
        "SHA256" => Sha256::digest(data).to_vec(),
        "SHA384" => Sha384::digest(data).to_vec(),
        "SHA512" => Sha512::digest(data).to_vec(),
        _ => panic!("unsupported hash {hash}"),
    }
}

fn hmac_digest(hash: &str, key: &[u8], data: &[u8]) -> Vec<u8> {
    match hash {
        "SHA1" => {
            let mut h = Hmac::<Sha1>::new_from_slice(key).unwrap();
            h.update(data);
            h.finalize().into_bytes().to_vec()
        }
        "SHA256" => {
            let mut h = Hmac::<Sha256>::new_from_slice(key).unwrap();
            h.update(data);
            h.finalize().into_bytes().to_vec()
        }
        "SHA384" => {
            let mut h = Hmac::<Sha384>::new_from_slice(key).unwrap();
            h.update(data);
            h.finalize().into_bytes().to_vec()
        }
        "SHA512" => {
            let mut h = Hmac::<Sha512>::new_from_slice(key).unwrap();
            h.update(data);
            h.finalize().into_bytes().to_vec()
        }
        _ => panic!("unsupported hash {hash}"),
    }
}

/// Truncate or pad with 0x36 to `len` (MS-OFFCRYPTO 2.3.4.11/2.3.4.12).
fn normalize_key(mut bytes: Vec<u8>, len: usize) -> Vec<u8> {
    bytes.resize(len, 0x36);
    bytes
}

/// Zero-pad to a multiple of the AES block size.
fn pad_to_block(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.resize(bytes.len().div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE, 0);
    bytes
}

fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    assert_eq!(plaintext.len() % AES_BLOCK_SIZE, 0);
    let mut ciphertext = vec![0u8; plaintext.len()];
    match key.len() {
        16 => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
            .unwrap()
            .encrypt_padded_b2b_mut::<NoPadding>(plaintext, &mut ciphertext),
        24 => cbc::Encryptor::<aes::Aes192>::new_from_slices(key, iv)
            .unwrap()
            .encrypt_padded_b2b_mut::<NoPadding>(plaintext, &mut ciphertext),
        32 => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
            .unwrap()
            .encrypt_padded_b2b_mut::<NoPadding>(plaintext, &mut ciphertext),
        _ => panic!("bad key length {}", key.len()),
    }
    .unwrap();
    ciphertext
}

/// Deterministic pseudo-random bytes so fixture generation is reproducible. Not secret — this is
/// test-only code.
fn test_bytes(label: &str, params: &AgileParams, len: usize) -> Vec<u8> {
    let seed = format!("{label}:{}:{}:{}", params.hash, params.key_bits, params.spin_count);
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u32;
    while out.len() < len {
        out.extend_from_slice(&Sha256::digest(
            [seed.as_bytes(), &counter.to_le_bytes()].concat(),
        ));
        counter += 1;
    }
    out.truncate(len);
    out
}

pub fn encrypt_agile(plaintext: &[u8], password: &str, params: &AgileParams) -> Vec<u8> {
    let hash = params.hash;
    let key_len = params.key_bits / 8;
    let hash_size = digest(hash, b"").len();

    // Salts are exactly one AES block, so they can be used directly as the password-path IV.
    let password_salt = test_bytes("password-salt", params, AES_BLOCK_SIZE);
    let key_data_salt = test_bytes("key-data-salt", params, AES_BLOCK_SIZE);

    // Iterated password hash.
    let pass_utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut h = digest(hash, &[password_salt.as_slice(), &pass_utf16].concat());
    for i in 0u32..params.spin_count {
        h = digest(hash, &[&i.to_le_bytes(), h.as_slice()].concat());
    }
    let derived_key = |block: &[u8]| {
        normalize_key(digest(hash, &[h.as_slice(), block].concat()), key_len)
    };

    // Verifier blocks.
    let verifier_input = test_bytes("verifier-input", params, 16);
    let encrypted_verifier_hash_input = aes_cbc_encrypt(
        &derived_key(&BLOCK_VERIFIER_HASH_INPUT),
        &password_salt,
        &verifier_input,
    );
    let verifier_hash = pad_to_block(digest(hash, &verifier_input));
    let encrypted_verifier_hash_value = aes_cbc_encrypt(
        &derived_key(&BLOCK_VERIFIER_HASH_VALUE),
        &password_salt,
        &verifier_hash,
    );

    // Intermediate (package) key, encrypted under the password-derived key.
    let secret_key = test_bytes("secret-key", params, key_len);
    let encrypted_key_value = aes_cbc_encrypt(
        &derived_key(&BLOCK_ENCRYPTED_KEY_VALUE),
        &password_salt,
        &pad_to_block(secret_key.clone()),
    );

    // Encrypted package: 8-byte plaintext size header, then 4096-byte segments each encrypted
    // with IV = hash(keyDataSalt + segmentIndex).
    let mut package = (plaintext.len() as u64).to_le_bytes().to_vec();
    for (i, segment) in plaintext.chunks(SEGMENT_LENGTH).enumerate() {
        let iv = normalize_key(
            digest(hash, &[key_data_salt.as_slice(), &(i as u32).to_le_bytes()].concat()),
            AES_BLOCK_SIZE,
        );
        package.extend_from_slice(&aes_cbc_encrypt(
            &secret_key,
            &iv,
            &pad_to_block(segment.to_vec()),
        ));
    }

    // Data integrity (HMAC over the whole EncryptedPackage stream).
    let hmac_key = test_bytes("hmac-key", params, hash_size);
    let iv1 = normalize_key(
        digest(hash, &[key_data_salt.as_slice(), &BLOCK_DATA_INTEGRITY_1].concat()),
        AES_BLOCK_SIZE,
    );
    let iv2 = normalize_key(
        digest(hash, &[key_data_salt.as_slice(), &BLOCK_DATA_INTEGRITY_2].concat()),
        AES_BLOCK_SIZE,
    );
    let encrypted_hmac_key = aes_cbc_encrypt(&secret_key, &iv1, &pad_to_block(hmac_key.clone()));
    let hmac_value = hmac_digest(hash, &hmac_key, &package);
    let encrypted_hmac_value = aes_cbc_encrypt(&secret_key, &iv2, &pad_to_block(hmac_value));

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password" xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">
    <keyData saltSize="16" blockSize="16" keyBits="{key_bits}" hashSize="{hash_size}" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="{hash}" saltValue="{key_data_salt}" />
    <dataIntegrity encryptedHmacKey="{encrypted_hmac_key}" encryptedHmacValue="{encrypted_hmac_value}" />
    <keyEncryptors>
        <keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
            <p:encryptedKey spinCount="{spin_count}" saltSize="16" blockSize="16" keyBits="{key_bits}" hashSize="{hash_size}" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="{hash}" saltValue="{password_salt}" encryptedVerifierHashInput="{encrypted_verifier_hash_input}" encryptedVerifierHashValue="{encrypted_verifier_hash_value}" encryptedKeyValue="{encrypted_key_value}" />
        </keyEncryptor>
    </keyEncryptors>
</encryption>"#,
        key_bits = params.key_bits,
        spin_count = params.spin_count,
        key_data_salt = B64.encode(&key_data_salt),
        encrypted_hmac_key = B64.encode(&encrypted_hmac_key),
        encrypted_hmac_value = B64.encode(&encrypted_hmac_value),
        password_salt = B64.encode(&password_salt),
        encrypted_verifier_hash_input = B64.encode(&encrypted_verifier_hash_input),
        encrypted_verifier_hash_value = B64.encode(&encrypted_verifier_hash_value),
        encrypted_key_value = B64.encode(&encrypted_key_value),
    );

    // EncryptionInfo stream: version 4.4, flags 0x40, then the XML descriptor.
    let mut encryption_info = vec![4, 0, 4, 0, 0x40, 0, 0, 0];
    encryption_info.extend_from_slice(xml.as_bytes());

    build_ole(&encryption_info, &package)
}
