use crate::ole::OleStream;
use crate::validate;
use crate::DecryptError::{self, *};

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyInit, KeyIvInit};
use base64::engine::general_purpose;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::io::prelude::*;
use std::io::Cursor;

// Block keys from MS-OFFCRYPTO 2.3.4.10 used to derive the purpose-specific keys.
const BLOCK_VERIFIER_HASH_INPUT: [u8; 8] = [0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79];
const BLOCK_VERIFIER_HASH_VALUE: [u8; 8] = [0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E];
const BLOCK_ENCRYPTED_KEY_VALUE: [u8; 8] = [0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6];

const SEGMENT_LENGTH: usize = 4096;
const AES_BLOCK_SIZE: usize = 16;
const STANDARD_ITER_COUNT: u32 = 50000;
// MS-OFFCRYPTO 2.3.4.5: spinCount MUST be no greater than 10,000,000.
const MAX_SPIN_COUNT: u32 = 10_000_000;

fn utf16le_bytes(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    fn parse(name: &str) -> Result<Self, DecryptError> {
        match name {
            "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "SHA256" | "SHA-256" => Ok(Self::Sha256),
            "SHA384" | "SHA-384" => Ok(Self::Sha384),
            "SHA512" | "SHA-512" => Ok(Self::Sha512),
            // Remaining algorithms allowed by the spec (MD2, MD4, MD5, RIPEMD-128/160, WHIRLPOOL)
            // have never been observed in the wild.
            other => Err(Unimplemented(other.to_owned())),
        }
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// The iterated hash of MS-OFFCRYPTO 2.3.4.11: `H_0 = H(salt + password)`, then
    /// `H_i = H(i + H_{i-1})` for spin_count rounds. Monomorphized per algorithm to keep the hash
    /// state on the stack in the hot loop.
    fn iterated_hash(&self, salt: &[u8], password: &[u8], spin_count: u32) -> Vec<u8> {
        fn run<D: Digest>(salt: &[u8], password: &[u8], spin_count: u32) -> Vec<u8> {
            let mut h = D::new().chain_update(salt).chain_update(password).finalize();
            for i in 0u32..spin_count {
                h = D::new().chain_update(i.to_le_bytes()).chain_update(&h).finalize();
            }
            h.to_vec()
        }
        match self {
            Self::Sha1 => run::<Sha1>(salt, password, spin_count),
            Self::Sha256 => run::<Sha256>(salt, password, spin_count),
            Self::Sha384 => run::<Sha384>(salt, password, spin_count),
            Self::Sha512 => run::<Sha512>(salt, password, spin_count),
        }
    }
}

/// Truncate or pad with 0x36 to `len`, per MS-OFFCRYPTO 2.3.4.11/2.3.4.12.
fn normalize_key(mut bytes: Vec<u8>, len: usize) -> Vec<u8> {
    bytes.resize(len, 0x36);
    bytes
}

/// AES-CBC-decrypt `ciphertext` (no padding), dispatching on key length (128/192/256 bits).
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
    validate!(ciphertext.len().is_multiple_of(AES_BLOCK_SIZE), InvalidStructure)?;
    let mut plaintext = vec![0u8; ciphertext.len()];
    match key.len() {
        16 => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
            .map_err(|_| InvalidStructure)?
            .decrypt_padded_b2b_mut::<NoPadding>(ciphertext, &mut plaintext),
        24 => cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv)
            .map_err(|_| InvalidStructure)?
            .decrypt_padded_b2b_mut::<NoPadding>(ciphertext, &mut plaintext),
        32 => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(|_| InvalidStructure)?
            .decrypt_padded_b2b_mut::<NoPadding>(ciphertext, &mut plaintext),
        _ => return Err(InvalidStructure),
    }
    .map_err(|_| InvalidStructure)?;
    Ok(plaintext)
}

/// AES-ECB-decrypt `ciphertext` (no padding), dispatching on key length (128/192/256 bits).
fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
    validate!(ciphertext.len().is_multiple_of(AES_BLOCK_SIZE), InvalidStructure)?;
    let mut plaintext = vec![0u8; ciphertext.len()];
    match key.len() {
        16 => ecb::Decryptor::<aes::Aes128>::new_from_slice(key)
            .map_err(|_| InvalidStructure)?
            .decrypt_padded_b2b_mut::<NoPadding>(ciphertext, &mut plaintext),
        24 => ecb::Decryptor::<aes::Aes192>::new_from_slice(key)
            .map_err(|_| InvalidStructure)?
            .decrypt_padded_b2b_mut::<NoPadding>(ciphertext, &mut plaintext),
        32 => ecb::Decryptor::<aes::Aes256>::new_from_slice(key)
            .map_err(|_| InvalidStructure)?
            .decrypt_padded_b2b_mut::<NoPadding>(ciphertext, &mut plaintext),
        _ => return Err(InvalidStructure),
    }
    .map_err(|_| InvalidStructure)?;
    Ok(plaintext)
}

#[allow(dead_code)]
#[derive(Default, Debug)]
pub(crate) struct AgileEncryptionInfo {
    key_data_salt: Vec<u8>,
    key_data_hash_algorithm: String,
    key_data_block_size: u32,
    key_data_key_bits: u32,
    encrypted_hmac_key: Vec<u8>,
    encrypted_hmac_value: Vec<u8>,
    encrypted_verifier_hash_input: Vec<u8>,
    encrypted_verifier_hash_value: Vec<u8>,
    encrypted_key_value: Vec<u8>,
    spin_count: u32,
    password_salt: Vec<u8>,
    password_hash_algorithm: String,
    password_key_bits: u32,
}

fn b64_decode(bytes: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let mut wrapped_reader = Cursor::new(bytes);
    let mut decoder =
        base64::read::DecoderReader::new(&mut wrapped_reader, &general_purpose::STANDARD);

    let mut result = Vec::new();
    decoder.read_to_end(&mut result).map_err(|_| Unknown)?;
    Ok(result)
}

impl AgileEncryptionInfo {
    pub fn new(encryption_info: &OleStream) -> Result<Self, DecryptError> {
        validate!(encryption_info.stream.len() >= 8, InvalidStructure)?;
        let raw_xml = String::from_utf8(encryption_info.stream[8..].to_vec())
            .map_err(|_| InvalidStructure)?;

        let mut reader = Reader::from_str(&raw_xml);
        reader.config_mut().trim_text(true);

        let mut aei = Self::default();
        let mut set_key_data = false;
        let mut set_hmac_data = false;
        let mut set_password_node = false;

        loop {
            match reader.read_event().map_err(|_| InvalidStructure)? {
                Event::Empty(e) => match e.name().as_ref() {
                    b"keyData" if !set_key_data => {
                        for attr in e.attributes() {
                            let attr = attr.map_err(|_| InvalidStructure)?;
                            match attr.key.as_ref() {
                                b"saltValue" => {
                                    aei.key_data_salt = b64_decode(&attr.value)?;
                                }
                                b"hashAlgorithm" => {
                                    aei.key_data_hash_algorithm =
                                        String::from_utf8(attr.value.into_owned())
                                            .map_err(|_| InvalidStructure)?;
                                }
                                b"blockSize" => {
                                    aei.key_data_block_size =
                                        String::from_utf8(attr.value.into_owned())
                                            .map_err(|_| InvalidStructure)?
                                            .parse()
                                            .map_err(|_| InvalidStructure)?;
                                }
                                b"keyBits" => {
                                    aei.key_data_key_bits =
                                        String::from_utf8(attr.value.into_owned())
                                            .map_err(|_| InvalidStructure)?
                                            .parse()
                                            .map_err(|_| InvalidStructure)?;
                                }
                                _ => (),
                            }
                        }
                        set_key_data = true;
                    }
                    b"dataIntegrity" if !set_hmac_data => {
                        for attr in e.attributes() {
                            let attr = attr.map_err(|_| InvalidStructure)?;
                            match attr.key.as_ref() {
                                b"encryptedHmacKey" => {
                                    aei.encrypted_hmac_key = b64_decode(&attr.value)?;
                                }
                                b"encryptedHmacValue" => {
                                    aei.encrypted_hmac_value = b64_decode(&attr.value)?;
                                }
                                _ => (),
                            }
                        }
                        set_hmac_data = true;
                    }
                    b"p:encryptedKey" if !set_password_node => {
                        for attr in e.attributes() {
                            let attr = attr.map_err(|_| InvalidStructure)?;
                            match attr.key.as_ref() {
                                b"encryptedVerifierHashInput" => {
                                    aei.encrypted_verifier_hash_input = b64_decode(&attr.value)?;
                                }
                                b"encryptedVerifierHashValue" => {
                                    aei.encrypted_verifier_hash_value = b64_decode(&attr.value)?;
                                }
                                b"encryptedKeyValue" => {
                                    aei.encrypted_key_value = b64_decode(&attr.value)?;
                                }
                                b"spinCount" => {
                                    aei.spin_count = String::from_utf8(attr.value.into_owned())
                                        .map_err(|_| InvalidStructure)?
                                        .parse()
                                        .map_err(|_| InvalidStructure)?;
                                }
                                b"saltValue" => {
                                    aei.password_salt = b64_decode(&attr.value)?;
                                }
                                b"hashAlgorithm" => {
                                    aei.password_hash_algorithm =
                                        String::from_utf8(attr.value.into_owned())
                                            .map_err(|_| InvalidStructure)?;
                                }
                                b"keyBits" => {
                                    aei.password_key_bits =
                                        String::from_utf8(attr.value.into_owned())
                                            .map_err(|_| InvalidStructure)?
                                            .parse()
                                            .map_err(|_| InvalidStructure)?;
                                }
                                _ => (),
                            }
                        }
                        set_password_node = true;
                    }
                    _ => (),
                },
                Event::Eof => break,
                _ => (),
            }
        }

        validate!(set_key_data, InvalidStructure)?;
        validate!(set_hmac_data, InvalidStructure)?;
        validate!(set_password_node, InvalidStructure)?;
        validate!(aei.spin_count <= MAX_SPIN_COUNT, InvalidStructure)?;
        validate!(
            matches!(aei.key_data_key_bits, 128 | 192 | 256),
            InvalidStructure
        )?;
        validate!(
            matches!(aei.password_key_bits, 128 | 192 | 256),
            InvalidStructure
        )?;

        Ok(aei)
    }

    /// The expensive iterated password hash (spin_count rounds). Compute once and reuse for
    /// verification and key derivation.
    pub fn password_hash(&self, password: &str) -> Result<Vec<u8>, DecryptError> {
        let alg = HashAlgorithm::parse(&self.password_hash_algorithm)?;
        Ok(alg.iterated_hash(&self.password_salt, &utf16le_bytes(password), self.spin_count))
    }

    /// Check the password against the verifier blocks (MS-OFFCRYPTO 2.3.4.13).
    pub fn verify_password(&self, password_hash: &[u8]) -> Result<bool, DecryptError> {
        let alg = HashAlgorithm::parse(&self.password_hash_algorithm)?;
        let iv = normalize_key(self.password_salt.clone(), AES_BLOCK_SIZE);

        let input_key = self.derived_key(password_hash, &BLOCK_VERIFIER_HASH_INPUT)?;
        let verifier_input = aes_cbc_decrypt(&input_key, &iv, &self.encrypted_verifier_hash_input)?;
        let actual_hash = alg.digest(&verifier_input);

        let value_key = self.derived_key(password_hash, &BLOCK_VERIFIER_HASH_VALUE)?;
        let expected_hash = aes_cbc_decrypt(&value_key, &iv, &self.encrypted_verifier_hash_value)?;

        // The stored hash is zero-padded up to a cipher block multiple; compare only the hash.
        validate!(expected_hash.len() >= actual_hash.len(), InvalidStructure)?;
        Ok(expected_hash[..actual_hash.len()] == actual_hash)
    }

    /// Decrypt the intermediate key that encrypts the package (MS-OFFCRYPTO 2.3.4.13).
    pub fn secret_key(&self, password_hash: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let key = self.derived_key(password_hash, &BLOCK_ENCRYPTED_KEY_VALUE)?;
        let iv = normalize_key(self.password_salt.clone(), AES_BLOCK_SIZE);
        let secret_key = aes_cbc_decrypt(&key, &iv, &self.encrypted_key_value)?;
        Ok(normalize_key(secret_key, self.key_data_key_bits as usize / 8))
    }

    pub fn decrypt(
        &self,
        key: &[u8],
        encrypted_stream: &OleStream,
    ) -> Result<Vec<u8>, DecryptError> {
        let alg = HashAlgorithm::parse(&self.key_data_hash_algorithm)?;
        let stream = &encrypted_stream.stream;
        validate!(stream.len() >= 8, InvalidStructure)?;
        let total_size = u64::from_le_bytes(stream[..8].try_into().map_err(|_| InvalidStructure)?);
        let total_size = usize::try_from(total_size).map_err(|_| InvalidStructure)?;

        let ciphertext = &stream[8..];
        let mut decrypted = Vec::with_capacity(ciphertext.len());
        for (block_index, segment) in ciphertext.chunks(SEGMENT_LENGTH).enumerate() {
            let iv = alg.digest(
                &[
                    self.key_data_salt.as_slice(),
                    &(block_index as u32).to_le_bytes(),
                ]
                .concat(),
            );
            let iv = normalize_key(iv, self.key_data_block_size as usize);
            decrypted.extend_from_slice(&aes_cbc_decrypt(key, &iv, segment)?);
        }

        validate!(decrypted.len() >= total_size, InvalidStructure)?;
        decrypted.truncate(total_size);
        Ok(decrypted)
    }

    fn derived_key(&self, password_hash: &[u8], block: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let alg = HashAlgorithm::parse(&self.password_hash_algorithm)?;
        let h = alg.digest(&[password_hash, block].concat());
        Ok(normalize_key(h, self.password_key_bits as usize / 8))
    }
}

#[allow(dead_code)]
#[derive(Default, Debug)]
pub(crate) struct StandardEncryptionInfo {
    flags: u32,
    size_extra: u32,
    alg_id: u32,
    alg_id_hash: u32,
    key_size: u32,
    provider_type: u32,
    reserved1: u32,
    reserved2: u32,
    csp_name: String,
    salt_size: u32,
    salt: Vec<u8>,
    encrypted_verifier: Vec<u8>,
    verifier_hash_size: u32,
    encrypted_verifier_hash: Vec<u8>,
}

impl StandardEncryptionInfo {
    pub fn new(encryption_info: &OleStream) -> Result<Self, DecryptError> {
        // let header_flags = u32::from_le_bytes(
        //     encryption_info.stream[4..8]
        //         .try_into()
        //         .map_err(|_| InvalidStructure)?,
        // );
        validate!(encryption_info.stream.len() >= 12, InvalidStructure)?;
        let header_size = u32::from_le_bytes(
            encryption_info.stream[8..12]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        let header_end = (header_size as usize)
            .checked_add(12)
            .ok_or(InvalidStructure)?;
        validate!(header_size >= 32, InvalidStructure)?;
        validate!(encryption_info.stream.len() >= header_end, InvalidStructure)?;
        let header_bytes = &encryption_info.stream[12..header_end];
        let mut sei = Self::default();

        // TODO switch to packed struct maybe
        sei.flags = u32::from_le_bytes(header_bytes[..4].try_into().map_err(|_| InvalidStructure)?);
        sei.size_extra = u32::from_le_bytes(
            header_bytes[4..8]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.alg_id = u32::from_le_bytes(
            header_bytes[8..12]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.alg_id_hash = u32::from_le_bytes(
            header_bytes[12..16]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.key_size = u32::from_le_bytes(
            header_bytes[16..20]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.provider_type = u32::from_le_bytes(
            header_bytes[20..24]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.reserved1 = u32::from_le_bytes(
            header_bytes[24..28]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.reserved2 = u32::from_le_bytes(
            header_bytes[28..32]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );

        let csp_utf16 = header_bytes[32..].to_owned();
        let csp_utf16: &[u16] = unsafe { csp_utf16.align_to::<u16>().1 };
        sei.csp_name = String::from_utf16(csp_utf16).map_err(|_| InvalidStructure)?;

        // check if AES, otherwise RC4
        validate!(
            sei.alg_id & 0xFF00 == 0x6600,
            Unimplemented("RC4".to_owned())
        )?;

        let verifier_bytes = &encryption_info.stream[header_end..];
        validate!(verifier_bytes.len() >= 72, InvalidStructure)?;

        sei.salt_size = u32::from_le_bytes(
            verifier_bytes[..4]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.salt = verifier_bytes[4..20].to_owned();
        sei.encrypted_verifier = verifier_bytes[20..36].to_owned();
        sei.verifier_hash_size = u32::from_le_bytes(
            verifier_bytes[36..40]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.encrypted_verifier_hash = verifier_bytes[40..72].to_owned();

        Ok(sei)
    }

    pub fn key_from_password(&self, password: &str) -> Result<Vec<u8>, DecryptError> {
        let pass_utf16 = utf16le_bytes(password);

        let mut h = Sha1::digest([self.salt.as_slice(), &pass_utf16].concat());
        for i in 0u32..STANDARD_ITER_COUNT {
            h = Sha1::digest([&i.to_le_bytes(), h.as_slice()].concat());
        }

        let block_bytes = [0, 0, 0, 0];
        h = Sha1::digest([h.as_slice(), &block_bytes].concat());
        let cb_required_key_length = self.key_size / 8;
        // let cb_hash = h.len();

        let mut buf1 = [0x36_u8; 64];
        buf1.iter_mut().zip(h.iter()).for_each(|(a, b)| *a ^= *b);
        let x1 = Sha1::digest(buf1);

        let mut buf2 = [0x5c_u8; 64];
        buf2.iter_mut().zip(h.iter()).for_each(|(a, b)| *a ^= *b);
        let x2 = Sha1::digest(buf2);

        Ok([x1, x2].concat()[..(cb_required_key_length as usize)].to_owned())
    }

    /// Check the password against the verifier blocks (MS-OFFCRYPTO 2.3.4.9).
    pub fn verify_password(&self, key: &[u8]) -> Result<bool, DecryptError> {
        let verifier = aes_ecb_decrypt(key, &self.encrypted_verifier)?;
        let verifier_hash = aes_ecb_decrypt(key, &self.encrypted_verifier_hash)?;
        let actual_hash = Sha1::digest(&verifier);

        let hash_size = self.verifier_hash_size as usize;
        validate!(hash_size <= actual_hash.len(), InvalidStructure)?;
        validate!(verifier_hash.len() >= hash_size, InvalidStructure)?;
        Ok(verifier_hash[..hash_size] == actual_hash[..hash_size])
    }

    pub fn decrypt(
        &self,
        key: &[u8],
        encrypted_stream: &OleStream,
    ) -> Result<Vec<u8>, DecryptError> {
        let total_size = u32::from_le_bytes(
            encrypted_stream.stream[..4]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        ) as usize;
        let block_start = 8;
        let ciphertext = &encrypted_stream.stream[block_start..];

        let mut decrypted = aes_ecb_decrypt(key, ciphertext)?;
        validate!(decrypted.len() >= total_size, InvalidStructure)?;
        decrypted.truncate(total_size);
        Ok(decrypted)
    }
}
