use office_crypto::*;

mod utils;

#[test]
fn agile_sha512() {
    let dec_docx = decrypt_from_bytes(
        utils::read_test_file("testAgileSha512.docx"),
        "testPassword",
    )
    .unwrap();
    let expected_docx = utils::read_test_file("expectedAgileSha512.docx");
    // std::fs::write("tests/files/expectedAgileSha512.docx", &dec_docx).unwrap();

    let dec_xlsx = decrypt_from_bytes(
        utils::read_test_file("testAgileSha512.xlsx"),
        "testPassword",
    )
    .unwrap();
    let expected_xlsx = utils::read_test_file("expectedAgileSha512.xlsx");
    // std::fs::write("tests/files/expectedAgileSha512.xlsx", &dec_xlsx).unwrap();

    assert!(dec_docx == expected_docx);
    assert!(dec_xlsx == expected_xlsx);
}

#[test]
fn agile_sha512_large() {
    let decrypted = decrypt_from_bytes(
        utils::read_test_file("testAgileSha512Large.docx"),
        "testPassword",
    )
    .unwrap();
    let expected = utils::read_test_file("expectedAgileSha512Large.docx");
    // std::fs::write("tests/files/expectedAgileSha512Large.docx", &decrypted).unwrap();

    assert!(decrypted == expected);
}

#[test]
fn standard_sha512() {
    // from msofficecrypto tests
    let decrypted =
        decrypt_from_bytes(utils::read_test_file("testStandard.docx"), "Password1234_").unwrap();
    let expected = utils::read_test_file("expectedStandard.docx");
    // std::fs::write("tests/files/expectedStandard.docx", &decrypted).unwrap();

    assert!(decrypted == expected);
}

#[test]
fn rc4_cryptoapi_doc() {
    // from msoffcrypto-tool tests
    let decrypted =
        decrypt_from_bytes(utils::read_test_file("testRC4CryptoAPI.doc"), "Password1234_")
            .unwrap();
    let expected = utils::read_test_file("expectedRC4CryptoAPI.doc");

    assert_eq!(decrypted, expected);
}

// Fixtures for hash algorithms / key sizes Office rarely emits (but tools like Apache POI do).
// Regenerate with `cargo test generate_agile_fixtures -- --ignored` (deterministic output);
// validate against msoffcrypto-tool before committing.
const AGILE_FIXTURES: &[(&str, utils::AgileParams)] = &[
    // Apache POI's default agile parameters — the variant seen in production.
    ("testAgileSha1Aes128.xlsx", utils::AgileParams { hash: "SHA1", key_bits: 128, spin_count: 100000 }),
    ("testAgileSha256Aes256.xlsx", utils::AgileParams { hash: "SHA256", key_bits: 256, spin_count: 100000 }),
    ("testAgileSha384Aes192.xlsx", utils::AgileParams { hash: "SHA384", key_bits: 192, spin_count: 100000 }),
];

#[test]
#[ignore = "writes tests/files fixtures; run manually when parameters change"]
fn generate_agile_fixtures() {
    let plaintext = utils::read_test_file("expectedAgileSha512.xlsx");
    for (name, params) in AGILE_FIXTURES {
        let encrypted = utils::encrypt_agile(&plaintext, "testPassword", params);
        std::fs::write(format!("tests/files/{name}"), encrypted).unwrap();
    }
}

#[test]
fn agile_other_hash_algorithms() {
    let expected = utils::read_test_file("expectedAgileSha512.xlsx");
    for (name, _) in AGILE_FIXTURES {
        let decrypted = decrypt_from_bytes(utils::read_test_file(name), "testPassword").unwrap();
        assert!(decrypted == expected, "fixture {name} did not round-trip");
    }
}

#[test]
fn agile_roundtrip_multi_segment() {
    // > 1 segment (4096) with a non-block-aligned tail, to exercise segment IVs and truncation.
    let plaintext: Vec<u8> = (0..10_000u32).flat_map(u32::to_le_bytes).collect();
    let plaintext = &plaintext[..39_999];
    let params = utils::AgileParams { hash: "SHA256", key_bits: 128, spin_count: 1000 };
    let encrypted = utils::encrypt_agile(plaintext, "pw", &params);
    let decrypted = decrypt_from_bytes(encrypted, "pw").unwrap();
    assert!(decrypted == plaintext);
}

#[test]
fn agile_wrong_password() {
    // Word-produced SHA512 file and a generated SHA1 file both report InvalidPassword.
    for name in ["testAgileSha512.xlsx", "testAgileSha1Aes128.xlsx"] {
        let result = decrypt_from_bytes(utils::read_test_file(name), "wrongPassword");
        assert!(
            matches!(result, Err(DecryptError::InvalidPassword)),
            "expected InvalidPassword for {name}, got {result:?}"
        );
    }
}

#[test]
fn standard_wrong_password() {
    let result = decrypt_from_bytes(utils::read_test_file("testStandard.docx"), "wrongPassword");
    assert!(matches!(result, Err(DecryptError::InvalidPassword)));
}

#[test]
fn standard_truncated_package() {
    let (info, _) = utils::read_ole_streams(utils::read_test_file("testStandard.docx"));
    let result = decrypt_from_bytes(utils::build_ole(&info, &[1, 2, 3]), "Password1234_");
    assert!(
        matches!(result, Err(DecryptError::InvalidStructure)),
        "expected InvalidStructure, got {result:?}"
    );
}

#[test]
fn agile_rejects_non_aes_block_size() {
    let (info, package) =
        utils::read_ole_streams(utils::read_test_file("testAgileSha1Aes128.xlsx"));
    let xml = String::from_utf8(info[8..].to_vec()).unwrap();
    // Rewrite keyData/@blockSize only; p:encryptedKey carries a blockSize of its own.
    let (key_data, rest) = xml.split_once("<dataIntegrity").unwrap();
    let key_data = key_data.replace(r#"blockSize="16""#, r#"blockSize="2000000000""#);
    let mut info = info[..8].to_vec();
    info.extend_from_slice(format!("{key_data}<dataIntegrity{rest}").as_bytes());

    // A wrong password, so this fails if blockSize is only rejected later by the cipher: the
    // verifier would reach InvalidPassword first, and nothing would bound the IV allocation.
    let result = decrypt_from_bytes(utils::build_ole(&info, &package), "wrongPassword");
    assert!(
        matches!(result, Err(DecryptError::InvalidStructure)),
        "expected InvalidStructure, got {result:?}"
    );
}

#[test]
fn doc97_not_encrypted() {
    // expectedRC4CryptoAPI.doc is an unencrypted doc file
    let result =
        decrypt_from_bytes(utils::read_test_file("expectedRC4CryptoAPI.doc"), "anypassword");

    assert!(matches!(result, Err(DecryptError::NotEncrypted)));
}
