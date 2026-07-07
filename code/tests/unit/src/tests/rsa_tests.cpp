
#include "rsa_tests.h"
#include "../../../../../dep/android/openssl/arm64-v8a/include/openssl/rsa.h"
#include "file.h"

#include <iostream>
#include <experimental/filesystem>

bool test_rsa_generate_keypair() {
    cpp::utils::RSA rsa;
    return rsa.generate_keypair(S_RSA_KEY_SIZE);
}

bool test_rsa_encrypt_decrypt() {
    cpp::utils::RSA rsa;
    if (!rsa.generate_keypair(S_RSA_KEY_SIZE)) return false;

    std::string plaintext = "Test RSA encryption";
    std::string ciphertext, decrypted;

    // Encrypt with public key
    if (!rsa.encrypt(plaintext, ciphertext, RSA_PKCS1_OAEP_PADDING)) return false;
    //std::cout << "ciphertext: " << ciphertext << std::endl;

    // Decrypt with private key
    if (!rsa.decrypt(ciphertext, decrypted, RSA_PKCS1_OAEP_PADDING)) return false;
    //std::cout << "decrypted: " << decrypted << std::endl;
    //std::cout << (int)(decrypted == plaintext) << std::endl;

    return decrypted == plaintext;
}

bool test_rsa_export_import_public_key() {
    cpp::utils::RSA sender;
    if (!sender.generate_keypair(S_RSA_KEY_SIZE)) return false;

    // Export public key to string
    std::string pubkey_str;
    if (!sender.public_key(pubkey_str)) return false;

    // Save to temp file
    std::string pubkey_path = "rsa_pub.pem";
    if (!cpp::utils::write_file_contents(pubkey_path, pubkey_str)) return false;

    // Create new object and load public key only
    cpp::utils::RSA public_user;
    if (!public_user.import_public_key(pubkey_path)) return false;

    // Encrypt using public key
    std::string message = "Encrypted with imported public key";
    std::string ciphertext;
    if (!public_user.encrypt(message, ciphertext, RSA_PKCS1_OAEP_PADDING)) return false;

    // Decrypt using original sender's private key
    std::string decrypted;
    if (!sender.decrypt(ciphertext, decrypted, RSA_PKCS1_OAEP_PADDING)) return false;

    std::remove(pubkey_path.c_str());
    return decrypted == message;
}

bool test_rsa_export_import_private_key() {
    cpp::utils::RSA rsa1;
    if (!rsa1.generate_keypair(S_RSA_KEY_SIZE)) return false;

    // Export both keys
    std::string pubkey_path = "rsa_pub.pem";
    std::string privkey_path = "rsa_priv.pem";
    if (!rsa1.export_public_key(pubkey_path)) return false;
    if (!rsa1.export_private_key(privkey_path)) return false;

    // Load both keys into new RSA instance
    cpp::utils::RSA rsa2;
    if (!rsa2.import_public_key(pubkey_path)) return false;
    if (!rsa2.import_private_key(privkey_path)) return false;

    // Test encryption/decryption
    std::string message = "Full key import test";
    std::string ciphertext, decrypted;
    if (!rsa2.encrypt(message, ciphertext, RSA_PKCS1_OAEP_PADDING)) return false;
    if (!rsa2.decrypt(ciphertext, decrypted, RSA_PKCS1_OAEP_PADDING)) return false;

    std::remove(pubkey_path.c_str());
    std::remove(privkey_path.c_str());

    return decrypted == message;
}

bool test_rsa_fail_on_invalid_key() {
    // Your class loads keys from file, not from string
    // So simulate by writing an invalid key to a file
    std::string bad_key = "-----BEGIN PUBLIC KEY-----\nINVALIDDATA\n-----END PUBLIC KEY-----";
    std::string bad_path = "invalid_key.pem";
    if (!cpp::utils::write_file_contents(bad_path, bad_key)) return false;

    cpp::utils::RSA rsa;
    return !rsa.import_public_key(bad_path); // Should fail
}

bool test_rsa_sign_verify_success() {
    cpp::utils::RSA rsa;
    if (!rsa.generate_keypair(S_RSA_KEY_SIZE)) return false;

    std::string message = "Test message for RSA signing";
    std::string signature;

    // Sign with private key
    if (!rsa.sign(message, signature, "sha256")) return false;

    // Verify with public key
    if (!rsa.verify(message, signature, "sha256")) return false;

    return true;
}

bool test_rsa_sign_verify_tampered_message() {
    cpp::utils::RSA rsa;
    if (!rsa.generate_keypair(S_RSA_KEY_SIZE)) return false;

    std::string message = "Authentic message";
    std::string tampered = "Modified message";
    std::string signature;

    if (!rsa.sign(message, signature, "sha256")) return false;

    // Tampered message should fail verification
    if (rsa.verify(tampered, signature, "sha256")) return false;

    return true;
}

bool test_rsa_sign_verify_tampered_signature() {
    cpp::utils::RSA rsa;
    if (!rsa.generate_keypair(S_RSA_KEY_SIZE)) return false;

    std::string message = "Message to sign";
    std::string signature;

    if (!rsa.sign(message, signature, "sha256")) return false;

    // Corrupt the signature
    if (!signature.empty()) {
        signature[0] ^= 0xFF;  // Flip first byte
    }

    // Verification should fail
    if (rsa.verify(message, signature, "sha256")) return false;

    return true;
}

bool test_rsa_sign_invalid_algorithm() {
    cpp::utils::RSA rsa;
    if (!rsa.generate_keypair(S_RSA_KEY_SIZE)) return false;

    std::string message = "Data";
    std::string signature;

    // Try to sign with an invalid hash algorithm
    if (rsa.sign(message, signature, "INVALID_HASH")) return false;

    return true;
}

bool test_rsa_verify_invalid_algorithm() {
    cpp::utils::RSA rsa;
    if (!rsa.generate_keypair(S_RSA_KEY_SIZE)) return false;

    std::string message = "Data";
    std::string signature;

    if (!rsa.sign(message, signature, "sha256")) return false;

    // Try to verify using an invalid algorithm
    if (rsa.verify(message, signature, "INVALID_HASH")) return false;

    return true;
}

bool test_rsa_key_copy() {
    cpp::utils::RSA rsa1;
    if (!rsa1.generate_keypair(S_RSA_KEY_SIZE)) return false;

    cpp::utils::RSA rsa2(rsa1);

    std::string pubkey1, privkey1;
    if (!rsa1.public_key(pubkey1)) return false;
    if (!rsa1.private_key(privkey1)) return false;

    std::string pubkey2, privkey2;
    if (!rsa2.public_key(pubkey2)) return false;
    if (!rsa2.private_key(privkey2)) return false;

    return pubkey1 == pubkey2 && privkey1 == privkey2;
}
