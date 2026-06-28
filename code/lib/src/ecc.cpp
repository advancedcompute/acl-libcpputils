/*
 © Copyright 2025 Dominic Finch
*/

#include <sstream>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

#include "ecc.h"
#include "base64.h"
#include "file.h"

namespace cpp {
namespace utils {

ECC::ECC() : _keypair(nullptr), _peer_key(nullptr) {}

ECC::~ECC() {
    clear_keypair();
}

void ECC::clear_keypair(bool clear_peer_key) {
    if (_keypair) {
        EVP_PKEY_free(_keypair);
        _keypair = nullptr;
    }
    if(clear_peer_key) {
        if (_peer_key) {
            EVP_PKEY_free(_peer_key);
            _peer_key = nullptr;
        }
    }
}

bool ECC::generate_own_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) return false;

    bool success = false;
    if (EVP_PKEY_keygen_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp521r1 /* OLD: NID_X9_62_prime256v1 */) > 0 &&
        EVP_PKEY_keygen(ctx, &_keypair) > 0) {
        success = true;
    }

    EVP_PKEY_CTX_free(ctx);
    return success;
}

bool ECC::load_peer_public_key_from_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
    if (!bio) return false;

    if (_peer_key) EVP_PKEY_free(_peer_key);
    _peer_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    return _peer_key != nullptr;
}

bool ECC::load_own_public_key_from_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
    if (!bio) return false;

    //if (_peer_key) EVP_PKEY_free(_peer_key);
    _keypair = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    return _keypair != nullptr;
}

bool ECC::load_own_public_key_from_pem_file(const std::string& fpath)
{
    std::lock_guard<std::mutex> lock(_lock_mutex);

    auto full_path = full_resolve_path(fpath);
    if(!file_exists(full_path))
        return false;
    
    FILE* fp = fopen(full_path.c_str(), "rb");
    if (!fp) return false;

    BIO* bio = BIO_new_fp(fp, BIO_NOCLOSE);
    _keypair = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);

    BIO_free(bio);
    fclose(fp);
    return _keypair != nullptr;
}

bool ECC::load_own_private_key_from_pem_string(const std::string& pem)
{
    std::lock_guard<std::mutex> lock(_lock_mutex);
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return false;

    _keypair = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return _keypair != nullptr;
}

bool ECC::load_own_private_key_from_pem_string(const std::string& pem, PasswordCallback cb)
{
    std::lock_guard<std::mutex> lock(_lock_mutex);

    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return false;

    PasswordCallbackWrapper wrapper{cb};
    _keypair = PEM_read_bio_PrivateKey(bio, nullptr, openssl_password_cb, &wrapper);

    BIO_free(bio);
    return _keypair != nullptr;
}

bool ECC::load_own_private_key_from_pem_file(const std::string& fpath)
{
    std::lock_guard<std::mutex> lock(_lock_mutex);

    auto full_path = full_resolve_path(fpath);
    if(!file_exists(full_path))
        return false;

    FILE* fp = fopen(full_path.c_str(), "rb");
    if (!fp) return false;

    _keypair = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);

    fclose(fp);
    return _keypair != nullptr;
}

bool ECC::load_own_private_key_from_pem_file(const std::string& fpath, PasswordCallback cb)
{
    std::lock_guard<std::mutex> lock(_lock_mutex);

    auto full_path = full_resolve_path(fpath);
    if(!file_exists(full_path))
        return false;
    FILE* fp = fopen(full_path.c_str(), "rb");
    if (!fp) return false;

    if(cb)
    {
        PasswordCallbackWrapper wrapper{cb};
        _keypair = PEM_read_PrivateKey(fp, nullptr, openssl_password_cb, &wrapper);
    } else {
        _keypair = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    }

    fclose(fp);
    return _keypair != nullptr;
}

bool ECC::export_public_key(const std::string& path) {
    bool success = false;
    std::string pubkey;
    if (get_own_public_key_pem(pubkey)) {
        if (write_file_contents(path, pubkey)) {
            success = true;
        }
    }
    return success;
}

bool ECC::export_private_key(const std::string& path)
{
    bool success = false;
    std::string privkey;
    if (get_own_private_key_pem(privkey)) {
        if (write_file_contents(path, privkey)) {
            success = true;
        }
    }
    return success;
}

bool ECC::export_private_key(const std::string& path, PasswordCallback cb)
{
    bool success = false;
    std::string privkey;
    if (get_own_private_key_pem(privkey, cb)) {
        if (write_file_contents(path, privkey)) {
            success = true;
        }
    }
    return success;
}

bool ECC::import_public_key(const std::string& path) {
    bool success = false;
    if (file_exists(path)) {
        BIO* bio = BIO_new(BIO_s_file());
        if (BIO_read_filename(bio, path.c_str()) > 0) {
            auto * key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);

            if (key != nullptr) {
                clear_keypair();
                _keypair = key;
                success = true;
            }
        }
        BIO_free(bio);
    }
    return success;
}

bool ECC::import_private_key(const std::string& path)
{
    bool success = false;
    if (file_exists(path)) {
        BIO* bio = BIO_new(BIO_s_file());
        if (BIO_read_filename(bio, path.c_str()) > 0) {
            auto * key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);

            if (key != nullptr) {
                clear_keypair(false);
                _keypair = key;
                success = true;
            }
        }
        BIO_free(bio);
    }
    return success;
}

bool ECC::import_private_key(const std::string& path, PasswordCallback cb)
{
    bool success = false;
    
    PasswordCallbackWrapper wrapper{cb};
    if (file_exists(path)) {
        BIO* bio = BIO_new(BIO_s_file());
        if (BIO_read_filename(bio, path.c_str()) > 0) {
            auto * key = PEM_read_bio_PrivateKey(bio, nullptr, openssl_password_cb, &wrapper);

            if (key != nullptr) {
                clear_keypair(false);
                _keypair = key;
                success = true;
            }
        }
        BIO_free(bio);
    }
    return success;
}

bool ECC::get_own_public_key_pem(std::string& pem) {
    bool success = false;

    if (_keypair != nullptr) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (PEM_write_bio_PUBKEY(bio, _keypair) == 1)
        {
            pem.clear();
            unsigned char* data;
            unsigned int nsize = -1;
            if ((nsize = BIO_get_mem_data(bio, &data)) > 0) {
                pem.resize(nsize, '\0');
                strncpy(&pem[0], (const char*)data, nsize);
                success = true;
            }
        }
        BIO_free(bio);
    }
    return success;
}

bool ECC::get_own_private_key_pem(std::string& pem)
{
    bool success = false;
    if (_keypair != nullptr) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (PEM_write_bio_PrivateKey(bio, _keypair, nullptr, nullptr, 0, nullptr, nullptr) == 1) {
            pem.clear();

            unsigned char* data;
            unsigned int nsize = -1;
            if ((nsize = BIO_get_mem_data(bio, &data)) > 0)
            {
                pem.resize(nsize, '\0');
                strncpy(&pem[0], (const char*)data, nsize);
                success = true;
            }
        }
        BIO_free(bio);
    }
    return success;
}

bool ECC::get_own_private_key_pem(std::string& pem, PasswordCallback cb)
{
    bool success = false;
    PasswordCallbackWrapper wrapper{cb};

    if (_keypair != nullptr) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (PEM_write_bio_PrivateKey(bio, _keypair, EVP_aes_256_cbc(), nullptr, 0, openssl_password_cb, &wrapper) == 1) {
            pem.clear();

            unsigned char* data;
            unsigned int nsize = -1;
            if ((nsize = BIO_get_mem_data(bio, &data)) > 0) {
                pem.resize(nsize, '\0');
                strncpy(&pem[0], (const char*)data, nsize);
                success = true;
            }
        }
        BIO_free(bio);
    }
    return success;
}

bool ECC::derive_shared_secret_with_peer(std::vector<uint8_t>& secret) {
    if (!_keypair || !_peer_key) return false;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(_keypair, nullptr);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, _peer_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    size_t len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    secret.resize(len);
    bool success = EVP_PKEY_derive(ctx, secret.data(), &len) > 0;
    secret.resize(len);
    EVP_PKEY_CTX_free(ctx);
    return success;
}

bool ECC::sign_with_own_key(const std::vector<uint8_t>& data, std::vector<uint8_t>& signature) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha512(), nullptr, _keypair) <= 0 ||
        EVP_DigestSignUpdate(ctx, data.data(), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    signature.resize(sig_len);
    bool ok = EVP_DigestSignFinal(ctx, signature.data(), &sig_len) > 0;
    signature.resize(sig_len);
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool ECC::verify_with_peer_key(const std::vector<uint8_t>& data, std::vector<uint8_t>& signature) {
    if (!_peer_key) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha512(), nullptr, _peer_key) <= 0 ||
        EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    int result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);
    return result == 1;
}

bool ECC::sign_with_own_key(const std::string& data, std::string& signature) {
    std::vector<uint8_t> sig_out, input(data.begin(), data.end());
    
    if (!sign_with_own_key(input, sig_out))
        return false;

    std::string raw_sig(reinterpret_cast<const char*>(sig_out.data()), sig_out.size());
    return Base64::encode(raw_sig, signature);
}

bool ECC::verify_with_peer_key(const std::string& data, const std::string& signature) {
    std::vector<uint8_t> input(data.begin(), data.end());
    std::vector<uint8_t> sig_vec(signature.begin(), signature.end());
    std::vector<uint8_t> sig_vec_out;

    if (!Base64::decode(sig_vec, sig_vec_out))
        return false;

    return verify_with_peer_key(input, sig_vec_out);
}

bool ECC::encrypt(const std::string& plaintext, std::string& ciphertext, std::vector<uint8_t>& iv, std::string& tag)
{
    std::vector<uint8_t> plaintext_vect(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> tag_vect;
    std::vector<uint8_t> ciphertext_vect;

    auto result = encrypt(plaintext_vect, ciphertext_vect, iv, tag_vect);
    ciphertext = Base64::encode(ciphertext_vect);
    tag = Base64::encode(tag_vect);
    return result;
}

bool ECC::encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, std::vector<uint8_t>& tag)
{
    std::vector<uint8_t> secret;
    if(plaintext.empty()) return false;

    if (!derive_shared_secret_with_peer(secret)) return false;

    std::vector<uint8_t> key(64);
    if (!EVP_Digest(secret.data(), secret.size(), key.data(), nullptr, EVP_sha512(), nullptr))
        return false;

    iv.resize(12);
    if (RAND_bytes(iv.data(), iv.size()) != 1) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    ciphertext.resize(plaintext.size() + 16);
    int len = 0, total_len = 0;

    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1 &&
              EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) == 1;

    total_len = len;
    ok = ok && EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) == 1;
    total_len += len;
    ciphertext.resize(total_len);

    tag.resize(16);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) == 1;

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool ECC::decrypt(const std::string& ciphertext, std::string& plaintext, const std::vector<uint8_t>& iv, const std::string& tag)
{
    // Decode ciphertext & tag
    auto ciphertext_vect = Base64::decode(ciphertext);
    auto tag_vect = Base64::decode(tag);
    std::vector<uint8_t> plaintext_vect;

    auto result = decrypt(ciphertext_vect, plaintext_vect, iv, tag_vect);

    std::stringstream ss;
    ss << plaintext_vect.data();
    plaintext = ss.str();
    return result;
}

bool ECC::decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& tag)
{
    std::vector<uint8_t> secret;
    if (!derive_shared_secret_with_peer(secret)) return false;

    std::vector<uint8_t> key(64);
    if (!EVP_Digest(secret.data(), secret.size(), key.data(), nullptr, EVP_sha512(), nullptr))
        return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    plaintext.resize(ciphertext.size());
    int len = 0, total_len = 0;

    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1 &&
              EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) == 1;

    total_len = len;

    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data()) == 1 &&
         EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) == 1;

    total_len += len;
    if(plaintext.back() != '\0')        // Just to make sure any C-string conversion stuff knows where the string ends
        plaintext.push_back('\0');
    plaintext.resize(total_len);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

} // namespace utils
} // namespace iar
