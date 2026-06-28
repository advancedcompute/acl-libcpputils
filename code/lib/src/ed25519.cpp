/*
 © Copyright 2025 Dominic Finch
*/

#include "ed25519.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <algorithm>
#include <cstring>
#include "file.h"

#include "ed25519.h"
#include "base64.h"

#ifdef WIN32
extern "C" {
#include <openssl/applink.c>
}
#endif // WIN32


namespace cpp { namespace utils {

// --- lexicographic concatenation for symmetric info ---
void lexicographic_concat(const std::string& label,
                                 const std::vector<uint8_t>& a,
                                 const std::vector<uint8_t>& b,
                                 std::vector<uint8_t>& out)
{
    out.clear();
    out.insert(out.end(), label.begin(), label.end());
    if (a < b) {
        out.insert(out.end(), a.begin(), a.end());
        out.insert(out.end(), b.begin(), b.end());
    } else {
        out.insert(out.end(), b.begin(), b.end());
        out.insert(out.end(), a.begin(), a.end());
    }
}

// --- Extract 32-byte Ed25519 seed (raw private) from EVP_PKEY ---
bool ed25519_seed_from_evp(EVP_PKEY* ed, std::vector<uint8_t>& seed_out)
{
    if (!ed) return false;
    size_t len = 0;
    if (EVP_PKEY_get_raw_private_key(ed, NULL, &len) != 1) return false;
    if (len != 32) return false;
    seed_out.resize(32);
    if (EVP_PKEY_get_raw_private_key(ed, seed_out.data(), &len) != 1) return false;
    return true;
}

// --- From Ed25519 32-byte seed produce X25519 (xpriv,xpub) using SHA512 + clamp ---
// Uses OpenSSL to derive public by creating EVP_PKEY from xpriv and calling EVP_PKEY_get_raw_public_key
bool ed25519_seed_to_x25519_pair(const std::vector<uint8_t>& ed_seed,
                                        std::vector<uint8_t>& xpriv_out,
                                        std::vector<uint8_t>& xpub_out)
{
    if (ed_seed.size() != 32) return false;

    unsigned char h[64];
    SHA512(ed_seed.data(), 32, h);

    unsigned char xpriv[32];
    memcpy(xpriv, h, 32);
    // clamp for X25519
    xpriv[0]  &= 248;
    xpriv[31] &= 127;
    xpriv[31] |= 64;

    // create EVP_PKEY X25519 private and get raw public
    EVP_PKEY* xkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, xpriv, sizeof(xpriv));
    if (!xkey) return false;

    size_t publen = 0;
    if (EVP_PKEY_get_raw_public_key(xkey, nullptr, &publen) != 1 || publen != 32) { EVP_PKEY_free(xkey); return false; }
    xpub_out.resize(publen);
    if (EVP_PKEY_get_raw_public_key(xkey, xpub_out.data(), &publen) != 1) { EVP_PKEY_free(xkey); return false; }

    xpriv_out.assign(xpriv, xpriv + sizeof(xpriv));
    EVP_PKEY_free(xkey);
    return true;
}

// --- Convert an EVP_PKEY Ed25519 into an EVP_PKEY X25519 (out must be freed by caller) ---
bool convert_ed25519_to_x25519(EVP_PKEY* ed25519_key, EVP_PKEY** x25519_key_out)
{
    if (!ed25519_key || !x25519_key_out) return false;
    std::vector<uint8_t> seed;
    if (!ed25519_seed_from_evp(ed25519_key, seed)) return false;
    std::vector<uint8_t> xpriv, xpub;
    if (!ed25519_seed_to_x25519_pair(seed, xpriv, xpub)) return false;

    EVP_PKEY* xkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, xpriv.data(), xpriv.size());
    if (!xkey) return false;
    *x25519_key_out = xkey;
    // zero sensitive
    OPENSSL_cleanse(xpriv.data(), xpriv.size());
    OPENSSL_cleanse(seed.data(), seed.size());
    return true;
}

// --- Get X25519 public bytes derived from Ed25519 private EVP_PKEY (caller gets 32 bytes) ---
bool get_x25519_public_from_ed25519_priv(EVP_PKEY* ed_priv, std::vector<uint8_t>& out_xpub)
{
    if (!ed_priv) return false;
    std::vector<uint8_t> seed;
    if (!ed25519_seed_from_evp(ed_priv, seed)) return false;
    std::vector<uint8_t> xpriv, xpub;
    if (!ed25519_seed_to_x25519_pair(seed, xpriv, xpub)) { OPENSSL_cleanse(seed.data(), seed.size()); return false; }
    out_xpub = xpub;
    OPENSSL_cleanse(xpriv.data(), xpriv.size());
    OPENSSL_cleanse(seed.data(), seed.size());
    return true;
}

// --- derive_shared_secret expects my_key being an EVP_PKEY X25519 private and peer_pub is raw 32-byte X25519 public ---
bool derive_shared_secret(EVP_PKEY* my_key, const std::vector<uint8_t>& peer_pub, std::vector<uint8_t>& secret)
{
    if (!my_key) return false;
    if (peer_pub.size() != 32) return false;
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), peer_pub.size());
    if (!peer) return false;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(my_key, nullptr);
    if (!ctx) { EVP_PKEY_free(peer); return false; }
    if (EVP_PKEY_derive_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer); return false; }
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer); return false; }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer); return false; }
    secret.resize(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) { EVP_PKEY_free(peer); EVP_PKEY_CTX_free(ctx); secret.clear(); return false; }
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);
    return true;
}


ED25519::ED25519() : ed25519_key_(nullptr) {}

ED25519::~ED25519()
{
    if(ed25519_key_) EVP_PKEY_free(ed25519_key_);
}

bool ED25519::generate_keypair()
{
    if(ed25519_key_) { EVP_PKEY_free(ed25519_key_); ed25519_key_ = nullptr; }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if(!ctx) return false;

    if(EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY* key = nullptr;
    if(EVP_PKEY_generate(ctx, &key) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    ed25519_key_ = key;
    return true;
}

bool ED25519::get_public_key_pem(std::string& pem)
{
    bool success = false;

    if (ed25519_key_ != nullptr) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (PEM_write_bio_PUBKEY(bio, ed25519_key_) == 1) {
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

bool ED25519::get_private_key_pem(std::string& pem)
{
    bool success = false;

    if (ed25519_key_ != nullptr) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (PEM_write_bio_PrivateKey(bio, ed25519_key_, nullptr, nullptr, 0, nullptr, nullptr) == 1) {
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

bool ED25519::get_private_key_pem(std::string& pem, PasswordCallback cb)
{
    bool success = false;

    if (ed25519_key_ != nullptr) {
        BIO* bio = BIO_new(BIO_s_mem());
        PasswordCallbackWrapper wrapper {cb};
        if (PEM_write_bio_PrivateKey(bio, ed25519_key_, EVP_aes_256_cbc(), nullptr, 0, openssl_password_cb, &wrapper) == 1)
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

bool ED25519::set_public_key_pem(const std::string& pem)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
    if (!bio) return false;
    
    ed25519_key_ = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    return ed25519_key_ != nullptr;
}

bool ED25519::set_private_key_pem(const std::string& pem)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
    if (!bio) return false;

    ed25519_key_ = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    return ed25519_key_ != nullptr;
}

bool ED25519::set_private_key_pem(const std::string& pem, PasswordCallback cb)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
    if (!bio) return false;

    PasswordCallbackWrapper wrapper{cb};
    ed25519_key_ = PEM_read_bio_PrivateKey(bio, nullptr, openssl_password_cb, &wrapper);
    BIO_free(bio);

    return ed25519_key_ != nullptr;
}

bool ED25519::export_private_key(const std::string& path)
{
    if(!ed25519_key_) return false;

    auto fullpath = full_resolve_path(path);
    FILE* f = fopen(fullpath.c_str(), "wb");
    if(!f) return false;
    bool ok = PEM_write_PrivateKey(f, ed25519_key_, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);
    return ok;
}

bool ED25519::export_private_key(const std::string& path, PasswordCallback cb)
{
    if(!ed25519_key_) return false;

    auto fullpath = full_resolve_path(path);
    FILE* f = fopen(fullpath.c_str(), "wb");
    if(!f) return false;

    PasswordCallbackWrapper wrapper{cb};
    bool ok = PEM_write_PrivateKey(f, ed25519_key_, EVP_aes_256_cbc(), nullptr, 0, openssl_password_cb, &wrapper);
    fclose(f);
    return ok;
}

bool ED25519::export_public_key(const std::string& path)
{
    if(!ed25519_key_) return false;

    auto fullpath = full_resolve_path(path);
    FILE* f = fopen(fullpath.c_str(), "wb");
    if(!f) return false;
    bool ok = PEM_write_PUBKEY(f, ed25519_key_);
    fclose(f);
    return ok;
}

bool ED25519::import_private_key(const std::string& path)
{
    auto fullpath = full_resolve_path(path);
    FILE* f = fopen(fullpath.c_str(), "rb");
    if(!f) return false;
    EVP_PKEY* key = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);
    if(!key) return false;
    if(ed25519_key_) EVP_PKEY_free(ed25519_key_);
    ed25519_key_ = key;
    return true;
}

bool ED25519::import_private_key(const std::string& path, PasswordCallback cb)
{
    auto fullpath = full_resolve_path(path);
    FILE* f = fopen(fullpath.c_str(), "rb");
    if(!f) return false;

    PasswordCallbackWrapper wrapper{cb};
    EVP_PKEY* key = PEM_read_PrivateKey(f, nullptr, openssl_password_cb, &wrapper);
    fclose(f);
    if(!key) return false;
    if(ed25519_key_) EVP_PKEY_free(ed25519_key_);
    ed25519_key_ = key;
    return true;
}

bool ED25519::import_public_key(const std::string& path)
{
    auto fullpath = full_resolve_path(path);
    FILE* f = fopen(fullpath.c_str(), "rb");
    if(!f) return false;
    EVP_PKEY* key = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);
    if(!key) return false;
    if(ed25519_key_) EVP_PKEY_free(ed25519_key_);
    ed25519_key_ = key;
    return true;
}

bool ED25519::export_x25519_public_key_bytes(std::vector<uint8_t>& out) const
{
    out.clear();
    if (!ed25519_key_) return false;

    EVP_PKEY* xkey = nullptr;
    if (!convert_ed25519_to_x25519(ed25519_key_, &xkey))
        return false;

    size_t len = 0;
    if (EVP_PKEY_get_raw_public_key(xkey, nullptr, &len) <= 0 || len != 32) {
        EVP_PKEY_free(xkey);
        return false;
    }

    out.resize(len);
    if (EVP_PKEY_get_raw_public_key(xkey, out.data(), &len) <= 0) {
        EVP_PKEY_free(xkey);
        return false;
    }

    EVP_PKEY_free(xkey);
    return true;
}

bool ED25519::export_public_key_bytes(std::vector<uint8_t>& pub) const
{
    if (!ed25519_key_) return false;

    // Export the X25519 public key derived from this Ed25519 private key.
    // This yields the 32-byte Montgomery public key usable with EVP_PKEY_new_raw_public_key(..., EVP_PKEY_X25519, ...)
    return get_x25519_public_from_ed25519_priv(ed25519_key_, pub);
}


// ========================================================================
// SIGN / VERIFY
// ========================================================================

bool ED25519::sign(const std::vector<uint8_t>& data, std::vector<uint8_t>& signature, const std::string&)
{
    if(!ed25519_key_) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx) return false;

    size_t sig_len = 0;

    if(EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, ed25519_key_) <= 0)
    { EVP_MD_CTX_free(ctx); return false; }

    // First call to get signature length
    EVP_DigestSign(ctx, nullptr, &sig_len, data.data(), data.size());
    signature.resize(sig_len);

    if(EVP_DigestSign(ctx, signature.data(), &sig_len, data.data(), data.size()) <= 0)
    { EVP_MD_CTX_free(ctx); return false; }

    signature.resize(sig_len);
    EVP_MD_CTX_free(ctx);
    return true;
}

bool ED25519::verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const std::string&)
{
    if(!ed25519_key_) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx) return false;

    if(EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, ed25519_key_) <= 0)
    { EVP_MD_CTX_free(ctx); return false; }

    int rc = EVP_DigestVerify(ctx, signature.data(), signature.size(), data.data(), data.size());
    EVP_MD_CTX_free(ctx);
    return rc == 1;
}

// String convenience
bool ED25519::sign(const std::string& data, std::string& signature, const std::string& hash)
{
    std::vector<uint8_t> sig;
    if(!sign(std::vector<uint8_t>(data.begin(), data.end()), sig, hash)) return false;
    signature = Base64::encode(sig);
    return true;
}

bool ED25519::verify(const std::string& data, const std::string& signature, const std::string& hash)
{
    auto sig = Base64::decode(signature);
    return verify(std::vector<uint8_t>(data.begin(), data.end()), sig, hash);
}


// ========================================================================
// ENCRYPT / DECRYPT (X25519 + AES-256-GCM)
// ========================================================================

// Encrypt: [32 sender_xpub][12 IV][ciphertext][16 TAG]
// peerPub must be recipient X25519 public bytes (32)
bool ED25519::encrypt(const std::vector<uint8_t>& plaintext,
                      const std::vector<uint8_t>& peerPub,
                      std::vector<uint8_t>& ciphertext)
{
    if (!ed25519_key_) return false;
    if (peerPub.size() != 32) return false;

    // 1) my xpub (32 bytes)
    std::vector<uint8_t> my_xpub;
    if (!get_x25519_public_from_ed25519_priv(ed25519_key_, my_xpub)) return false;

    // 2) my xpriv (EVP_PKEY *)
    EVP_PKEY* my_xpriv = nullptr;
    if (!convert_ed25519_to_x25519(ed25519_key_, &my_xpriv)) return false;

    // 3) derive raw shared secret
    std::vector<uint8_t> shared;
    if (!derive_shared_secret(my_xpriv, peerPub, shared)) {
        EVP_PKEY_free(my_xpriv);
        return false;
    }
    EVP_PKEY_free(my_xpriv);
    if (shared.size() < 32) { OPENSSL_cleanse(shared.data(), shared.size()); return false; }

    // 4) derive AEAD key via HKDF-SHA256 with symmetric info
    const std::string label = "ED25519-X25519-AES-GCM";
    std::vector<uint8_t> info;
    lexicographic_concat(label, my_xpub, peerPub, info);

    std::vector<uint8_t> key;
    std::vector<uint8_t> salt; // empty salt => treated as zeros
    if (!hkdf_sha256(salt, shared, info, key, 32)) {
        OPENSSL_cleanse(shared.data(), shared.size());
        return false;
    }

    // 5) AES-256-GCM encrypt
    std::vector<uint8_t> iv(12);
    if (RAND_bytes(iv.data(), (int)iv.size()) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(shared.data(), shared.size());
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(shared.data(), shared.size());
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(shared.data(), shared.size());
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(shared.data(), shared.size());
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(shared.data(), shared.size());
        return false;
    }

    std::vector<uint8_t> outbuf(plaintext.size() + 16);
    int outlen1 = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, outbuf.data(), &outlen1, plaintext.data(), (int)plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            OPENSSL_cleanse(key.data(), key.size());
            OPENSSL_cleanse(shared.data(), shared.size());
            return false;
        }
    } else {
        outlen1 = 0;
    }

    int outlen2 = 0;
    if (EVP_EncryptFinal_ex(ctx, outbuf.data() + outlen1, &outlen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(shared.data(), shared.size());
        return false;
    }

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(tag), tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(shared.data(), shared.size());
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    size_t cipher_body_len = (size_t)outlen1 + (size_t)outlen2;

    // 6) Build ciphertext: [32 sender_xpub][12 iv][ct][16 tag]
    ciphertext.clear();
    ciphertext.reserve(32 + iv.size() + cipher_body_len + sizeof(tag));
    ciphertext.insert(ciphertext.end(), my_xpub.begin(), my_xpub.end());
    ciphertext.insert(ciphertext.end(), iv.begin(), iv.end());
    ciphertext.insert(ciphertext.end(), outbuf.begin(), outbuf.begin() + cipher_body_len);
    ciphertext.insert(ciphertext.end(), tag, tag + sizeof(tag));

    // cleanup
    OPENSSL_cleanse(key.data(), key.size());
    OPENSSL_cleanse(shared.data(), shared.size());
    return true;
}

// Decrypt: reads [32 sender_xpub][12 IV][ct][16 tag] and derives same HKDF key
bool ED25519::decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext)
{
    const size_t PUB_LEN = 32;
    const size_t IV_LEN = 12;
    const size_t TAG_LEN = 16;

    if (!ed25519_key_) return false;
    if (ciphertext.size() < PUB_LEN + IV_LEN + TAG_LEN) return false;

    const uint8_t* ptr = ciphertext.data();
    std::vector<uint8_t> sender_xpub(ptr, ptr + PUB_LEN);
    ptr += PUB_LEN;
    const uint8_t* iv_ptr = ptr; ptr += IV_LEN;
    size_t enc_len = ciphertext.size() - PUB_LEN - IV_LEN - TAG_LEN;
    const uint8_t* enc_ptr = ptr; ptr += enc_len;
    const uint8_t* tag_ptr = ptr;

    // 1) convert own Ed25519 -> X25519 private
    EVP_PKEY* my_xpriv = nullptr;
    if (!convert_ed25519_to_x25519(ed25519_key_, &my_xpriv)) return false;

    // 2) derive raw shared
    std::vector<uint8_t> shared;
    if (!derive_shared_secret(my_xpriv, sender_xpub, shared)) { EVP_PKEY_free(my_xpriv); return false; }
    EVP_PKEY_free(my_xpriv);
    if (shared.size() < 32) { OPENSSL_cleanse(shared.data(), shared.size()); return false; }

    // 3) get my xpub for symmetric info
    std::vector<uint8_t> my_xpub;
    if (!get_x25519_public_from_ed25519_priv(ed25519_key_, my_xpub)) { OPENSSL_cleanse(shared.data(), shared.size()); return false; }

    // 4) lexicographically build info (symmetric)
    const std::string label = "ED25519-X25519-AES-GCM";
    std::vector<uint8_t> info;
    lexicographic_concat(label, sender_xpub, my_xpub, info);

    // 5) HKDF to derive AEAD key
    std::vector<uint8_t> key;
    std::vector<uint8_t> salt;
    if (!hkdf_sha256(salt, shared, info, key, 32)) { OPENSSL_cleanse(shared.data(), shared.size()); return false; }

    // 6) AES-GCM decrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { OPENSSL_cleanse(key.data(), key.size()); OPENSSL_cleanse(shared.data(), shared.size()); return false; }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key.data(), key.size()); OPENSSL_cleanse(shared.data(), shared.size()); return false; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)IV_LEN, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key.data(), key.size()); OPENSSL_cleanse(shared.data(), shared.size()); return false; }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_ptr) != 1) { EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key.data(), key.size()); OPENSSL_cleanse(shared.data(), shared.size()); return false; }

    plaintext.resize(enc_len);
    int outlen1 = 0;
    if (enc_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen1, enc_ptr, (int)enc_len) != 1) { EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key.data(), key.size()); OPENSSL_cleanse(shared.data(), shared.size()); return false; }
    } else outlen1 = 0;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)TAG_LEN, (void*)tag_ptr) != 1) { EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key.data(), key.size()); OPENSSL_cleanse(shared.data(), shared.size()); return false; }

    int outlen2 = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);
    if (outlen2 <= 0) { OPENSSL_cleanse(key.data(), key.size()); OPENSSL_cleanse(shared.data(), shared.size()); return false; }

    plaintext.resize(outlen1 + outlen2);
    if (plaintext.back() == '\0')
        plaintext.pop_back();

    OPENSSL_cleanse(key.data(), key.size());
    OPENSSL_cleanse(shared.data(), shared.size());
    return true;
}

// String versions
bool ED25519::encrypt(const std::string& plaintext, const std::vector<uint8_t>& peerPub, std::string& ciphertext)
{
    std::vector<uint8_t> out;
    if(!encrypt(std::vector<uint8_t>(plaintext.begin(), plaintext.end()), peerPub, out)) return false;
    ciphertext = Base64::encode(out);
    return true;
}

bool ED25519::decrypt(const std::string& ciphertext, std::string& plaintext)
{
    std::vector<uint8_t> bin = Base64::decode(ciphertext);
    std::vector<uint8_t> out;
    if(!decrypt(bin, out)) return false;
    plaintext.assign(out.begin(), out.end());
    return true;
}

}}