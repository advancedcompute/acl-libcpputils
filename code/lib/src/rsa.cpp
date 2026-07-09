/*
 © Copyright 2025 Dominic Finch
*/

#include "base64.h"
#include "rsa.h"
#include "file.h"

#include <openssl/bio.h>
#include <openssl/err.h>

namespace cpp {
    namespace utils {

        RSA::RSA() {

        }

        RSA::RSA(const utils::RSA& other) {
            key = deep_key_copy(other.key);
        }

        RSA::~RSA() {
            clear_keypair();
        }

        bool RSA::public_key(std::string& pubkey) {
            bool success = false;

            if (key != nullptr) {
                BIO* bio = BIO_new(BIO_s_mem());
                if (PEM_write_bio_PUBKEY(bio, key) == 1) {
                    pubkey.clear();

                    unsigned char* data;
                    unsigned int nsize = -1;
                    if ((nsize = BIO_get_mem_data(bio, &data)) > 0) {
                        pubkey.resize(nsize, '\0');
                        strncpy(&pubkey[0], (const char*)data, nsize);
                        success = true;
                    }
                }
                BIO_free(bio);
            }
            return success;
        }

        bool RSA::private_key(std::string& pkey) 
        {
            bool success = false;

            if (key != nullptr) {
                BIO* bio = BIO_new(BIO_s_mem());
                if (PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1) {
                    pkey.clear();

                    unsigned char* data;
                    unsigned int nsize = -1;
                    if ((nsize = BIO_get_mem_data(bio, &data)) > 0) {
                        pkey.resize(nsize, '\0');
                        strncpy(&pkey[0], (const char*)data, nsize);
                        success = true;
                    }
                }
                BIO_free(bio);
            }
            return success;
        }

        bool RSA::private_key(std::string& pkey, PasswordCallback cb)
        {
            bool success = false;
            if (key != nullptr) {
                BIO* bio = BIO_new(BIO_s_mem());
                PasswordCallbackWrapper wrapper{cb};
                if (PEM_write_bio_PrivateKey(bio, key, EVP_aes_256_cbc(), nullptr, 0, openssl_password_cb, &wrapper) == 1) {
                    pkey.clear();

                    unsigned char* data;
                    unsigned int nsize = -1;
                    if ((nsize = BIO_get_mem_data(bio, &data)) > 0) {
                        pkey.resize(nsize, '\0');
                        strncpy(&pkey[0], (const char*)data, nsize);
                        success = true;
                    }
                }
                BIO_free(bio);
            }
            return success;
        }

        bool RSA::generate_keypair(unsigned int bitsize) {
            bool success = false;

            if ((bitsize & (bitsize - 1)) == 0) {     // Ensures bitsize is power of two
                clear_keypair();
                
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
                if (key == nullptr) {
                    if (EVP_PKEY_keygen_init(ctx) > 0) {
                        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bitsize) > 0) {
                            if (EVP_PKEY_keygen(ctx, &key) > 0) {
                                success = true;
                            }
                        }
                    }
                }
                EVP_PKEY_CTX_free(ctx);
            }
            return success;
        }

        void RSA::clear_keypair() {
            if (key != nullptr) {
                EVP_PKEY_free(key);
                key = nullptr;
            }
        }

        bool RSA::export_public_key(const std::string& fpath) {
            bool success = false;
            std::string pubkey;
            if (public_key(pubkey)) {
                if (write_file_contents(fpath, pubkey)) {
                    success = true;
                }
            }
            return success;
        }

        bool RSA::export_private_key(const std::string& fpath) {
            bool success = false;
            std::string privkey;
            if (private_key(privkey)) {
                if (write_file_contents(fpath, privkey)) {
                    success = true;
                }
            }
            return success;
        }

        bool RSA::export_private_key(const std::string& fpath, PasswordCallback cb)
        {
            bool success = false;
            std::string privkey;
            if (private_key(privkey, cb)) {
                if (write_file_contents(fpath, privkey)) {
                    success = true;
                }
            }
            return success;
        }

        bool RSA::import_private_key(const std::string& fpath) {
            bool success = false;
            auto fullpath = full_resolve_path(fpath);
            if (file_exists(fullpath)) {
                BIO* bio = BIO_new(BIO_s_file());
                if (BIO_read_filename(bio, fullpath.c_str()) > 0) {
                    auto * pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);

                    if (pkey != nullptr) {
                        clear_keypair();
                        key = pkey;
                        success = true;
                    }
                }
                BIO_free(bio);
            }
            return success;
        }

        bool RSA::import_private_key(const std::string& fpath, PasswordCallback cb) {
            bool success = false;
            auto fullpath = full_resolve_path(fpath);
            if (file_exists(fullpath)) {
                BIO* bio = BIO_new(BIO_s_file());
                if (BIO_read_filename(bio, fullpath.c_str()) > 0) {
                    PasswordCallbackWrapper wrapper{cb};
                    auto * pkey = PEM_read_bio_PrivateKey(bio, nullptr, openssl_password_cb, &wrapper);

                    if (pkey != nullptr) {
                        clear_keypair();
                        key = pkey;
                        success = true;
                    }
                }
                BIO_free(bio);
            }
            return success;
        }

        bool RSA::import_public_key(const std::string& fpath) {
            bool success = false;
            if (file_exists(fpath)) {
                BIO* bio = BIO_new(BIO_s_file());
                if (BIO_read_filename(bio, fpath.c_str()) > 0) {
                    auto * pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);

                    if (pkey != nullptr) {
                        clear_keypair();
                        key = pkey;
                        success = true;
                    }
                }
                BIO_free(bio);
            }
            return success;
        }

        bool RSA::encrypt(const std::string& input, std::string& output, int padding) {
            std::vector<uint8_t> uc_input(input.begin(), input.end());
            std::vector<uint8_t> uc_output, output_char;

            if (!encrypt(uc_input, uc_output, padding)) return false;
            
            auto success = Base64::encode(uc_output, output_char);
            output = std::string(output_char.begin(), output_char.end());
            return success;
        }

        bool RSA::decrypt(const std::string& input, std::string& output, int padding) {
            std::string binary;
            if (!Base64::decode(input, binary)) return false;

            std::vector<uint8_t> uc_input(binary.begin(), binary.end());
            std::vector<uint8_t> uc_output;

            if (!decrypt(uc_input, uc_output, padding)) return false;

            output.assign(uc_output.begin(), uc_output.end());
            return true;
        }

        bool RSA::encrypt(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, int padding) {
            if (!key) return false;

            output.clear();
            const int keysize = EVP_PKEY_get_size(key);
            int max_chunk = keysize;
            switch (padding) {
                case RSA_PKCS1_PADDING: max_chunk -= 11; break;
                case RSA_PKCS1_OAEP_PADDING: max_chunk -= 42; break;
            }

            if ((int)input.size() > max_chunk) {
                // RSA is not suited for large plaintext
                fprintf(stderr, "Input too large for RSA encryption\n");
                return false;
            }

            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
            if (!ctx) return false;

            bool success = false;
            if (EVP_PKEY_encrypt_init(ctx) > 0 &&
                EVP_PKEY_CTX_set_rsa_padding(ctx, padding) > 0) {
                size_t outlen = 0;
                if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, input.data(), input.size()) > 0) {
                    std::vector<uint8_t> buffer(outlen);
                    if (EVP_PKEY_encrypt(ctx, buffer.data(), &outlen, input.data(), input.size()) > 0) {
                        buffer.resize(outlen);
                        output.swap(buffer);
                        success = true;
                    }
                }
            }

            EVP_PKEY_CTX_free(ctx);
            return success;
        }

        bool RSA::decrypt(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, int padding) {
            if (!key) return false;

            output.clear();
            const int keysize = EVP_PKEY_get_size(key);
            //if ((int)input.size() != keysize) {
            //    fprintf(stderr, "Ciphertext size (%zu) does not match key size (%d)\n", input.size(), keysize);
            //    return false;
            //}

            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
            if (!ctx) return false;

            bool success = false;
            if (EVP_PKEY_decrypt_init(ctx) > 0 &&
                EVP_PKEY_CTX_set_rsa_padding(ctx, padding) > 0) {
                size_t outlen = 0;
                if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, input.data(), input.size()) > 0) {
                    std::vector<uint8_t> buffer(outlen);
                    if (EVP_PKEY_decrypt(ctx, buffer.data(), &outlen, input.data(), input.size()) > 0) {
                        buffer.resize(outlen);
                        output.swap(buffer);
                        success = true;
                    }
                }
            }

            EVP_PKEY_CTX_free(ctx);
            return success;
        }

        bool RSA::sign(const std::string& content, std::string& signature, const std::string& algo) {
            std::vector<uint8_t> uc_input(content.begin(), content.end());
            std::vector<uint8_t> uc_output, uc_output_encoded;
            bool success = sign(uc_input, uc_output, algo);
            success &= Base64::encode(uc_output, uc_output_encoded);
            signature = std::string(uc_output_encoded.begin(), uc_output_encoded.end());
            return success;
        }

        bool RSA::verify(const std::string& content, std::string& signature, const std::string& algo) {
            std::vector<uint8_t> uc_input(content.begin(), content.end());
            std::vector<uint8_t> uc_output(signature.begin(), signature.end());
            std::vector<uint8_t> uc_output_decoded;

            bool success = Base64::decode(uc_output, uc_output_decoded);
            success &= verify(uc_input, uc_output_decoded, algo);
            return success;
        }

        bool RSA::sign(const std::vector<uint8_t>& content, std::vector<uint8_t>& signature, const std::string& algo) {
            bool success = false;

            if (key != nullptr) {
                auto* algo_struct = EVP_get_digestbyname(algo.c_str());
                if (algo_struct != nullptr) {
                    signature.clear();

                    EVP_MD_CTX* sign_ctx = EVP_MD_CTX_create();
                    if (EVP_DigestInit_ex(sign_ctx, algo_struct, nullptr) == 1) {
                        if (EVP_DigestSignInit(sign_ctx, NULL, algo_struct, NULL, key) == 1) {
                            if (EVP_DigestSignUpdate(sign_ctx, content.data(), content.size()) == 1) {
                                size_t signature_size = 0;
                                if (EVP_DigestSignFinal(sign_ctx, NULL, &signature_size) == 1) {
                                    uint8_t* sig_buffer = new uint8_t[signature_size]{ '\0' };
                                    if (EVP_DigestSignFinal(sign_ctx, sig_buffer, &signature_size) == 1) {
                                        signature.insert(signature.end(), sig_buffer, sig_buffer + signature_size);
                                        success = true;
                                    }
                                    delete[] sig_buffer;
                                }
                            }
                        }
                    }

                    EVP_MD_CTX_destroy(sign_ctx);
                }
                else {
                    fprintf(stderr, " - Error: Unsupported hash algorithm\n");
                }
            }
            return success;
        }

        bool RSA::verify(const std::vector<uint8_t>& content, std::vector<uint8_t>& signature, const std::string& algo) {
            bool success = false;

            if (key != nullptr) {
                auto* algo_struct = EVP_get_digestbyname(algo.c_str());
                if (algo_struct != nullptr) {
                    EVP_MD_CTX* sign_ctx = EVP_MD_CTX_create();
                    if (EVP_DigestInit_ex(sign_ctx, algo_struct, nullptr) == 1) {
                        if (EVP_DigestVerifyInit(sign_ctx, NULL, algo_struct, NULL, key) == 1) {
                            if (EVP_DigestVerifyUpdate(sign_ctx, content.data(), content.size()) == 1) {
                                int rc = 0;
                                if ((rc = EVP_DigestVerifyFinal(sign_ctx, signature.data(), signature.size())) == 1) {
                                    success = true;
                                }
                                else if (rc == 0) {
                                    fprintf(stderr, " - Error: RSA verification failed\n");
                                }
                            }
                        }
                    }
                    EVP_MD_CTX_destroy(sign_ctx);
                }
                else {
                    fprintf(stderr, " - Error: Unsupported hash algorithm\n");
                }
            }
            return success;
        }

        EVP_PKEY* RSA::deep_key_copy(EVP_PKEY* original) {
            if (!original) return nullptr;

            // Create a memory BIO
            BIO* mem = BIO_new(BIO_s_mem());
            if (!mem) return nullptr;

            // Try writing as private key first
            if (!PEM_write_bio_PrivateKey(mem, original, nullptr, nullptr, 0, nullptr, nullptr)) {
                BIO_reset(mem); // Reset in case it’s a public key

                // Try writing as public key
                if (!PEM_write_bio_PUBKEY(mem, original)) {
                    BIO_free(mem);
                    return nullptr;
                }
            }

            // Read key from BIO to create a deep copy
            EVP_PKEY* copy = PEM_read_bio_PrivateKey(mem, nullptr, nullptr, nullptr);
            if (!copy) {
                BIO_reset(mem);
                copy = PEM_read_bio_PUBKEY(mem, nullptr, nullptr, nullptr);
            }

            BIO_free(mem);
            return copy;
        }
    }
}