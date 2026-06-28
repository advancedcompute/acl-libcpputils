
/*
 © Copyright 2025 Dominic Finch
*/

#pragma once

#include <mutex>
#include <cstring>
#include <vector>
#include <functional>
#include <openssl/evp.h>
#include "crypto_common.h"

namespace cpp {
    namespace utils {

        class ECC {
        public:
            ECC();
            ~ECC();

            bool generate_own_keypair();
            void clear_keypair(bool clear_peer_key=true);

            bool load_peer_public_key_from_pem(const std::string& pem);

            bool load_own_public_key_from_pem(const std::string& pem);
            bool load_own_public_key_from_pem_file(const std::string& fpath);
            bool load_own_private_key_from_pem_string(const std::string& pem);          // No password callback variant
            bool load_own_private_key_from_pem_string(const std::string& pem, PasswordCallback cb);
            
            bool load_own_private_key_from_pem_file(const std::string& path);
            bool load_own_private_key_from_pem_file(const std::string& path, PasswordCallback cb);

            // Import / Export //
            bool export_public_key(const std::string& path);
            bool export_private_key(const std::string& path);
            bool export_private_key(const std::string& path, PasswordCallback cb);

            bool import_public_key(const std::string& path);
            bool import_private_key(const std::string& path);
            bool import_private_key(const std::string& path, PasswordCallback cb);
            //

            bool get_own_public_key_pem(std::string& pem);
            bool get_own_private_key_pem(std::string& pem);
            bool get_own_private_key_pem(std::string& pem, PasswordCallback cb);

            bool derive_shared_secret_with_peer(std::vector<uint8_t>& shared_secret);
            
            bool sign_with_own_key(const std::string& data, std::string& signature);
            bool verify_with_peer_key(const std::string& data, const std::string& signature);

            bool sign_with_own_key(const std::vector<uint8_t>& data, std::vector<uint8_t>& signature);
            bool verify_with_peer_key(const std::vector<uint8_t>& data, std::vector<uint8_t>& signature);

            bool encrypt(const std::string& plaintext, std::string& ciphertext, std::vector<uint8_t>& iv, std::string& tag);
            bool decrypt(const std::string& ciphertext, std::string& plaintext, const std::vector<uint8_t>& iv, const std::string& tag);

            bool encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, std::vector<uint8_t>& tag);
            bool decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& tag);

        private:
            EVP_PKEY* _keypair;
            EVP_PKEY* _peer_key;
            std::mutex _lock_mutex;

            //const size_t GCM_KEY_SIZE = 32;   // 256-bit AES key
            //const size_t GCM_IV_SIZE  = 12;   // Recommended IV size for GCM
            //const size_t GCM_TAG_SIZE = 16;   // 128-bit GCM tag
        };

    }
}