/*
 © Copyright 2025 Dominic Finch
*/

#include "certificate_builder.h"
#include "ecc.h"
#include "rsa.h"

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <stdexcept>
#include <fstream>

// --- Utility RAII helpers ---
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

// =============================================================
// CertificateBuilder
// =============================================================

cpp::utils::CertificateBuilder::CertificateBuilder()
    : x509_(X509_new(), X509_free)
{
    if (!x509_) throw std::runtime_error("Failed to allocate X509");
    X509_set_version(x509_.get(), 2); // v3 certificate
}

void cpp::utils::CertificateBuilder::set_subject(const std::string& dn) {
    X509_NAME* name = X509_NAME_new();
    if (!name) throw std::runtime_error("Failed to create X509_NAME");

    // Very simple DN parser: just use CN for now
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(dn.c_str()),
                               -1, -1, 0);
    X509_set_subject_name(x509_.get(), name);
    X509_NAME_free(name);
}

void cpp::utils::CertificateBuilder::set_validity_days(int days) {
    X509_gmtime_adj(X509_getm_notBefore(x509_.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509_.get()), 60L * 60 * 24 * days);
}

void cpp::utils::CertificateBuilder::set_serial_number(long serial) {
    ASN1_INTEGER_set(X509_get_serialNumber(x509_.get()), serial);
}

void cpp::utils::CertificateBuilder::set_public_key_from_ecc(cpp::utils::ECC& ecc) {
    std::string pubPem;
    if (!ecc.get_own_public_key_pem(pubPem))
        throw std::runtime_error("Failed to extract ECC public key PEM");

    BIO* bio = BIO_new_mem_buf(pubPem.data(), (int)pubPem.size());
    EVP_PKEY_ptr pkey(PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr), EVP_PKEY_free);
    BIO_free(bio);
    if (!pkey) throw std::runtime_error("Failed to load ECC public key");
    X509_set_pubkey(x509_.get(), pkey.get());
}

void cpp::utils::CertificateBuilder::set_public_key_from_rsa(cpp::utils::RSA& rsa) {
    std::string pubPem;
    if (!rsa.public_key(pubPem))
        throw std::runtime_error("Failed to extract RSA public key PEM");

    BIO* bio = BIO_new_mem_buf(pubPem.data(), (int)pubPem.size());
    EVP_PKEY_ptr pkey(PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr), EVP_PKEY_free);
    BIO_free(bio);
    if (!pkey) throw std::runtime_error("Failed to load RSA public key");
    X509_set_pubkey(x509_.get(), pkey.get());
}

void cpp::utils::CertificateBuilder::sign_with_private_pem(const std::string& pem, const EVP_MD* md) {
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    EVP_PKEY_ptr pkey(PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr), EVP_PKEY_free);
    BIO_free(bio);
    if (!pkey) throw std::runtime_error("Failed to load private key PEM");
    if (!X509_sign(x509_.get(), pkey.get(), md))
        throw std::runtime_error("X509_sign failed");
}

void cpp::utils::CertificateBuilder::self_sign_with_ecc(ECC& ecc) {
    std::string privPem;
    if (!ecc.get_own_private_key_pem(privPem))
        throw std::runtime_error("Failed to get ECC private key PEM");
    X509_set_issuer_name(x509_.get(), X509_get_subject_name(x509_.get()));
    sign_with_private_pem(privPem, EVP_sha256());
}

void cpp::utils::CertificateBuilder::self_sign_with_rsa(cpp::utils::RSA& rsa) {
    std::string privPem;
    if (!rsa.private_key(privPem))
        throw std::runtime_error("Failed to get RSA private key PEM");
    X509_set_issuer_name(x509_.get(), X509_get_subject_name(x509_.get()));
    sign_with_private_pem(privPem, EVP_sha256());
}

void cpp::utils::CertificateBuilder::sign_with_ca(const CertificateBuilder& ca, cpp::utils::ECC& ecc) {
    std::string privPem;
    if (!ecc.get_own_private_key_pem(privPem))
        throw std::runtime_error("Failed to get ECC CA private key PEM");
    X509_set_issuer_name(x509_.get(), X509_get_subject_name(ca.x509_.get()));
    sign_with_private_pem(privPem, EVP_sha256());
}

void cpp::utils::CertificateBuilder::sign_with_ca(const CertificateBuilder& ca, cpp::utils::RSA& rsa) {
    std::string privPem;
    if (!rsa.private_key(privPem))
        throw std::runtime_error("Failed to get RSA CA private key PEM");
    X509_set_issuer_name(x509_.get(), X509_get_subject_name(ca.x509_.get()));
    sign_with_private_pem(privPem, EVP_sha256());
}

bool cpp::utils::CertificateBuilder::save_pem(const std::string& path) const {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    bool ok = PEM_write_X509(f, x509_.get());
    fclose(f);
    return ok;
}

bool cpp::utils::CertificateBuilder::save_der(const std::string& path) const {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    bool ok = i2d_X509_fp(f, x509_.get());
    fclose(f);
    return ok;
}

bool cpp::utils::CertificateBuilder::get_certificate_pem(std::string& out) const {
    BIO* mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mem, x509_.get());
    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    out.assign(bptr->data, bptr->length);
    BIO_free(mem);
    return true;
}

bool cpp::utils::CertificateBuilder::get_certificate_der(std::vector<uint8_t>& out) const {
    int len = i2d_X509(x509_.get(), nullptr);
    out.resize(len);
    unsigned char* p = out.data();
    i2d_X509(x509_.get(), &p);
    return true;
}

bool cpp::utils::CertificateBuilder::export_to_pkcs12(const std::string& path,
                                          const std::string& password,
                                          cpp::utils::RSA& rsa) const {
    std::string privPem;
    if (!rsa.private_key(privPem)) return false;

    BIO* bio = BIO_new_mem_buf(privPem.data(), (int)privPem.size());
    EVP_PKEY_ptr pkey(PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr), EVP_PKEY_free);
    BIO_free(bio);
    if (!pkey) return false;

    PKCS12* p12 = PKCS12_create(password.c_str(), "certificate",
                                pkey.get(), x509_.get(), nullptr, 0, 0, 0, 0, 0);
    if (!p12) return false;

    FILE* fp = fopen(path.c_str(), "wb");
    if (!fp) { PKCS12_free(p12); return false; }
    bool ok = i2d_PKCS12_fp(fp, p12);
    fclose(fp);
    PKCS12_free(p12);
    return ok;
}

// =============================================================
// Certificate
// =============================================================

/*
cpp::utils::Certificate::Certificate() : x509_(nullptr, X509_free) {}

bool cpp::utils::Certificate::load_from_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) return false;
    x509_.reset(cert);
    return true;
}

bool cpp::utils::Certificate::load_from_pem_file(const std::string& path) {
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return false;
    X509* cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!cert) return false;
    x509_.reset(cert);
    return true;
}

bool cpp::utils::Certificate::load_from_der_file(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    X509* cert = d2i_X509_fp(f, nullptr);
    fclose(f);
    if (!cert) return false;
    x509_.reset(cert);
    return true;
}

bool cpp::utils::Certificate::get_common_name(std::string& cn) const {
    if (!x509_) return false;
    X509_NAME* subj = X509_get_subject_name(x509_.get());
    int idx = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
    if (idx < 0) return false;
    X509_NAME_ENTRY* e = X509_NAME_get_entry(subj, idx);
    ASN1_STRING* d = X509_NAME_ENTRY_get_data(e);
    
    unsigned char* utf8 = nullptr;
    int len = ASN1_STRING_to_UTF8(&utf8, d);
    if (len < 0) return false;
    cn.assign((char*)utf8, len);
    OPENSSL_free(utf8);
    return true;
}

bool cpp::utils::Certificate::verify_signature(const Certificate& issuer) const {
    EVP_PKEY* pub = X509_get_pubkey(issuer.x509_.get());
    if (!pub) return false;
    int ok = X509_verify(x509_.get(), pub);
    EVP_PKEY_free(pub);
    return ok == 1;
}

*/
