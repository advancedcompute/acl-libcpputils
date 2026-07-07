
#include "certificate_builder_tests.h"
#include "certificate_builder.h"
#include "../../../../../dep/android/openssl/arm64-v8a/include/openssl/rsa.h"
#include "ecc.h"

#include <iostream>
#include <fstream>
#include <vector>

// -----------------------------
// Helpers
// -----------------------------

static std::string tmpfile_path(const std::string& name) {
    return "/tmp/" + name;
}

static bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

// -----------------------------
// CertificateBuilder tests
// -----------------------------

bool test_certificatebuilder_set_subject() {
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("TestCN");
    std::string pem;
    cpp::utils::ECC ecc; ecc.generate_own_keypair();
    builder.set_public_key_from_ecc(ecc);
    builder.self_sign_with_ecc(ecc);
    return builder.get_certificate_pem(pem) && !pem.empty();
}

bool test_certificatebuilder_set_validity_days() {
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("TestCN");
    builder.set_validity_days(365);
    std::string pem;
    cpp::utils::RSA rsa; rsa.generate_keypair();
    builder.set_public_key_from_rsa(rsa);
    builder.self_sign_with_rsa(rsa);
    return builder.get_certificate_pem(pem) && !pem.empty();
}

bool test_certificatebuilder_set_serial_number() {
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("TestCN");
    builder.set_serial_number(12345);
    std::string pem;
    cpp::utils::RSA rsa; rsa.generate_keypair();
    builder.set_public_key_from_rsa(rsa);
    builder.self_sign_with_rsa(rsa);
    return builder.get_certificate_pem(pem) && !pem.empty();
}

bool test_certificatebuilder_set_public_key_from_rsa() {
    cpp::utils::RSA rsa; rsa.generate_keypair();
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("RSAKeyTest");
    builder.set_public_key_from_rsa(rsa);
    builder.self_sign_with_rsa(rsa);
    std::string pem;
    return builder.get_certificate_pem(pem) && !pem.empty();
}

bool test_certificatebuilder_set_public_key_from_ecc() {
    cpp::utils::ECC ecc; ecc.generate_own_keypair();
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("ECCKeyTest");
    builder.set_public_key_from_ecc(ecc);
    builder.self_sign_with_ecc(ecc);
    std::string pem;
    return builder.get_certificate_pem(pem) && !pem.empty();
}

bool test_certificatebuilder_self_sign_with_rsa() {
    cpp::utils::RSA rsa; rsa.generate_keypair();
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("SelfSignRSA");
    builder.set_public_key_from_rsa(rsa);
    builder.self_sign_with_rsa(rsa);
    std::string pem;
    return builder.get_certificate_pem(pem) && !pem.empty();
}

bool test_certificatebuilder_self_sign_with_ecc() {
    cpp::utils::ECC ecc; ecc.generate_own_keypair();
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("SelfSignECC");
    builder.set_public_key_from_ecc(ecc);
    builder.self_sign_with_ecc(ecc);
    std::string pem;
    return builder.get_certificate_pem(pem) && !pem.empty();
}

bool test_certificatebuilder_sign_with_ca_rsa() {
    cpp::utils::RSA caRsa, leafRsa;
    caRsa.generate_keypair(); leafRsa.generate_keypair();

    cpp::utils::CertificateBuilder ca;
    ca.set_subject("CARoot");
    ca.set_public_key_from_rsa(caRsa);
    ca.self_sign_with_rsa(caRsa);

    cpp::utils::CertificateBuilder leaf;
    leaf.set_subject("LeafRSA");
    leaf.set_public_key_from_rsa(leafRsa);
    leaf.sign_with_ca(ca, caRsa);

    std::string pem;
    return leaf.get_certificate_pem(pem) && !pem.empty();
}

bool test_certificatebuilder_sign_with_ca_ecc() {
    cpp::utils::ECC caEcc, leafEcc;
    caEcc.generate_own_keypair(); leafEcc.generate_own_keypair();

    cpp::utils::CertificateBuilder ca;
    ca.set_subject("CAECC");
    ca.set_public_key_from_ecc(caEcc);
    ca.self_sign_with_ecc(caEcc);

    cpp::utils::CertificateBuilder leaf;
    leaf.set_subject("LeafECC");
    leaf.set_public_key_from_ecc(leafEcc);
    leaf.sign_with_ca(ca, caEcc);

    std::string pem;
    return leaf.get_certificate_pem(pem) && !pem.empty();
}

bool test_certificatebuilder_save_pem() {
    cpp::utils::RSA rsa; rsa.generate_keypair();
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("SavePEM");
    builder.set_public_key_from_rsa(rsa);
    builder.self_sign_with_rsa(rsa);
    std::string path = tmpfile_path("save.pem");
    return builder.save_pem(path) && file_exists(path);
}

bool test_certificatebuilder_save_der() {
    cpp::utils::RSA rsa; rsa.generate_keypair();
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("SaveDER");
    builder.set_public_key_from_rsa(rsa);
    builder.self_sign_with_rsa(rsa);
    std::string path = tmpfile_path("save.der");
    return builder.save_der(path) && file_exists(path);
}

bool test_certificatebuilder_get_certificate_pem() {
    cpp::utils::RSA rsa; rsa.generate_keypair();
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("GetPEM");
    builder.set_public_key_from_rsa(rsa);
    builder.self_sign_with_rsa(rsa);
    std::string pem;
    return builder.get_certificate_pem(pem) && !pem.empty();
}

bool test_certificatebuilder_get_certificate_der() {
    cpp::utils::RSA rsa; rsa.generate_keypair();
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("GetDER");
    builder.set_public_key_from_rsa(rsa);
    builder.self_sign_with_rsa(rsa);
    std::vector<uint8_t> der;
    return builder.get_certificate_der(der) && !der.empty();
}

bool test_certificatebuilder_export_to_pkcs12() {
    cpp::utils::RSA rsa; rsa.generate_keypair();
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("PKCS12");
    builder.set_public_key_from_rsa(rsa);
    builder.self_sign_with_rsa(rsa);
    std::string path = tmpfile_path("test.p12");
    return builder.export_to_pkcs12(path, "password", rsa) && file_exists(path);
}

// -----------------------------
// Certificate tests
// -----------------------------

static bool generate_self_signed_cert(std::string& pemOut, std::vector<uint8_t>& derOut, cpp::utils::RSA& rsa) {
    rsa.generate_keypair();
    cpp::utils::CertificateBuilder builder;
    builder.set_subject("UnitTestCN");
    builder.set_validity_days(365);
    builder.set_serial_number(123);
    builder.set_public_key_from_rsa(rsa);
    builder.self_sign_with_rsa(rsa);
    if (!builder.get_certificate_pem(pemOut)) return false;
    if (!builder.get_certificate_der(derOut)) return false;
    return true;
}

// Helper to write PEM or DER to a temporary file
static std::string write_temp_file(const std::string& name, const std::string& contents, bool binary=false) {
    std::string path = "/tmp/" + name;
    std::ofstream f(path, binary ? std::ios::binary : std::ios::out);
    f.write(contents.data(), contents.size());
    f.close();
    return path;
}

static std::string write_temp_file(const std::string& name, const std::vector<uint8_t>& contents) {
    std::string path = "/tmp/" + name;
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    f.close();
    return path;
}

// -----------------------------
// Certificate Unit Tests
// -----------------------------
/*
bool test_load_from_pem() {
    cpp::utils::RSA rsa;
    std::string pem;
    std::vector<uint8_t> der;
    if (!generate_self_signed_cert(pem, der, rsa)) return false;

    cpp::utils::Certificate cert;
    return cert.load_from_pem(pem);
}

bool test_load_from_pem_file() {
    cpp::utils::RSA rsa;
    std::string pem;
    std::vector<uint8_t> der;
    if (!generate_self_signed_cert(pem, der, rsa)) return false;

    std::string path = write_temp_file("cert.pem", pem);
    cpp::utils::Certificate cert;
    return cert.load_from_pem_file(path);
}

bool test_load_from_der_file() {
    cpp::utils::RSA rsa;
    std::string pem;
    std::vector<uint8_t> der;
    if (!generate_self_signed_cert(pem, der, rsa)) return false;

    std::string path = write_temp_file("cert.der", der);
    cpp::utils::Certificate cert;
    return cert.load_from_der_file(path);
}

bool test_get_common_name() {
    cpp::utils::RSA rsa;
    std::string pem;
    std::vector<uint8_t> der;
    if (!generate_self_signed_cert(pem, der, rsa)) return false;

    cpp::utils::Certificate cert;
    if (!cert.load_from_pem(pem)) return false;

    std::string cn;
    if (!cert.get_common_name(cn)) return false;
    return cn == "UnitTestCN";
}

bool test_verify_signature_self_signed() {
    cpp::utils::RSA rsa;
    std::string pem;
    std::vector<uint8_t> der;
    if (!generate_self_signed_cert(pem, der, rsa)) return false;

    cpp::utils::Certificate cert;
    if (!cert.load_from_pem(pem)) return false;

    // Self-signed: issuer = subject
    return cert.verify_signature(cert);
}
*/