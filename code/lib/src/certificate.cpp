
#include "certificate.h"

//#include <time.h>
#include <ctime>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "file.h"       // libcpputils

namespace cpp { namespace utils {

Certificate::Certificate() : cert_(nullptr) {}

Certificate::~Certificate() {
    if (cert_) X509_free(cert_);
}

Certificate::Certificate(X509 * cert)
{
    
}

Certificate::Certificate(const Certificate& other) {
    cert_ = other.cert_ ? X509_dup(other.cert_) : nullptr;
}

Certificate& Certificate::operator=(const Certificate& other) {
    if (this != &other) {
        if (cert_) X509_free(cert_);
        cert_ = other.cert_ ? X509_dup(other.cert_) : nullptr;
    }
    return *this;
}

Certificate::Certificate(Certificate&& other) noexcept {
    cert_ = other.cert_;
    other.cert_ = nullptr;
}

/*
Certificate& Certificate::operator=(Certificate&& other) noexcept {
    if (this != &other) {
        if (cert_) X509_free(cert_);
        cert_ = other.cert_;
        other.cert_ = nullptr;
    }
    return *this;
}
*/


bool Certificate::load_from_pem(const std::string& pem)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    if (!bio) return false;

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) return false;

    if (cert_) X509_free(cert_);
    cert_ = cert;

    return true;
}

bool Certificate::as_pem(std::string& output) const
{
    output.clear();
    if (!cert_) return false;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;

    if (PEM_write_bio_X509(bio, cert_) != 1)
    {
        BIO_free(bio);
        return false;
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);

    if (mem && mem->data && mem->length > 0)
    {
        output.assign(mem->data, mem->length);
    }

    BIO_free(bio);
    return !output.empty();
}

bool Certificate::load_from_pem(const std::string& pem, PasswordCallback cb)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    if (!bio) return false;

    PasswordCallbackWrapper wrapper {cb};
    X509* cert = PEM_read_bio_X509(bio, nullptr, openssl_password_cb, &wrapper);
    BIO_free(bio);

    if (!cert) return false;
    if (cert_) X509_free(cert_);
    cert_ = cert;
    return true;
}

bool Certificate::load_pem_file(const std::string& path)
{
    auto full_path = cpp::utils::full_resolve_path(path);
    if(!cpp::utils::file_exists(full_path))
        return false;

    FILE* f = fopen(full_path.c_str(), "rb");
    if (!f) return false;

    X509* c = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);

    if (!c) return false;
    if (cert_) X509_free(cert_);
    cert_ = c;
    return true;
}

bool Certificate::load_pem_file(const std::string& path, PasswordCallback cb)
{
    auto full_path = cpp::utils::full_resolve_path(path);
    if(!cpp::utils::file_exists(full_path))
        return false;
    FILE* f = fopen(full_path.c_str(), "rb");
    if (!f) return false;

    PasswordCallbackWrapper wrapper{cb};
    X509* c = PEM_read_X509(f, nullptr, openssl_password_cb, &wrapper);
    fclose(f);

    if (!c) return false;
    if (cert_) X509_free(cert_);
    cert_ = c;
    return true;
}

bool Certificate::save_pem_file(const std::string& path) const {
    if (!cert_) return false;
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    bool ok = PEM_write_X509(f, cert_);
    fclose(f);
    return ok;
}

bool Certificate::load_der_file(const std::string& path)
{
    auto full_path = cpp::utils::full_resolve_path(path);
    if(!cpp::utils::file_exists(full_path))
        return false;
    FILE* f = fopen(full_path.c_str(), "rb");
    if (!f) return false;

    X509* cert = d2i_X509_fp(f, nullptr);
    fclose(f);

    if (!cert) return false;
    if (cert_) X509_free(cert_);
    cert_ = cert;

    return true;
}

bool Certificate::save_der_file(const std::string& path) const
{
    if (!cert_) return false;

    auto full_path = cpp::utils::full_resolve_path(path);
    FILE* f = fopen(full_path.c_str(), "wb");
    if (!f) return false;

    int ret = i2d_X509_fp(f, cert_);
    fclose(f);

    return ret == 1;
}

std::string Certificate::subject() const {
    if (!cert_) return {};
    char buf[512];
    X509_NAME_oneline(X509_get_subject_name(cert_), buf, sizeof(buf));
    return buf;
}

std::string Certificate::subject_dn() const
{
    if (!cert_) return "";

    X509_NAME* name = X509_get_subject_name(cert_);
    if (!name) return "";

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    // RFC2253 is also an option, but this is the common OpenSSL style
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);

    std::string result;
    if (mem && mem->data && mem->length > 0)
        result.assign(mem->data, mem->length);

    BIO_free(bio);
    return result;
}

std::string Certificate::issuer() const {
    if (!cert_) return {};
    char buf[512];
    X509_NAME_oneline(X509_get_issuer_name(cert_), buf, sizeof(buf));
    return buf;
}

std::string Certificate::serial() const
{
    if (!cert_) return "";

    ASN1_INTEGER* asn1 = X509_get_serialNumber(cert_);
    if (!asn1) return "";

    BIGNUM* bn = ASN1_INTEGER_to_BN(asn1, nullptr);
    if (!bn) return "";

    char* hex = BN_bn2hex(bn);
    std::string result = hex ? hex : "";

    OPENSSL_free(hex);
    BN_free(bn);

    return result;
}

std::string Certificate::common_name() const
{
    std::string cn;
    get_common_name(cn);
    return cn;
}

bool Certificate::is_ca() const
{
    if (!cert_) return false;

    BASIC_CONSTRAINTS* bc = (BASIC_CONSTRAINTS*)X509_get_ext_d2i(
        cert_, NID_basic_constraints, nullptr, nullptr);

    if (!bc) return false;

    bool result = bc->ca;
    BASIC_CONSTRAINTS_free(bc);

    return result;
}

bool Certificate::is_self_signed() const
{
    if (!cert_) return false;

    // Compare subject and issuer
    if (X509_NAME_cmp(X509_get_subject_name(cert_),
                      X509_get_issuer_name(cert_)) != 0)
        return false;

    // Verify signature with its own public key
    EVP_PKEY* pubkey = X509_get_pubkey(cert_);
    if (!pubkey) return false;

    int ret = X509_verify(cert_, pubkey);
    EVP_PKEY_free(pubkey);

    return ret == 1;
}

bool Certificate::get_common_name(std::string& cn) const
{
    cn.clear();
    if (!cert_) return false;

    X509_NAME* subj = X509_get_subject_name(cert_);
    if (!subj) return false;

    int idx = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
    if (idx < 0) return false;

    X509_NAME_ENTRY* entry = X509_NAME_get_entry(subj, idx);
    if (!entry) return false;

    ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    if (!data) return false;

    unsigned char* utf8 = nullptr;
    int len = ASN1_STRING_to_UTF8(&utf8, data);
    if (len < 0) return false;

    cn.assign(reinterpret_cast<char*>(utf8), len);
    OPENSSL_free(utf8);

    return true;
}

bool Certificate::verify(const Certificate& issuer) const
{
    if (!cert_ || !issuer.cert_) return false;

    EVP_PKEY* pubkey = X509_get_pubkey(issuer.cert_);
    if (!pubkey) return false;

    int ret = X509_verify(cert_, pubkey);
    EVP_PKEY_free(pubkey);

    return ret == 1;
}

time_t Certificate::not_before() const {
    if (!cert_) return 0;
    return ASN1_TIME_get(X509_get0_notBefore(cert_));
}

time_t Certificate::not_after() const {
    if (!cert_) return 0;
    return ASN1_TIME_get(X509_get0_notAfter(cert_));
}

bool Certificate::is_valid_now() const {
    time_t now = std::time(nullptr);
    return now >= not_before() && now <= not_after();
}

bool Certificate::fingerprint_sha256(std::vector<uint8_t>& out) const {
    if (!cert_) return false;
    unsigned int len = 0;
    out.resize(EVP_MAX_MD_SIZE);
    if (!X509_digest(cert_, EVP_sha256(), out.data(), &len))
        return false;
    out.resize(len);
    return true;
}

EVP_PKEY* Certificate::extract_public_key() const {
    if (!cert_) return nullptr;
    return X509_get_pubkey(cert_); // caller owns
}


bool Certificate::get_subject_alternative_names(std::vector<std::string>& out) const
{
    out.clear();
    if (!cert_) return false;

    GENERAL_NAMES* san_names = (GENERAL_NAMES*)X509_get_ext_d2i(
        cert_, NID_subject_alt_name, nullptr, nullptr);

    if (!san_names) return false;

    int count = sk_GENERAL_NAME_num(san_names);
    for (int i = 0; i < count; ++i)
    {
        const GENERAL_NAME* name = sk_GENERAL_NAME_value(san_names, i);

        if (name->type == GEN_DNS)
        {
            const ASN1_STRING* asn1 = name->d.dNSName;
            unsigned char* utf8 = nullptr;

            int len = ASN1_STRING_to_UTF8(&utf8, asn1);
            if (len >= 0 && utf8)
            {
                out.emplace_back(reinterpret_cast<char*>(utf8), len);
                OPENSSL_free(utf8);
            }
        }
        else if (name->type == GEN_URI)
        {
            const ASN1_STRING* asn1 = name->d.uniformResourceIdentifier;
            unsigned char* utf8 = nullptr;

            int len = ASN1_STRING_to_UTF8(&utf8, asn1);
            if (len >= 0 && utf8)
            {
                out.emplace_back(reinterpret_cast<char*>(utf8), len);
                OPENSSL_free(utf8);
            }
        }
        // You can add GEN_IPADD etc. if needed
    }

    GENERAL_NAMES_free(san_names);
    return !out.empty();
}

bool Certificate::verify_hostname(const std::string& hostname) const
{
    if (!cert_) return false;

    std::vector<std::string> sans;
    get_subject_alternative_names(sans);

    // 1. Prefer SANs
    for (const auto& san : sans)
    {
        if (match_hostname_pattern(san, hostname))
            return true;
    }

    // 2. Fallback to CN only if no SAN
    if (sans.empty())
    {
        std::string cn;
        if (get_common_name(cn))
        {
            if (match_hostname_pattern(cn, hostname))
                return true;
        }
    }

    return false;
}

std::string Certificate::get_ocsp_url() const
{
    if (!cert_) return "";

    AUTHORITY_INFO_ACCESS* aia = (AUTHORITY_INFO_ACCESS*)
        X509_get_ext_d2i(cert_, NID_info_access, nullptr, nullptr);

    if (!aia) return "";
    std::string url;
    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++)
    {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (OBJ_obj2nid(ad->method) == NID_ad_OCSP)
        {
            if (ad->location->type == GEN_URI)
            {
                ASN1_IA5STRING* uri = ad->location->d.uniformResourceIdentifier;
                url.assign((char*)uri->data, uri->length);
                break;
            }
        }
    }

    AUTHORITY_INFO_ACCESS_free(aia);
    return url;
}


//////////////////////////////


time_t Certificate::ASN1_TIME_get(const ASN1_TIME* time)
{
    struct tm t;
    const char* str = (const char*) time->data;
    size_t i = 0;

    memset(&t, 0, sizeof(t));

    if (time->type == V_ASN1_UTCTIME) {/* two digit year */
        t.tm_year = (str[i++] - '0') * 10;
        t.tm_year += (str[i++] - '0');
        if (t.tm_year < 70)
            t.tm_year += 100;
    } else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
        t.tm_year = (str[i++] - '0') * 1000;
        t.tm_year+= (str[i++] - '0') * 100;
        t.tm_year+= (str[i++] - '0') * 10;
        t.tm_year+= (str[i++] - '0');
        t.tm_year -= 1900;
    }
    t.tm_mon  = (str[i++] - '0') * 10;
    t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
    t.tm_mday = (str[i++] - '0') * 10;
    t.tm_mday+= (str[i++] - '0');
    t.tm_hour = (str[i++] - '0') * 10;
    t.tm_hour+= (str[i++] - '0');
    t.tm_min  = (str[i++] - '0') * 10;
    t.tm_min += (str[i++] - '0');
    t.tm_sec  = (str[i++] - '0') * 10;
    t.tm_sec += (str[i++] - '0');

    /* Note: we did not adjust the time based on time zone information */
    return mktime(&t);
}



} }