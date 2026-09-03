#pragma once

#include <string>
#include <vector>
#include <utility>
#include <cstdint>
#include <chrono>

struct CertIdentity {
    std::string subject;
    std::string issuer;
    std::string serial_hex;
    std::string not_before;
    std::string not_after;
    std::string sig_alg;
};

struct PubKeyInfo {
    std::string algorithm;
    int bits = 0;
    std::string spki_sha256; // colon-hex SHA-256 of SubjectPublicKeyInfo (SPKI pin)
};

struct KeyUsageInfo {
    bool present = false;
    bool digital_signature = false;
    bool key_encipherment  = false;
    bool key_cert_sign     = false;
    bool non_repudiation   = false;
    bool key_agreement     = false;
    bool crl_sign          = false;
};

struct BasicConstraintsInfo {
    bool present = false;
    bool is_ca = false;
    int  pathlen = -1; // -1 = unset
};

struct SctInfo {
    std::string log_id_hex;
    uint64_t    timestamp_ms = 0;
};

struct TlsVersionSupport {
    bool probed  = false; // false if detect_protocol_support was off or probing failed to run
    bool tls1_0  = false;
    bool tls1_1  = false;
    bool tls1_2  = false;
    bool tls1_3  = false;
};

struct AiaCrlInfo {
    std::vector<std::string> ocsp_urls;
    std::vector<std::string> ca_issuer_urls;
    std::vector<std::string> crl_urls;
};

struct SslHandshakeResult {
    std::string target_ip;
    std::string hostname;      // SNI hostname used; empty if send_sni was false
    int         port = 0;
    bool        sni_sent = false;
    std::string family;        // "IPv4" | "IPv6"

    bool        success = false;
    std::string error;         // populated when !success (connect/handshake failure reason)

    std::string tls_version;    // version actually negotiated by this handshake
    std::string cipher_name;
    TlsVersionSupport version_support; // full protocol matrix (see TlsVersionSupport)

    CertIdentity leaf;
    PubKeyInfo   pubkey;
    std::vector<std::string> sans;
    bool         hostname_verified = false; // X509_check_host() against SAN/CN, RFC 6125

    std::string sha1_fingerprint;
    std::string sha256_fingerprint;

    KeyUsageInfo          key_usage;
    std::vector<std::string> extended_key_usage;
    BasicConstraintsInfo  basic_constraints;
    std::vector<SctInfo>  scts;
    AiaCrlInfo             aia_crl;

    long        verify_result_code = -1;
    std::string verify_result_string;

    bool   ocsp_stapled = false;
    size_t ocsp_response_size = 0;

    std::vector<CertIdentity> chain; // [0] = leaf, then intermediates as presented by the server
    bool weak_key         = false;  // RSA < 2048 bits, or EC < 224 bits
    bool expired          = false;
    bool not_yet_valid    = false;
    bool self_signed      = false;  // subject == issuer (heuristic, not full chain proof)
    std::vector<std::string> signature_algorithm_warnings; // e.g. "sha1WithRSAEncryption", "md5WithRSAEncryption"
};

struct SslEnumResult {
    std::string target_ip;
    std::string hostname; 

    std::vector<SslHandshakeResult> handshakes;

    bool checked_sni_variance     = false;
    bool sni_vs_no_sni_same_cert  = false;

    bool checked_dual_stack       = false;
    bool ipv4_ipv6_same_cert      = false;
};

struct SslEnumOptions {
    bool enabled = false;

    std::vector<int> ports = {443};

    int timeout_ms   = 4000;  
    int concurrency  = 64;    

    bool check_sni_variance = true;  
    bool fetch_chain        = true; 
    size_t max_chain_certs  = 16;    
    bool detect_protocol_support = true;

    bool verbose = false;
    std::string save_json_file;
};

struct SslTarget {
    std::string ip;
    std::string hostname;
};

std::vector<SslEnumResult> run_ssl_enum_batch(const std::vector<SslTarget>& targets,
                                               const SslEnumOptions& opts);
SslEnumResult run_ssl_enum(const std::string& target_ip, const std::string& hostname_hint,
                            const SslEnumOptions& opts);
void print_ssl_enum_result(const SslEnumResult& result, const SslEnumOptions& opts);
bool save_ssl_enum_result(const std::vector<SslEnumResult>& results, const std::string& path);
