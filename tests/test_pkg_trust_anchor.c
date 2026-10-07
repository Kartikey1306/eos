/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 EoS Project
 *
 * @file test_pkg_trust_anchor.c
 * @brief eos_pkg must have a real trust anchor, or refuse to verify.
 *
 * #99 taught services/crypto to reject low-order public keys, which closed the
 * half of #98 where eos_pkg accepted every package. It left the other half:
 * the anchor itself was still
 *
 *     static const uint8_t eos_pkg_public_key[32] = {0};
 *
 * so eos_pkg went from accepting everything to rejecting everything, and said
 * "signature verification failed" while doing it -- blaming the package for a
 * key that was never provisioned. A verifier that rejects a correctly signed
 * package is not a working signature check either.
 *
 * The packages below are signed with the RFC 8032 section 7.1 TEST 2 key, so
 * they are genuinely signed by a real key and a test that only ever rejects
 * is caught. The v2 envelope (#162) is signed as Ed25519 over
 * eos_pkg_envelope_digest(): SHA-256 over the header with the signature field
 * zeroed, then the binary, then the resources blob.
 *
 * Nothing compiled services/pkg/eos_pkg.c before this change -- it was in no
 * CMakeLists -- which is why none of this was reachable by a test.
 */

#include <stdio.h>
#ifdef _WIN32
#include <eos/eos_windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "eos_pkg.h"
#include <eos/crypto.h>
#include <ed25519.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void name(void); \
    static void run_##name(void) { \
        printf("  %-56s ", #name); \
        fflush(stdout); \
        name(); \
        tests_passed++; \
        printf("[PASS]\n"); \
    } \
    static void name(void)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

/* ---- signing key --------------------------------------------------------- */

/* The v2 envelope is signed at test time with the key derived from this fixed
 * seed. The derived public key was cross-validated against OpenSSL
 * (openssl pkey -inform DER derives the identical pubkey, and OpenSSL
 * verifies the signatures this code produces), so the packages below are
 * genuinely signed by a real key -- a test that only ever rejects is caught.
 * sign_header() asserts the derivation reproduces TEST_PUB, so the test
 * fails loudly if key derivation ever drifts. */
static const uint8_t TEST_SEED[32] = {
 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x00,0x01,0x02,0x03,0x04,0x05,
 0x06,0x07,0x08,0x09,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x00,0x01};
static const uint8_t TEST_PUB[32] = {
 0xc9,0x9a,0xff,0x66,0x7c,0x75,0x78,0x05,0x6b,0xd7,0xd4,0x59,0x0d,0xf9,0x2b,0xf2,
 0xae,0x10,0x8a,0x6a,0x7f,0x33,0xdd,0x52,0x38,0x4a,0x83,0xbf,0x32,0x5f,0x02,0x69};

/* ---- RFC 8032 section 7.1 (verify vectors) -------------------------------- */

/* TEST 2: a 1-byte message, so the package payload is the signed message.
 * T2_SIG is a valid v1 .eapp signature over T2_MSG, which is what makes it
 * the right fixture for test_a_version_1_package_is_refused. */
static const uint8_t T2_PUB[32] = {
 0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
 0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c};

/* TEST 2 signature over the 1-byte message 0x72. This is exactly a valid v1
 * .eapp signature for the payload below, which is what makes it the right
 * fixture for test_a_version_1_package_is_refused: a v1 package must be
 * refused at the version gate even when its v1 signature is genuine. */
static const uint8_t T2_SIG[64] = {
 0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
 0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
 0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
 0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00};
static const uint8_t T2_MSG[1] = { 0x72 };

/* The eight low-order encodings. None can authenticate anything, so none is a
 * usable anchor. The first is the value this file used to ship. */
static const uint8_t LOW_ORDER[8][32] = {
    /* y = 0, order 4 -- the encoding eos_pkg carried as its trust anchor */
    {0},
    /* the identity, order 1 */
    {1},
    /* order 8 */
    {0x26,0xe8,0x95,0x8f,0xc2,0xb2,0x27,0xb0,0x45,0xc3,0xf4,0x89,0xf2,0xef,0x98,0xf0,
     0xd5,0xdf,0xac,0x05,0xd3,0xc6,0x33,0x39,0xb1,0x38,0x02,0x88,0x6d,0x53,0xfc,0x05},
    /* order 8 */
    {0xc7,0x17,0x6a,0x70,0x3d,0x4d,0xd8,0x4f,0xba,0x3c,0x0b,0x76,0x0d,0x10,0x67,0x0f,
     0x2a,0x20,0x53,0xfa,0x2c,0x39,0xcc,0xc6,0x4e,0xc7,0xfd,0x77,0x92,0xac,0x03,0x7a},
    /* p - 1 */
    {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* p, which reduces to y = 0 */
    {0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* p + 1, which reduces to the identity */
    {0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* non-canonical, above p */
    {0xd9,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
};

/* ---- package construction ------------------------------------------------ */

#define EAPP_PATH "test_trust_anchor.eapp"

/* Fill a v2 header for the given payload. The signature field is left zeroed:
 * the envelope digest covers the header with the signature zeroed, so the
 * header is signed first and the signature embedded after. The header hash is
 * computed over the payload actually written, so the SHA-256 check always
 * passes and every failure below is the signature check, never integrity. */
static void make_header(eapp_header_t *h,
                        const uint8_t *payload, uint32_t payload_len,
                        const uint8_t *res, uint32_t res_len)
{
    EosSha256 c;

    memset(h, 0, sizeof(*h));
    h->magic = EAPP_MAGIC;
    h->version = EAPP_VERSION;
    snprintf(h->name, sizeof(h->name), "%s", "trust-anchor-test");
    snprintf(h->package_id, sizeof(h->package_id), "%s", "org.eos.test.anchor");
    h->ver_major = 1;
    h->arch_count = 1;
    h->binary_offset = (uint32_t)sizeof(*h);
    h->binary_size = payload_len;
    if (res && res_len > 0) {
        h->resources_offset = h->binary_offset + payload_len;
        h->resources_size = res_len;
    }

    eos_sha256_init(&c);
    eos_sha256_update(&c, payload, payload_len);
    eos_sha256_final(&c, h->hash);
}

/* Sign the v2 envelope of (h, payload, res) with the key derived from seed
 * and embed the signature in the header. */
static void sign_header(eapp_header_t *h,
                        const uint8_t *payload, uint32_t payload_len,
                        const uint8_t *res, uint32_t res_len,
                        const uint8_t seed[32])
{
    uint8_t digest[EAPP_HASH_LEN];
    uint8_t pub[EAPP_PUBKEY_LEN], priv[64];
    uint8_t sig[EAPP_SIGNATURE_LEN];

    ed25519_create_keypair(pub, priv, seed);
    /* The seed must derive TEST_PUB (cross-validated against OpenSSL), so
     * the package is genuinely signed by a real key. If key derivation ever
     * drifts, this fails loudly instead of silently testing nothing. */
    ASSERT(memcmp(pub, TEST_PUB, EAPP_PUBKEY_LEN) == 0);

    eos_pkg_envelope_digest(h, payload, payload_len, res, res_len, digest);
    ed25519_sign(sig, digest, sizeof(digest), pub, priv);
    memset(priv, 0, sizeof(priv));
    memcpy(h->signature, sig, sizeof(sig));
}

static void write_package(const char *path, const eapp_header_t *h,
                          const uint8_t *payload, uint32_t payload_len,
                          const uint8_t *res, uint32_t res_len)
{
    FILE *f;

    /* POSIX creates these fixtures with 0600 so other users cannot rewrite a
     * signed package between creation and verification. Windows has no
     * equivalent portable CRT mode, so its branch uses the build directory's
     * inherited ACL; this test validates package verification, not filesystem
     * permission isolation. */
#ifdef _WIN32
    f = fopen(path, "wb");
#else
    {
        int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
        ASSERT(fd >= 0);
        f = fdopen(fd, "wb");
        if (!f) close(fd);
    }
#endif
    ASSERT(f != NULL);
    ASSERT(fwrite(h, sizeof(*h), 1, f) == 1);
    ASSERT(fwrite(payload, 1, payload_len, f) == payload_len);
    if (res && res_len > 0)
        ASSERT(fwrite(res, 1, res_len, f) == res_len);
    fclose(f);
}

static void write_genuine_eapp(void)
{
    eapp_header_t h;

    make_header(&h, T2_MSG, (uint32_t)sizeof(T2_MSG), NULL, 0);
    sign_header(&h, T2_MSG, (uint32_t)sizeof(T2_MSG), NULL, 0, TEST_SEED);
    write_package(EAPP_PATH, &h, T2_MSG, (uint32_t)sizeof(T2_MSG), NULL, 0);
}

/* ---- tests --------------------------------------------------------------- */

TEST(test_no_anchor_refuses_a_genuine_package)
{
    /* The state this file shipped in, stated as a test: a package signed by a
     * real key, refused. Before the fix this printed "signature verification
     * failed" and the caller had no way to tell that the anchor, not the
     * package, was the problem. */
    ASSERT(eos_pkg_set_trust_anchor(NULL) == 0);
    ASSERT(eos_pkg_trust_anchor() == NULL);

    write_genuine_eapp();
    ASSERT(eos_pkg_verify(EAPP_PATH) != 0);
}

TEST(test_low_order_keys_are_refused_as_anchors)
{
    /* Refused when configured, not when a package arrives. All eight, because
     * the all-zero encoding this file used is only one of them and a fix aimed
     * at that single value would leave the class open. */
    size_t i;
    for (i = 0; i < 8; i++) {
        ASSERT(eos_pkg_set_trust_anchor(LOW_ORDER[i]) != 0);
        ASSERT(eos_pkg_trust_anchor() == NULL);
    }
}

TEST(test_a_real_key_is_accepted_as_an_anchor)
{
    const uint8_t *held;

    ASSERT(eos_pkg_set_trust_anchor(NULL) == 0);
    ASSERT(eos_pkg_set_trust_anchor(TEST_PUB) == 0);

    held = eos_pkg_trust_anchor();
    ASSERT(held != NULL);
    ASSERT(memcmp(held, TEST_PUB, EAPP_PUBKEY_LEN) == 0);
}

TEST(test_a_genuine_package_verifies_under_its_own_key)
{
    /* Without this the tests above are satisfied by a verifier that rejects
     * everything, which is the bug in its other form. */
    ASSERT(eos_pkg_set_trust_anchor(TEST_PUB) == 0);
    write_genuine_eapp();
    ASSERT(eos_pkg_verify(EAPP_PATH) == 0);
}

TEST(test_another_real_key_does_not_verify_the_package)
{
    ASSERT(eos_pkg_set_trust_anchor(T2_PUB) == 0);
    write_genuine_eapp();
    ASSERT(eos_pkg_verify(EAPP_PATH) != 0);
}

TEST(test_a_tampered_payload_is_rejected_by_the_signature)
{
    /* The header hash is recomputed over the tampered payload, so the SHA-256
     * comparison passes and only the signature can reject this. That is the
     * point: the hash travels with the package, so an attacker who replaces
     * the payload replaces the hash too. The genuine v2 signature covers the
     * envelope digest, so the payload flip breaks it. */
    static const uint8_t tampered[1] = { 0x73 };
    eapp_header_t h;
    uint8_t genuine_sig[EAPP_SIGNATURE_LEN];

    ASSERT(eos_pkg_set_trust_anchor(T2_PUB) == 0);

    /* Genuine signature over the genuine envelope. */
    make_header(&h, T2_MSG, (uint32_t)sizeof(T2_MSG), NULL, 0);
    sign_header(&h, T2_MSG, (uint32_t)sizeof(T2_MSG), NULL, 0, TEST_SEED);
    memcpy(genuine_sig, h.signature, sizeof(genuine_sig));

    /* Same signature, tampered payload, hash recomputed: only the signature
     * stands between this package and installation. */
    make_header(&h, tampered, (uint32_t)sizeof(tampered), NULL, 0);
    memcpy(h.signature, genuine_sig, sizeof(genuine_sig));
    write_package(EAPP_PATH, &h, tampered, (uint32_t)sizeof(tampered), NULL, 0);

    ASSERT(eos_pkg_verify(EAPP_PATH) != 0);
}

TEST(test_a_tampered_capability_is_rejected_by_the_signature)
{
    /* The v2 fix proper: in v1 the capabilities bitfield was unsigned, so a
     * granted capability (here: network) could be flipped on a genuinely
     * signed package. The envelope digest covers the header, so verification
     * must fail. */
    eapp_header_t h;

    ASSERT(eos_pkg_set_trust_anchor(T2_PUB) == 0);
    make_header(&h, T2_MSG, (uint32_t)sizeof(T2_MSG), NULL, 0);
    sign_header(&h, T2_MSG, (uint32_t)sizeof(T2_MSG), NULL, 0, TEST_SEED);
    h.capabilities |= EAPP_CAP_NETWORK;  /* attacker grants network */
    write_package(EAPP_PATH, &h, T2_MSG, (uint32_t)sizeof(T2_MSG), NULL, 0);

    ASSERT(eos_pkg_verify(EAPP_PATH) != 0);
}

TEST(test_tampered_resources_are_rejected_by_the_signature)
{
    /* The resources blob was neither hashed nor signed in v1. In v2 the
     * envelope digest covers it, so swapping the blob under a genuine
     * signature must fail verification. */
    static const uint8_t res[4] = { 'd', 'a', 't', 'a' };
    static const uint8_t res_bad[4] = { 'd', 'a', 't', 'X' };
    eapp_header_t h;

    ASSERT(eos_pkg_set_trust_anchor(TEST_PUB) == 0);
    make_header(&h, T2_MSG, (uint32_t)sizeof(T2_MSG), res, (uint32_t)sizeof(res));
    sign_header(&h, T2_MSG, (uint32_t)sizeof(T2_MSG),
                res, (uint32_t)sizeof(res), TEST_SEED);
    write_package(EAPP_PATH, &h, T2_MSG, (uint32_t)sizeof(T2_MSG),
                  res_bad, (uint32_t)sizeof(res_bad));

    ASSERT(eos_pkg_verify(EAPP_PATH) != 0);
}

TEST(test_a_genuine_package_with_resources_verifies)
{
    /* The positive companion to the resources-tamper test: an honestly built
     * package carrying a resources blob verifies. */
    static const uint8_t res[4] = { 'd', 'a', 't', 'a' };
    eapp_header_t h;

    ASSERT(eos_pkg_set_trust_anchor(TEST_PUB) == 0);
    make_header(&h, T2_MSG, (uint32_t)sizeof(T2_MSG), res, (uint32_t)sizeof(res));
    sign_header(&h, T2_MSG, (uint32_t)sizeof(T2_MSG),
                res, (uint32_t)sizeof(res), TEST_SEED);
    write_package(EAPP_PATH, &h, T2_MSG, (uint32_t)sizeof(T2_MSG),
                  res, (uint32_t)sizeof(res));

    ASSERT(eos_pkg_verify(EAPP_PATH) == 0);
}

TEST(test_a_version_1_package_is_refused)
{
    /* The old format signed the binary alone. A v1 package must be refused at
     * the version gate even when its v1 signature is genuine -- T2_SIG is a
     * valid v1 signature over this exact 1-byte payload, so this package
     * would have verified under the old rules. */
    eapp_header_t h;

    ASSERT(eos_pkg_set_trust_anchor(T2_PUB) == 0);
    make_header(&h, T2_MSG, (uint32_t)sizeof(T2_MSG), NULL, 0);
    h.version = 1;
    memcpy(h.signature, T2_SIG, EAPP_SIGNATURE_LEN);
    write_package(EAPP_PATH, &h, T2_MSG, (uint32_t)sizeof(T2_MSG), NULL, 0);

    ASSERT(eos_pkg_verify(EAPP_PATH) != 0);
}

TEST(test_removing_the_anchor_restores_refusal)
{
    ASSERT(eos_pkg_set_trust_anchor(TEST_PUB) == 0);
    write_genuine_eapp();
    ASSERT(eos_pkg_verify(EAPP_PATH) == 0);

    ASSERT(eos_pkg_set_trust_anchor(NULL) == 0);
    ASSERT(eos_pkg_trust_anchor() == NULL);
    ASSERT(eos_pkg_verify(EAPP_PATH) != 0);
}

TEST(test_a_rejected_anchor_does_not_replace_the_one_in_force)
{
    /* A failed provisioning attempt must not disarm a working installation. */
    ASSERT(eos_pkg_set_trust_anchor(TEST_PUB) == 0);
    ASSERT(eos_pkg_set_trust_anchor(LOW_ORDER[0]) != 0);

    ASSERT(eos_pkg_trust_anchor() != NULL);
    ASSERT(memcmp(eos_pkg_trust_anchor(), TEST_PUB, EAPP_PUBKEY_LEN) == 0);

    write_genuine_eapp();
    ASSERT(eos_pkg_verify(EAPP_PATH) == 0);
}

int main(void)
{
    printf("eos_pkg trust anchor\n");

    run_test_no_anchor_refuses_a_genuine_package();
    run_test_low_order_keys_are_refused_as_anchors();
    run_test_a_real_key_is_accepted_as_an_anchor();
    run_test_a_genuine_package_verifies_under_its_own_key();
    run_test_another_real_key_does_not_verify_the_package();
    run_test_a_tampered_payload_is_rejected_by_the_signature();
    run_test_a_tampered_capability_is_rejected_by_the_signature();
    run_test_tampered_resources_are_rejected_by_the_signature();
    run_test_a_genuine_package_with_resources_verifies();
    run_test_a_version_1_package_is_refused();
    run_test_removing_the_anchor_restores_refusal();
    run_test_a_rejected_anchor_does_not_replace_the_one_in_force();

    remove(EAPP_PATH);

    tests_run = 12;
    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
