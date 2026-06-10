#include "mbedtls/build_info.h"

#include "mbedtls/ecjpake.h"
#include "mbedtls/ecp.h"
#include "mbedtls/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return (unsigned char) (c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return (unsigned char) (10 + c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return (unsigned char) (10 + c - 'A');
    }
    fprintf(stderr, "invalid hex character: %c\n", c);
    exit(2);
}

static unsigned char *decode_hex(const char *hex, size_t *out_len)
{
    size_t len = strlen(hex);
    unsigned char *out;

    if (len % 2 != 0) {
        fprintf(stderr, "hex input has odd length\n");
        exit(2);
    }

    *out_len = len / 2;
    out = calloc(*out_len == 0 ? 1 : *out_len, 1);
    if (out == NULL) {
        fprintf(stderr, "calloc failed\n");
        exit(2);
    }

    for (size_t i = 0; i < *out_len; i++) {
        out[i] = (hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]);
    }

    return out;
}

static int skip_tls_point(const unsigned char **p, const unsigned char *end)
{
    size_t len;

    if (*p >= end) {
        return -1;
    }
    len = *(*p)++;
    if ((size_t) (end - *p) < len) {
        return -1;
    }
    *p += len;
    return 0;
}

static int skip_schnorr_proof(const unsigned char **p, const unsigned char *end)
{
    size_t len;

    if (skip_tls_point(p, end) != 0 || *p >= end) {
        return -1;
    }
    len = *(*p)++;
    if (len == 0 || (size_t) (end - *p) < len) {
        return -1;
    }
    *p += len;
    return 0;
}

static int parse_round_one_public_points(mbedtls_ecjpake_context *ctx,
                                         const unsigned char *buf,
                                         size_t len)
{
    const unsigned char *p = buf;
    const unsigned char *end = buf + len;
    int ret;

    ret = mbedtls_ecp_tls_read_point(&ctx->MBEDTLS_PRIVATE(grp),
                                     &ctx->MBEDTLS_PRIVATE(Xm1),
                                     &p,
                                     end - p);
    if (ret != 0) {
        return ret;
    }
    if (skip_schnorr_proof(&p, end) != 0) {
        return -1;
    }

    ret = mbedtls_ecp_tls_read_point(&ctx->MBEDTLS_PRIVATE(grp),
                                     &ctx->MBEDTLS_PRIVATE(Xm2),
                                     &p,
                                     end - p);
    if (ret != 0) {
        return ret;
    }
    if (skip_schnorr_proof(&p, end) != 0 || p != end) {
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    unsigned char dummy_secret[16] = { 0 };
    unsigned char *client_one = NULL;
    unsigned char *server_one = NULL;
    unsigned char *client_two = NULL;
    size_t client_one_len = 0;
    size_t server_one_len = 0;
    size_t client_two_len = 0;
    int ret = 0;
    mbedtls_ecjpake_context server;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <client-round-one-hex> <server-round-one-hex> <client-round-two-hex>\n", argv[0]);
        return 2;
    }

    client_one = decode_hex(argv[1], &client_one_len);
    server_one = decode_hex(argv[2], &server_one_len);
    client_two = decode_hex(argv[3], &client_two_len);

    mbedtls_ecjpake_init(&server);
    ret = mbedtls_ecjpake_setup(&server,
                                MBEDTLS_ECJPAKE_SERVER,
                                MBEDTLS_MD_SHA256,
                                MBEDTLS_ECP_DP_SECP256R1,
                                dummy_secret,
                                sizeof(dummy_secret));
    if (ret != 0) {
        goto exit;
    }

    ret = mbedtls_ecjpake_read_round_one(&server, client_one, client_one_len);
    if (ret != 0) {
        fprintf(stderr, "client round one rejected\n");
        goto exit;
    }

    ret = parse_round_one_public_points(&server, server_one, server_one_len);
    if (ret != 0) {
        fprintf(stderr, "server round one public parse failed\n");
        goto exit;
    }

    ret = mbedtls_ecjpake_read_round_two(&server, client_two, client_two_len);
    if (ret != 0) {
        fprintf(stderr, "client round two rejected\n");
        goto exit;
    }

    printf("client round two accepted\n");

exit:
    if (ret != 0) {
        char error[160];
        mbedtls_strerror(ret, error, sizeof(error));
        fprintf(stderr, "mbedtls error: -0x%x: %s\n", (unsigned int) -ret, error);
    }
    mbedtls_ecjpake_free(&server);
    free(client_one);
    free(server_one);
    free(client_two);
    return ret == 0 ? 0 : 1;
}
