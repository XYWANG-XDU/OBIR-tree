/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <cstdarg>
#include <cstdio>      /* vsnprintf */
#include <cstring>
#include <chrono>
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <set>
#include <string>
#include <sstream>
#include <iostream>
#include "sgx_urts.h"
#include <chrono>
#include <vector>
#include "Pdefault.h"
#include <algorithm>
#include <sgx_tcrypto.h>
#include <list>
#include "../App/Node.h"
#include "../App/Branch.h"
#include "sgx_tcrypto.h"
#define FAIL_SHA	0x1
#define FAIL_AES	0x2
#define FAIL_ECDSA	0x4
#include <cstring>    // 为了使用strcpy等字符串操作函数
#define mbedtls_printf       printf
#include "sgx_tkey_exchange.h"
#include "sgx_tprotected_fs.h"
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 *   'printf' function is required for sgx protobuf logging module.
 */
int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return 0;
}

static int mbedtls_crypto_sha256()
{
    unsigned char output[65];
    memset(output, 0x00, 65);
    if (mbedtls_sha256( (const unsigned char*)"", 0, output, 0 ) != 0 )
    {
        mbedtls_printf ("SHA256 failed\n");
	return -1;
    } else {
        for (int i = 0; i < 32; i++)
            mbedtls_printf("%02x", output[i]);
    }
    mbedtls_printf("\nSHA256 PASSED\n");
    return 0;
}

static int mbedtls_crypto_aes_ctr_enc_dec_buf()
{
    int ret = -1;
    size_t length = 49, outlen, total_len, i, block_size, iv_len;
    unsigned char key[64];
    unsigned char iv[16];
    unsigned char ad[13];
    unsigned char tag[16];
    unsigned char inbuf[64];
    unsigned char encbuf[64];
    unsigned char decbuf[64];

    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_context_t ctx_dec;
    mbedtls_cipher_context_t ctx_enc;

    /*
     * Prepare contexts
     */
    mbedtls_cipher_init( &ctx_dec );
    mbedtls_cipher_init( &ctx_enc );

    memset( key, 0x2a, sizeof( key ) );

    /* Check and get info structures */
    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR);
    if( NULL == cipher_info ) goto exit;
    if( mbedtls_cipher_info_from_string( "AES-128-CTR" ) != cipher_info ) goto exit;
    if( strcmp( mbedtls_cipher_info_get_name( cipher_info ),
                         "AES-128-CTR" ) != 0 ) goto exit;

    /* Initialise enc and dec contexts */
    if( 0 != mbedtls_cipher_setup( &ctx_dec, cipher_info ) ) goto exit;
    if( 0 != mbedtls_cipher_setup( &ctx_enc, cipher_info ) ) goto exit;

    if( 0 != mbedtls_cipher_setkey( &ctx_dec, key, 128, MBEDTLS_DECRYPT ) ) goto exit;
    if( 0 != mbedtls_cipher_setkey( &ctx_enc, key, 128, MBEDTLS_ENCRYPT ) ) goto exit;

    /*
     * Do a few encode/decode cycles
     */
    for( i = 0; i < 3; i++ )
    {
    memset( iv , 0x00 + (int)i, sizeof( iv ) );
    memset( ad, 0x10 + (int)i, sizeof( ad ) );
    memset( inbuf, 0x20 + (int)i, sizeof( inbuf ) );

    memset( encbuf, 0, sizeof( encbuf ) );
    memset( decbuf, 0, sizeof( decbuf ) );
    memset( tag, 0, sizeof( tag ) );

    iv_len = sizeof(iv);

    if( 0 != mbedtls_cipher_set_iv( &ctx_dec, iv, iv_len ) ) goto exit;
    if( 0 != mbedtls_cipher_set_iv( &ctx_enc, iv, iv_len ) ) goto exit;

    if( 0 != mbedtls_cipher_reset( &ctx_dec ) ) goto exit;
    if( 0 != mbedtls_cipher_reset( &ctx_enc ) ) goto exit;

    block_size = mbedtls_cipher_get_block_size( &ctx_enc );
    if( 0 == block_size ) goto exit;

    /* encode length number of bytes from inbuf */
    if( 0 != mbedtls_cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) ) goto exit;
    total_len = outlen;

    if( total_len != length ||
                 ( total_len % block_size == 0 &&
                   total_len < length &&
                   total_len + block_size > length ) ) goto exit;

    if( 0 != mbedtls_cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) ) goto exit;
    total_len += outlen;

    if( total_len != length ||
                 ( total_len % block_size == 0 &&
                   total_len > length &&
                   total_len <= length + block_size ) ) goto exit;

    /* decode the previously encoded string */
    if( 0 != mbedtls_cipher_update( &ctx_dec, encbuf, total_len, decbuf, &outlen ) ) goto exit;
    total_len = outlen;

    if( total_len != length ||
                 ( total_len % block_size == 0 &&
                   total_len < length &&
                   total_len + block_size >= length ) ) goto exit;

    if( 0 != mbedtls_cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) ) goto exit;
    total_len += outlen;

    /* check result */
    if( total_len != length ) goto exit;
    if( 0 != memcmp(inbuf, decbuf, length) ) goto exit;
    }
    mbedtls_printf("AES-CTR PASSED\n");
    ret = 0;
exit:
    mbedtls_cipher_free( &ctx_dec );
    mbedtls_cipher_free( &ctx_enc );
    return ret;
}

#define ECPARAMS    MBEDTLS_ECP_DP_SECP192R1

static int mbedtls_crypto_ecdsa()
{
    int ret = 1;
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char message[100];
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len;
    const char *pers = "ecdsa";

    mbedtls_ecdsa_init( &ctx_sign );
    mbedtls_ecdsa_init( &ctx_verify );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    memset( sig, 0, sizeof( sig ) );
    memset( message, 0x25, sizeof( message ) );

    /*
     * Generate a key pair for signing
     */
    mbedtls_printf( "  . Seeding the random number generator..." );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n  . Generating key pair..." );

    if( ( ret = mbedtls_ecdsa_genkey( &ctx_sign, ECPARAMS,
                              mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok (key size: %d bits)\n", (int) ctx_sign.MBEDTLS_PRIVATE(grp).pbits );

    /*
     * Compute message hash
     */
    mbedtls_printf( "  . Computing message hash..." );

    if( ( ret = mbedtls_sha256( message, sizeof( message ), hash, 0 ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_sha256 returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * Sign message hash
     */
    mbedtls_printf( "  . Signing message hash..." );

    if( ( ret = mbedtls_ecdsa_write_signature( &ctx_sign, MBEDTLS_MD_SHA256,
                                       hash, sizeof( hash ),
                                       sig, sizeof( sig ), &sig_len,
                                       mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_write_signature returned %d\n", ret );
        goto exit;
    }
    mbedtls_printf( " ok (signature length = %u)\n", (unsigned int) sig_len );

    /*
     * Transfer public information to verifying context
     *
     * We could use the same context for verification and signatures, but we
     * chose to use a new one in order to make it clear that the verifying
     * context only needs the public key (Q), and not the private key (d).
     */
    mbedtls_printf( "  . Preparing verification context..." );

    if( ( ret = mbedtls_ecp_group_copy( &ctx_verify.MBEDTLS_PRIVATE(grp), &ctx_sign.MBEDTLS_PRIVATE(grp) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_copy returned %d\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ecp_copy( &ctx_verify.MBEDTLS_PRIVATE(Q), &ctx_sign.MBEDTLS_PRIVATE(Q) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_copy returned %d\n", ret );
        goto exit;
    }

    /*
     * Verify signature
     */
    mbedtls_printf( " ok\n  . Verifying signature..." );

    if( ( ret = mbedtls_ecdsa_read_signature( &ctx_verify,
                                      hash, sizeof( hash ),
                                      sig, sig_len ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_read_signature returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\nECDSA PASSED\n" );

exit:

    mbedtls_ecdsa_free( &ctx_verify );
    mbedtls_ecdsa_free( &ctx_sign );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return ret;
}

int ecall_mbedtls_crypto()
{
    int ret = 0;
    if ( 0 != mbedtls_crypto_sha256()) ret |= FAIL_SHA;
    if ( 0 != mbedtls_crypto_aes_ctr_enc_dec_buf())  ret |= FAIL_AES;
    if ( 0 != mbedtls_crypto_ecdsa()) ret |= FAIL_ECDSA;
    return ret;

}

using namespace std;
set<Branch*> temp_stash;
set<Branch*> stash;
// key;
//struct kNNUtil {
//    bool isleaf;
//    double rele;
//    Branch* pBranch;
//
//};
sgx_aes_gcm_128bit_key_t* key = new sgx_aes_gcm_128bit_key_t [0];

struct kNNUtil;
void aes_encrypt(const char *plain,char *cipher) {


    // 设置AES加密的IV
    uint8_t iv[SGX_AESGCM_IV_SIZE] = {0}; // 你应该使用一个安全的随机数生成器来生成IV

    // 加密操作
    sgx_status_t status = sgx_rijndael128GCM_encrypt(key, (const uint8_t*)plain, 4, (uint8_t*)cipher, iv, sizeof(iv), NULL, 0, NULL);
    if (status != SGX_SUCCESS) {
        // 加密失败处理
        return;
    }

}
void aes_dncrypt(const char *cipher,char *plain) {
    uint8_t iv[SGX_AESGCM_IV_SIZE] = {0}; // 这里应该使用与加密时相同的IV

    // 解密操作
    sgx_status_t status = sgx_rijndael128GCM_decrypt(key, (const uint8_t*)cipher, 4, (uint8_t*)plain, iv, sizeof(iv), NULL, 0, NULL);

    if (status != SGX_SUCCESS) {
        // 解密失败处理，可以记录日志或者抛出异常
        return;
    }


    return;
}
void generate_random_block(int length,char *st) {
    std::vector<uint8_t> buf(length);

    // 使用SGX的随机数生成器填充缓冲区
//    sgx_status_t ret = sgx_read_rand(buf.data(), buf.size());
//    if (ret != SGX_SUCCESS) {
//        // 处理错误情况
//        // 可能需要抛出异常或者返回一个错误代码
//    }

    // 将生成的随机数转换为std::string
//    return std::string(reinterpret_cast<const char*>(buf.data()), length);
}
//memset(&key, 0, sizeof(key));

//list<kNNUtil>::iterator pKnn;
vector<Datatype> results;
int searchs (kNNUtil* pKnn)
{
//    if (user_check(pknn, sizeof(kNNUtil)) != SGX_SUCCESS) {
//        return SGX_ERROR_INVALID_PARAMETER;
//    }
//    if (user_check(flag, sizeof(int)) != SGX_SUCCESS) {
//        return SGX_ERROR_INVALID_PARAMETER;
//    }
        int flag=1;
        string out_line;
//    out_line=aes_decrypt((pKnn)->pBranch->trueData);0000000000000000
        results.push_back(out_line);
        if (stash.size() == 0) {
            for (auto pr = stash.begin(); pr != stash.end(); pr++) {
                string out_line_2;
                if ((*pr)->level == 0) {

//                    out_line_2=aes_decrypt((*pr)->trueData);00000000000000000000000
                    if (out_line.compare(out_line_2) == 0) {
                        flag = 0;
                        stash.erase(pr);
                        break;
                    }
                    if (flag == 0) {
                        break;
                    }
                }
            }
        }
    return flag;
}

void pathR(Node* node1, Node* node2)
{
    while (node1 != NULL)
    {
        for (auto pr = stash.begin(); pr != stash.end(); pr++)
        {
            if ((*pr)->curNode == node1)
            {
                Node* temp_node = (*pr)->curNode;

                for (int i = 0; i < MAX_SIZE; i++)
                {
                    if (temp_node->mBranch[i]->is_virtual == true)
                    {
                        break;
                    }
                    Branch* temp_branch = temp_node->mBranch[i];
                    if (temp_branch->pointBranch == NULL)
                    {
                        temp_branch = (*pr);
                        stash.erase(*pr);
                        break;
                    }
                }
            }
            if (node1 == NULL)
            {
                break;
            }
            node1 = node1->parentNode;
        }
    }
    while (node2 != NULL)
    {
        for (auto pr = stash.begin(); pr != stash.end(); pr++)
        {
            if ((*pr)->curNode == node2)
            {
                Node* temp_node = (*pr)->curNode;
                for (int i = 0; i < MAX_SIZE; i++)
                {
                    if (temp_node->mBranch[i]->is_virtual == true)
                    {
                        break;
                    }
                    Branch* temp_branch = temp_node->mBranch[i];
                    if (temp_branch->pointBranch == NULL)
                    {
                        temp_branch = (*pr);
                        stash.erase(*pr);
                    }
                }
            }
            if (node2 == NULL)
            {
                return;
            }
            node2 = node2->parentNode;
        }
    }
}
void insert( Node* node){
for (int i = 0; i < MAX_SIZE; i++)
{
stash.insert(node->mBranch[i]);
//temp_node->mBranch[i]->pointBranch = NULL;
}
//    stash.insert(branches);
}
void erase(Branch* mBranch){
    stash.erase(mBranch);
}
void tempstash(Branch* mBranch){
    temp_stash.insert(mBranch);
}


// 解密函数的实现类似，需要确保传入正确的IV和MAC标签

