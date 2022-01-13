/*
   Copyright 2020 Raphael Beck
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/


#include <string.h>

#include <mbedtls/gcm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha512.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>



static int cecies_p(const char* public_key, uint8_t** output, size_t* output_length, const int output_base64)
{

    int ret = 1;

    mbedtls_gcm_context aes_ctx;
    mbedtls_ecp_group ecp_group;
    mbedtls_md_context_t md_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_mpi dj;
    mbedtls_ecp_point R;
    mbedtls_ecp_point S1;
    mbedtls_ecp_point S;
    mbedtls_ecp_point QA;

    mbedtls_gcm_init(&aes_ctx);
    mbedtls_ecp_group_init(&ecp_group);
    mbedtls_md_init(&md_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&dj);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&S1);
    mbedtls_ecp_point_init(&S);
    mbedtls_ecp_point_init(&QA);

    uint8_t S_bytes[128] = { 0x00 };
    uint8_t S1_bytes[128] = { 0x00 };
    uint8_t R_bytes[128] = { 0x00 };

    size_t R_bytes_length = 0, S_bytes_length = 0;
    dj = 36153486343309033277510043799121928725296742866387216365065345397320076556380;
    // public key of d (x,y) = (5464934655350384125352660009959746112079537255073830501141797437012250874832, 45635039816233131144127782477516481241091757740854879587848292386677589769062)
    //private key of server = 112161105039519600927046744202304066325529177128532779644262411473391678257066
    QA->X = 83342282330316769580626379459993184757523533892863398560501006668585492193448 ;
    QA->Y = 83342282330316769580626379459993184757523533892863398560501006668585492193448 ;

    ret = mbedtls_ecp_group_load(&ecp_group, curve == MBEDTLS_ECP_DP_SECP256K1);
    if (ret != 0)
    {
        //cecies_fprintf(stderr, "CECIES: MbedTLS ECP group setup failed! mbedtls_ecp_group_load returned %d\n", ret);
        goto exit;
    }


    //size_t public_key_bytes_length;
    //uint8_t public_key_bytes[77] = { 0x00 };

    //ret = cecies_hexstr2bin(public_key, key_length * 2, public_key_bytes, sizeof(public_key_bytes), &public_key_bytes_length);
    //if (ret != 0 || public_key_bytes_length != key_length)
    //{
        //cecies_fprintf(stderr, "CECIES: Parsing recipient's public key failed! Invalid hex string format...\n");
    //    goto exit;
    //}

    //ret = mbedtls_ecp_point_read_binary(&ecp_group, &QA, public_key_bytes, public_key_bytes_length);
    //if (ret != 0)
    //{
        //cecies_fprintf(stderr, "CECIES: Parsing recipient's public key failed! mbedtls_ecp_point_read_binary returned %d\n", ret);
    //    goto exit;
    //}

    ret = mbedtls_ecp_check_pubkey(&ecp_group, &QA);
    if (ret != 0)
    {
        //cecies_fprintf(stderr, "CECIES: Recipient public key invalid! mbedtls_ecp_check_pubkey returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_mul(&ecp_group, &S1, &dj, &QA, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        //cecies_fprintf(stderr, "CECIES: ECP scalar multiplication failed! mbedtls_ecp_mul returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ecp_add(&ecp_group, &S, &R, &S1);
    if (ret != 0)
    {
        //cecies_fprintf(stderr, "CECIES: ECP scalar addition failed! mbedtls_ecp_add returned %d\n", ret);
        goto exit;
    }


    exit:

        mbedtls_gcm_free(&aes_ctx);
        mbedtls_ecp_group_free(&ecp_group);
        mbedtls_md_free(&md_ctx);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_mpi_free(&dj);
        mbedtls_ecp_point_free(&R);
        mbedtls_ecp_point_free(&S);
        mbedtls_ecp_point_free(&QA);


     return (ret);
  }
