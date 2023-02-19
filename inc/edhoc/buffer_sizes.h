/*
 * Copyright (c) 2023 Eriptic Technologies
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#ifndef BUFFER_SIZES_H
#define BUFFER_SIZES_H

#define P_256_PRIV_KEY_SIZE 32
#define P_256_PUB_KEY_COMPRESSED_SIZE 33
#define P_256_PUB_KEY_UNCOMPRESSED_SIZE 65
#define P_256_PUB_KEY_X_CORD_SIZE 32
#define PK_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define G_Y_SIZE P_256_PUB_KEY_X_CORD_SIZE
#define G_X_SIZE P_256_PUB_KEY_X_CORD_SIZE
#define G_R_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define G_I_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define SIGNATURE_SIZE 64
#define ECDH_SECRET_SIZE 32
#define PRK_SIZE 32
#define HASH_SIZE 32
#define AEAD_IV_SIZE 13
#define MAC_SIZE 16
#define MAC23_SIZE 32
#define AAD_SIZE 45
#define KID_SIZE 8
#define SIG_OR_MAC_SIZE 64
#define ENCODING_OVERHEAD 10
#define COSE_SIGN1_STR_LEN 10 /*the length of the string "COSE_Sign1"*/

#define PLAINTEXT2_SIZE (ID_CRED_R_SIZE + (SIG_OR_MAC_SIZE + 2) + EAD_SIZE)
#define CIPHERTEXT2_SIZE PLAINTEXT2_SIZE

#define PLAINTEXT3_SIZE (ID_CRED_I_SIZE + (SIG_OR_MAC_SIZE + 2) + EAD_SIZE)
#define CIPHERTEXT3_SIZE (PLAINTEXT3_SIZE + ENCODING_OVERHEAD)

#define PLAINTEXT4_SIZE EAD_SIZE
#define CIPHERTEXT4_SIZE (PLAINTEXT4_SIZE + ENCODING_OVERHEAD)

#define MSG_1_SIZE (1 + SUITES_I_SIZE + G_X_SIZE + C_I_SIZE + EAD_SIZE)
#define MSG_2_SIZE (G_Y_SIZE + CIPHERTEXT2_SIZE + C_R_SIZE + ENCODING_OVERHEAD)
#define MSG_3_SIZE CIPHERTEXT3_SIZE
#define MSG_4_SIZE CIPHERTEXT4_SIZE

#define MSG12_MAX (((MSG_1_SIZE) > (MSG_2_SIZE)) ? (MSG_1_SIZE) : (MSG_2_SIZE))
#define MSG34_MAX (((MSG_3_SIZE) > (MSG_4_SIZE)) ? (MSG_3_SIZE) : (MSG_4_SIZE))
#define MSG_MAX_SIZE (((MSG12_MAX) > (MSG34_MAX)) ? (MSG12_MAX) : (MSG34_MAX))

#define PLAINTEXT23_MAX_SIZE                                                   \
	(((PLAINTEXT2_SIZE) > (PLAINTEXT3_SIZE)) ? (PLAINTEXT2_SIZE) :         \
						   (PLAINTEXT3_SIZE))

#define CRED_MAX_SIZE                                                          \
	(((CRED_R_SIZE) > (CRED_I_SIZE)) ? (CRED_R_SIZE) : (CRED_I_SIZE))

#define ID_CRED_MAX_SIZE                                                       \
	(((ID_CRED_R_SIZE) > (ID_CRED_I_SIZE)) ? (ID_CRED_R_SIZE) :            \
						 (ID_CRED_I_SIZE))

#define SIG_STRUCT_SIZE                                                        \
	((2 + HASH_SIZE) + COSE_SIGN1_STR_LEN + ID_CRED_MAX_SIZE +             \
	 CRED_MAX_SIZE + EAD_SIZE + MAC23_SIZE + ENCODING_OVERHEAD)

#define CONTEXT_MAC_SIZE                                                       \
	(HASH_SIZE + ID_CRED_MAX_SIZE + CRED_MAX_SIZE + EAD_SIZE +             \
	 ENCODING_OVERHEAD)
#define INFO_MAX_SIZE CONTEXT_MAC_SIZE + ENCODING_OVERHEAD

#define TH34_INPUT_SIZE (HASH_SIZE + PLAINTEXT23_MAX_SIZE + CRED_MAX_SIZE + 2)
#define TH2_DEFAULT_SIZE (G_Y_SIZE + C_R_SIZE + HASH_SIZE + ENCODING_OVERHEAD)

/*define EDHOC_BUF_SIZES_RPK in order to use smaller buffers and save some RAM if need when RPKs are used*/
//#define EDHOC_BUF_SIZES_RPK
//#define EDHOC_BUF_SIZES_C509_CERT
//#define EDHOC_BUF_SIZES_X509_CERT

// #if defined EDHOC_BUF_SIZES_RPK
// #define MSG_MAX_SIZE 100
// #define CIPHERTEXT2_DEFAULT_SIZE 100
// #define CIPHERTEXT3_DEFAULT_SIZE 100
// #define A_2M_DEFAULT_SIZE 200
// #define M_3_DEFAULT_SIZE 200
// #define CRED_DEFAULT_SIZE 128
// #define SGN_OR_MAC_DEFAULT_SIZE 128
// #define ID_CRED_DEFAULT_SIZE 20
// #define PRK_3AE_DEFAULT_SIZE 100
// #define CERT_DEFAUT_SIZE 128
// #define CONTEXT_MAC_DEFAULT_SIZE 200
// #define INFO_DEFAULT_SIZE 250
// #define SIGNATURE_STRUCT_DEFAULT_SIZE 300
// #endif

// #if defined EDHOC_BUF_SIZES_C509_CERT
// #define MSG_MAX_SIZE 255
// #define CIPHERTEXT2_DEFAULT_SIZE 255
// #define CIPHERTEXT3_DEFAULT_SIZE 255
// #define CIPHERTEXT4_DEFAULT_SIZE 255
// #define A_2M_DEFAULT_SIZE 512
// #define M_3_DEFAULT_SIZE 512
// #define CRED_DEFAULT_SIZE 255
// #define SGN_OR_MAC_DEFAULT_SIZE 128
// #define ID_CRED_DEFAULT_SIZE 255
// #define PLAINTEXT_DEFAULT_SIZE 255
// #define CERT_DEFAUT_SIZE 255
// #define CONTEXT_MAC_DEFAULT_SIZE 200
// #define INFO_DEFAULT_SIZE 250
// #define SIGNATURE_STRUCT_DEFAULT_SIZE 300
// #endif

//#if defined EDHOC_BUF_SIZES_X509_CERT
//#define MSG_MAX_SIZE 700
// #define PLAINTEXT_DEFAULT_SIZE 1580
// #define CIPHERTEXT2_DEFAULT_SIZE PLAINTEXT_DEFAULT_SIZE
// #define CIPHERTEXT3_DEFAULT_SIZE PLAINTEXT_DEFAULT_SIZE
// #define CIPHERTEXT4_DEFAULT_SIZE PLAINTEXT_DEFAULT_SIZE
// #define A_2M_DEFAULT_SIZE 512
// #define M_3_DEFAULT_SIZE 512
// #define CRED_DEFAULT_SIZE 600
// #define SGN_OR_MAC_DEFAULT_SIZE 128
// #define ID_CRED_DEFAULT_SIZE 600
// #define CERT_DEFAULT_SIZE 600
// #define CONTEXT_MAC_DEFAULT_SIZE 1580
// #define INFO_DEFAULT_SIZE 1580
// #define SIGNATURE_STRUCT_DEFAULT_SIZE 1580
//#endif

//#define SUITES_MAX 5
//#define ERR_MSG_DEFAULT_SIZE 64
// #define P_256_PRIV_KEY_SIZE 32
// #define P_256_PUB_KEY_COMPRESSED_SIZE 33
// #define P_256_PUB_KEY_UNCOMPRESSED_SIZE 65
// #define P_256_PUB_KEY_X_CORD_SIZE 32
// #define PK_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
// //#define C_R_DEFAULT_SIZE 16
// //#define C_I_DEFAULT_SIZE 16
// #define G_Y_SIZE P_256_PUB_KEY_X_CORD_SIZE
// #define G_X_SIZE P_256_PUB_KEY_X_CORD_SIZE
// #define G_R_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
// #define G_I_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
// #define DATA_2_DEFAULT_SIZE (C_I_DEFAULT_SIZE + G_Y_SIZE + C_R_DEFAULT_SIZE)
// #define TH2_INPUT_DEFAULT_SIZE (G_Y_SIZE + C_R_DEFAULT_SIZE + HASH_SIZE)
// #define TH34_INPUT_DEFAULT_SIZE
// 	(HASH_SIZE + PLAINTEXT_DEFAULT_SIZE + CRED_DEFAULT_SIZE)
// #define ECDH_SECRET_DEFAULT_SIZE 32
// #define DERIVED_SECRET_DEFAULT_SIZE 32
// #define AD_DEFAULT_SIZE 256
// #define PRK_SIZE 32
// #define AAD_DEFAULT_SIZE 64
// #define KID_DEFAULT_SIZE 8
// #define HASH_SIZE 32
// #define AEAD_KEY_DEFAULT_SIZE 16
// #define MAC_DEFAULT_SIZE 16
// #define AEAD_IV_DEFAULT_SIZE 13
// #define SIGNATURE_SIZE 64
// #define TH_ENC_DEFAULT_SIZE 42
// #define ENCODING_OVERHEAD 6
// #define OSCORE_MASTER_SECRET_SIZE 16
// #define OSCORE_MASTER_SALT_SIZE 8

#endif