/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef CRYPTO_WRAPPER_H
#define CRYPTO_WRAPPER_H

#include "byte_array.h"
#include "oscore_edhoc_error.h"

#include "edhoc/suites.h"

/*Indicates what kind of operation a symmetric cipher will execute*/
enum aes_operation {
	ENCRYPT,
	DECRYPT,
};

/**
 * @brief			Calculates AEAD encryption decryption.
 * 
 * @param op 			Operation to be executed (ENCRYPT or DECRYPT).
 * @param[in] in		Input message.
 * @param[in] key 		The symmetric key to be used.
 * @param[in] nonce 		The nonce.
 * @param[in] aad 		Additional authenticated data.
 * @param[out] out 		The cipher text.
 * @param[in,out] tag 		The authentication tag.
 * @return 			Ok or error code.
 */
enum err aead(enum aes_operation op, const struct byte_array *in,
	      const struct byte_array *key, struct byte_array *nonce,
	      const struct byte_array *aad, struct byte_array *out,
	      struct byte_array *tag);

/**
 * @brief			Derives ECDH shared secret.
 * 
 * @param alg			The ECDH algorithm to be used.
 * @param[in] sk 		Private key.
 * @param[in] pk 		Public key.
 * @param[out] shared_secret 	The result.
 * @return 			Ok or error code.
 */
enum err shared_secret_derive(enum ecdh_alg alg, const struct byte_array *sk,
			      const struct byte_array *pk,
			      uint8_t *shared_secret);

/**
 * @brief 						KEM encapsulation.
 * 
 * @param[in] alg				The selected ML-KEM algorithm.
 * @param[in] pk				The pointer to input public key.
 * @param[out] ct				The pointer to output ciphertext.
 * @param[out] shared_secret	The pointer to output shared secret.
 * @return						Ok or error code.
 */
enum err kem_encap(enum ecdh_alg alg, const struct byte_array *pk, struct byte_array *ct, uint8_t *shared_secret);

/**
 * @brief						KEM decapsulation.
 * 
 * @param[in] alg				The selected ML-KEM algorithm.
 * @param[in] sk				The pointer to input secret key.
 * @param[in] ct				The pointer to input ciphertext.
 * @param[out] shared_secret	The pointer to output shared secret.
 * @return 						Ok or error code.
 */
enum err kem_decap(enum ecdh_alg alg, const struct byte_array *sk, const struct byte_array *ct, uint8_t *shared_secret);

/**
 * @brief			HKDF extract function, see rfc5869.
 * 
 * @param alg			Hash algorithm to be used.
 * @param[in] salt		Salt value.
 * @param[in] ikm 		Input keying material.
 * @param[out] out		The result.
 * @return 			Ok or error code.
 */
enum err hkdf_extract(enum hash_alg alg, const struct byte_array *salt,
		      struct byte_array *ikm, uint8_t *out);

/**
 * @brief			HKDF expand function, see rfc5869.
 * 
 * @param alg			Hash algorithm to be used.
 * @param[in] prk 		Input pseudo random key.
 * @param[in] info 		Info input parameter.
 * @param[out] out		The result.
 * @return 			Ok or error code.
 */
enum err hkdf_expand(enum hash_alg alg, const struct byte_array *prk,
		     const struct byte_array *info, struct byte_array *out);

/**
 * @brief			Computes a hash.
 * 
 * @param alg 			The hash algorithm to be used.
 * @param[in] in 		The input message.
 * @param[out] out 		The hash.
 * @return 			Ok or error code.
 */
enum err hash(enum hash_alg alg, const struct byte_array *in,
	      struct byte_array *out);

/**
 * @brief			Verifies an asymmetric signature.
 * @param alg			Signature algorithm to be used.
 * @param[in] sk 		Secret key.
 * @param[in] pk 		Public key.
 * @param[in] msg 		The message to be signed.
 * @param[out] out 		Signature.
 * @return 			Ok or error code.
 */
enum err sign(enum sign_alg alg, const struct byte_array *sk,
	      const struct byte_array *pk, const struct byte_array *msg,
	      uint8_t *out);

/**
 * @brief			Verifies an asymmetric signature.
 * 
 * @param alg 			Signature algorithm to be used.
 * @param[in] pk 		Public key.
 * @param[in] msg 		The signed message.
 * @param[in] sgn 		Signature.
 * @param[out] result 		True if the verification is successfully.
 * @return 			Ok or error code.
 */
enum err verify(enum sign_alg alg, const struct byte_array *pk,
		struct const_byte_array *msg, struct const_byte_array *sgn,
		bool *result);

/**
 * @brief			HKDF function used for the derivation of the 
 *				Common IV, Recipient/Sender keys.
 *
 * @param[in] master_secret	The master secret.
 * @param[in] master_salt 	The master salt.
 * @param[in] info 		A CBOR structure containing id, id_context, 
 * 				alg_aead, type, L. 
 * @param[out] out 		The derived Common IV, Recipient/Sender keys
 * @return 			Ok or error code.
 */
enum err hkdf_sha_256(struct byte_array *master_secret,
		      struct byte_array *master_salt, struct byte_array *info,
		      struct byte_array *out);

#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
/*
 * Elliptic curve based signature algorithms generate signatures that are not 
 * deterministic. In order to test edhoc module against test vectors provided 
 * by the RFC authors, a mocking functionality has been added.
 *
 * When EDHOC_MOCK_CRYPTO_WRAPPER macro is defined, structure 
 * edhoc_crypto_mock_cb can be used to define values returned/generated by 
 * the sign() and aead() functions. Predefined value will be used only if the 
 * function has been called with arguments values matching those provided in
 * edhoc_crypto_mock_cb.aead_in_out / edhoc_crypto_mock_cb.sign_in_out structure.
 *
 * When there is no matching arguments, the function aead()/sign() will 
 * continue normally.
 */
struct edhoc_mock_aead_in_out {
	struct byte_array out;
	struct byte_array in;
	struct byte_array key;
	struct byte_array nonce;
	struct byte_array aad;
	struct byte_array tag;
};

struct edhoc_mock_sign_in_out {
	enum sign_alg curve;
	struct byte_array sk;
	struct byte_array pk;
	struct byte_array msg;
	struct byte_array out;
};

struct edhoc_mock_cb {
	int aead_in_out_count;
	struct edhoc_mock_aead_in_out *aead_in_out;
	int sign_in_out_count;
	struct edhoc_mock_sign_in_out *sign_in_out;
};

extern struct edhoc_mock_cb edhoc_crypto_mock_cb;
#endif // EDHOC_MOCK_CRYPTO_WRAPPER

#endif
