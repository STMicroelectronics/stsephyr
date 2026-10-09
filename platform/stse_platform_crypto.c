/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include <psa/crypto.h>

#include <stselib.h>

#ifdef CONFIG_STSEPHYR_ECC_ED25519
#include <monocypher-ed25519.h>
#endif

LOG_MODULE_DECLARE(stsephyr, CONFIG_STSEPHYR_LOG_LEVEL);

struct ecc_parameters {
	psa_ecc_family_t family;
	size_t bits;
	size_t public_size;
	size_t private_size;
	size_t signature_size;
	bool prefix_public_key;
};

static psa_mac_operation_t cmac_operation = PSA_MAC_OPERATION_INIT;
static psa_key_id_t cmac_key;
static size_t cmac_expected_tag_size;

static void secure_zero(void *buffer, size_t length)
{
	volatile uint8_t *p = buffer;

	while (length-- != 0U) {
		*p++ = 0U;
	}
}

static stse_ReturnCode_t crypto_error(psa_status_t status, stse_ReturnCode_t error)
{
	if (status != PSA_SUCCESS) {
		LOG_DBG("PSA Crypto status: %d", status);
		return error;
	}

	return STSE_OK;
}

static bool ecc_parameters_get(stse_ecc_key_type_t key_type, struct ecc_parameters *parameters)
{
	if (parameters == NULL) {
		return false;
	}

	switch (key_type) {
#ifdef CONFIG_STSEPHYR_ECC_NIST_P256
	case STSE_ECC_KT_NIST_P_256:
		*parameters =
			(struct ecc_parameters){PSA_ECC_FAMILY_SECP_R1, 256, 64, 32, 64, true};
		return true;
#endif
#ifdef CONFIG_STSEPHYR_ECC_NIST_P384
	case STSE_ECC_KT_NIST_P_384:
		*parameters =
			(struct ecc_parameters){PSA_ECC_FAMILY_SECP_R1, 384, 96, 48, 96, true};
		return true;
#endif
#ifdef CONFIG_STSEPHYR_ECC_NIST_P521
	case STSE_ECC_KT_NIST_P_521:
		*parameters =
			(struct ecc_parameters){PSA_ECC_FAMILY_SECP_R1, 521, 132, 66, 132, true};
		return true;
#endif
#ifdef CONFIG_STSEPHYR_ECC_BRAINPOOL_P256
	case STSE_ECC_KT_BP_P_256:
		*parameters = (struct ecc_parameters){
			PSA_ECC_FAMILY_BRAINPOOL_P_R1, 256, 64, 32, 64, true};
		return true;
#endif
#ifdef CONFIG_STSEPHYR_ECC_BRAINPOOL_P384
	case STSE_ECC_KT_BP_P_384:
		*parameters = (struct ecc_parameters){
			PSA_ECC_FAMILY_BRAINPOOL_P_R1, 384, 96, 48, 96, true};
		return true;
#endif
#ifdef CONFIG_STSEPHYR_ECC_BRAINPOOL_P512
	case STSE_ECC_KT_BP_P_512:
		*parameters = (struct ecc_parameters){
			PSA_ECC_FAMILY_BRAINPOOL_P_R1, 512, 128, 64, 128, true};
		return true;
#endif
#ifdef CONFIG_STSEPHYR_ECC_CURVE25519
	case STSE_ECC_KT_CURVE25519:
		*parameters =
			(struct ecc_parameters){PSA_ECC_FAMILY_MONTGOMERY, 255, 32, 32, 0, false};
		return true;
#endif
	default:
		return false;
	}
}

static psa_algorithm_t hash_algorithm_get(stse_hash_algorithm_t algorithm)
{
	switch (algorithm) {
#ifdef CONFIG_STSEPHYR_HASH_SHA256
	case STSE_SHA_256:
		return PSA_ALG_SHA_256;
#endif
#ifdef CONFIG_STSEPHYR_HASH_SHA384
	case STSE_SHA_384:
		return PSA_ALG_SHA_384;
#endif
#ifdef CONFIG_STSEPHYR_HASH_SHA512
	case STSE_SHA_512:
		return PSA_ALG_SHA_512;
#endif
#ifdef CONFIG_STSEPHYR_HASH_SHA3_256
	case STSE_SHA3_256:
		return PSA_ALG_SHA3_256;
#endif
#ifdef CONFIG_STSEPHYR_HASH_SHA3_384
	case STSE_SHA3_384:
		return PSA_ALG_SHA3_384;
#endif
#ifdef CONFIG_STSEPHYR_HASH_SHA3_512
	case STSE_SHA3_512:
		return PSA_ALG_SHA3_512;
#endif
	default:
		return PSA_ALG_NONE;
	}
}

static psa_algorithm_t digest_algorithm_get(size_t digest_length)
{
	switch (digest_length) {
	case 32:
		return PSA_ALG_SHA_256;
	case 48:
		return PSA_ALG_SHA_384;
	case 64:
		return PSA_ALG_SHA_512;
	default:
		return PSA_ALG_NONE;
	}
}

static psa_status_t import_aes_key(const uint8_t *key, size_t key_length, psa_key_usage_t usage,
				   psa_algorithm_t algorithm, psa_key_id_t *key_id)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, key_length * 8U);
	psa_set_key_usage_flags(&attributes, usage);
	psa_set_key_algorithm(&attributes, algorithm);
	status = psa_import_key(&attributes, key, key_length, key_id);
	psa_reset_key_attributes(&attributes);
	return status;
}

static psa_status_t import_ecc_key(const struct ecc_parameters *parameters, bool public_key,
				   const uint8_t *key, psa_key_usage_t usage,
				   psa_algorithm_t algorithm, psa_key_id_t *key_id)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t formatted_public[133];
	const uint8_t *material = key;
	size_t material_length = public_key ? parameters->public_size : parameters->private_size;
	psa_status_t status;

	if (public_key && parameters->prefix_public_key) {
		formatted_public[0] = 0x04U;
		memcpy(&formatted_public[1], key, parameters->public_size);
		material = formatted_public;
		material_length++;
	}

	psa_set_key_type(&attributes, public_key ? PSA_KEY_TYPE_ECC_PUBLIC_KEY(parameters->family)
						 : PSA_KEY_TYPE_ECC_KEY_PAIR(parameters->family));
	psa_set_key_bits(&attributes, parameters->bits);
	psa_set_key_usage_flags(&attributes, usage);
	psa_set_key_algorithm(&attributes, algorithm);
	status = psa_import_key(&attributes, material, material_length, key_id);
	psa_reset_key_attributes(&attributes);
	return status;
}

stse_ReturnCode_t stse_platform_crypto_init(void)
{
	return crypto_error(psa_crypto_init(), STSE_PLATFORM_CRYPTO_INIT_ERROR);
}

stse_ReturnCode_t stse_platform_hash_compute(stse_hash_algorithm_t hash_algo, PLAT_UI8 *pPayload,
					     PLAT_UI16 payload_length, PLAT_UI8 *pHash,
					     PLAT_UI16 *hash_length)
{
	psa_algorithm_t algorithm = hash_algorithm_get(hash_algo);
	size_t output_length = 0U;
	psa_status_t status;

	if (algorithm == PSA_ALG_NONE || pHash == NULL || hash_length == NULL ||
	    (pPayload == NULL && payload_length != 0U)) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}

	status = psa_hash_compute(algorithm, pPayload, payload_length, pHash, *hash_length,
				  &output_length);
	*hash_length = output_length;
	return crypto_error(status, STSE_PLATFORM_HASH_ERROR);
}

stse_ReturnCode_t stse_platform_ecc_verify(stse_ecc_key_type_t key_type, const PLAT_UI8 *pPubKey,
					   PLAT_UI8 *pDigest, PLAT_UI16 digestLen,
					   PLAT_UI8 *pSignature)
{
	struct ecc_parameters parameters;
	psa_algorithm_t hash_algorithm = digest_algorithm_get(digestLen);
	psa_algorithm_t signature_algorithm;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	psa_status_t status;

#ifdef CONFIG_STSEPHYR_ECC_ED25519
	if (key_type == STSE_ECC_KT_ED25519) {
		if (pPubKey == NULL || pDigest == NULL || pSignature == NULL) {
			return STSE_PLATFORM_INVALID_PARAMETER;
		}

		return crypto_ed25519_check(pSignature, pPubKey, pDigest, digestLen) == 0
			       ? STSE_OK
			       : STSE_PLATFORM_ECC_VERIFY_ERROR;
	}
#endif

	if (!ecc_parameters_get(key_type, &parameters) || !parameters.prefix_public_key ||
	    hash_algorithm == PSA_ALG_NONE || pPubKey == NULL || pDigest == NULL ||
	    pSignature == NULL) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}

	signature_algorithm = PSA_ALG_ECDSA(hash_algorithm);
	status = import_ecc_key(&parameters, true, pPubKey, PSA_KEY_USAGE_VERIFY_HASH,
				signature_algorithm, &key_id);
	if (status == PSA_SUCCESS) {
		status = psa_verify_hash(key_id, signature_algorithm, pDigest, digestLen,
					 pSignature, parameters.signature_size);
	}
	if (key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(key_id);
	}

	return crypto_error(status, STSE_PLATFORM_ECC_VERIFY_ERROR);
}

stse_ReturnCode_t stse_platform_ecc_generate_key_pair(stse_ecc_key_type_t key_type,
						      PLAT_UI8 *pPrivKey, PLAT_UI8 *pPubKey)
{
	struct ecc_parameters parameters;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	uint8_t public_key[133];
	size_t private_length = 0U;
	size_t public_length = 0U;
	psa_status_t status;

	if (!ecc_parameters_get(key_type, &parameters) || pPrivKey == NULL || pPubKey == NULL) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}

	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(parameters.family));
	psa_set_key_bits(&attributes, parameters.bits);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
	status = psa_generate_key(&attributes, &key_id);
	if (status == PSA_SUCCESS) {
		status = psa_export_key(key_id, pPrivKey, parameters.private_size, &private_length);
	}
	if (status == PSA_SUCCESS) {
		status = psa_export_public_key(key_id, public_key, sizeof(public_key),
					       &public_length);
	}
	if (status == PSA_SUCCESS &&
	    (private_length != parameters.private_size ||
	     public_length != parameters.public_size + (parameters.prefix_public_key ? 1U : 0U))) {
		status = PSA_ERROR_DATA_INVALID;
	}
	if (status == PSA_SUCCESS) {
		if (parameters.prefix_public_key) {
			if (public_length != parameters.public_size + 1U ||
			    public_key[0] != 0x04U) {
				status = PSA_ERROR_DATA_INVALID;
			} else {
				memcpy(pPubKey, &public_key[1], parameters.public_size);
			}
		} else {
			memcpy(pPubKey, public_key, parameters.public_size);
		}
	}
	if (key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(key_id);
	}
	psa_reset_key_attributes(&attributes);

	return crypto_error(status, STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR);
}

stse_ReturnCode_t stse_platform_ecc_sign(stse_ecc_key_type_t key_type, PLAT_UI8 *pPrivKey,
					 PLAT_UI8 *pDigest, PLAT_UI16 digestLen,
					 PLAT_UI8 *pSignature)
{
	struct ecc_parameters parameters;
	psa_algorithm_t hash_algorithm = digest_algorithm_get(digestLen);
	psa_algorithm_t signature_algorithm;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	size_t signature_length = 0U;
	psa_status_t status;

	if (!ecc_parameters_get(key_type, &parameters) || !parameters.prefix_public_key ||
	    hash_algorithm == PSA_ALG_NONE || pPrivKey == NULL || pDigest == NULL ||
	    pSignature == NULL) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}

	signature_algorithm = PSA_ALG_ECDSA(hash_algorithm);
	status = import_ecc_key(&parameters, false, pPrivKey, PSA_KEY_USAGE_SIGN_HASH,
				signature_algorithm, &key_id);
	if (status == PSA_SUCCESS) {
		status = psa_sign_hash(key_id, signature_algorithm, pDigest, digestLen, pSignature,
				       parameters.signature_size, &signature_length);
	}
	if (key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(key_id);
	}

	return crypto_error(status, STSE_PLATFORM_ECC_SIGN_ERROR);
}

stse_ReturnCode_t stse_platform_ecc_ecdh(stse_ecc_key_type_t key_type, const PLAT_UI8 *pPubKey,
					 const PLAT_UI8 *pPrivKey, PLAT_UI8 *pSharedSecret)
{
	struct ecc_parameters parameters;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	uint8_t public_key[133];
	const uint8_t *peer_key = pPubKey;
	size_t peer_key_length;
	size_t output_length = 0U;
	psa_status_t status;

	if (!ecc_parameters_get(key_type, &parameters) || pPubKey == NULL || pPrivKey == NULL ||
	    pSharedSecret == NULL) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}

	peer_key_length = parameters.public_size;
	if (parameters.prefix_public_key) {
		public_key[0] = 0x04U;
		memcpy(&public_key[1], pPubKey, parameters.public_size);
		peer_key = public_key;
		peer_key_length++;
	}

	status = import_ecc_key(&parameters, false, pPrivKey, PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH,
				&key_id);
	if (status == PSA_SUCCESS) {
		status = psa_raw_key_agreement(PSA_ALG_ECDH, key_id, peer_key, peer_key_length,
					       pSharedSecret, parameters.private_size,
					       &output_length);
	}
	if (key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(key_id);
	}

	return crypto_error(status, STSE_PLATFORM_ECC_ECDH_ERROR);
}

stse_ReturnCode_t stse_platform_aes_cmac_init(const PLAT_UI8 *pKey, PLAT_UI16 key_length,
					      PLAT_UI16 exp_tag_size)
{
	psa_algorithm_t algorithm;
	psa_status_t status;

	if (pKey == NULL || (key_length != 16U && key_length != 24U && key_length != 32U) ||
	    (exp_tag_size == 0U) ||
	    (exp_tag_size > PSA_MAC_LENGTH(PSA_KEY_TYPE_AES, key_length * 8U, PSA_ALG_CMAC))) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}
	algorithm = PSA_ALG_TRUNCATED_MAC(PSA_ALG_CMAC, exp_tag_size);

	(void)psa_mac_abort(&cmac_operation);
	if (cmac_key != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(cmac_key);
		cmac_key = PSA_KEY_ID_NULL;
	}

	status = import_aes_key(pKey, key_length,
				PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE,
				algorithm, &cmac_key);
	if (status == PSA_SUCCESS) {
		status = psa_mac_sign_setup(&cmac_operation, cmac_key, algorithm);
	}
	cmac_expected_tag_size = exp_tag_size;
	return crypto_error(status, STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR);
}

stse_ReturnCode_t stse_platform_aes_cmac_append(PLAT_UI8 *pInput, PLAT_UI16 length)
{
	return crypto_error(psa_mac_update(&cmac_operation, pInput, length),
			    STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR);
}

static void cmac_cleanup(void)
{
	(void)psa_mac_abort(&cmac_operation);
	if (cmac_key != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(cmac_key);
		cmac_key = PSA_KEY_ID_NULL;
	}
}

stse_ReturnCode_t stse_platform_aes_cmac_compute_finish(PLAT_UI8 *pTag, PLAT_UI8 *pTagLen)
{
	size_t tag_length = 0U;
	psa_status_t status;

	if (pTag == NULL || pTagLen == NULL) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}
	status = psa_mac_sign_finish(&cmac_operation, pTag, cmac_expected_tag_size, &tag_length);
	*pTagLen = tag_length;
	cmac_cleanup();
	return crypto_error(status, STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR);
}

stse_ReturnCode_t stse_platform_aes_cmac_verify_finish(PLAT_UI8 *pTag)
{
	uint8_t computed_tag[PSA_MAC_MAX_SIZE];
	uint8_t difference = 0U;
	size_t tag_length = 0U;
	psa_status_t status;

	if (pTag == NULL) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}
	status = psa_mac_sign_finish(&cmac_operation, computed_tag, cmac_expected_tag_size,
				     &tag_length);
	if (status == PSA_SUCCESS && tag_length != cmac_expected_tag_size) {
		status = PSA_ERROR_INVALID_SIGNATURE;
	}
	if (status == PSA_SUCCESS) {
		for (size_t i = 0U; i < tag_length; ++i) {
			difference |= computed_tag[i] ^ pTag[i];
		}
		if (difference != 0U) {
			status = PSA_ERROR_INVALID_SIGNATURE;
		}
	}
	secure_zero(computed_tag, sizeof(computed_tag));
	cmac_cleanup();
	return crypto_error(status, STSE_PLATFORM_AES_CMAC_VERIFY_ERROR);
}

stse_ReturnCode_t stse_platform_aes_cmac_compute(const PLAT_UI8 *pPayload, PLAT_UI16 payload_length,
						 const PLAT_UI8 *pKey, PLAT_UI16 key_length,
						 PLAT_UI16 exp_tag_size, PLAT_UI8 *pTag,
						 PLAT_UI16 *pTag_length)
{
	psa_algorithm_t algorithm;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	size_t output_length = 0U;
	psa_status_t status;

	if (pKey == NULL || (key_length != 16U && key_length != 24U && key_length != 32U) ||
	    (exp_tag_size == 0U) ||
	    (exp_tag_size > PSA_MAC_LENGTH(PSA_KEY_TYPE_AES, key_length * 8U, PSA_ALG_CMAC))) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}
	algorithm = PSA_ALG_TRUNCATED_MAC(PSA_ALG_CMAC, exp_tag_size);
	status = import_aes_key(pKey, key_length, PSA_KEY_USAGE_SIGN_MESSAGE, algorithm, &key_id);
	if (status == PSA_SUCCESS) {
		status = psa_mac_compute(key_id, algorithm, pPayload, payload_length, pTag,
					 exp_tag_size, &output_length);
	}
	if (key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(key_id);
	}
	if (pTag_length != NULL) {
		*pTag_length = output_length;
	}
	return crypto_error(status, STSE_PLATFORM_AES_CMAC_COMPUTE_ERROR);
}

stse_ReturnCode_t stse_platform_aes_cmac_verify(const PLAT_UI8 *pPayload, PLAT_UI16 payload_length,
						const PLAT_UI8 *pKey, PLAT_UI16 key_length,
						const PLAT_UI8 *pTag, PLAT_UI16 tag_length)
{
	psa_algorithm_t algorithm;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	psa_status_t status;

	if (pKey == NULL || pTag == NULL || (pPayload == NULL && payload_length != 0U) ||
	    (key_length != 16U && key_length != 24U && key_length != 32U) || (tag_length == 0U) ||
	    (tag_length > PSA_MAC_LENGTH(PSA_KEY_TYPE_AES, key_length * 8U, PSA_ALG_CMAC))) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}
	algorithm = PSA_ALG_TRUNCATED_MAC(PSA_ALG_CMAC, tag_length);
	status = import_aes_key(pKey, key_length, PSA_KEY_USAGE_VERIFY_MESSAGE, algorithm, &key_id);
	if (status == PSA_SUCCESS) {
		status = psa_mac_verify(key_id, algorithm, pPayload, payload_length, pTag,
					tag_length);
	}
	if (key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(key_id);
	}
	return crypto_error(status, STSE_PLATFORM_AES_CMAC_VERIFY_ERROR);
}

static stse_ReturnCode_t aes_cipher(const uint8_t *input, size_t input_length, const uint8_t *iv,
				    const uint8_t *key, size_t key_length,
				    psa_algorithm_t algorithm, bool encrypt, uint8_t *output,
				    PLAT_UI16 *output_length)
{
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	size_t update_length = 0U;
	size_t finish_length = 0U;
	psa_status_t status;

	if (key == NULL || output == NULL || (input == NULL && input_length != 0U) ||
	    (input_length % 16U) != 0U ||
	    (key_length != 16U && key_length != 24U && key_length != 32U) ||
	    (algorithm == PSA_ALG_CBC_NO_PADDING && iv == NULL)) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}
	status = import_aes_key(key, key_length,
				encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT, algorithm,
				&key_id);
	if (status == PSA_SUCCESS) {
		status = encrypt ? psa_cipher_encrypt_setup(&operation, key_id, algorithm)
				 : psa_cipher_decrypt_setup(&operation, key_id, algorithm);
	}
	if (status == PSA_SUCCESS && iv != NULL) {
		status = psa_cipher_set_iv(&operation, iv, 16U);
	}
	if (status == PSA_SUCCESS) {
		status = psa_cipher_update(&operation, input, input_length, output, input_length,
					   &update_length);
	}
	if (status == PSA_SUCCESS) {
		status = psa_cipher_finish(&operation, output + update_length,
					   input_length - update_length, &finish_length);
	}
	(void)psa_cipher_abort(&operation);
	if (key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(key_id);
	}
	if (output_length != NULL) {
		*output_length = update_length + finish_length;
	}
	return crypto_error(status, encrypt ? STSE_PLATFORM_AES_CBC_ENCRYPT_ERROR
					    : STSE_PLATFORM_AES_CBC_DECRYPT_ERROR);
}

stse_ReturnCode_t stse_platform_aes_cbc_enc(const PLAT_UI8 *pPlaintext, PLAT_UI16 plaintext_length,
					    PLAT_UI8 *pInitial_value, const PLAT_UI8 *pKey,
					    PLAT_UI16 key_length, PLAT_UI8 *pEncryptedtext,
					    PLAT_UI16 *pEncryptedtext_length)
{
	return aes_cipher(pPlaintext, plaintext_length, pInitial_value, pKey, key_length,
			  PSA_ALG_CBC_NO_PADDING, true, pEncryptedtext, pEncryptedtext_length);
}

stse_ReturnCode_t stse_platform_aes_cbc_dec(const PLAT_UI8 *pEncryptedtext,
					    PLAT_UI16 encryptedtext_length,
					    PLAT_UI8 *pInitial_value, const PLAT_UI8 *pKey,
					    PLAT_UI16 key_length, PLAT_UI8 *pPlaintext,
					    PLAT_UI16 *pPlaintext_length)
{
	return aes_cipher(pEncryptedtext, encryptedtext_length, pInitial_value, pKey, key_length,
			  PSA_ALG_CBC_NO_PADDING, false, pPlaintext, pPlaintext_length);
}

stse_ReturnCode_t stse_platform_aes_ecb_enc(const PLAT_UI8 *pPlaintext, PLAT_UI16 plaintext_length,
					    const PLAT_UI8 *pKey, PLAT_UI16 key_length,
					    PLAT_UI8 *pEncryptedtext,
					    PLAT_UI16 *pEncryptedtext_length)
{
	return aes_cipher(pPlaintext, plaintext_length, NULL, pKey, key_length,
			  PSA_ALG_ECB_NO_PADDING, true, pEncryptedtext, pEncryptedtext_length);
}

static stse_ReturnCode_t hmac_sha256(const uint8_t *key, size_t key_length, const uint8_t *input,
				     size_t input_length, uint8_t *output, size_t output_size,
				     size_t *output_length)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	psa_algorithm_t algorithm = PSA_ALG_HMAC(PSA_ALG_SHA_256);
	psa_status_t status;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, key_length * 8U);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, algorithm);
	status = psa_import_key(&attributes, key, key_length, &key_id);
	if (status == PSA_SUCCESS) {
		status = psa_mac_compute(key_id, algorithm, input, input_length, output,
					 output_size, output_length);
	}
	if (key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(key_id);
	}
	psa_reset_key_attributes(&attributes);
	return crypto_error(status, STSE_PLATFORM_HKDF_ERROR);
}

stse_ReturnCode_t stse_platform_hmac_sha256_extract(PLAT_UI8 *pSalt, PLAT_UI16 salt_length,
						    PLAT_UI8 *pInput_keying_material,
						    PLAT_UI16 input_keying_material_length,
						    PLAT_UI8 *pPseudorandom_key,
						    PLAT_UI16 pseudorandom_key_expected_length)
{
	static const uint8_t zero_salt[32];
	size_t output_length = 0U;
	stse_ReturnCode_t status;

	if (pInput_keying_material == NULL || pPseudorandom_key == NULL ||
	    pseudorandom_key_expected_length < 32U) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}
	if (pSalt == NULL || salt_length == 0U) {
		pSalt = (uint8_t *)zero_salt;
		salt_length = sizeof(zero_salt);
	}

	status = hmac_sha256(pSalt, salt_length, pInput_keying_material,
			     input_keying_material_length, pPseudorandom_key,
			     pseudorandom_key_expected_length, &output_length);
	return status == STSE_OK && output_length == 32U ? STSE_OK : STSE_PLATFORM_HKDF_ERROR;
}

stse_ReturnCode_t stse_platform_hmac_sha256_expand(PLAT_UI8 *pPseudorandom_key,
						   PLAT_UI16 pseudorandom_key_length,
						   PLAT_UI8 *pInfo, PLAT_UI16 info_length,
						   PLAT_UI8 *pOutput_keying_material,
						   PLAT_UI16 output_keying_material_length)
{
	uint8_t previous[32];
	uint8_t input[32 + 255 + 1];
	size_t previous_length = 0U;
	size_t produced = 0U;
	uint8_t counter = 1U;

	if (pPseudorandom_key == NULL || pOutput_keying_material == NULL ||
	    (pInfo == NULL && info_length != 0U) || info_length > 255U ||
	    output_keying_material_length > 255U * 32U) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}

	while (produced < output_keying_material_length) {
		size_t input_length = 0U;
		size_t block_length = 0U;
		size_t copy_length;
		stse_ReturnCode_t status;

		memcpy(input, previous, previous_length);
		input_length += previous_length;
		if (pInfo != NULL && info_length != 0U) {
			memcpy(input + input_length, pInfo, info_length);
			input_length += info_length;
		}
		input[input_length++] = counter++;
		status = hmac_sha256(pPseudorandom_key, pseudorandom_key_length, input,
				     input_length, previous, sizeof(previous), &block_length);
		if (status != STSE_OK || block_length != sizeof(previous)) {
			secure_zero(previous, sizeof(previous));
			secure_zero(input, sizeof(input));
			secure_zero(pOutput_keying_material, produced);
			return STSE_PLATFORM_HKDF_ERROR;
		}
		previous_length = block_length;
		copy_length = MIN(block_length, output_keying_material_length - produced);
		memcpy(pOutput_keying_material + produced, previous, copy_length);
		produced += copy_length;
	}

	secure_zero(previous, sizeof(previous));
	secure_zero(input, sizeof(input));
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_hmac_sha256_compute(PLAT_UI8 *pSalt, PLAT_UI16 salt_length,
						    PLAT_UI8 *pInput_keying_material,
						    PLAT_UI16 input_keying_material_length,
						    PLAT_UI8 *pInfo, PLAT_UI16 info_length,
						    PLAT_UI8 *pOutput_keying_material,
						    PLAT_UI16 output_keying_material_length)
{
	uint8_t pseudorandom_key[32];
	stse_ReturnCode_t status;

	status = stse_platform_hmac_sha256_extract(pSalt, salt_length, pInput_keying_material,
						   input_keying_material_length, pseudorandom_key,
						   sizeof(pseudorandom_key));
	if (status == STSE_OK) {
		status = stse_platform_hmac_sha256_expand(
			pseudorandom_key, sizeof(pseudorandom_key), pInfo, info_length,
			pOutput_keying_material, output_keying_material_length);
	}
	secure_zero(pseudorandom_key, sizeof(pseudorandom_key));
	return status;
}

stse_ReturnCode_t stse_platform_nist_kw_encrypt(PLAT_UI8 *pPayload, PLAT_UI32 payload_length,
						PLAT_UI8 *pKey, PLAT_UI8 key_length,
						PLAT_UI8 *pOutput, PLAT_UI32 *pOutput_length)
{
	uint8_t block[16];
	uint8_t encrypted[16];
	uint8_t a[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
	size_t n;

	if (pPayload == NULL || pKey == NULL || pOutput == NULL || pOutput_length == NULL ||
	    payload_length < 16U || (payload_length % 8U) != 0U) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}
	n = payload_length / 8U;
	memmove(pOutput + 8U, pPayload, payload_length);

	for (uint64_t j = 0U; j < 6U; ++j) {
		for (uint64_t i = 1U; i <= n; ++i) {
			PLAT_UI16 encrypted_length = 0U;
			uint64_t t = n * j + i;

			memcpy(block, a, 8U);
			memcpy(block + 8U, pOutput + i * 8U, 8U);
			if (aes_cipher(block, sizeof(block), NULL, pKey, key_length,
				       PSA_ALG_ECB_NO_PADDING, true, encrypted,
				       &encrypted_length) != STSE_OK ||
			    encrypted_length != sizeof(encrypted)) {
				secure_zero(block, sizeof(block));
				secure_zero(encrypted, sizeof(encrypted));
				return STSE_PLATFORM_KEYWRAP_ERROR;
			}
			memcpy(a, encrypted, 8U);
			for (size_t byte = 0U; byte < 8U; ++byte) {
				a[7U - byte] ^= (uint8_t)(t >> (byte * 8U));
			}
			memcpy(pOutput + i * 8U, encrypted + 8U, 8U);
		}
	}

	memcpy(pOutput, a, sizeof(a));
	*pOutput_length = payload_length + sizeof(a);
	secure_zero(block, sizeof(block));
	secure_zero(encrypted, sizeof(encrypted));
	return STSE_OK;
}
