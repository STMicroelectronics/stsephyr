/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "tls13.h"
#include <stsephyr/stsafe_a120.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include <api/stse_aes.h>
#include <api/stse_ecc.h>
#include <api/stse_hash.h>
#include <api/stse_mac.h>
#include <services/stsafea/stsafea_derive_keys.h>
#include <services/stsafea/stsafea_symmetric_key_slots.h>

LOG_MODULE_DECLARE(stsephyr, CONFIG_STSEPHYR_LOG_LEVEL);

#define TLS13_SLOT_INVALID	   0xFFU
#define TLS13_REQUIRED_EMPTY_SLOTS STSEPHYR_TLS13_MAX_TEMPORARY_SLOTS
#define TLS13_MAX_SYMMETRIC_SLOTS  32U
#define TLS13_HKDF_LABEL_PREFIX	   "tls13 "
#define TLS13_HKDF_LABEL_MAX_SIZE  72U

/* Derive-Secret(HKDF-Extract(0, 0), "derived", Hash("")) for SHA-256. */
static const uint8_t tls13_derived_early_secret[STSEPHYR_TLS13_SHA256_SIZE] = {
	0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54,
	0xfc, 0x9d, 0xba, 0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48,
	0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba,
};

static const uint8_t sha256_empty_hash[STSEPHYR_TLS13_SHA256_SIZE] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
	0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
	0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

static void secure_zero(void *buffer, size_t length)
{
	volatile uint8_t *cursor = buffer;

	while (length-- > 0U) {
		*cursor++ = 0U;
	}
}

static int track_slot(struct stsephyr_tls13_client_context *context, uint8_t slot)
{
	for (size_t i = 0U; i < ARRAY_SIZE(context->temporary_slots); ++i) {
		if (context->temporary_slots[i] == TLS13_SLOT_INVALID) {
			context->temporary_slots[i] = slot;
			return 0;
		}
	}
	return -EOVERFLOW;
}

static int erase_slot(stse_Handler_t *handler, struct stsephyr_tls13_client_context *context,
		      uint8_t *slot)
{
	stse_ReturnCode_t status;

	if (*slot == TLS13_SLOT_INVALID) {
		return 0;
	}
	status = stsafea_erase_symmetric_key_slot(handler, *slot);
	if (status != STSE_OK) {
		return stsephyr_stse_to_errno(status);
	}
	for (size_t i = 0U; i < ARRAY_SIZE(context->temporary_slots); ++i) {
		if (context->temporary_slots[i] == *slot) {
			context->temporary_slots[i] = TLS13_SLOT_INVALID;
		}
	}
	*slot = TLS13_SLOT_INVALID;
	return 0;
}

static int make_hkdf_label(uint16_t output_length, const char *label, const uint8_t *context,
			   size_t context_length, uint8_t *output, size_t output_size,
			   uint16_t *label_length)
{
	size_t short_label_length;
	size_t full_label_length;
	size_t required;
	size_t offset = 0U;

	if ((label == NULL) || (output == NULL) || (label_length == NULL) ||
	    ((context == NULL) && (context_length != 0U)) || (context_length > UINT8_MAX)) {
		return -EINVAL;
	}

	short_label_length = strlen(label);
	full_label_length = (sizeof(TLS13_HKDF_LABEL_PREFIX) - 1U) + short_label_length;
	required = 2U + 1U + full_label_length + 1U + context_length;
	if ((full_label_length > UINT8_MAX) || (required > output_size)) {
		return -EMSGSIZE;
	}

	output[offset++] = (uint8_t)(output_length >> 8);
	output[offset++] = (uint8_t)output_length;
	output[offset++] = (uint8_t)full_label_length;
	memcpy(&output[offset], TLS13_HKDF_LABEL_PREFIX, sizeof(TLS13_HKDF_LABEL_PREFIX) - 1U);
	offset += sizeof(TLS13_HKDF_LABEL_PREFIX) - 1U;
	memcpy(&output[offset], label, short_label_length);
	offset += short_label_length;
	output[offset++] = (uint8_t)context_length;
	if (context_length != 0U) {
		memcpy(&output[offset], context, context_length);
		offset += context_length;
	}

	*label_length = (uint16_t)offset;
	return 0;
}

static int preflight_empty_derived_slots(stse_Handler_t *handler)
{
	stsafea_symmetric_key_slot_information_t slots[TLS13_MAX_SYMMETRIC_SLOTS];
	stsafea_symmetric_key_slot_provisioning_ctrl_fields_t controls;
	uint8_t slot_count = 0U;
	uint8_t eligible = 0U;
	stse_ReturnCode_t status;

	status = stsafea_query_symmetric_key_slots_count(handler, &slot_count);
	if (status != STSE_OK) {
		return stsephyr_stse_to_errno(status);
	}
	if ((slot_count == 0U) || (slot_count > ARRAY_SIZE(slots))) {
		return -EOVERFLOW;
	}

	memset(slots, 0, sizeof(slots));
	status = stsafea_query_symmetric_key_table(handler, slot_count, slots);
	if (status != STSE_OK) {
		return stsephyr_stse_to_errno(status);
	}

	for (uint8_t slot = 0U; slot < slot_count; ++slot) {
		if (slots[slot].key_presence != 0U) {
			continue;
		}
		status = stsafea_query_symmetric_key_slot_provisioning_ctrl_fields(handler, slot,
										   &controls);
		if (status != STSE_OK) {
			return stsephyr_stse_to_errno(status);
		}
		if (controls.derived != 0U) {
			eligible++;
		}
	}

	LOG_INF("TLS slot preflight: %u empty derivation-enabled slots, %u required", eligible,
		TLS13_REQUIRED_EMPTY_SLOTS);
	return eligible >= TLS13_REQUIRED_EMPTY_SLOTS ? 0 : -ENOSPC;
}

static int extract_command_key(stse_Handler_t *handler, uint8_t *input_key,
			       const uint8_t *command_salt, uint8_t salt_slot,
			       uint8_t *destination_slot)
{
	stsafea_hkdf_input_key_t input = {
		.source = STSAFEA_KEY_SOURCE_COMMAND,
		.command =
			{
				.mode_of_operation = STSAFEA_KEY_OPERATION_MODE_HKDF,
				.length = STSEPHYR_TLS13_SHA256_SIZE,
				.data = input_key,
			},
	};
	stsafea_hkdf_salt_t salt = {0};
	stsafea_hkdf_output_t output = {0};
	stse_ReturnCode_t status;

	if (command_salt != NULL) {
		salt.source = STSAFEA_KEY_SOURCE_COMMAND;
		salt.command.length = STSEPHYR_TLS13_SHA256_SIZE;
		salt.command.data = (uint8_t *)command_salt;
	} else {
		salt.source = STSAFEA_KEY_SOURCE_SYMMKEY;
		salt.symmkey.slot_number = salt_slot;
	}
	status = stsafea_derive_keys(handler, &input, 1U, 0U, &salt, NULL, NULL, 0U, &output);
	if (status != STSE_OK) {
		LOG_ERR("TLS HKDF-Extract failed (0x%04x)", status);
		return stsephyr_stse_to_errno(status);
	}
	*destination_slot = output.prk_slot;
	return 0;
}

static int expand_to_slot(stse_Handler_t *handler, uint8_t source_slot, uint8_t *info,
			  uint16_t info_length,
			  stsafe_output_key_description_information_t *key_info,
			  uint8_t *destination_slot)
{
	stsafea_hkdf_input_key_t input = {
		.source = STSAFEA_KEY_SOURCE_SYMMKEY,
		.symmkey = {.slot_number = source_slot},
	};
	stsafea_hkdf_info_t hkdf_info = {.length = info_length, .data = info};
	stsafea_hkdf_okm_description_t map = {
		.destination = STSAFEA_KEY_SOURCE_SYMMKEY,
		.symmkey = {.key_info = key_info},
	};
	stsafea_hkdf_derived_key_output_t derived = {0};
	stsafea_hkdf_output_t output = {.derived_keys = &derived};
	stse_ReturnCode_t status;

	status = stsafea_derive_keys(handler, &input, 0U, 1U, NULL, &hkdf_info, &map, 1U, &output);
	if (status != STSE_OK) {
		LOG_ERR("TLS HKDF-Expand-to-slot failed (0x%04x)", status);
		return stsephyr_stse_to_errno(status);
	}
	*destination_slot = derived.symmkey.slot_number;
	return 0;
}

static int expand_to_host(stse_Handler_t *handler, uint8_t source_slot, uint8_t *info,
			  uint16_t info_length, uint8_t *output_key, uint16_t output_length)
{
	stsafea_hkdf_input_key_t input = {
		.source = STSAFEA_KEY_SOURCE_SYMMKEY,
		.symmkey = {.slot_number = source_slot},
	};
	stsafea_hkdf_info_t hkdf_info = {.length = info_length, .data = info};
	stsafea_hkdf_okm_description_t map = {
		.destination = STSAFEA_KEY_SOURCE_RESPONSE,
		.response = {.key_length = output_length},
	};
	stsafea_hkdf_derived_key_output_t derived = {.response = {.data = output_key}};
	stsafea_hkdf_output_t output = {.derived_keys = &derived};
	stse_ReturnCode_t status;

	status = stsafea_derive_keys(handler, &input, 0U, 1U, NULL, &hkdf_info, &map, 1U, &output);
	if (status != STSE_OK) {
		LOG_ERR("TLS HKDF-Expand-to-host failed (0x%04x)", status);
	}
	return status == STSE_OK ? 0 : stsephyr_stse_to_errno(status);
}

static void make_hkdf_key_info(stsafe_output_key_description_information_t *key_info)
{
	memset(key_info, 0, sizeof(*key_info));
	key_info->info_length = STSAFEA_KEY_INFO_LENGTH_HKDF - 1U;
	key_info->lock_indicator = STSAFEA_SYMMETRIC_KEY_LOCK_INDICATOR_ERASABLE;
	key_info->type = STSAFEA_SYMMETRIC_KEY_TYPE_GENERIC_SECRET;
	key_info->mode_of_operation = STSAFEA_KEY_OPERATION_MODE_HKDF;
	key_info->usage.derive = 1U;
	key_info->HKDF.allow_derived_key_to_host = 1U;
	key_info->HKDF.generic_secret_key_length = STSEPHYR_TLS13_SHA256_SIZE;
}

static int derive_secret(stse_Handler_t *handler, struct stsephyr_tls13_client_context *context,
			 uint8_t source_slot, const char *label, const uint8_t *transcript_hash,
			 uint8_t *destination_slot)
{
	uint8_t hkdf_label[TLS13_HKDF_LABEL_MAX_SIZE];
	uint16_t hkdf_label_length;
	stsafe_output_key_description_information_t key_info;
	int ret;

	ret = make_hkdf_label(STSEPHYR_TLS13_SHA256_SIZE, label, transcript_hash,
			      STSEPHYR_TLS13_SHA256_SIZE, hkdf_label, sizeof(hkdf_label),
			      &hkdf_label_length);
	if (ret == 0) {
		make_hkdf_key_info(&key_info);
		ret = expand_to_slot(handler, source_slot, hkdf_label, hkdf_label_length, &key_info,
				     destination_slot);
	}
	secure_zero(hkdf_label, sizeof(hkdf_label));
	if (ret == 0) {
		ret = track_slot(context, *destination_slot);
	}
	return ret;
}

static int derive_gcm_key(stse_Handler_t *handler, struct stsephyr_tls13_client_context *context,
			  uint8_t traffic_slot, bool encrypt, uint8_t *key_slot)
{
	uint8_t hkdf_label[TLS13_HKDF_LABEL_MAX_SIZE];
	uint16_t hkdf_label_length;
	stsafe_output_key_description_information_t key_info;
	int ret;

	ret = make_hkdf_label(STSEPHYR_TLS13_AES_128_KEY_SIZE, "key", NULL, 0U, hkdf_label,
			      sizeof(hkdf_label), &hkdf_label_length);
	if (ret == 0) {
		memset(&key_info, 0, sizeof(key_info));
		key_info.info_length = STSAFEA_KEY_INFO_LENGTH_GCM - 1U;
		key_info.lock_indicator = STSAFEA_SYMMETRIC_KEY_LOCK_INDICATOR_ERASABLE;
		key_info.type = STSAFEA_SYMMETRIC_KEY_TYPE_AES_128;
		key_info.mode_of_operation = STSAFEA_KEY_OPERATION_MODE_GCM;
		key_info.usage.encryption = encrypt ? 1U : 0U;
		key_info.usage.decryption = encrypt ? 0U : 1U;
		key_info.GCM.auth_tag_length = STSEPHYR_TLS13_GCM_TAG_SIZE;
		ret = expand_to_slot(handler, traffic_slot, hkdf_label, hkdf_label_length,
				     &key_info, key_slot);
	}
	secure_zero(hkdf_label, sizeof(hkdf_label));
	if (ret == 0) {
		ret = track_slot(context, *key_slot);
	}
	return ret;
}

static int derive_finished_key(stse_Handler_t *handler,
			       struct stsephyr_tls13_client_context *context, uint8_t traffic_slot,
			       bool generate, uint8_t *key_slot)
{
	uint8_t hkdf_label[TLS13_HKDF_LABEL_MAX_SIZE];
	uint16_t hkdf_label_length;
	stsafe_output_key_description_information_t key_info;
	int ret;

	ret = make_hkdf_label(STSEPHYR_TLS13_SHA256_SIZE, "finished", NULL, 0U, hkdf_label,
			      sizeof(hkdf_label), &hkdf_label_length);
	if (ret == 0) {
		memset(&key_info, 0, sizeof(key_info));
		key_info.info_length = STSAFEA_KEY_INFO_LENGTH_HMAC - 1U;
		key_info.lock_indicator = STSAFEA_SYMMETRIC_KEY_LOCK_INDICATOR_ERASABLE;
		key_info.type = STSAFEA_SYMMETRIC_KEY_TYPE_GENERIC_SECRET;
		key_info.mode_of_operation = STSAFEA_KEY_OPERATION_MODE_HMAC;
		key_info.usage.mac_generation = generate ? 1U : 0U;
		key_info.usage.mac_verification = generate ? 0U : 1U;
		key_info.HMAC.min_MAC_length = STSEPHYR_TLS13_SHA256_SIZE;
		key_info.HMAC.generic_secret_key_length = STSEPHYR_TLS13_SHA256_SIZE;
		ret = expand_to_slot(handler, traffic_slot, hkdf_label, hkdf_label_length,
				     &key_info, key_slot);
	}
	secure_zero(hkdf_label, sizeof(hkdf_label));
	if (ret == 0) {
		ret = track_slot(context, *key_slot);
	}
	return ret;
}

static int derive_iv(stse_Handler_t *handler, uint8_t traffic_slot,
		     uint8_t iv[STSEPHYR_TLS13_GCM_IV_SIZE])
{
	uint8_t hkdf_label[TLS13_HKDF_LABEL_MAX_SIZE];
	uint16_t hkdf_label_length;
	int ret;

	ret = make_hkdf_label(STSEPHYR_TLS13_GCM_IV_SIZE, "iv", NULL, 0U, hkdf_label,
			      sizeof(hkdf_label), &hkdf_label_length);
	if (ret == 0) {
		ret = expand_to_host(handler, traffic_slot, hkdf_label, hkdf_label_length, iv,
				     STSEPHYR_TLS13_GCM_IV_SIZE);
	}
	secure_zero(hkdf_label, sizeof(hkdf_label));
	return ret;
}

static int
derive_traffic_bundle(stse_Handler_t *handler, struct stsephyr_tls13_client_context *context,
		      uint8_t secret_slot, const char *traffic_label,
		      const uint8_t transcript_hash[STSEPHYR_TLS13_SHA256_SIZE], bool client,
		      bool with_finished, uint8_t *traffic_slot, uint8_t *write_key_slot,
		      uint8_t write_iv[STSEPHYR_TLS13_GCM_IV_SIZE], uint8_t *finished_slot)
{
	int ret;

	ret = derive_secret(handler, context, secret_slot, traffic_label, transcript_hash,
			    traffic_slot);
	if (ret == 0) {
		ret = derive_gcm_key(handler, context, *traffic_slot, client, write_key_slot);
	}
	if (ret == 0) {
		ret = derive_iv(handler, *traffic_slot, write_iv);
	}
	if ((ret == 0) && with_finished) {
		ret = derive_finished_key(handler, context, *traffic_slot, client, finished_slot);
	}
	return ret;
}

static void make_nonce(const uint8_t iv[STSEPHYR_TLS13_GCM_IV_SIZE], uint64_t sequence_number,
		       uint8_t nonce[STSEPHYR_TLS13_GCM_IV_SIZE])
{
	memcpy(nonce, iv, STSEPHYR_TLS13_GCM_IV_SIZE);
	for (size_t i = 0U; i < sizeof(sequence_number); ++i) {
		nonce[STSEPHYR_TLS13_GCM_IV_SIZE - 1U - i] ^=
			(uint8_t)(sequence_number >> (i * 8U));
	}
}

void stsephyr_tls13_client_context_init(struct stsephyr_tls13_client_context *context)
{
	if (context == NULL) {
		return;
	}
	memset(context, 0, sizeof(*context));
	memset(context->temporary_slots, TLS13_SLOT_INVALID, sizeof(context->temporary_slots));
	context->handshake_secret_slot = TLS13_SLOT_INVALID;
	context->client_traffic_secret_slot = TLS13_SLOT_INVALID;
	context->server_traffic_secret_slot = TLS13_SLOT_INVALID;
	context->client_finished_key_slot = TLS13_SLOT_INVALID;
	context->server_finished_key_slot = TLS13_SLOT_INVALID;
	context->client_write_key_slot = TLS13_SLOT_INVALID;
	context->server_write_key_slot = TLS13_SLOT_INVALID;
	context->phase = STSEPHYR_TLS13_PHASE_EMPTY;
}

int stsephyr_tls13_client_handshake_setup(
	stse_Handler_t *handler, uint8_t private_key_slot,
	const uint8_t server_public_key[STSEPHYR_TLS13_P256_PUBLIC_KEY_SIZE],
	const uint8_t hello_transcript_hash[STSEPHYR_TLS13_SHA256_SIZE],
	struct stsephyr_tls13_client_context *context)
{
	uint8_t shared_secret[STSEPHYR_TLS13_SHA256_SIZE];
	stse_ReturnCode_t status;
	int ret;

	if ((handler == NULL) || (server_public_key == NULL) || (hello_transcript_hash == NULL) ||
	    (context == NULL)) {
		return -EINVAL;
	}
	if (context->phase != STSEPHYR_TLS13_PHASE_EMPTY) {
		return -EALREADY;
	}
	for (size_t i = 0; i < ARRAY_SIZE(context->temporary_slots); ++i) {
		if (context->temporary_slots[i] != TLS13_SLOT_INVALID) {
			return -EALREADY;
		}
	}
	ret = preflight_empty_derived_slots(handler);
	if (ret != 0) {
		return ret;
	}

	LOG_INF("TLS ECDHE: Establish Key using private slot 0x%02x", private_key_slot);
	status = stse_ecc_establish_shared_secret(handler, private_key_slot, STSE_ECC_KT_NIST_P_256,
						  (uint8_t *)server_public_key, shared_secret);
	if (status != STSE_OK) {
		secure_zero(shared_secret, sizeof(shared_secret));
		return stsephyr_stse_to_errno(status);
	}
	LOG_INF("TLS ECDHE: importing returned Z directly into STSAFE HKDF-Extract");
	ret = extract_command_key(handler, shared_secret, tls13_derived_early_secret,
				  TLS13_SLOT_INVALID, &context->handshake_secret_slot);
	secure_zero(shared_secret, sizeof(shared_secret));
	if (ret != 0) {
		return ret;
	}
	ret = track_slot(context, context->handshake_secret_slot);
	if (ret != 0) {
		goto cleanup;
	}

	ret = derive_traffic_bundle(handler, context, context->handshake_secret_slot,
				    "c hs traffic", hello_transcript_hash, true, true,
				    &context->client_traffic_secret_slot,
				    &context->client_write_key_slot, context->client_write_iv,
				    &context->client_finished_key_slot);
	if (ret != 0) {
		goto cleanup;
	}
	ret = derive_traffic_bundle(handler, context, context->handshake_secret_slot,
				    "s hs traffic", hello_transcript_hash, false, true,
				    &context->server_traffic_secret_slot,
				    &context->server_write_key_slot, context->server_write_iv,
				    &context->server_finished_key_slot);
	if (ret != 0) {
		goto cleanup;
	}
	context->phase = STSEPHYR_TLS13_PHASE_HANDSHAKE;
	LOG_INF("TLS handshake slots: secret=%u c_traffic=%u s_traffic=%u c_key=%u s_key=%u "
		"c_finished=%u s_finished=%u",
		context->handshake_secret_slot, context->client_traffic_secret_slot,
		context->server_traffic_secret_slot, context->client_write_key_slot,
		context->server_write_key_slot, context->client_finished_key_slot,
		context->server_finished_key_slot);
	return 0;

cleanup:
	(void)stsephyr_tls13_client_context_release(handler, context);
	return ret;
}

int stsephyr_tls13_verify_server_certificate_verify(
	stse_Handler_t *handler,
	const uint8_t server_signing_public_key[STSEPHYR_TLS13_P256_PUBLIC_KEY_SIZE],
	const uint8_t transcript_hash[STSEPHYR_TLS13_SHA256_SIZE],
	const uint8_t signature[STSEPHYR_TLS13_P256_SIGNATURE_SIZE])
{
	static const char context_string[] = "TLS 1.3, server CertificateVerify";
	uint8_t content[64U + sizeof(context_string) + STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t digest[STSEPHYR_TLS13_SHA256_SIZE];
	uint16_t digest_length = sizeof(digest);
	uint8_t validity = 0U;
	stse_ReturnCode_t status;
	size_t offset = 0U;

	if ((handler == NULL) || (server_signing_public_key == NULL) || (transcript_hash == NULL) ||
	    (signature == NULL)) {
		return -EINVAL;
	}
	memset(content, 0x20, 64U);
	offset += 64U;
	memcpy(&content[offset], context_string, sizeof(context_string) - 1U);
	offset += sizeof(context_string) - 1U;
	content[offset++] = 0U;
	memcpy(&content[offset], transcript_hash, STSEPHYR_TLS13_SHA256_SIZE);
	offset += STSEPHYR_TLS13_SHA256_SIZE;

	/* The A120 ECDSA verify command consumes a digest, not the signed message. */
	status = stse_compute_hash(handler, STSE_SHA_256, content, (uint16_t)offset, digest,
				   &digest_length);
	if (status == STSE_OK && digest_length == sizeof(digest)) {
		status = stse_ecc_verify_signature(handler, STSE_ECC_KT_NIST_P_256,
						   server_signing_public_key, signature, digest,
						   sizeof(digest), 0U, &validity);
	}
	secure_zero(content, sizeof(content));
	secure_zero(digest, sizeof(digest));
	if (status != STSE_OK) {
		return stsephyr_stse_to_errno(status);
	}
	return validity == STSAFEA_TRUE ? 0 : -EBADMSG;
}

int stsephyr_tls13_verify_server_finished(stse_Handler_t *handler,
					  struct stsephyr_tls13_client_context *context,
					  const uint8_t transcript_hash[STSEPHYR_TLS13_SHA256_SIZE],
					  const uint8_t verify_data[STSEPHYR_TLS13_SHA256_SIZE])
{
	uint8_t verification = 0U;
	stse_ReturnCode_t status;

	if ((handler == NULL) || (context == NULL) || (transcript_hash == NULL) ||
	    (verify_data == NULL) || (context->phase != STSEPHYR_TLS13_PHASE_HANDSHAKE)) {
		return -EINVAL;
	}
	status = stse_cmac_hmac_verify(handler, context->server_finished_key_slot,
				       (uint8_t *)verify_data, STSEPHYR_TLS13_SHA256_SIZE,
				       (uint8_t *)transcript_hash, STSEPHYR_TLS13_SHA256_SIZE,
				       &verification);
	if (status != STSE_OK) {
		return stsephyr_stse_to_errno(status);
	}
	if (verification != STSAFEA_TRUE) {
		return -EBADMSG;
	}
	context->server_finished_verified = true;
	return 0;
}

int stsephyr_tls13_generate_client_finished(
	stse_Handler_t *handler, struct stsephyr_tls13_client_context *context,
	const uint8_t transcript_hash[STSEPHYR_TLS13_SHA256_SIZE],
	uint8_t verify_data[STSEPHYR_TLS13_SHA256_SIZE])
{
	stse_ReturnCode_t status;

	if ((handler == NULL) || (context == NULL) || (transcript_hash == NULL) ||
	    (verify_data == NULL) || (context->phase != STSEPHYR_TLS13_PHASE_HANDSHAKE) ||
	    !context->server_finished_verified) {
		return -EINVAL;
	}
	status = stse_cmac_hmac_compute(handler, context->client_finished_key_slot,
					(uint8_t *)transcript_hash, STSEPHYR_TLS13_SHA256_SIZE,
					verify_data, STSEPHYR_TLS13_SHA256_SIZE);
	if (status != STSE_OK) {
		return stsephyr_stse_to_errno(status);
	}
	context->client_finished_generated = true;
	return 0;
}

int stsephyr_tls13_client_application_setup(
	stse_Handler_t *handler, struct stsephyr_tls13_client_context *context,
	const uint8_t transcript_hash[STSEPHYR_TLS13_SHA256_SIZE])
{
	uint8_t derived_slot = TLS13_SLOT_INVALID;
	uint8_t master_slot = TLS13_SLOT_INVALID;
	uint8_t zeros[STSEPHYR_TLS13_SHA256_SIZE] = {0};
	int ret;

	if ((handler == NULL) || (context == NULL) || (transcript_hash == NULL) ||
	    (context->phase != STSEPHYR_TLS13_PHASE_HANDSHAKE) ||
	    !context->server_finished_verified || !context->client_finished_generated) {
		return -EINVAL;
	}

	ret = derive_secret(handler, context, context->handshake_secret_slot, "derived",
			    sha256_empty_hash, &derived_slot);
	if (ret == 0) {
		ret = extract_command_key(handler, zeros, NULL, derived_slot, &master_slot);
	}
	secure_zero(zeros, sizeof(zeros));
	if (ret == 0) {
		ret = track_slot(context, master_slot);
	}
	if (ret != 0) {
		goto cleanup;
	}

	/* Master is now sufficient; retire every handshake-generation key. */
	ret = erase_slot(handler, context, &context->client_finished_key_slot);
	ret = ret == 0 ? erase_slot(handler, context, &context->server_finished_key_slot) : ret;
	ret = ret == 0 ? erase_slot(handler, context, &context->client_write_key_slot) : ret;
	ret = ret == 0 ? erase_slot(handler, context, &context->server_write_key_slot) : ret;
	ret = ret == 0 ? erase_slot(handler, context, &context->client_traffic_secret_slot) : ret;
	ret = ret == 0 ? erase_slot(handler, context, &context->server_traffic_secret_slot) : ret;
	ret = ret == 0 ? erase_slot(handler, context, &context->handshake_secret_slot) : ret;
	ret = ret == 0 ? erase_slot(handler, context, &derived_slot) : ret;
	if (ret != 0) {
		goto cleanup;
	}
	secure_zero(context->client_write_iv, sizeof(context->client_write_iv));
	secure_zero(context->server_write_iv, sizeof(context->server_write_iv));

	ret = derive_traffic_bundle(handler, context, master_slot, "c ap traffic", transcript_hash,
				    true, false, &context->client_traffic_secret_slot,
				    &context->client_write_key_slot, context->client_write_iv,
				    NULL);
	if (ret == 0) {
		ret = derive_traffic_bundle(
			handler, context, master_slot, "s ap traffic", transcript_hash, false,
			false, &context->server_traffic_secret_slot,
			&context->server_write_key_slot, context->server_write_iv, NULL);
	}
	if (ret == 0) {
		ret = erase_slot(handler, context, &master_slot);
	}
	if (ret != 0) {
		goto cleanup;
	}

	context->phase = STSEPHYR_TLS13_PHASE_APPLICATION;
	LOG_INF("TLS application slots: c_traffic=%u s_traffic=%u c_key=%u s_key=%u",
		context->client_traffic_secret_slot, context->server_traffic_secret_slot,
		context->client_write_key_slot, context->server_write_key_slot);
	return 0;

cleanup:
	(void)stsephyr_tls13_client_context_release(handler, context);
	return ret;
}

int stsephyr_tls13_client_encrypt(stse_Handler_t *handler,
				  const struct stsephyr_tls13_client_context *context,
				  uint64_t sequence_number, const uint8_t *associated_data,
				  size_t associated_data_length, const uint8_t *plaintext,
				  size_t plaintext_length, uint8_t *ciphertext,
				  uint8_t tag[STSEPHYR_TLS13_GCM_TAG_SIZE])
{
	uint8_t nonce[STSEPHYR_TLS13_GCM_IV_SIZE];
	stse_ReturnCode_t status;

	if ((handler == NULL) || (context == NULL) ||
	    (context->phase != STSEPHYR_TLS13_PHASE_HANDSHAKE &&
	     context->phase != STSEPHYR_TLS13_PHASE_APPLICATION) ||
	    ((associated_data == NULL) && (associated_data_length != 0U)) ||
	    ((plaintext == NULL) && (plaintext_length != 0U)) || (ciphertext == NULL) ||
	    (tag == NULL) || (associated_data_length > UINT16_MAX) ||
	    (plaintext_length > UINT16_MAX)) {
		return -EINVAL;
	}
	make_nonce(context->client_write_iv, sequence_number, nonce);
	status = stse_aes_gcm_encrypt(
		handler, context->client_write_key_slot, STSEPHYR_TLS13_GCM_TAG_SIZE, sizeof(nonce),
		nonce, (uint16_t)associated_data_length, (uint8_t *)associated_data,
		(uint16_t)plaintext_length, (uint8_t *)plaintext, ciphertext, tag);
	secure_zero(nonce, sizeof(nonce));
	return status == STSE_OK ? 0 : stsephyr_stse_to_errno(status);
}

int stsephyr_tls13_client_decrypt(stse_Handler_t *handler,
				  const struct stsephyr_tls13_client_context *context,
				  uint64_t sequence_number, const uint8_t *associated_data,
				  size_t associated_data_length, const uint8_t *ciphertext,
				  size_t ciphertext_length,
				  const uint8_t tag[STSEPHYR_TLS13_GCM_TAG_SIZE],
				  uint8_t *plaintext)
{
	uint8_t nonce[STSEPHYR_TLS13_GCM_IV_SIZE];
	uint8_t verification = 0U;
	stse_ReturnCode_t status;

	if ((handler == NULL) || (context == NULL) ||
	    (context->phase != STSEPHYR_TLS13_PHASE_HANDSHAKE &&
	     context->phase != STSEPHYR_TLS13_PHASE_APPLICATION) ||
	    ((associated_data == NULL) && (associated_data_length != 0U)) ||
	    ((ciphertext == NULL) && (ciphertext_length != 0U)) || (tag == NULL) ||
	    (plaintext == NULL) || (associated_data_length > UINT16_MAX) ||
	    (ciphertext_length > UINT16_MAX)) {
		return -EINVAL;
	}
	make_nonce(context->server_write_iv, sequence_number, nonce);
	status = stse_aes_gcm_decrypt(handler, context->server_write_key_slot,
				      STSEPHYR_TLS13_GCM_TAG_SIZE, sizeof(nonce), nonce,
				      (uint16_t)associated_data_length, (uint8_t *)associated_data,
				      (uint16_t)ciphertext_length, (uint8_t *)ciphertext,
				      (uint8_t *)tag, &verification, plaintext);
	secure_zero(nonce, sizeof(nonce));
	if (status != STSE_OK || verification != STSAFEA_TRUE) {
		secure_zero(plaintext, ciphertext_length);
	}
	if (status != STSE_OK) {
		return stsephyr_stse_to_errno(status);
	}
	return verification == STSAFEA_TRUE ? 0 : -EBADMSG;
}

int stsephyr_tls13_client_context_release(stse_Handler_t *handler,
					  struct stsephyr_tls13_client_context *context)
{
	int result = 0;

	if ((handler == NULL) || (context == NULL)) {
		return -EINVAL;
	}
	/* Failed erasure preserves slot IDs for retry, but keys must no longer be used. */
	context->phase = STSEPHYR_TLS13_PHASE_FAILED;
	for (size_t i = 0U; i < ARRAY_SIZE(context->temporary_slots); ++i) {
		stse_ReturnCode_t status;

		if (context->temporary_slots[i] == TLS13_SLOT_INVALID) {
			continue;
		}
		status = stsafea_erase_symmetric_key_slot(handler, context->temporary_slots[i]);
		if (status == STSE_OK) {
			context->temporary_slots[i] = TLS13_SLOT_INVALID;
		} else if (result == 0) {
			result = stsephyr_stse_to_errno(status);
		}
	}
	if (result == 0) {
		stsephyr_tls13_client_context_init(context);
	}
	return result;
}
