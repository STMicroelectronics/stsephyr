/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 *
 * Runs the client side of a TLS 1.3 (TLS_AES_128_GCM_SHA256, P-256) key schedule
 * and record protection inside the STSAFE-A120, and checks every result against
 * a mock server implemented with PSA Crypto on the same MCU. There is no network
 * and no real TLS stack: see README.md for the limitations.
 */

#include "sample_common.h"

#include <stdbool.h>
#include <string.h>

#include <psa/crypto.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include "tls13.h"
#include <api/stse_hash.h>
#include <api/stse_random.h>

#define TLS13_EPHEMERAL_SLOT		 0xFFU
#define P256_PUBLIC_KEY_WITH_PREFIX_SIZE (STSEPHYR_TLS13_P256_PUBLIC_KEY_SIZE + 1U)
#define TLS_RECORD_HEADER_SIZE		 5U
#define MOCK_TRANSCRIPT_CAPACITY	 512U

struct mock_server_secrets {
	uint8_t handshake_secret[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t client_handshake_traffic[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t server_handshake_traffic[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t client_finished_key[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t server_finished_key[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t client_handshake_key[STSEPHYR_TLS13_AES_128_KEY_SIZE];
	uint8_t server_handshake_key[STSEPHYR_TLS13_AES_128_KEY_SIZE];
	uint8_t client_handshake_iv[STSEPHYR_TLS13_GCM_IV_SIZE];
	uint8_t server_handshake_iv[STSEPHYR_TLS13_GCM_IV_SIZE];
	uint8_t client_application_key[STSEPHYR_TLS13_AES_128_KEY_SIZE];
	uint8_t server_application_key[STSEPHYR_TLS13_AES_128_KEY_SIZE];
	uint8_t client_application_iv[STSEPHYR_TLS13_GCM_IV_SIZE];
	uint8_t server_application_iv[STSEPHYR_TLS13_GCM_IV_SIZE];
};

static void secure_zero(void *buffer, size_t length)
{
	volatile uint8_t *cursor = buffer;

	while (length-- > 0U) {
		*cursor++ = 0U;
	}
}

static int64_t stage_start(unsigned int number, const char *name)
{
	int64_t now = k_uptime_get();

	printk("\n[%lld ms] Stage %u: %s\n", now, number, name);
	return now;
}

static void stage_complete(int64_t started)
{
	printk(" - Stage completed in %lld ms\n", k_uptime_get() - started);
}

static int hex_decode(const char *hex, uint8_t *data, size_t length)
{
	if (strlen(hex) != 2U * length) {
		return -1;
	}
	for (size_t i = 0U; i < 2U * length; i++) {
		char c = hex[i];
		uint8_t nibble;

		if (c >= '0' && c <= '9') {
			nibble = c - '0';
		} else if (c >= 'a' && c <= 'f') {
			nibble = c - 'a' + 10;
		} else if (c >= 'A' && c <= 'F') {
			nibble = c - 'A' + 10;
		} else {
			return -1;
		}
		data[i / 2U] = (i % 2U) == 0U ? nibble << 4 : data[i / 2U] | nibble;
	}
	return 0;
}

static int load_host_keys(stsafea_aes_128_host_keys_t *keys)
{
	if (hex_decode(CONFIG_SAMPLE_STSAFE_HOST_MAC_KEY_HEX, keys->host_mac_key,
		       STSAFEA_HOST_AES_128_MAC_KEY_SIZE) != 0 ||
	    hex_decode(CONFIG_SAMPLE_STSAFE_HOST_CIPHER_KEY_HEX, keys->host_cipher_key,
		       STSAFEA_HOST_AES_128_CIPHER_KEY_SIZE) != 0) {
		return -1;
	}
	return 0;
}

/* Opening a session only stores the keys; the device checks them on the first protected command. */
static stse_ReturnCode_t open_host_session(stse_Handler_t *handler, stse_session_t *session,
					   stsafea_aes_128_host_keys_t *keys)
{
	stsafea_host_key_slot_v2_t slot;
	stse_ReturnCode_t status = stsafea_query_host_key_v2(handler, &slot);

	if (status != STSE_OK) {
		return status;
	}
	if (slot.key_presence_flag == 0U || slot.key_type != STSE_AES_128_KT) {
		printk("FAIL: the device has no AES-128 host keys\n");
		return STSE_SERVICE_INVALID_PARAMETER;
	}
	return stsafea_open_host_session(handler, session, keys->host_mac_key,
					 keys->host_cipher_key);
}

static int psa_check(const char *operation, psa_status_t status)
{
	if (status != PSA_SUCCESS) {
		printk("FAIL: %s returned PSA status %d\n", operation, (int)status);
		return -1;
	}
	return 0;
}

static int audit_symmetric_slots(stse_Handler_t *handler)
{
	stsafea_symmetric_key_slot_information_t slots[32];
	stsafea_symmetric_key_slot_provisioning_ctrl_fields_t controls;
	uint8_t slot_count;
	uint8_t eligible = 0U;
	uint8_t occupied = 0U;
	stse_ReturnCode_t status;

	status = stsafea_query_symmetric_key_slots_count(handler, &slot_count);
	if ((status != STSE_OK) || (slot_count > ARRAY_SIZE(slots))) {
		return -1;
	}
	memset(slots, 0, sizeof(slots));
	status = stsafea_query_symmetric_key_table(handler, slot_count, slots);
	if (status != STSE_OK) {
		return -1;
	}

	printk(" - Symmetric key table: %u slots\n", slot_count);
	printk(" - slot | present | lock | derived | plaintext | mode\n");
	for (uint8_t slot = 0U; slot < slot_count; ++slot) {
		status = stsafea_query_symmetric_key_slot_provisioning_ctrl_fields(handler, slot,
										   &controls);
		if (status != STSE_OK) {
			return -1;
		}
		printk("     %2u |    %u    |  %u   |    %u    |     %u     | %u\n", slot,
		       slots[slot].key_presence, slots[slot].lock_indicator, controls.derived,
		       controls.plaintext, slots[slot].mode_of_operation);
		occupied += slots[slot].key_presence != 0U ? 1U : 0U;
		eligible += (slots[slot].key_presence == 0U) && (controls.derived != 0U) ? 1U : 0U;
	}
	printk(" - Audit result: %u occupied, %u empty derivation-enabled; %u required\n", occupied,
	       eligible, STSEPHYR_TLS13_MAX_TEMPORARY_SLOTS);
	return eligible >= STSEPHYR_TLS13_MAX_TEMPORARY_SLOTS ? 0 : -1;
}

static int append_handshake(uint8_t *transcript, size_t *transcript_length, uint8_t type,
			    const uint8_t *body, size_t body_length)
{
	size_t offset = *transcript_length;

	if ((body_length > 0xFFFFFFU) || ((offset + 4U + body_length) > MOCK_TRANSCRIPT_CAPACITY)) {
		return -1;
	}
	transcript[offset++] = type;
	transcript[offset++] = (uint8_t)(body_length >> 16);
	transcript[offset++] = (uint8_t)(body_length >> 8);
	transcript[offset++] = (uint8_t)body_length;
	memcpy(&transcript[offset], body, body_length);
	*transcript_length = offset + body_length;
	return 0;
}

static int transcript_hash(stse_Handler_t *handler, const uint8_t *transcript,
			   size_t transcript_length, uint8_t digest[STSEPHYR_TLS13_SHA256_SIZE])
{
	uint8_t reference[STSEPHYR_TLS13_SHA256_SIZE];
	uint16_t digest_length = sizeof(reference);
	size_t reference_length = 0U;
	stse_ReturnCode_t status;
	psa_status_t psa_status;

	status = stse_compute_hash(handler, STSE_SHA_256, (uint8_t *)transcript,
				   (uint16_t)transcript_length, digest, &digest_length);
	psa_status = psa_hash_compute(PSA_ALG_SHA_256, transcript, transcript_length, reference,
				      sizeof(reference), &reference_length);
	if ((status != STSE_OK) || (psa_status != PSA_SUCCESS) ||
	    (digest_length != STSEPHYR_TLS13_SHA256_SIZE) ||
	    (reference_length != STSEPHYR_TLS13_SHA256_SIZE) ||
	    (memcmp(digest, reference, sizeof(reference)) != 0)) {
		secure_zero(reference, sizeof(reference));
		return -1;
	}
	secure_zero(reference, sizeof(reference));
	printk(" - Transcript: %u bytes; STSAFE SHA-256 matches PSA mock server\n",
	       (unsigned int)transcript_length);
	sample_print_hex("Transcript hash", digest, STSEPHYR_TLS13_SHA256_SIZE);
	return 0;
}

static int hmac_sha256(const uint8_t *key, size_t key_length, const uint8_t *input,
		       size_t input_length, uint8_t output[STSEPHYR_TLS13_SHA256_SIZE])
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	size_t output_length = 0U;
	psa_status_t status;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, key_length * 8U);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	status = psa_import_key(&attributes, key, key_length, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		return -1;
	}
	status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), input, input_length, output,
				 STSEPHYR_TLS13_SHA256_SIZE, &output_length);
	(void)psa_destroy_key(key_id);
	return (status == PSA_SUCCESS) && (output_length == STSEPHYR_TLS13_SHA256_SIZE) ? 0 : -1;
}

static int make_hkdf_label(uint16_t derived_length, const char *label, const uint8_t *context,
			   size_t context_length, uint8_t *output, size_t *encoded_length)
{
	static const char prefix[] = "tls13 ";
	size_t label_length = strlen(label);
	size_t full_label_length = (sizeof(prefix) - 1U) + label_length;
	size_t offset = 0U;

	if ((full_label_length > UINT8_MAX) || (context_length > UINT8_MAX)) {
		return -1;
	}
	output[offset++] = (uint8_t)(derived_length >> 8);
	output[offset++] = (uint8_t)derived_length;
	output[offset++] = (uint8_t)full_label_length;
	memcpy(&output[offset], prefix, sizeof(prefix) - 1U);
	offset += sizeof(prefix) - 1U;
	memcpy(&output[offset], label, label_length);
	offset += label_length;
	output[offset++] = (uint8_t)context_length;
	if (context_length != 0U) {
		memcpy(&output[offset], context, context_length);
		offset += context_length;
	}
	*encoded_length = offset;
	return 0;
}

static int hkdf_expand_label(const uint8_t prk[STSEPHYR_TLS13_SHA256_SIZE], const char *label,
			     const uint8_t *context, size_t context_length, uint8_t *output,
			     size_t output_length)
{
	uint8_t info[72];
	uint8_t input[73];
	uint8_t block[STSEPHYR_TLS13_SHA256_SIZE];
	size_t info_length;

	if ((output_length > sizeof(block)) ||
	    (make_hkdf_label((uint16_t)output_length, label, context, context_length, info,
			     &info_length) != 0)) {
		return -1;
	}
	memcpy(input, info, info_length);
	input[info_length] = 1U;
	if (hmac_sha256(prk, STSEPHYR_TLS13_SHA256_SIZE, input, info_length + 1U, block) != 0) {
		return -1;
	}
	memcpy(output, block, output_length);
	secure_zero(block, sizeof(block));
	secure_zero(input, sizeof(input));
	return 0;
}

static int derive_mock_handshake(const uint8_t shared_secret[STSEPHYR_TLS13_SHA256_SIZE],
				 const uint8_t transcript_digest[STSEPHYR_TLS13_SHA256_SIZE],
				 struct mock_server_secrets *secrets)
{
	uint8_t zeros[STSEPHYR_TLS13_SHA256_SIZE] = {0};
	uint8_t empty_hash[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t early_secret[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t derived_secret[STSEPHYR_TLS13_SHA256_SIZE];
	size_t hash_length;
	int ret = -1;

	if ((psa_hash_compute(PSA_ALG_SHA_256, NULL, 0U, empty_hash, sizeof(empty_hash),
			      &hash_length) != PSA_SUCCESS) ||
	    (hash_length != sizeof(empty_hash)) ||
	    (hmac_sha256(zeros, sizeof(zeros), zeros, sizeof(zeros), early_secret) != 0) ||
	    (hkdf_expand_label(early_secret, "derived", empty_hash, sizeof(empty_hash),
			       derived_secret, sizeof(derived_secret)) != 0) ||
	    (hmac_sha256(derived_secret, sizeof(derived_secret), shared_secret,
			 sizeof(secrets->handshake_secret), secrets->handshake_secret) != 0) ||
	    (hkdf_expand_label(secrets->handshake_secret, "c hs traffic", transcript_digest,
			       STSEPHYR_TLS13_SHA256_SIZE, secrets->client_handshake_traffic,
			       sizeof(secrets->client_handshake_traffic)) != 0) ||
	    (hkdf_expand_label(secrets->handshake_secret, "s hs traffic", transcript_digest,
			       STSEPHYR_TLS13_SHA256_SIZE, secrets->server_handshake_traffic,
			       sizeof(secrets->server_handshake_traffic)) != 0) ||
	    (hkdf_expand_label(secrets->client_handshake_traffic, "key", NULL, 0U,
			       secrets->client_handshake_key,
			       sizeof(secrets->client_handshake_key)) != 0) ||
	    (hkdf_expand_label(secrets->server_handshake_traffic, "key", NULL, 0U,
			       secrets->server_handshake_key,
			       sizeof(secrets->server_handshake_key)) != 0) ||
	    (hkdf_expand_label(secrets->client_handshake_traffic, "iv", NULL, 0U,
			       secrets->client_handshake_iv,
			       sizeof(secrets->client_handshake_iv)) != 0) ||
	    (hkdf_expand_label(secrets->server_handshake_traffic, "iv", NULL, 0U,
			       secrets->server_handshake_iv,
			       sizeof(secrets->server_handshake_iv)) != 0) ||
	    (hkdf_expand_label(secrets->client_handshake_traffic, "finished", NULL, 0U,
			       secrets->client_finished_key,
			       sizeof(secrets->client_finished_key)) != 0) ||
	    (hkdf_expand_label(secrets->server_handshake_traffic, "finished", NULL, 0U,
			       secrets->server_finished_key,
			       sizeof(secrets->server_finished_key)) != 0)) {
		goto out;
	}
	ret = 0;
out:
	secure_zero(early_secret, sizeof(early_secret));
	secure_zero(derived_secret, sizeof(derived_secret));
	return ret;
}

static int derive_mock_application(const uint8_t transcript_digest[STSEPHYR_TLS13_SHA256_SIZE],
				   struct mock_server_secrets *secrets)
{
	uint8_t zeros[STSEPHYR_TLS13_SHA256_SIZE] = {0};
	uint8_t empty_hash[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t derived_secret[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t master_secret[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t client_traffic[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t server_traffic[STSEPHYR_TLS13_SHA256_SIZE];
	size_t hash_length;
	int ret = -1;

	if ((psa_hash_compute(PSA_ALG_SHA_256, NULL, 0U, empty_hash, sizeof(empty_hash),
			      &hash_length) != PSA_SUCCESS) ||
	    (hkdf_expand_label(secrets->handshake_secret, "derived", empty_hash, sizeof(empty_hash),
			       derived_secret, sizeof(derived_secret)) != 0) ||
	    (hmac_sha256(derived_secret, sizeof(derived_secret), zeros, sizeof(zeros),
			 master_secret) != 0) ||
	    (hkdf_expand_label(master_secret, "c ap traffic", transcript_digest,
			       STSEPHYR_TLS13_SHA256_SIZE, client_traffic,
			       sizeof(client_traffic)) != 0) ||
	    (hkdf_expand_label(master_secret, "s ap traffic", transcript_digest,
			       STSEPHYR_TLS13_SHA256_SIZE, server_traffic,
			       sizeof(server_traffic)) != 0) ||
	    (hkdf_expand_label(client_traffic, "key", NULL, 0U, secrets->client_application_key,
			       sizeof(secrets->client_application_key)) != 0) ||
	    (hkdf_expand_label(server_traffic, "key", NULL, 0U, secrets->server_application_key,
			       sizeof(secrets->server_application_key)) != 0) ||
	    (hkdf_expand_label(client_traffic, "iv", NULL, 0U, secrets->client_application_iv,
			       sizeof(secrets->client_application_iv)) != 0) ||
	    (hkdf_expand_label(server_traffic, "iv", NULL, 0U, secrets->server_application_iv,
			       sizeof(secrets->server_application_iv)) != 0)) {
		goto out;
	}
	ret = 0;
out:
	secure_zero(derived_secret, sizeof(derived_secret));
	secure_zero(master_secret, sizeof(master_secret));
	secure_zero(client_traffic, sizeof(client_traffic));
	secure_zero(server_traffic, sizeof(server_traffic));
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

static int mock_aead(bool encrypt, const uint8_t key[STSEPHYR_TLS13_AES_128_KEY_SIZE],
		     const uint8_t iv[STSEPHYR_TLS13_GCM_IV_SIZE], uint64_t sequence_number,
		     const uint8_t header[TLS_RECORD_HEADER_SIZE], const uint8_t *input,
		     size_t input_length, uint8_t *output, size_t output_size,
		     size_t *output_length)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	uint8_t nonce[STSEPHYR_TLS13_GCM_IV_SIZE];
	psa_status_t status;

	make_nonce(iv, sequence_number, nonce);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, STSEPHYR_TLS13_AES_128_KEY_SIZE * 8U);
	psa_set_key_usage_flags(&attributes,
				encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
	status = psa_import_key(&attributes, key, STSEPHYR_TLS13_AES_128_KEY_SIZE, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status == PSA_SUCCESS) {
		if (encrypt) {
			status = psa_aead_encrypt(key_id, PSA_ALG_GCM, nonce, sizeof(nonce), header,
						  TLS_RECORD_HEADER_SIZE, input, input_length,
						  output, output_size, output_length);
		} else {
			status = psa_aead_decrypt(key_id, PSA_ALG_GCM, nonce, sizeof(nonce), header,
						  TLS_RECORD_HEADER_SIZE, input, input_length,
						  output, output_size, output_length);
		}
	}
	(void)psa_destroy_key(key_id);
	secure_zero(nonce, sizeof(nonce));
	return status == PSA_SUCCESS ? 0 : -1;
}

static void make_record_header(size_t plaintext_length, uint8_t header[TLS_RECORD_HEADER_SIZE])
{
	size_t wire_length = plaintext_length + STSEPHYR_TLS13_GCM_TAG_SIZE;

	header[0] = 0x17;
	header[1] = 0x03;
	header[2] = 0x03;
	header[3] = (uint8_t)(wire_length >> 8);
	header[4] = (uint8_t)wire_length;
}

static int
make_certificate_verify_content(const uint8_t transcript_digest[STSEPHYR_TLS13_SHA256_SIZE],
				uint8_t *content, size_t *content_length)
{
	static const char context_string[] = "TLS 1.3, server CertificateVerify";
	size_t offset = 0U;

	memset(content, 0x20, 64U);
	offset += 64U;
	memcpy(&content[offset], context_string, sizeof(context_string) - 1U);
	offset += sizeof(context_string) - 1U;
	content[offset++] = 0U;
	memcpy(&content[offset], transcript_digest, STSEPHYR_TLS13_SHA256_SIZE);
	*content_length = offset + STSEPHYR_TLS13_SHA256_SIZE;
	return 0;
}

static int exercise_record_pair(stse_Handler_t *handler,
				const struct stsephyr_tls13_client_context *context,
				const uint8_t client_key[STSEPHYR_TLS13_AES_128_KEY_SIZE],
				const uint8_t client_iv[STSEPHYR_TLS13_GCM_IV_SIZE],
				const uint8_t server_key[STSEPHYR_TLS13_AES_128_KEY_SIZE],
				const uint8_t server_iv[STSEPHYR_TLS13_GCM_IV_SIZE],
				const char *label)
{
	static const uint8_t client_plaintext[] = {
		'c', 'l', 'i', 'e', 'n', 't', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd', 0x17,
	};
	static const uint8_t server_plaintext[] = {
		's', 'e', 'r', 'v', 'e', 'r', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd', 0x17,
	};
	uint8_t header[TLS_RECORD_HEADER_SIZE];
	uint8_t wire[64];
	uint8_t ciphertext[32];
	uint8_t tag[STSEPHYR_TLS13_GCM_TAG_SIZE];
	uint8_t plaintext[32];
	size_t wire_length;
	size_t plaintext_length;

	make_record_header(sizeof(client_plaintext), header);
	if (stsephyr_tls13_client_encrypt(handler, context, 0U, header, sizeof(header),
					  client_plaintext, sizeof(client_plaintext), ciphertext,
					  tag) != 0) {
		return -1;
	}
	memcpy(wire, ciphertext, sizeof(client_plaintext));
	memcpy(&wire[sizeof(client_plaintext)], tag, sizeof(tag));
	if ((mock_aead(false, client_key, client_iv, 0U, header, wire,
		       sizeof(client_plaintext) + sizeof(tag), plaintext, sizeof(plaintext),
		       &plaintext_length) != 0) ||
	    (plaintext_length != sizeof(client_plaintext)) ||
	    (memcmp(plaintext, client_plaintext, sizeof(client_plaintext)) != 0)) {
		return -1;
	}
	printk(" - STSAFE encrypted the client %s record; PSA server authenticated it\n", label);
	sample_print_hex("Client TLSCiphertext", ciphertext, sizeof(client_plaintext));
	sample_print_hex("Client GCM tag", tag, sizeof(tag));

	make_record_header(sizeof(server_plaintext), header);
	if (mock_aead(true, server_key, server_iv, 0U, header, server_plaintext,
		      sizeof(server_plaintext), wire, sizeof(wire), &wire_length) != 0) {
		return -1;
	}
	if (wire_length != (sizeof(server_plaintext) + STSEPHYR_TLS13_GCM_TAG_SIZE)) {
		return -1;
	}
	if (stsephyr_tls13_client_decrypt(handler, context, 0U, header, sizeof(header), wire,
					  sizeof(server_plaintext), &wire[sizeof(server_plaintext)],
					  plaintext) != 0 ||
	    (memcmp(plaintext, server_plaintext, sizeof(server_plaintext)) != 0)) {
		return -1;
	}
	printk(" - STSAFE authenticated and decrypted the server %s record\n", label);
	sample_print_hex("Server TLSCiphertext", wire, sizeof(server_plaintext));
	sample_print_hex("Server GCM tag", &wire[sizeof(server_plaintext)],
			 STSEPHYR_TLS13_GCM_TAG_SIZE);
	return 0;
}

int main(void)
{
	static const uint8_t encrypted_extensions[] = "mock encrypted extensions";
	uint8_t transcript[MOCK_TRANSCRIPT_CAPACITY] = {0};
	uint8_t client_hello_body[32U + P256_PUBLIC_KEY_WITH_PREFIX_SIZE];
	uint8_t server_hello_body[32U + P256_PUBLIC_KEY_WITH_PREFIX_SIZE];
	uint8_t certificate_body[P256_PUBLIC_KEY_WITH_PREFIX_SIZE];
	uint8_t server_ecdh_public[P256_PUBLIC_KEY_WITH_PREFIX_SIZE];
	uint8_t server_ecdh_public_raw[STSEPHYR_TLS13_P256_PUBLIC_KEY_SIZE];
	uint8_t server_signing_public[P256_PUBLIC_KEY_WITH_PREFIX_SIZE];
	uint8_t server_signing_public_raw[STSEPHYR_TLS13_P256_PUBLIC_KEY_SIZE];
	uint8_t client_public_raw[STSEPHYR_TLS13_P256_PUBLIC_KEY_SIZE];
	uint8_t client_public_psa[P256_PUBLIC_KEY_WITH_PREFIX_SIZE];
	uint8_t shared_secret[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t transcript_digest[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t certificate_verify_content[160];
	uint8_t certificate_verify_signature[STSEPHYR_TLS13_P256_SIGNATURE_SIZE];
	uint8_t server_finished[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t client_finished[STSEPHYR_TLS13_SHA256_SIZE];
	uint8_t expected_client_finished[STSEPHYR_TLS13_SHA256_SIZE];
	stsafea_aes_128_host_keys_t host_keys;
	struct stsephyr_tls13_client_context tls_context;
	struct mock_server_secrets mock_secrets;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t server_ecdh_key = PSA_KEY_ID_NULL;
	psa_key_id_t server_signing_key = PSA_KEY_ID_NULL;
	stse_session_t session;
	stse_Handler_t *handler = NULL;
	stse_ReturnCode_t status;
	psa_status_t psa_status;
	size_t transcript_length = 0U;
	size_t output_length;
	size_t certificate_verify_content_length;
	int64_t total_started = k_uptime_get();
	int64_t started;
	bool acquired = false;
	bool session_open = false;
	int result = -1;

	memset(&mock_secrets, 0, sizeof(mock_secrets));
	stsephyr_tls13_client_context_init(&tls_context);
	printk("STSAFE-A120 TLS 1.3 cryptography experiment (offline, mock peer)\n");

	if (!IS_ENABLED(CONFIG_SAMPLE_STSAFE_ALLOW_TLS_SLOT_WRITES)) {
		printk("SKIPPED: TLS slot writes require explicit opt-in; see README.md.\n");
		return 0;
	}
	if (load_host_keys(&host_keys) != 0) {
		printk("SKIPPED: provide the provisioned host MAC and cipher keys in an untracked "
		       "configuration file.\n");

		secure_zero(&host_keys, sizeof(host_keys));
		return 0;
	}
	if (psa_check("psa_crypto_init", psa_crypto_init()) != 0) {
		goto out;
	}

	started = stage_start(1U, "Create the independent mock server and audit STSAFE slots");
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256U);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
	psa_status = psa_generate_key(&attributes, &server_ecdh_key);
	psa_reset_key_attributes(&attributes);
	if ((psa_check("server ECDHE key generation", psa_status) != 0) ||
	    (psa_check("server ECDHE public key export",
		       psa_export_public_key(server_ecdh_key, server_ecdh_public,
					     sizeof(server_ecdh_public), &output_length)) != 0) ||
	    (output_length != sizeof(server_ecdh_public))) {
		goto out;
	}
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256U);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_status = psa_generate_key(&attributes, &server_signing_key);
	psa_reset_key_attributes(&attributes);
	if ((psa_check("server signing key generation", psa_status) != 0) ||
	    (psa_check("server signing public key export",
		       psa_export_public_key(server_signing_key, server_signing_public,
					     sizeof(server_signing_public), &output_length)) !=
	     0) ||
	    (output_length != sizeof(server_signing_public))) {
		goto out;
	}
	memcpy(server_ecdh_public_raw, &server_ecdh_public[1], sizeof(server_ecdh_public_raw));
	memcpy(server_signing_public_raw, &server_signing_public[1],
	       sizeof(server_signing_public_raw));
	if (sample_open(&handler) != 0) {
		goto out;
	}
	acquired = true;
	if (audit_symmetric_slots(handler) != 0) {
		printk("FAIL: nine empty derivation-enabled symmetric slots are required\n");
		goto out;
	}
	stage_complete(started);

	started = stage_start(2U, "Build ClientHello and ServerHello, then perform P-256 ECDHE");
	status = stse_generate_random(handler, client_hello_body, 32U);
	if (sample_check("STSAFE client_random generation", status) != 0) {
		goto out;
	}
	if (psa_check("mock server_random generation",
		      psa_generate_random(server_hello_body, 32U)) != 0) {
		goto out;
	}
	status = stsafea_generate_ecc_key_pair(handler, TLS13_EPHEMERAL_SLOT,
					       STSE_ECC_KT_NIST_P_256, 1U, client_public_raw);
	if (sample_check("STSAFE ephemeral P-256 key in slot 0xFF", status) != 0) {
		goto out;
	}
	client_public_psa[0] = 0x04U;
	memcpy(&client_public_psa[1], client_public_raw, sizeof(client_public_raw));
	memcpy(&client_hello_body[32], client_public_psa, sizeof(client_public_psa));
	memcpy(&server_hello_body[32], server_ecdh_public, sizeof(server_ecdh_public));
	if ((append_handshake(transcript, &transcript_length, 0x01, client_hello_body,
			      sizeof(client_hello_body)) != 0) ||
	    (append_handshake(transcript, &transcript_length, 0x02, server_hello_body,
			      sizeof(server_hello_body)) != 0)) {
		goto out;
	}
	if ((psa_check("mock server ECDHE",
		       psa_raw_key_agreement(PSA_ALG_ECDH, server_ecdh_key, client_public_psa,
					     sizeof(client_public_psa), shared_secret,
					     sizeof(shared_secret), &output_length)) != 0) ||
	    (output_length != sizeof(shared_secret))) {
		goto out;
	}
	sample_print_hex("Client ephemeral public key X||Y", client_public_raw,
			 sizeof(client_public_raw));
	sample_print_hex("Server ephemeral public key X||Y", server_ecdh_public_raw,
			 sizeof(server_ecdh_public_raw));
	stage_complete(started);

	started = stage_start(3U, "Open a host-session context and derive handshake keys");
	stsafea_session_clear_context(&session);
	status = open_host_session(handler, &session, &host_keys);
	if (sample_check("open STSAFE host-session context", status) != 0) {
		goto out;
	}
	session_open = true;
	if ((transcript_hash(handler, transcript, transcript_length, transcript_digest) != 0) ||
	    (derive_mock_handshake(shared_secret, transcript_digest, &mock_secrets) != 0)) {
		printk("FAIL: mock server handshake key schedule failed\n");
		goto out;
	}
	secure_zero(shared_secret, sizeof(shared_secret));
	if (stsephyr_tls13_client_handshake_setup(handler, TLS13_EPHEMERAL_SLOT,
						  server_ecdh_public_raw, transcript_digest,
						  &tls_context) != 0) {
		printk("FAIL: STSAFE TLS handshake key setup failed\n");
		goto out;
	}
	printk(" - Internal slots: handshake=%u c_traffic=%u s_traffic=%u c_GCM=%u "
	       "s_GCM=%u c_finished=%u s_finished=%u\n",
	       tls_context.handshake_secret_slot, tls_context.client_traffic_secret_slot,
	       tls_context.server_traffic_secret_slot, tls_context.client_write_key_slot,
	       tls_context.server_write_key_slot, tls_context.client_finished_key_slot,
	       tls_context.server_finished_key_slot);
	sample_print_hex("Client handshake IV", tls_context.client_write_iv,
			 sizeof(tls_context.client_write_iv));
	sample_print_hex("Server handshake IV", tls_context.server_write_iv,
			 sizeof(tls_context.server_write_iv));
	if ((memcmp(tls_context.client_write_iv, mock_secrets.client_handshake_iv,
		    sizeof(tls_context.client_write_iv)) != 0) ||
	    (memcmp(tls_context.server_write_iv, mock_secrets.server_handshake_iv,
		    sizeof(tls_context.server_write_iv)) != 0)) {
		printk("FAIL: STSAFE and mock server handshake IVs differ\n");
		goto out;
	}
	printk(" - Both handshake IVs match the independent RFC 8446 schedule\n");
	stage_complete(started);

	started = stage_start(4U, "Verify the server certificate signature with STSAFE");
	memcpy(certificate_body, server_signing_public, sizeof(certificate_body));
	if ((append_handshake(transcript, &transcript_length, 0x08, encrypted_extensions,
			      sizeof(encrypted_extensions)) != 0) ||
	    (append_handshake(transcript, &transcript_length, 0x0b, certificate_body,
			      sizeof(certificate_body)) != 0) ||
	    (transcript_hash(handler, transcript, transcript_length, transcript_digest) != 0)) {
		goto out;
	}
	make_certificate_verify_content(transcript_digest, certificate_verify_content,
					&certificate_verify_content_length);
	psa_status = psa_sign_message(server_signing_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
				      certificate_verify_content, certificate_verify_content_length,
				      certificate_verify_signature,
				      sizeof(certificate_verify_signature), &output_length);
	if ((psa_check("mock server CertificateVerify signature", psa_status) != 0) ||
	    (output_length != sizeof(certificate_verify_signature)) ||
	    (stsephyr_tls13_verify_server_certificate_verify(handler, server_signing_public_raw,
							     transcript_digest,
							     certificate_verify_signature) != 0)) {
		printk("FAIL: STSAFE rejected server CertificateVerify\n");
		goto out;
	}
	printk(" - STSAFE accepted the P-256/SHA-256 CertificateVerify signature\n");
	sample_print_hex("Server signing public key X||Y", server_signing_public_raw,
			 sizeof(server_signing_public_raw));
	sample_print_hex("CertificateVerify R||S", certificate_verify_signature,
			 sizeof(certificate_verify_signature));
	if (append_handshake(transcript, &transcript_length, 0x0f, certificate_verify_signature,
			     sizeof(certificate_verify_signature)) != 0) {
		goto out;
	}
	stage_complete(started);

	started = stage_start(5U, "Exercise both protected handshake record directions");
	if (exercise_record_pair(handler, &tls_context, mock_secrets.client_handshake_key,
				 mock_secrets.client_handshake_iv,
				 mock_secrets.server_handshake_key,
				 mock_secrets.server_handshake_iv, "handshake") != 0) {
		printk("FAIL: handshake record interoperability failed\n");
		goto out;
	}
	stage_complete(started);

	started = stage_start(6U, "Verify server Finished and generate client Finished in STSAFE");
	if ((transcript_hash(handler, transcript, transcript_length, transcript_digest) != 0) ||
	    (hmac_sha256(mock_secrets.server_finished_key, sizeof(mock_secrets.server_finished_key),
			 transcript_digest, sizeof(transcript_digest), server_finished) != 0) ||
	    (stsephyr_tls13_verify_server_finished(handler, &tls_context, transcript_digest,
						   server_finished) != 0)) {
		printk("FAIL: STSAFE rejected server Finished\n");
		goto out;
	}
	printk(" - STSAFE verified server Finished with its internal HMAC key\n");
	sample_print_hex("Server Finished.verify_data", server_finished, sizeof(server_finished));
	if ((append_handshake(transcript, &transcript_length, 0x14, server_finished,
			      sizeof(server_finished)) != 0) ||
	    (transcript_hash(handler, transcript, transcript_length, transcript_digest) != 0) ||
	    (stsephyr_tls13_generate_client_finished(handler, &tls_context, transcript_digest,
						     client_finished) != 0) ||
	    (hmac_sha256(mock_secrets.client_finished_key, sizeof(mock_secrets.client_finished_key),
			 transcript_digest, sizeof(transcript_digest),
			 expected_client_finished) != 0) ||
	    (memcmp(client_finished, expected_client_finished, sizeof(client_finished)) != 0)) {
		printk("FAIL: client Finished did not match the mock server\n");
		goto out;
	}
	printk(" - STSAFE generated client Finished; independent server value matches\n");
	sample_print_hex("Client Finished.verify_data", client_finished, sizeof(client_finished));
	/* Application traffic uses the transcript through server Finished (RFC 8446). */
	stage_complete(started);

	started = stage_start(7U, "Derive application traffic keys and erase handshake keys");
	if ((transcript_hash(handler, transcript, transcript_length, transcript_digest) != 0) ||
	    (derive_mock_application(transcript_digest, &mock_secrets) != 0) ||
	    (stsephyr_tls13_client_application_setup(handler, &tls_context, transcript_digest) !=
	     0)) {
		printk("FAIL: application key schedule failed\n");
		goto out;
	}
	printk(" - Internal application slots: c_traffic=%u s_traffic=%u c_GCM=%u s_GCM=%u\n",
	       tls_context.client_traffic_secret_slot, tls_context.server_traffic_secret_slot,
	       tls_context.client_write_key_slot, tls_context.server_write_key_slot);
	sample_print_hex("Client application IV", tls_context.client_write_iv,
			 sizeof(tls_context.client_write_iv));
	sample_print_hex("Server application IV", tls_context.server_write_iv,
			 sizeof(tls_context.server_write_iv));
	if ((memcmp(tls_context.client_write_iv, mock_secrets.client_application_iv,
		    sizeof(tls_context.client_write_iv)) != 0) ||
	    (memcmp(tls_context.server_write_iv, mock_secrets.server_application_iv,
		    sizeof(tls_context.server_write_iv)) != 0)) {
		printk("FAIL: STSAFE and mock server application IVs differ\n");
		goto out;
	}
	printk(" - Both application IVs match; all handshake-generation slots were erased\n");
	stage_complete(started);

	started = stage_start(8U, "Exchange bidirectional application records");
	if (exercise_record_pair(handler, &tls_context, mock_secrets.client_application_key,
				 mock_secrets.client_application_iv,
				 mock_secrets.server_application_key,
				 mock_secrets.server_application_iv, "application") != 0) {
		printk("FAIL: application record interoperability failed\n");
		goto out;
	}
	stage_complete(started);
	result = 0;

out:
	if (session_open) {
		started = stage_start(9U, "Erase every remaining temporary TLS slot");
		if (stsephyr_tls13_client_context_release(handler, &tls_context) != 0) {
			printk("FAIL: one or more temporary TLS slots could not be erased\n");
			result = -1;
		} else {
			printk(" - Temporary application traffic and AES-GCM slots erased\n");
		}
		stage_complete(started);
	}
	if (session_open) {
		stsafea_close_host_session(&session);
	}
	if (acquired) {
		sample_close();
	}
	if (server_ecdh_key != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(server_ecdh_key);
	}
	if (server_signing_key != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(server_signing_key);
	}
	secure_zero(shared_secret, sizeof(shared_secret));
	secure_zero(&mock_secrets, sizeof(mock_secrets));
	secure_zero(&host_keys, sizeof(host_keys));
	secure_zero(certificate_verify_content, sizeof(certificate_verify_content));
	printk("\nTotal example time: %lld ms\n", k_uptime_get() - total_started);

	if (result == 0) {
		printk("PASS: 03_tls13_crypto\n");
	}
	return 0;
}
