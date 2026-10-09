/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef STSEPHYR_STSAFE_A120_TLS13_H_
#define STSEPHYR_STSAFE_A120_TLS13_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <stselib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STSEPHYR_TLS13_P256_PUBLIC_KEY_SIZE 64U
#define STSEPHYR_TLS13_P256_SIGNATURE_SIZE  64U
#define STSEPHYR_TLS13_SHA256_SIZE	    32U
#define STSEPHYR_TLS13_AES_128_KEY_SIZE	    16U
#define STSEPHYR_TLS13_GCM_IV_SIZE	    12U
#define STSEPHYR_TLS13_GCM_TAG_SIZE	    16U
#define STSEPHYR_TLS13_MAX_TEMPORARY_SLOTS  9U

enum stsephyr_tls13_phase {
	STSEPHYR_TLS13_PHASE_EMPTY,
	STSEPHYR_TLS13_PHASE_HANDSHAKE,
	STSEPHYR_TLS13_PHASE_APPLICATION,
	STSEPHYR_TLS13_PHASE_FAILED,
};

/**
 * @brief Sample-local TLS state; not a supported driver or protocol API.
 *
 * Slot identifiers are exposed for auditing only. The associated secrets and
 * AES keys are stored in erasable, persistent STSAFE-A120 symmetric slots.
 */
struct stsephyr_tls13_client_context {
	uint8_t temporary_slots[STSEPHYR_TLS13_MAX_TEMPORARY_SLOTS];
	uint8_t handshake_secret_slot;
	uint8_t client_traffic_secret_slot;
	uint8_t server_traffic_secret_slot;
	uint8_t client_finished_key_slot;
	uint8_t server_finished_key_slot;
	uint8_t client_write_key_slot;
	uint8_t server_write_key_slot;
	uint8_t client_write_iv[STSEPHYR_TLS13_GCM_IV_SIZE];
	uint8_t server_write_iv[STSEPHYR_TLS13_GCM_IV_SIZE];
	enum stsephyr_tls13_phase phase;
	bool server_finished_verified;
	bool client_finished_generated;
};

/** Initialize an empty TLS 1.3 client crypto context. */
void stsephyr_tls13_client_context_init(struct stsephyr_tls13_client_context *context);

/**
 * @brief Establish both TLS 1.3 handshake traffic directions.
 *
 * The caller must hold the device lock and an open host-session context, and
 * verify that the personalization requires suitable command protection. This performs
 * P-256 ECDH, the no-PSK SHA-256 handshake key schedule, and derives client and
 * server AES-128-GCM keys, IVs, and Finished HMAC keys. Secret values and AES
 * keys are placed in erasable symmetric slots.
 *
 * STSAFE-A120 Establish Key returns ECDH Z to the host. The implementation
 * immediately supplies that value to Derive Keys, then zeroes the MCU buffer.
 * The public command set has no route from asymmetric slot 0xFF or its ECDHE
 * state directly into generic HKDF.
 */
int stsephyr_tls13_client_handshake_setup(
	stse_Handler_t *handler, uint8_t private_key_slot,
	const uint8_t server_public_key[STSEPHYR_TLS13_P256_PUBLIC_KEY_SIZE],
	const uint8_t hello_transcript_hash[STSEPHYR_TLS13_SHA256_SIZE],
	struct stsephyr_tls13_client_context *context);

/** Verify the TLS 1.3 server CertificateVerify P-256/SHA-256 signature. */
int stsephyr_tls13_verify_server_certificate_verify(
	stse_Handler_t *handler,
	const uint8_t server_signing_public_key[STSEPHYR_TLS13_P256_PUBLIC_KEY_SIZE],
	const uint8_t transcript_hash[STSEPHYR_TLS13_SHA256_SIZE],
	const uint8_t signature[STSEPHYR_TLS13_P256_SIGNATURE_SIZE]);

/** Verify the server Finished value with the internal server Finished key. */
int stsephyr_tls13_verify_server_finished(stse_Handler_t *handler,
					  struct stsephyr_tls13_client_context *context,
					  const uint8_t transcript_hash[STSEPHYR_TLS13_SHA256_SIZE],
					  const uint8_t verify_data[STSEPHYR_TLS13_SHA256_SIZE]);

/** Generate the client Finished value with the internal client Finished key. */
int stsephyr_tls13_generate_client_finished(
	stse_Handler_t *handler, struct stsephyr_tls13_client_context *context,
	const uint8_t transcript_hash[STSEPHYR_TLS13_SHA256_SIZE],
	uint8_t verify_data[STSEPHYR_TLS13_SHA256_SIZE]);

/**
 * @brief Replace handshake keys with TLS 1.3 application traffic keys.
 *
 * Both Finished operations must have succeeded first. The function derives the
 * master secret, both application traffic secrets, AES-128-GCM keys and IVs,
 * then erases the no-longer-needed handshake slots.
 */
int stsephyr_tls13_client_application_setup(
	stse_Handler_t *handler, struct stsephyr_tls13_client_context *context,
	const uint8_t transcript_hash[STSEPHYR_TLS13_SHA256_SIZE]);

/** Encrypt a handshake or application TLSCiphertext payload. */
int stsephyr_tls13_client_encrypt(stse_Handler_t *handler,
				  const struct stsephyr_tls13_client_context *context,
				  uint64_t sequence_number, const uint8_t *associated_data,
				  size_t associated_data_length, const uint8_t *plaintext,
				  size_t plaintext_length, uint8_t *ciphertext,
				  uint8_t tag[STSEPHYR_TLS13_GCM_TAG_SIZE]);

/** Authenticate and decrypt a server handshake or application TLSCiphertext payload. */
int stsephyr_tls13_client_decrypt(stse_Handler_t *handler,
				  const struct stsephyr_tls13_client_context *context,
				  uint64_t sequence_number, const uint8_t *associated_data,
				  size_t associated_data_length, const uint8_t *ciphertext,
				  size_t ciphertext_length,
				  const uint8_t tag[STSEPHYR_TLS13_GCM_TAG_SIZE],
				  uint8_t *plaintext);

/** Erase every temporary symmetric slot recorded by @p context. */
int stsephyr_tls13_client_context_release(stse_Handler_t *handler,
					  struct stsephyr_tls13_client_context *context);

#ifdef __cplusplus
}
#endif

#endif /* STSEPHYR_STSAFE_A120_TLS13_H_ */
