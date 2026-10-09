/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authenticates the STSAFE-A120 the way a remote verifier would:
 *  1. read the device certificate from data zone 0,
 *  2. verify it against the ST production root CA,
 *  3. (opt-in) have the device sign a random challenge with private-key slot 0
 *     and verify the signature with the certificate's public key.
 *
 * stse_device_authenticate() performs the same three steps in a single call.
 */

#include "sample_common.h"

#include <certificate/stse_certificate_prints.h>

#include <zephyr/random/random.h>
#include <zephyr/sys/printk.h>

#define CERTIFICATE_ZONE     0U
#define PRIVATE_KEY_SLOT     0U
#define MAX_CERTIFICATE_SIZE 1024U
#define MAX_CHALLENGE_SIZE   66U
#define MAX_SIGNATURE_SIZE   132U

extern const uint8_t st_root_ca[];

static int prove_key_possession(stse_Handler_t *handler, stse_certificate_t *device_certificate)
{
	uint8_t challenge[MAX_CHALLENGE_SIZE];
	uint8_t signature[MAX_SIGNATURE_SIZE];
	stse_ecc_key_type_t key_type = stse_certificate_get_key_type(device_certificate);
	uint16_t challenge_size;
	uint16_t half;

	if (key_type >= STSE_ECC_KT_INVALID) {
		printk("FAIL: unsupported certificate key type\n");
		return -1;
	}
	challenge_size = stse_ecc_info_table[key_type].min_signature_message_size;
	half = stse_ecc_info_table[key_type].signature_size / 2U;
	if (challenge_size > sizeof(challenge) || 2U * half > sizeof(signature)) {
		printk("FAIL: certificate key is larger than the sample buffers\n");
		return -1;
	}

	if (sys_csrand_get(challenge, challenge_size) != 0) {
		printk("FAIL: host random generator\n");
		return -1;
	}
	sample_print_hex("Host challenge", challenge, challenge_size);

	if (sample_check("Sign challenge with slot 0",
			 stse_ecc_generate_signature(handler, PRIVATE_KEY_SLOT, key_type, challenge,
						     challenge_size, signature)) != 0) {
		return -1;
	}
	sample_print_hex("Signature (r || s)", signature, 2U * half);

	return sample_check("Verify signature with the certificate public key",
			    stse_certificate_verify_signature(device_certificate, challenge,
							      challenge_size, signature, half,
							      &signature[half], half));
}

int main(void)
{
	uint8_t certificate[MAX_CERTIFICATE_SIZE];
	stse_certificate_t root;
	stse_certificate_t device_certificate;
	stse_Handler_t *handler;
	uint16_t certificate_size;

	printk("STSAFE-A120 device authentication\n");
	if (sample_open(&handler) != 0) {
		return 0;
	}

	if (sample_check("Read certificate size",
			 stse_get_device_certificate_size(handler, CERTIFICATE_ZONE,
							  &certificate_size)) != 0) {
		goto out;
	}
	if (certificate_size > sizeof(certificate)) {
		printk("FAIL: certificate is %u bytes, buffer is %u\n", certificate_size,
		       (unsigned int)sizeof(certificate));
		goto out;
	}
	if (sample_check("Read device certificate",
			 stse_get_device_certificate(handler, CERTIFICATE_ZONE, certificate_size,
						     certificate)) != 0 ||
	    sample_check("Parse device certificate",
			 stse_certificate_parse(certificate, &device_certificate, NULL)) != 0) {
		goto out;
	}
	stse_certificate_print_parsed_cert(&device_certificate);
	printk("\n");

	if (sample_check("Parse root CA", stse_certificate_parse(st_root_ca, &root, NULL)) != 0 ||
	    sample_check("Verify device certificate against the ST root CA",
			 stse_certificate_is_parent(&root, &device_certificate, NULL)) != 0) {
		goto out;
	}

	if (!IS_ENABLED(CONFIG_SAMPLE_STSAFE_ALLOW_SIGNATURE)) {
		printk("Proof of key possession skipped (CONFIG_SAMPLE_STSAFE_ALLOW_SIGNATURE)\n");
		printk("DONE: certificate chain verified\n");
		goto out;
	}

	if (prove_key_possession(handler, &device_certificate) == 0) {
		printk("PASS: 01_device_authentication\n");
	}

out:
	sample_close();
	return 0;
}
