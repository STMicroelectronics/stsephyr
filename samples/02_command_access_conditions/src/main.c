/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 *
 * Prints the access condition and host-encryption requirement of every
 * STSAFE-A120 command. Commands marked "host" need a host session (provisioned
 * host keys) and advance the device's persistent host C-MAC counter.
 * This sample only queries; it changes nothing.
 */

#include "sample_common.h"

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#define MAX_RECORDS 64U
#define EXTENDED    0x1FU

/* Command names from the STSAFE-A120 user manual, indexed by command header. */
static const char *const commands[] = {
	[0x00] = "Echo",
	[0x02] = "Generate random",
	[0x03] = "Start session",
	[0x04] = "Decrement",
	[0x05] = "Read",
	[0x06] = "Update",
	[0x09] = "Generate MAC",
	[0x0A] = "Verify MAC",
	[0x0C] = "Delete password",
	[0x0E] = "Wrap local envelope",
	[0x0F] = "Unwrap local envelope",
	[0x11] = "Generate key",
	[0x15] = "Get signature",
	[0x16] = "Generate signature",
	[0x17] = "Verify signature",
	[0x18] = "Establish key",
	[0x1A] = "Verify password",
	[0x1B] = "Encrypt",
	[0x1C] = "Decrypt",
};

static const char *const extended_commands[] = {
	"Start hash",
	"Process hash",
	"Finish hash",
	"Start volatile KEK session",
	"Establish symmetric keys",
	"Confirm symmetric keys",
	"Stop volatile KEK session",
	"Write host key V2 plaintext",
	"Write host key V2 wrapped",
	"Write symmetric key wrapped",
	"Write public key",
	"Generate ECDHE key",
	NULL,
	NULL,
	"Generate challenge",
	"Verify entity signature",
	"Derive keys",
	"Start encrypt",
	"Process encrypt",
	"Finish encrypt",
	"Start decrypt",
	"Process decrypt",
	"Finish decrypt",
	"Write symmetric key plaintext",
	"Establish host key V2",
	"Erase symmetric key slot",
	"Decompress public key",
};

static const char *command_name(const stse_cmd_authorization_record_t *record)
{
	const char *name = NULL;

	if (record->header == EXTENDED) {
		if (record->extended_header < ARRAY_SIZE(extended_commands)) {
			name = extended_commands[record->extended_header];
		}
	} else if (record->header < ARRAY_SIZE(commands)) {
		name = commands[record->header];
	}
	return name != NULL ? name : "(legacy)";
}

static const char *access_name(stse_cmd_access_conditions_t condition)
{
	switch (condition) {
	case STSE_CMD_AC_FREE:
		return "free";
	case STSE_CMD_AC_ADMIN:
		return "admin";
	case STSE_CMD_AC_HOST:
		return "host";
	case STSE_CMD_AC_ADMIN_OR_PWD:
		return "admin/password";
	case STSE_CMD_AC_ADMIN_OR_HOST:
		return "admin/host";
	default:
		return "never";
	}
}

int main(void)
{
	static stse_cmd_authorization_record_t records[MAX_RECORDS];
	stse_cmd_authorization_CR_t change_rights;
	stse_Handler_t *handler;
	uint8_t count;

	printk("STSAFE-A120 command access conditions\n");
	if (sample_open(&handler) != 0) {
		return 0;
	}

	if (sample_check("Read command count", stse_device_get_command_count(handler, &count)) !=
	    0) {
		goto out;
	}
	if (count > MAX_RECORDS) {
		printk("FAIL: %u commands, sample supports %u\n", count, MAX_RECORDS);
		goto out;
	}
	if (sample_check("Read access conditions",
			 stse_device_get_command_AC_records(handler, count, &change_rights,
							    records)) != 0) {
		goto out;
	}

	printk("Access conditions can be changed: %s\n", change_rights.cmd_AC_CR ? "yes" : "no");
	printk("Encryption flags can be changed:  %s\n",
	       change_rights.host_encryption_flag_CR ? "yes" : "no");
	printk("\nCode    Command                        Access          Encrypted\n");
	for (uint8_t i = 0U; i < count; i++) {
		const stse_cmd_authorization_record_t *record = &records[i];
		bool cmd = record->host_encryption_flags.cmd;
		bool rsp = record->host_encryption_flags.rsp;

		if (record->header == EXTENDED) {
			printk("%02X%02X", record->header, record->extended_header);
		} else {
			printk("%02X  ", record->header);
		}
		printk("    %-30s %-15s %s\n", command_name(record),
		       access_name(record->command_AC),
		       cmd && rsp ? "cmd+rsp" : (cmd ? "cmd" : (rsp ? "rsp" : "-")));
	}

	printk("PASS: 02_command_access_conditions\n");
out:
	sample_close();
	return 0;
}
