/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lists the STSAFE-A120 data partitions, then reads one data zone and one
 * counter zone. Nothing is written: updating a zone or decrementing a counter
 * (stse_data_storage_update_data_zone(), stse_data_storage_decrement_counter_zone())
 * permanently changes the device.
 */

#include "sample_common.h"

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#define MAX_PARTITIONS 32U
#define READ_SIZE      32U

static const char *access_name(uint8_t access_condition)
{
	switch (access_condition) {
	case STSE_AC_ALWAYS:
		return "free";
	case STSE_AC_HOST:
		return "host";
	case STSE_AC_AUTH_AND_HOST:
		return "auth+host";
	default:
		return "never";
	}
}

static const stsafea_data_partition_record_t *
find_zone(const stsafea_data_partition_record_t *table, uint8_t count, uint8_t index)
{
	for (uint8_t i = 0U; i < count; i++) {
		if (table[i].index == index) {
			return &table[i];
		}
	}
	return NULL;
}

int main(void)
{
	static stsafea_data_partition_record_t table[MAX_PARTITIONS];
	const stsafea_data_partition_record_t *zone;
	uint8_t data[READ_SIZE];
	stse_Handler_t *handler;
	uint8_t count;
	uint32_t counter;
	uint16_t length;

	printk("STSAFE-A120 secure data storage (read only)\n");
	if (sample_open(&handler) != 0) {
		return 0;
	}

	if (sample_check("Read partition count",
			 stse_data_storage_get_total_partition_count(handler, &count)) != 0) {
		goto out;
	}
	if (count > MAX_PARTITIONS) {
		printk("FAIL: %u partitions, sample supports %u\n", count, MAX_PARTITIONS);
		goto out;
	}
	if (sample_check("Read partition table",
			 stse_data_storage_get_partitioning_table(handler, count, table,
								  count * sizeof(table[0]))) != 0) {
		goto out;
	}

	printk("Zone  Type     Size  Read       Update     Counter\n");
	for (uint8_t i = 0U; i < count; i++) {
		printk("%4u  %-7s %5u  %-9s  %-9s  ", table[i].index,
		       table[i].zone_type != 0U ? "counter" : "data", table[i].data_segment_length,
		       access_name(table[i].read_ac), access_name(table[i].update_ac));
		if (table[i].zone_type != 0U) {
			printk("%u\n", (unsigned int)table[i].counter_value);
		} else {
			printk("-\n");
		}
	}

	zone = find_zone(table, count, CONFIG_SAMPLE_DATA_ZONE);
	if (zone == NULL || zone->zone_type != 0U) {
		printk("FAIL: zone %d is not a data zone\n", CONFIG_SAMPLE_DATA_ZONE);
		goto out;
	}
	length = MIN(zone->data_segment_length, sizeof(data));
	if (sample_check("Read data zone",
			 stse_data_storage_read_data_zone(handler, zone->index, 0U, data, length,
							  0U, STSE_NO_PROT)) != 0) {
		goto out;
	}
	printk("Data zone %u, first %u bytes:\n", zone->index, length);
	sample_print_hex("Data", data, length);

	zone = find_zone(table, count, CONFIG_SAMPLE_COUNTER_ZONE);
	if (zone == NULL || zone->zone_type == 0U) {
		printk("FAIL: zone %d is not a counter zone\n", CONFIG_SAMPLE_COUNTER_ZONE);
		goto out;
	}
	length = MIN(zone->data_segment_length, sizeof(data));
	if (sample_check("Read counter zone",
			 stse_data_storage_read_counter_zone(handler, zone->index, 0U, data, length,
							     0U, &counter, STSE_NO_PROT)) != 0) {
		goto out;
	}
	printk("Counter zone %u: counter = %u\n", zone->index, (unsigned int)counter);
	sample_print_hex("Associated data", data, length);

	printk("PASS: 01_secure_data_storage\n");
out:
	sample_close();
	return 0;
}
