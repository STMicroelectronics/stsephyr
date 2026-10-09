# Validation

Last run: **2026-10-10**.

| | |
| --- | --- |
| Board | NUCLEO-L452RE + X-NUCLEO-ESE01A1 |
| Secure element | STSAFE-A120, ST evaluation personalization (certificate `eval5-...`) |
| Software | Zephyr v4.4.0, Zephyr SDK 1.0.1, west 1.5.0, STSELib v1.1.11, Monocypher 4.0.3 |
| Flashing | `stm32cubeprogrammer` runner, STM32CubeProgrammer v2.23.0, ST-LINK V2J33M25 |
| Host | Windows 11 |

Every image below built with **no compiler warnings** (Twister builds with
warnings as errors).

## Samples run on the board

These samples only read from the secure element. Each one was built, flashed
and its console output checked for the success line.

| Sample (configuration) | Result | Flash | RAM |
| --- | --- | ---: | ---: |
| `basic` | `PASS: basic` | 38,976 | 14,272 |
| `basic` + `full.conf` (all algorithms and helpers enabled) | `PASS: basic` | 99,312 | 24,000 |
| `01_echo_loop` | 10 echoes from 1 to 500 bytes match | 35,040 | 13,120 |
| `01_random_number` | 64 random bytes | 35,132 | 12,160 |
| `01_hash` SHA-256 | STSAFE-A120 and MCU digests match | 41,408 | 12,160 |
| `01_hash` SHA3-256 / SHA3-384 / SHA3-512 | digests match | 43,388 | 12,160 |
| `01_ed25519` | RFC 8032 vector verified by the STSAFE-A120 and the MCU; corrupted signature rejected | 69,940 | 12,160 |
| `01_device_authentication` (default) | device certificate chain verified against the ST root CA; signature step skipped | 88,548 | 16,256 |
| `01_secure_data_storage` | partition table, data zone 1 and counter zone 5 read | 37,072 | 12,544 |
| `02_command_access_conditions` | 45 command records listed | 36,160 | 12,416 |
| `03_tls13_crypto` (default) | prints `SKIPPED`, sends no command | 33,564 | 16,192 |

Sizes are in bytes, as reported by `west build`.

## Unit tests

`tests/platform_crc` (2 tests) and `tests/platform_crypto` (5 tests) passed on
the NUCLEO-L452RE. They test the platform callbacks only and send nothing to
the STSAFE-A120.

## Built but not run

These configurations change the secure element permanently, so they were only
compiled:

| Configuration | Why it was not run | Flash | RAM |
| --- | --- | ---: | ---: |
| `01_device_authentication` with `CONFIG_SAMPLE_STSAFE_ALLOW_SIGNATURE=y` | Signing can decrement private-key usage limits, which cannot be read back | 89,404 | 16,256 |
| `03_tls13_crypto` with `CONFIG_SAMPLE_STSAFE_ALLOW_TLS_SLOT_WRITES=y` and dummy host keys | Writes key slots, advances the host C-MAC counter, needs provisioned host keys | 98,344 | 25,408 |

The challenge-response signature of `01_device_authentication` did run on
this board in July 2026 (with STSELib v1.1.9, before this cleanup), as did an
earlier, shorter version of the TLS experiment. The current full TLS flow has
never run on hardware.

`samples/basic` also builds without warnings for `nucleo_g474re` with the same
shield (39,528 bytes flash; compile only, no G4 board available).

## Twister

The documented command (see [README.md](README.md#testing)) ran with
`-T stsephyr/samples -T stsephyr/tests --short-build-path`: 16 scenarios
selected, the 2 `build_only` ones filtered, **14 of 14 passed** on the board
(19 test cases, 217 s). `03_tls13_crypto` (default) is not a Twister scenario;
it was flashed with `west flash` and its console read directly.

On Windows, use `--short-build-path` and a short output directory (for example
`-O C:/tw`): otherwise object paths exceed 260 characters and some builds fail.

## Device state observed

- Command access conditions and encryption flags are locked (change right `no`).
- *Establish key*, *Encrypt*, *Decrypt*, *Wrap* and *Unwrap* require a host
  C-MAC, so ECDH, key wrapping, symmetric-key operations and the TLS experiment
  cannot run without provisioned host keys.
- Counter zone 5 reads `4294967288` (`0xFFFFFFF8`): it had been decremented 7
  times before this validation. Nothing in this run writes to it.
