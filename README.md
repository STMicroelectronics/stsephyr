# STSEphyr

Zephyr RTOS support for the **STSAFE-A120** secure element from
STMicroelectronics.

STSEphyr is a [Zephyr module](https://docs.zephyrproject.org/latest/develop/modules.html)
that runs ST's [STSELib](https://github.com/STMicroelectronics/STSELib)
middleware on Zephyr. It provides the Zephyr device driver, the devicetree
binding, the I2C, reset and host-cryptography glue STSELib needs, a shield
definition for the X-NUCLEO-ESE01A1 expansion board, and samples.

Your application then uses the regular STSELib API for device authentication,
secure storage, random numbers, hashing, signatures and the other STSAFE-A120
services.

| | Version tested |
| --- | --- |
| Zephyr | v4.4.0 |
| STSELib | v1.1.11 (used unmodified) |
| Monocypher (only for Ed25519, optional) | 4.0.3 |
| Hardware | NUCLEO-L452RE + X-NUCLEO-ESE01A1 (STSAFE-A120, ST evaluation personalization) |

## How it fits together

```text
 Your application
   │   stsephyr_acquire()  →  STSELib API calls  →  stsephyr_release()
   ▼
 STSELib (ST middleware, fetched by west, not modified)
   │   platform callbacks
   ▼
 STSEphyr: I2C transport, reset GPIO, CRC, host crypto (PSA Crypto)
   │
   ▼
 Zephyr I2C and GPIO drivers  ──I2C──►  STSAFE-A120
```

The driver initializes the secure element at boot. Applications borrow the
STSELib handle with `stsephyr_acquire()` and give it back with
`stsephyr_release()`.

> **New to Zephyr?** `west` is Zephyr's command-line tool: it downloads the
> sources listed in a manifest (`west.yml`), builds (`west build`) and flashes
> (`west flash`). A *shield* is an add-on board; `--shield x_nucleo_ese01a1`
> adds its wiring to the build. Hardware is described in *devicetree* files and
> features are enabled with *Kconfig* options (`CONFIG_...`), usually in a
> `prj.conf` file.

## Getting started

### 1. Install the tools

Follow the Zephyr [Getting Started Guide](https://docs.zephyrproject.org/4.4.0/develop/getting_started/index.html)
up to the Zephyr SDK installation; you do not need to fetch the Zephyr sources
yourself. To flash the Nucleo board, also install
[STM32CubeProgrammer](https://www.st.com/en/development-tools/stm32cubeprog.html).

### 2. Create a workspace

```sh
west init -m https://github.com/STMicroelectronics/stsephyr stsephyr-workspace
cd stsephyr-workspace
west update
west zephyr-export
west packages pip --install
```

This fetches STSEphyr into `stsephyr/`, and Zephyr, STSELib, Monocypher and
the few Zephyr modules needed for STM32 next to it.

### 3. Build, flash and run the basic sample

Plug the X-NUCLEO-ESE01A1 onto the NUCLEO-L452RE and connect the Nucleo's
ST-LINK USB port. From the workspace directory:

```sh
west build -p always -b nucleo_l452re --shield x_nucleo_ese01a1 stsephyr/samples/basic
west flash
```

Open the ST-LINK virtual COM port with a serial terminal (Tera Term, PuTTY,
`minicom`...) at **115200 baud, 8N1**, then press the board's reset button:

```text
[00:00:00.051,000] <inf> stsephyr: stsafe-a120@20 ready at 0x20 on i2c@40005400
*** Booting Zephyr OS build v4.4.0 ***
[00:00:00.062,000] <inf> basic: STSAFE-A120 echo successful
PASS: basic
```

## Samples

Build any sample by changing the path in the `west build` command. All of them
target `nucleo_l452re` with `--shield x_nucleo_ese01a1`.

| Sample | What it shows | Changes the device? |
| --- | --- | --- |
| [`basic`](samples/basic) | Minimal application: initialize the device and send one echo command. Start here. | No |
| [`01_echo_loop`](samples/01_echo_loop) | Echo of 1 to 500 byte messages (I2C framing) | No |
| [`01_random_number`](samples/01_random_number) | Random bytes from the STSAFE-A120 | No |
| [`01_hash`](samples/01_hash) | SHA-256 or SHA3 in the STSAFE-A120, compared with the MCU | No |
| [`01_ed25519`](samples/01_ed25519) | Ed25519 signature verification in the STSAFE-A120 and on the MCU | No |
| [`01_device_authentication`](samples/01_device_authentication) | Read the device certificate and verify it against the ST root CA; optionally prove possession of the private key | No by default; the opt-in signature can consume key usage counters |
| [`01_secure_data_storage`](samples/01_secure_data_storage) | List data partitions, read a data zone and a counter zone | No |
| [`02_command_access_conditions`](samples/02_command_access_conditions) | Which commands are free and which need host keys or encryption | No |
| [`03_tls13_crypto`](samples/03_tls13_crypto) | **Experimental.** TLS 1.3 key schedule and records inside the STSAFE-A120, offline, against a mock server. Read its [limitations](samples/03_tls13_crypto/README.md#limitations). | Yes, opt-in only (key slots and host C-MAC counter) |

The numbers follow the example categories of ST's
[STSAFE-A SDK](https://github.com/STMicroelectronics/stsafe-a-sdk): `01` basic
services, `02` configuration, `03` key establishment with host keys.

Anything that changes the secure element is disabled unless you set the
sample's `CONFIG_SAMPLE_STSAFE_ALLOW_*` option yourself. STSAFE-A120 state
changes are permanent: writes, counter decrements and key usage limits cannot
be undone by reflashing the MCU.

## Using STSEphyr in your application

**1. Add the module** to your application's `west.yml`, then run `west update`:

```yaml
  projects:
    - name: stsephyr
      url: https://github.com/STMicroelectronics/stsephyr
      revision: main
      import:
        name-allowlist: [stselib, monocypher]
```

The import pulls the STSELib and Monocypher revisions STSEphyr was tested
with; your manifest keeps control of the Zephyr version.

**2. Describe the hardware.** With an X-NUCLEO-ESE01A1 on an Arduino-compatible
board, `--shield x_nucleo_ese01a1` is enough. For your own board, add an
`st,stsafe-a120` node to its devicetree; see [PORTING.md](PORTING.md).

**3. Enable it.** `CONFIG_STSEPHYR` turns on automatically when the devicetree
has an enabled `st,stsafe-a120` node. It also enables I2C, GPIO and PSA Crypto.

**4. Call STSELib** while holding the device:

```c
#include <stsephyr/stsafe_a120.h>

static const struct device *const stsafe = DEVICE_DT_GET_ONE(st_stsafe_a120);

int read_random(uint8_t *buf, uint16_t len)
{
	stse_Handler_t *handler;
	stse_ReturnCode_t status;
	int ret = stsephyr_acquire(stsafe, K_SECONDS(5), &handler);

	if (ret != 0) {
		return ret;
	}
	status = stse_generate_random(handler, buf, len);
	stsephyr_release(stsafe);

	return stsephyr_stse_to_errno(status);
}
```

Keep the device acquired for a whole sequence of related commands, for example
an entire host session, and release it from the same thread. The public API is
in [`include/stsephyr/stsafe_a120.h`](include/stsephyr/stsafe_a120.h).

### Main configuration options

| Option | Default | Purpose |
| --- | --- | --- |
| `CONFIG_STSEPHYR_ECC_NIST_P256`, `_P384` | `y` | NIST curves |
| `CONFIG_STSEPHYR_ECC_NIST_P521`, `_BRAINPOOL_P256/P384/P512`, `_CURVE25519` | `n` | Other curves |
| `CONFIG_STSEPHYR_ECC_ED25519` | `n` | Ed25519; adds Monocypher for MCU-side verification |
| `CONFIG_STSEPHYR_HASH_SHA256`, `_SHA384`, `_SHA512` | `y` | SHA-2 |
| `CONFIG_STSEPHYR_HASH_SHA3_256`, `_SHA3_384`, `_SHA3_512` | `n` | SHA-3 |
| `CONFIG_STSEPHYR_HOST_SESSION` | `n` | Authenticated and encrypted host sessions (needs provisioned host keys) |
| `CONFIG_STSEPHYR_LOCK_TIMEOUT_MS` | `5000` | Default timeout used by the samples to acquire the device |
| `CONFIG_STSEPHYR_LOG_LEVEL` | log default | Driver log level |

Disabled algorithms are compiled out of STSELib. All options are in
[`drivers/stsafe/Kconfig`](drivers/stsafe/Kconfig).

## Testing

Build every sample configuration, including the opt-in ones that are never
flashed by the test runner:

```sh
west twister -T stsephyr/samples -p nucleo_l452re --build-only
```

Run the unit tests of the CRC and host-crypto glue (Linux or WSL):

```sh
west twister -T stsephyr/tests -p native_sim
```

Run the samples on the board with Twister: copy `stsephyr/hardware-map.yml` to
`stsephyr/hardware-map.local.yml`, fill in the ST-LINK serial number and COM
port, close any serial terminal, then:

```sh
west twister -T stsephyr/samples -p nucleo_l452re --device-testing --hardware-map stsephyr/hardware-map.local.yml
```

Twister flashes only the scenarios that leave the device unchanged; the others
are marked `build_only`. On Windows, add `--short-build-path` if paths get too
long. Results of the last validation are in [VALIDATION.md](VALIDATION.md).

## Limitations

- **STSAFE-A120 over I2C only.** STSAFE-A110 and STSAFE-L are not supported.
- **One validated board.** Only NUCLEO-L452RE + X-NUCLEO-ESE01A1 has been run.
  Other boards should work through devicetree ([PORTING.md](PORTING.md)) but
  are untested.
- **Read-only validation.** Operations that permanently change the secure
  element (key generation, provisioning, storage writes, counters, host
  sessions) are available through STSELib but were not exercised.
- **STSELib API, not a Zephyr crypto API.** There is no Zephyr `crypto` driver
  and no PSA Crypto secure-element driver, so Mbed TLS and Zephyr TLS sockets do
  not use the STSAFE-A120 automatically.
- **One device at a time.** Several STSAFE-A120 nodes can be declared, but all
  calls are serialized by one lock and multi-device setups are untested.
- **TLS is an experiment**, not a feature; see its
  [limitations](samples/03_tls13_crypto/README.md#limitations).

[TECHNICAL_DETAILS.md](TECHNICAL_DETAILS.md) explains the design choices and
the integration limits in more detail.

## License

STSEphyr is licensed under Apache-2.0. STSELib (BSD-3-Clause) and Monocypher
(BSD-2-Clause or CC0-1.0) keep their own licenses in their own repositories.
