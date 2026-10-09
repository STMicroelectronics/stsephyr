# Technical details

This page is for reviewers and for anyone porting or extending STSEphyr. For
day-to-day use, the [README](README.md) is enough.

## Repository layout

| Path | Content |
| --- | --- |
| `drivers/stsafe/` | Zephyr device driver, Kconfig, and the list of STSELib sources to build |
| `platform/` | STSELib platform callbacks: I2C, reset, delay, random, CRC, host crypto |
| `include/stsephyr/stsafe_a120.h` | Public API: acquire, release, reset, error conversion |
| `dts/bindings/crypto/st,stsafe-a120.yaml` | Devicetree binding |
| `boards/shields/x_nucleo_ese01a1/` | Shield definition and the NUCLEO-L452RE overlay |
| `samples/` | Applications, sharing small helpers in `samples/common` |
| `tests/` | Unit tests of the CRC and host-crypto callbacks |
| `zephyr/module.yml`, `west.yml` | Module definition and pinned dependencies |

## Responsibilities

STSELib implements the STSAFE-A120 command set, framing, sessions,
certificate parsing and the high-level services. STSEphyr only provides what
STSELib expects from a platform:

- **Device driver** (`drivers/stsafe/stsafe_a120.c`): one Zephyr device per
  `st,stsafe-a120` node. At `POST_KERNEL` it checks the I2C bus and reset GPIO,
  pulses reset, fills the STSELib handler (address, bus, speed) and calls
  `stse_init()`. Initialization never writes to the secure element.
- **Platform callbacks** (`platform/`): the functions declared in STSELib's
  `core/stse_platform.h`.
- **Configuration** (`platform/stse_conf.h`): translates `CONFIG_STSEPHYR_*`
  options into STSELib's `STSE_CONF_*` macros, so unused algorithms are not
  compiled.

STSELib is built from the west checkout without patches.
`drivers/stsafe/CMakeLists.txt` lists the STSELib files explicitly so that a
dependency update cannot silently add sources. Another checkout can be used by
setting `STSELIB_ROOT` (and `MONOCYPHER_ROOT` for Ed25519).

## Concurrency

STSELib keeps global state (CRC accumulator, streaming CMAC context) and is not
thread safe, so STSEphyr uses one global mutex for every STSAFE-A120 instance:

- `stsephyr_acquire()` takes the mutex and returns the handler only if the
  device initialized correctly. `stsephyr_release()` gives it back.
- Hold the lock for a complete operation. A host session stores pointers to
  caller-owned keys, so open and close it within one acquire/release pair.
- `stsephyr_reset()` takes the same lock, resets the device and initializes the
  handler again. It also invalidates any open session.
- The handler must not be used after release.

## Platform callbacks

| Callback | Implementation |
| --- | --- |
| I2C | `i2c_write_dt()` / `i2c_read_dt()`. STSELib sends frames in pieces; they are assembled in a 756-byte buffer per device, with bounds checks on every piece. |
| Wake-up | Zero-length I2C write |
| Delay | `k_msleep()` |
| Reset / power | The `reset-gpios` line from devicetree. STSELib's power-on and power-off callbacks release and assert it. |
| Random | `sys_csrand_get()`. If the CSPRNG fails at runtime the system panics, because STSELib's random callback cannot return an error. |
| CRC | CRC-16/X-25, also incremental |
| Host crypto | PSA Crypto: ECDSA, ECDH, key generation, SHA-2/SHA-3, AES ECB/CBC/CMAC, HMAC-SHA256/HKDF, AES key wrap. Ed25519 verification uses Monocypher, because the PSA Crypto implementation shipped with Zephyr does not provide EdDSA. |

Only the segmented I2C receive path is implemented; the legacy single-call
receive returns an error. The devicetree address is authoritative: changing
the I2C address at runtime is not supported.

Each `select` in `drivers/stsafe/Kconfig` enables the PSA algorithms the
callbacks need. The board must provide a real entropy source (on STM32 the RNG
peripheral, enabled by the board overlay).

## Error handling

STSELib functions return `stse_ReturnCode_t`. `stsephyr_stse_to_errno()` maps
the common cases (invalid parameter, buffer size, timeout, access denied, key
not found) to errno values and everything else to `-EIO`. Log the original
STSELib status when the details matter.

## Limits

- STSAFE-A120 over I2C only. STSAFE-A110 and STSAFE-L would need other
  STSELib sources and qualification.
- No Zephyr `crypto` API driver and no PSA Crypto driver (opaque keys); Mbed TLS
  and TLS sockets do not use the secure element.
- No runtime power management. No production provisioning or key storage on
  the MCU.
- Several devices can be declared in devicetree, but they share one lock and
  this has not been tested on hardware.
- STSELib's X.509 parser expects device certificates from a trusted source. It
  is not a general-purpose certificate validator.
- The unit tests cover the CRC and crypto callbacks with standard test
  vectors. There is no I2C fault injection, stress or power-loss testing.
- STSEphyr does not restrict what an application can do: every persistent
  STSELib operation is available. Only the samples are guarded.
