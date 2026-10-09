# TLS 1.3 cryptography experiment

> **Experimental.** This is not a TLS client and not a supported STSEphyr API.
> It writes persistent key slots and needs provisioned host keys.

This sample shows how far the STSAFE-A120 can carry the client side of a
TLS 1.3 handshake, so that the traffic keys are created and used inside the
secure element instead of in MCU RAM.

There is no network. A mock server, written with PSA Crypto and running on the
same MCU, computes the same key schedule independently, and every result from
the STSAFE-A120 is compared with it.

## What it does

Cipher suite `TLS_AES_128_GCM_SHA256` with a P-256 key exchange:

| Step | Where it runs |
| --- | --- |
| Ephemeral P-256 key pair (slot `0xFF`) | STSAFE-A120 |
| ECDHE shared secret | STSAFE-A120 (the secret is then returned to the MCU, see limitation 4) |
| Transcript SHA-256 | STSAFE-A120, compared with PSA |
| HKDF handshake and application key schedule | STSAFE-A120, keys kept in symmetric slots |
| Server `CertificateVerify` (ECDSA P-256) | STSAFE-A120 |
| Server `Finished` check, client `Finished` (HMAC) | STSAFE-A120 |
| AES-128-GCM records, both directions | STSAFE-A120, checked by the mock server |
| Erase all temporary key slots | STSAFE-A120 |

`src/tls13.c` contains the STSAFE-A120 side; `src/main.c` contains the mock
server and the step-by-step checks.

## Why some secrets reach the MCU

The STSAFE-A120 has every primitive TLS 1.3 needs (ECDH, HKDF, HMAC,
AES-GCM), but its commands cannot be chained entirely inside the chip:

- **ECDHE result.** *Establish key* returns the shared secret in its response,
  and the HKDF command only accepts an input key from the command data or from
  a symmetric key slot. The MCU therefore receives the shared secret and sends
  it back for HKDF-Extract.
- **GCM nonces.** The AES-GCM commands take the nonce from the host; the chip
  cannot build the TLS 1.3 nonce (static IV XOR record sequence number) itself.
  The MCU needs the IVs, which are derived from the traffic secrets, so those
  slots must allow derived values to be returned to the host. That permission
  applies to the whole slot: the MCU could request the traffic keys the same
  way.
- **Host keys.** The host MAC and cipher keys that authorize these commands are
  stored on the MCU.

As a result, the session keys are protected against an attacker on the I2C
bus, and mostly against one who reads MCU memory after the handshake, but not
against code running on the MCU, which sees the application data in clear
anyway. For a TLS client, the secret most worth keeping in the secure element
is the device's long-term private key: it never leaves the STSAFE-A120 (see
[`01_device_authentication`](../01_device_authentication)), while a TLS stack
on the MCU handles the short-lived session keys.

## Requirements

- AES-128 host MAC and cipher keys already provisioned in the device. On the
  ST evaluation personalization, *Establish key* requires a host C-MAC (check
  with `02_command_access_conditions`).
- Nine empty symmetric key slots that accept derived keys. The sample checks
  this before writing anything and stops if they are not available.

## Running it

By default the sample prints `SKIPPED` and does not talk to the device. Only on
a device whose slots and host C-MAC counter you are allowed to change, create
an untracked file, for example `tls.local.conf`:

```ini
CONFIG_SAMPLE_STSAFE_ALLOW_TLS_SLOT_WRITES=y
CONFIG_SAMPLE_STSAFE_HOST_MAC_KEY_HEX="<32 hex characters>"
CONFIG_SAMPLE_STSAFE_HOST_CIPHER_KEY_HEX="<32 hex characters>"
```

```sh
west build -p always -b nucleo_l452re --shield x_nucleo_ese01a1 stsephyr/samples/03_tls13_crypto -- -DEXTRA_CONF_FILE=$PWD/tls.local.conf
west flash
```

The keys end up in the firmware image and in the build directory; do not share
them. A successful run ends with `PASS: 03_tls13_crypto`.

## Limitations

1. **No TLS protocol.** No sockets, record layer, message parsing or
   encoding, extension negotiation, alerts, or integration with Mbed TLS or the
   Zephyr TLS sockets. Handshake messages are simplified placeholders, so a
   successful run says nothing about interoperability with a real server.
2. **No server authentication.** The mock server's public key is trusted
   directly. There is no X.509 chain, host name, validity or revocation check,
   and no client certificate.
3. **One configuration only.** One cipher suite, one curve, one full handshake.
   No PSK, resumption, 0-RTT, HelloRetryRequest, KeyUpdate or exporters.
4. **Secrets pass through the MCU**, for the reasons
   [above](#why-some-secrets-reach-the-mcu). The sample erases its own copies,
   but STSELib and I2C buffers are not wiped. This is not end-to-end key
   isolation.
5. **Bus protection depends on the personalization.** Commands are encrypted
   on the I2C bus only if the device's encryption flags require it.
6. **Persistent side effects.** Up to nine keys are written to EEPROM slots and
   erased at the end, and the host C-MAC counter advances. A reset, power loss
   or I2C error in the middle can leave keys behind; recovering them needs a
   manual look at the key table.
7. **No record bookkeeping.** Sequence numbers are passed in by the caller.
   Replay, nonce reuse, sequence overflow and AEAD usage limits are not
   tracked. Only short records are tested; no fragmentation or 16 KB records.
8. **Minimal state machine.** The helper enforces the order of the Finished
   and key-update steps, nothing more. Only one handshake per device at a
   time, and the caller must hold the STSEphyr lock for the whole flow.
9. **Not production ready.** Host keys are build-time strings, and there is
   no secure key storage on the MCU, fault-injection testing, endurance
   analysis or timing data.
