# Contributing

- Keep STSELib unmodified. Fixes to STSELib go to
  [STSELib](https://github.com/STMicroelectronics/STSELib) itself.
- Format C code with the repository `.clang-format` and start every file with
  the copyright line and `SPDX-License-Identifier: Apache-2.0`.
- Comment what is not obvious from the code: hardware constraints, STSELib
  contracts, security decisions.
- Update the documentation when behavior changes.

## Before opening a pull request

```sh
west twister -T stsephyr/tests -p native_sim
west twister -T stsephyr/samples -p nucleo_l452re --build-only
git ls-files '*.c' '*.h' | xargs clang-format --dry-run --Werror
```

If you have the hardware, also run the samples on it (see "Testing" in the
README) and update [VALIDATION.md](VALIDATION.md).

## Samples that change the secure element

STSAFE-A120 changes are permanent: key writes, storage updates, counter
decrements, key usage limits and host C-MAC counters cannot be rolled back.
A sample that does any of this must:

- do it only behind a `CONFIG_SAMPLE_STSAFE_ALLOW_*` option that defaults to
  `n`,
- be `build_only: true` in `sample.yaml` for that configuration,
- never print its `PASS:` line when the operation was skipped.

Never commit keys, firmware images or configuration files containing keys, or
the serial numbers of your probes. Use `*.local.conf` and
`hardware-map.local.yml`, which are ignored by git.

## Dependency updates

Update Zephyr, STSELib or Monocypher in a separate pull request. Check the
platform callback signatures in STSELib's `core/stse_platform.h` and the
source list in `drivers/stsafe/CMakeLists.txt`, then rebuild every sample and
rerun the hardware tests.
