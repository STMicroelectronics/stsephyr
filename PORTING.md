# Using another board

STSEphyr is not tied to the STM32L452. The driver needs:

- an I2C controller connected to the STSAFE-A120,
- one GPIO for the reset line,
- a real entropy source for Zephyr's CSPRNG (`sys_csrand_get()`),
- and, for the samples, a console UART.

Everything board specific is in devicetree; the C code normally does not change.

## X-NUCLEO-ESE01A1 on another Arduino-compatible board

The shield overlay uses Zephyr's standard `arduino_i2c` bus and
`arduino_header` connector, so on most boards with an Arduino UNO R3 header it
works as is:

```sh
west build -p always -b <board> --shield x_nucleo_ese01a1 stsephyr/samples/basic
```

| Signal | Arduino pin |
| --- | --- |
| SDA / SCL | D14 / D15 |
| STSAFE-A120 reset (through an inverting PMOS on the shield) | A5 |

The STSAFE-A120 answers at 7-bit I2C address `0x20` in the ST evaluation
personalization.

After the build, open `build/zephyr/zephyr.dts` and check that:

- `stsafe-a120@20` sits under the I2C controller wired to D14/D15,
- the I2C pins, the reset GPIO and the I2C clock frequency match the board
  schematic,
- an entropy source (`rng` or similar) is enabled.

If a pin mapping or a clock differs, add a board overlay to the shield, as
done for the L452RE in
[`boards/shields/x_nucleo_ese01a1/boards/nucleo_l452re.overlay`](boards/shields/x_nucleo_ese01a1/boards/nucleo_l452re.overlay):

```text
boards/shields/x_nucleo_ese01a1/boards/<board>.overlay
```

For example, `nucleo_g474re` builds without any extra overlay (compile tested
only).

## Custom wiring

Describe the device under the I2C controller it is connected to, in a board
file or an application overlay:

```dts
#include <zephyr/dt-bindings/gpio/gpio.h>
#include <zephyr/dt-bindings/i2c/i2c.h>

&i2c2 {
	pinctrl-0 = <&i2c2_scl_pb10 &i2c2_sda_pb11>;
	pinctrl-names = "default";
	clock-frequency = <I2C_BITRATE_STANDARD>;
	status = "okay";

	stsafe-a120@20 {
		compatible = "st,stsafe-a120";
		reg = <0x20>;
		reset-gpios = <&gpioa 5 GPIO_ACTIVE_LOW>;
	};
};
```

- **Reset polarity:** with a direct connection to the STSAFE-A120 reset pin
  the line is normally `GPIO_ACTIVE_LOW`. Through the X-NUCLEO-ESE01A1 PMOS it
  is `GPIO_ACTIVE_HIGH`. Follow your schematic.
- **I2C speed:** start at 100 kHz (`I2C_BITRATE_STANDARD`); move to 400 kHz
  once the basic sample is reliable and the pull-ups allow it.

Build with the overlay:

```sh
west build -p always -b <board> stsephyr/samples/basic -- -DEXTRA_DTC_OVERLAY_FILE=/path/to/stsafe.overlay
```

## First run

Flash `basic` first. It only sends an echo command:

```text
<inf> stsephyr: stsafe-a120@20 ready at 0x20 on <i2c controller>
PASS: basic
```

If initialization fails, the usual causes are the reset polarity, the I2C
address, missing pull-ups, an I2C controller or pinctrl not enabled, or the
console on another UART.

Then run the other samples that do not change the device (`01_echo_loop`,
`01_random_number`, `01_hash`, `01_secure_data_storage`,
`02_command_access_conditions`, `01_device_authentication` without the opt-in).

## Adding the board to the tests

Once the samples pass on the new board, add it to `platform_allow` and
`integration_platforms` in the `sample.yaml` files you validated, and add an
entry to your hardware map:

```yaml
- connected: true
  fixtures: [stsafe_a120]
  id: <debug probe serial number>
  platform: <board>
  product: <probe product name, e.g. STM32 STLink>
  runner: <flash runner>
  serial: <serial port>
  baud: 115200
```

`west twister --generate-hardware-map <file>` can generate the probe and port
fields.
