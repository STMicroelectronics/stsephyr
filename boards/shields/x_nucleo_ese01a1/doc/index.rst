.. _x_nucleo_ese01a1:

X-NUCLEO-ESE01A1
################

Overview
********

The X-NUCLEO-ESE01A1 is an Arduino UNO R3 expansion board with an STSAFE-A120
secure element. The STSAFE-A120 is connected to the Arduino I2C bus (D14/D15)
at 7-bit address ``0x20``, and its reset is controlled from Arduino pin A5
through an inverting PMOS, so the reset GPIO is active high on the MCU side.

The shield requires the STSEphyr module, which provides the ``st,stsafe-a120``
driver.

Requirements
************

A board with an Arduino UNO R3 header, Zephyr ``arduino_i2c`` and
``arduino_header`` definitions, and an entropy source. Check the I2C pull-up
solder bridges against the X-NUCLEO-ESE01A1 user manual (UM3531).

On NUCLEO-L452RE, ``boards/nucleo_l452re.overlay`` routes Arduino I2C to
PB8/PB9 and enables the RNG with its HSI48 clock.

Programming
***********

.. code-block:: console

   west build -b nucleo_l452re --shield x_nucleo_ese01a1 stsephyr/samples/basic
   west flash
