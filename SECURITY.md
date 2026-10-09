# Security policy

Please report vulnerabilities privately to the maintainers rather than in a
public issue. Include the affected revision, the hardware and personalization,
the steps to reproduce and the impact.

STSEphyr does not log I2C frames. Do not add logs that print host keys, session
keys, provisioning data, passwords or other secrets.

Code that provisions keys, changes access conditions, changes the I2C address
or locks the device must never run automatically, at boot or in CI.
