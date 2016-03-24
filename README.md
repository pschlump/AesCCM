# AesCCM - An imlementation of CCM for signing AES encrypted messages

Note: this has been designed to work specifically with the Go-FTL AesSRP middleware.
It should be a general purpose CCM implementation - but all of the testing has been

1. On 64 bit architecture. No 32 bit tests have been run.
2. With AES encryption.  No other encryption has been tested.

## License

MIT except for ./xor.go and ./xor_test.go that are from the GO source code.
See LICENSE file.

