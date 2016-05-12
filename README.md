# AesCCM - An imlementation of CCM for signing AES encrypted messages

 [![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/pschlump/Go-FTL/master/LICENSE)

Note: this has been designed to work specifically with the Go-FTL AesSRP middleware.
It should be a general purpose CCM implementation - but all of the testing has been

1. On 64 bit architecture. No 32 bit tests have been run.
2. With AES encryption.  No other encryption has been tested.

## Referneces

[https://tools.ietf.org/html/rfc3610][https://tools.ietf.org/html/rfc3610]

[https://en.wikipedia.org/wiki/CCM_mode][https://en.wikipedia.org/wiki/CCM_mode]

[http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CCM.pdf][http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CCM.pdf]

[http://csrc.nist.gov/groups/STM/cavp/documents/mac/ccmval.html][http://csrc.nist.gov/groups/STM/cavp/documents/mac/ccmval.html]

[https://www.cryptopp.com/wiki/CCM_Mode][https://www.cryptopp.com/wiki/CCM_Mode]

[https://github.com/weidai11/cryptopp/blob/master/ccm.cpp][https://github.com/weidai11/cryptopp/blob/master/ccm.cpp]

Also look in ./doc directory

## License

MIT except for ./xor.go and ./xor_test.go that are from the GO source code.
See LICENSE file.

