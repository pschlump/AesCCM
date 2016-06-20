// Implement CCM as per RFC 3610 - https://tools.ietf.org/html/rfc3610
// Counter with CBC-MAC
//
//
// From: http://www.codeproject.com/Articles/21877/Applied-Crypto-Block-Ciphers
//
// "FIPS 81 specifies two MACs: CFB and CBC. CBC-MAC, which is based
// on DES, is a widely used algorithm to compute a message authentication
// code. CFB mode MACs are lesser known, and have some disadvantages
// compared to the CBC mode. CBC-MAC is now considered insecure for
// certain messages, such as those which vary in length. This has lead
// to the development of stronger MACs using 128 bit ciphers such as
// AES with a counter (RFC 3610). This is known as CCM, or Counter
// with CBC-MAC.'
//
// From: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ccm/ccm.pdf
//
package aesccm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"math"
)

// ok - from spec
// CCMType represents a Counter with CBC-MAC with a specific key.
type CCMType struct {
	blk cipher.Block //
	M   uint64       // # of octets(bytes) in authentication field	(field size 3) == (M-2)/2
	L   uint64       // # of octets(bytes) in length field			(field size 3) == L-1
	err error
}

// ok - from spec
const CcmBlockSize = aes.BlockSize
const CcmTagSize = 16
const is64BitArch = uint64(^uint(0)) == ^uint64(0)

// ok - from spec
// Definition: CCM is a block cipher in Counter with CBC-MAC mode.
// Meat the cipher.AEAD interface specification.
/*
type AEAD interface {
        // NonceSize returns the size of the nonce that must be passed to Seal
        // and Open.
        NonceSize() int

        // Overhead returns the maximum difference between the lengths of a
        // plaintext and its ciphertext.
        Overhead() int

        // Seal encrypts and authenticates plaintext, authenticates the
        // additional data and appends the result to dst, returning the updated
        // slice. The nonce must be NonceSize() bytes long and unique for all
        // time, for a given key.
        //
        // The plaintext and dst may alias exactly or not at all. To reuse
        // plaintext's storage for the encrypted output, use plaintext[:0] as dst.
        Seal(dst, nonce, plaintext, additionalData []byte) []byte

        // Open decrypts and authenticates ciphertext, authenticates the
        // additional data and, if successful, appends the resulting plaintext
        // to dst, returning the updated slice. The nonce must be NonceSize()
        // bytes long and both it and the additional data must match the
        // value passed to Seal.
        //
        // The ciphertext and dst may alias exactly or not at all. To reuse
        // ciphertext's storage for the decrypted output, use ciphertext[:0] as dst.
        //
        // Even if the function fails, the contents of dst, up to its capacity,
        // may be overwritten.
        Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}
*/
type CCM interface {
	cipher.AEAD
	// MaxLength calculates the maximum length of plaintext that can be used in calls to Seal.
	// The maximum length of ciphertext in calls to Open is MaxLength()+'c.M'.
	// The maximum length is related to CCM's `L` parameter (15-noncesize) and
	// is 1<<(8*L) - 1 (but also limited by the maximum size of an int).
	MaxLength() int
}

// ok -
// NewCCM builds the 128-bit block cipher (input) into the CCM interface type.
// Check That TagSize is an even integer between 4 and 16 inclusive. This is used as CCM's `M` parameter.
// Check That NonceSize is an integer between 7 and 13 inclusive.  This is 15-noncesize is used as CCM's `L` parameter.
func NewCCM(blk cipher.Block, TagSize int, NonceSize int) (c CCM, err error) {
	return newCCMType(blk, TagSize, NonceSize)
}

// Exists just for testing of functions
// Same as CCM but not meating interface requirements - could be folded in
func newCCMType(blk cipher.Block, TagSize int, NonceSize int) (c *CCMType, err error) {
	// verify block size of cypher is acceptable
	if blk.BlockSize() != CcmBlockSize {
		return nil, ErrInvalidBlockSize
	}

	// checks that tag size is divisable by 2 and between 4 and 16
	if TagSize < 4 || TagSize > 16 || TagSize%2 == 1 {
		return nil, ErrTagSize
	}

	// Check that NonceSize is in range of proper sizes
	l := 15 - NonceSize
	if l < 2 || l > 8 {
		return nil, ErrNonceSize
	}

	// All Good - return it.
	c = &CCMType{blk: blk, M: uint64(TagSize), L: uint64(l)}
	return
}

// ok - from spec
// Directly from rfc3610 - this is the TagSize -- Interface Function
func (ccmt *CCMType) Overhead() int {
	return int(ccmt.M)
}

// ok - from spec
// Directly from rfc3610 -
func (ccmt *CCMType) MaxLength() int {
	return maximumLengthForMessage(ccmt.L, ccmt.M) // ccmt.M is the overhead
}

// ok - from spec
// Directly from rfc3610 - Interface Function
func (ccmt *CCMType) NonceSize() int {
	return 15 - int(ccmt.L)
}

// -- ok --
// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
//
// From: crypto/cipher/gcm.go - with no modification.
//
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// ok -
// MaxNonceLength returns the maximum nonce length for a given input plaintext.
// Negative return value is an error with too long a palaintext.
//
// Taken Directly from SJCL code: See: https://github.com/bitwiseshiftleft/sjcl/blob/version-0.8/core/ccm.js
// This matches with the older "public domain" version of SJCL - current implemenation is a little fancier but works the same.
// // compute the length of the length
//    for (L=2; L<4 && ol >>> 8*L; L++) {}
//    if (L < 15 - ivl) { L = 15-ivl; }
func MaxNonceLength(pdatalen int) int {
	const TagSize = uint64(16)
	for L := uint64(2); L <= 8; L++ {
		if maximumLengthForMessage(L, TagSize) >= pdatalen {
			return int(uint64(15) - L)
		}
	}
	return 0
}

// Working with SJCL assumes that you have a 32 bit arcitecture and this limits the outputs from this.
func CalculateNonceLengthFromMessageLength(lenOfPlaintext int) int {
	var L int
	// ivl := 4 * 4 // ivl  - length of 'iv' in bytes -				// From SJCL

	// compute the length of the length
	// 63     for (L=2; L<4 && lenOfPlaintext >>> 8*L; L++) {}		// From SJCL
	for L = 2; L < 4 && (lenOfPlaintext>>uint32(8*L)) > 0; L++ {
	}
	// 64     if (L < 15 - ivl) { L = 15-ivl; } 					// From SJCL
	// 65     iv = w.clamp(iv,8*(15-L));
	return 15 - L
}

/*

   The message is encrypted by XORing the octets of message m with the
   first l(m) octets of the concatenation of S_1, S_2, S_3, ... .  Note
   that S_0 is not used to encrypt the message.

   The authentication value U is computed by encrypting T with the key
   stream block S_0 and truncating it to the desired length.

      U := T XOR first-M-bytes( S_0 )

   The final result c consists of the encrypted message followed by the
   encrypted authentication value U.

*/

// One XOR and Encrypt pass of a block
func (ccmt *CCMType) cbcOneBLock(mac, data []byte) {
	xorBytes(mac, mac[0:CcmBlockSize], data[0:CcmBlockSize])
	ccmt.blk.Encrypt(mac, mac)
}

// Calculate a CBC for the data
func (ccmt *CCMType) cbcString(mac, data []byte) {
	var block [CcmBlockSize]byte
	var i int
	for i = 0; i < len(data)-CcmBlockSize; i += CcmBlockSize {
		ccmt.cbcOneBLock(mac, data[i:i+CcmBlockSize])
	}
	if i < len(data) {
		copy(block[:], data[i:])
		ccmt.cbcOneBLock(mac, block[:])
	}
}

func (ccmt *CCMType) calculateCcmTag(nonce, plaintext, adata []byte) ([]byte, error) {
	var i int

	if len(plaintext) > ccmt.MaxLength() {
		return nil, ErrPlaintextTooLong
	}
	if len(nonce) != ccmt.NonceSize() {
		return nil, ErrNonceSize
	}

	var mac [CcmBlockSize]byte

	/*
	   The first block B_0 is formatted as follows, where l(m) is encoded in
	   most-significant-byte first order:

	      Octet Number   Contents
	      ------------   ---------
	      0              Flags
	      1 ... 15-L     Nonce N
	      16-L ... 15    l(m)

	   Within the first block B_0, the Flags field is formatted as follows:

	      Bit Number   Contents
	      ----------   ----------------------
	      7            Reserved (always zero)
	      6            Adata
	      5 ... 3      M'
	      2 ... 0      L'

	   Another way say the same thing is:  Flags = 64*Adata + 8*M' + L'.

	   The Reserved bit is reserved for future expansions and should always
	   be set to zero.  The Adata bit is set to zero if l(a)=0, and set to
	   one if l(a)>0.  The M' field is set to (M-2)/2.  As M can take on the
	   even values from 4 to 16, the 3-bit M' field can take on the values
	   from one to seven.  The 3-bit field MUST NOT have a value of zero,
	   which would correspond to a 16-bit integrity check value.  The L'
	   field encodes the size of the length field used to store l(m).  The
	   parameter L can take on the values from 2 to 8 (recall, the value L=1
	   is reserved).  This value is encoded in the 3-bit L' field using the
	   values from one to seven by choosing L' = L-1 (the zero value is
	   reserved).

	   If l(a)>0 (as indicated by the Adata field), then one or more blocks
	   of authentication data are added.  These blocks contain l(a) and a
	   encoded in a reversible manner.  We first construct a string that
	   encodes l(a).
	*/

	mac[0] = mac[0] | uint8((ccmt.M-2)<<2) | uint8(ccmt.L-1) // ok - from spec
	if len(adata) > 0 {                                      // Ok From spec
		mac[0] |= 1 << 6 // set bit for having length of adata > 0, adata is included in processing.
	}

	// Copy to mac, 8 bytes, len of plaintext
	binary.BigEndian.PutUint64(mac[8:], uint64(len(plaintext))) // https://golang.org/src/encoding/binary/binary.go
	copy(mac[1:CcmBlockSize-ccmt.L], nonce)
	ccmt.blk.Encrypt(mac[:], mac[:])

	/*
	   If 0 < l(a) < (2^16 - 2^8), then the length field is encoded as two
	   octets which contain the value l(a) in most-significant-byte first
	   order.

	   If (2^16 - 2^8) <= l(a) < 2^32, then the length field is encoded as
	   six octets consisting of the octets 0xff, 0xfe, and four octets
	   encoding l(a) in most-significant-byte-first order.

	   If 2^32 <= l(a) < 2^64, then the length field is encoded as ten
	   octets consisting of the octets 0xff, 0xff, and eight octets encoding
	   l(a) in most-significant-byte-first order.

	   The length encoding conventions are summarized in the following
	   table.  Note that all fields are interpreted in most-significant-byte
	   first order.

	    First two octets   Followed by       Comment
	    -----------------  ----------------  -------------------------------
	    0x0000             Nothing           Reserved
	    0x0001 ... 0xFEFF  Nothing           For 0 < l(a) < (2^16 - 2^8)
	    0xFF00 ... 0xFFFD  Nothing           Reserved
	    0xFFFE             4 octets of l(a)  For (2^16 - 2^8) <= l(a) < 2^32
	    0xFFFF             8 octets of l(a)  For 2^32 <= l(a) < 2^64

	*/
	if n := uint64(len(adata)); n > 0 {
		var tmp [CcmBlockSize]byte
		switch {
		case n <= 0xfeff:
			i = 2
			binary.BigEndian.PutUint16(tmp[:i], uint16(n))
		case n > 0xfeff && n < uint64(1<<32):
			i = 6 // 2 + 4 for len
			binary.BigEndian.PutUint16(tmp[0:], uint16(0xfeff))
			binary.BigEndian.PutUint64(tmp[2:i], uint64(n))
		default:
			i = 10 // 2 + 8 for len
			binary.BigEndian.PutUint16(tmp[0:], uint16(0xfeff))
			binary.BigEndian.PutUint64(tmp[2:i], uint64(n))
		}
		i = copy(tmp[i:], adata)
		ccmt.cbcOneBLock(mac[:], tmp[:])  // add in tmp
		ccmt.cbcString(mac[:], adata[i:]) // add in adata
	}

	if len(plaintext) > 0 {
		ccmt.cbcString(mac[:], plaintext)
	}

	return mac[:ccmt.M], nil
}

func (ccmt *CCMType) calcCcmTag(nonce, aTag []byte, InitializationVector *[CcmBlockSize]byte) {
	InitializationVector[0] = uint8(ccmt.L - 1)
	copy(InitializationVector[1:CcmBlockSize-ccmt.L], nonce)
	var tmpTag [CcmBlockSize]byte
	ccmt.blk.Encrypt(tmpTag[:], InitializationVector[:])
	for i := 0; i < int(ccmt.M); i++ {
		aTag[i] ^= tmpTag[i]
	}
	InitializationVector[len(InitializationVector)-1] |= 1 //
}

// Seal - adds the CCM tag to the plaintext.   The data is encrypted
// and the results are added to 'dst'.  The nonce is used and therefore
// must be NonceSize() long.
func (ccmt *CCMType) Seal(dst, nonce, plaintext, adata []byte) (rv []byte) {
	var InitializationVector [CcmBlockSize]byte // CcmBlockSize == 16

	ccmt.err = nil // No errors yet

	// if nonce is too long then truncate it.
	NonceLength := CalculateNonceLengthFromMessageLength(len(plaintext))
	if len(nonce) > NonceLength {
		nonce = nonce[0:NonceLength]
	}

	if ll := 15 - NonceLength; ll != int(ccmt.L) {
		// godebug.Printf(db1, "****************** l=%d ccmt.L=%d\n", ll, ccmt.L)
		ccmt.err = ErrInvalidNonceLength
		return
	}

	aTag, err := ccmt.calculateCcmTag(nonce, plaintext, adata)
	if err != nil {
		ccmt.err = err
		return
	}

	ccmt.calcCcmTag(nonce, aTag, &InitializationVector)
	stream := cipher.NewCTR(ccmt.blk, InitializationVector[:])  //
	ret, out := sliceForAppend(dst, len(plaintext)+int(ccmt.M)) //	<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< diff >>>>>>>>>>>>>>>>>>>>>>>>>
	stream.XORKeyStream(out, plaintext)                         // do the encrypt of plaintext

	copy(out[len(plaintext):], aTag) // stick tag on end, after encrypted plaintext	 -- was aTag
	return ret
}

// Open is the complement operation to Seal.  This is what you do on the
// receiving end when you have a CCM sealed and encrypted  message.
// It calculates the CCM based on the nonce, cypher text and adata
// then performs a compare to verify that the data matches the
// original.
func (ccmt *CCMType) Open(dst, nonce, ct, adata []byte) ([]byte, error) {
	var InitializationVector [CcmBlockSize]byte

	NonceLength := CalculateNonceLengthFromMessageLength(len(ct) - int(ccmt.M))
	if len(nonce) > NonceLength {
		nonce = nonce[0:NonceLength] // Truncate if too long
	}

	if len(ct) > ccmt.MaxLength()+ccmt.Overhead() {
		return nil, ErrCiphertextTooLong
	}

	if len(ct) < int(ccmt.M) {
		return nil, ErrCiphertextTooShort
	}

	CipherText := ct[:len(ct)-int(ccmt.M)]     //
	aTag := ct[len(ct)-int(ccmt.M):]           // Tag from Sender of Message
	PlainText := make([]byte, len(CipherText)) //

	ccmt.calcCcmTag(nonce, aTag, &InitializationVector)        // Generate the tag from the data - so can compare and validate tags.
	stream := cipher.NewCTR(ccmt.blk, InitializationVector[:]) //
	stream.XORKeyStream(PlainText, CipherText)

	expectedTag, err := ccmt.calculateCcmTag(nonce, PlainText, adata)
	if err != nil {
		return nil, err
	}

	// fmt.Printf("Tag in message[%x] Expected[%x], %s\n", SenderOrigTag, expectedTag, godebug.LF())
	// if the orignal tag and the current tag match then we are golden!
	if subtle.ConstantTimeCompare(expectedTag, aTag) == 1 {
		return append(dst, PlainText...), nil
	}
	return nil, ErrOpenError
}

func maximumLengthForMessage(L uint64, TagSize uint64) int {
	//godebug.Printf(db2, "input L=%v TagSize=%v, %s\n", L, TagSize, godebug.LF())
	if !is64BitArch {
		//godebug.Printf(db2, "**** At: %s\n", godebug.LF())
		return int(math.MaxInt32 - TagSize)
	}
	max := (uint64(1) << (8 * L)) - 1 // 32 bit maximum length - works with SJCL
	if m64 := uint64(math.MaxInt64) - TagSize; L > 8 || max > m64 {
		//godebug.Printf(db2, "At: %s\n", godebug.LF())
		return (int(m64)) // The maximum lentgh on a 64bit arch
	}
	return int(max)
	// }
	//godebug.Printf(db2, "At: %s\n", godebug.LF())
	// return int(math.MaxInt32)
}

const db1 = false
const db2 = false

/* vim: set noai ts=4 sw=4: */
