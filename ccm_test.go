package aesccm

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/pschlump/godebug"
)

func TestMaxLength(t *testing.T) {
	const min = 7
	const max = 13
	var key [aes.BlockSize]byte
	const TagLength = CcmTagSize
	aes, err := aes.NewCipher(key[:])
	if err != nil {
		t.Errorf("AesCCM FATAL ERROR: Unable to setup AES with given key")
		return
	}

	var maxavail uint64
	if is64BitArch {
		maxavail = uint64(math.MaxInt64) - TagLength
	} else {
		maxavail = uint64(math.MaxInt32 - TagLength)
	}

	if _, err := NewCCM(aes, TagLength, min-1); err == nil {
		t.Errorf("NewCCM with noncelength=%d expected error for noence out of range", min-1)
	}
	if _, err := NewCCM(aes, TagLength, max+1); err == nil {
		t.Errorf("NewCCM with noncelength=%d expected error -fr noence out of range", max+1)
	}
	if _, err := NewCCM(aes, TagLength, max+100); err == nil {
		t.Errorf("NewCCM with noncelength=%d expected error -fr noence out of range", max+1)
	}
	if AesCCM, err := NewCCM(aes, TagLength, min); err != nil {
		t.Errorf("NewCCM should work at minimum length, got error %s instead", err)
	} else {
		maxlen := AesCCM.MaxLength() // Get the maximum length now
		if uint64(maxlen) != maxavail {
			t.Error("MaxLength(): did not return the maximum possible length for minimum data")
		}
	}

	// Walk across the potental legngths and check them
	for noncelen, pos := min, 0; noncelen <= max; noncelen++ {
		AesCCM, err := NewCCM(aes, TagLength, noncelen)
		if err != nil {
			t.Fatalf("NewCCM Test %v - noncelen=%d - Should have succeded - Error: %s", pos, noncelen, err)
		}
		maxlen := AesCCM.MaxLength()   // Get the maximum length now
		if is64BitArch && maxlen < 0 { // skip test on 32 bit systems
			t.Errorf("MaxLength(): Test %d - negative - initcating error - 32bit system limitation - noncelen:%d maxlen%d", pos, noncelen, maxlen)
		}
		if uint64(maxlen) > maxavail {
			t.Errorf("MaxLength(): Test %v - missing TAG room", pos)
		}
		pos++
	}
}

func TestAESCCM(t *testing.T) {
	// Test vectors are directly from from rfc3610
	var testDataRfc3610 = []struct {
		key        string
		nonce      string
		adata      string
		plaintext  string
		ciphertext string
	}{
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "00000003020100a0a1a2a3a4a5", adata: "0001020304050607", plaintext: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e", ciphertext: "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0"},
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "00000004030201a0a1a2a3a4a5", adata: "0001020304050607", plaintext: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", ciphertext: "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916"},
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "00000005040302a0a1a2a3a4a5", adata: "0001020304050607", plaintext: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", ciphertext: "51b1e5f44a197d1da46b0f8e2d282ae871e838bb64da8596574adaa76fbd9fb0c5"},
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "00000006050403a0a1a2a3a4a5", adata: "000102030405060708090a0b", plaintext: "0c0d0e0f101112131415161718191a1b1c1d1e", ciphertext: "a28c6865939a9a79faaa5c4c2a9d4a91cdac8c96c861b9c9e61ef1"},
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "00000007060504a0a1a2a3a4a5", adata: "000102030405060708090a0b", plaintext: "0c0d0e0f101112131415161718191a1b1c1d1e1f", ciphertext: "dcf1fb7b5d9e23fb9d4e131253658ad86ebdca3e51e83f077d9c2d93"},
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "00000008070605a0a1a2a3a4a5", adata: "000102030405060708090a0b", plaintext: "0c0d0e0f101112131415161718191a1b1c1d1e1f20", ciphertext: "6fc1b011f006568b5171a42d953d469b2570a4bd87405a0443ac91cb94"},
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "00000009080706a0a1a2a3a4a5", adata: "0001020304050607", plaintext: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e", ciphertext: "0135d1b2c95f41d5d1d4fec185d166b8094e999dfed96c048c56602c97acbb7490"},
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "0000000a090807a0a1a2a3a4a5", adata: "0001020304050607", plaintext: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", ciphertext: "7b75399ac0831dd2f0bbd75879a2fd8f6cae6b6cd9b7db24c17b4433f434963f34b4"},
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "0000000b0a0908a0a1a2a3a4a5", adata: "0001020304050607", plaintext: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", ciphertext: "82531a60cc24945a4b8279181ab5c84df21ce7f9b73f42e197ea9c07e56b5eb17e5f4e"},
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "0000000c0b0a09a0a1a2a3a4a5", adata: "000102030405060708090a0b", plaintext: "0c0d0e0f101112131415161718191a1b1c1d1e", ciphertext: "07342594157785152b074098330abb141b947b566aa9406b4d999988dd"},
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "0000000d0c0b0aa0a1a2a3a4a5", adata: "000102030405060708090a0b", plaintext: "0c0d0e0f101112131415161718191a1b1c1d1e1f", ciphertext: "676bb20380b0e301e8ab79590a396da78b834934f53aa2e9107a8b6c022c"},
		{key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", nonce: "0000000e0d0c0ba0a1a2a3a4a5", adata: "000102030405060708090a0b", plaintext: "0c0d0e0f101112131415161718191a1b1c1d1e1f20", ciphertext: "c0ffa0d6f05bdb67f24d43a4338d2aa4bed7b20e43cd1aa31662e7ad65d6db"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "00412b4ea9cdbe3c9696766cfa", adata: "0be1a88bace018b1", plaintext: "08e8cf97d820ea258460e96ad9cf5289054d895ceac47c", ciphertext: "4cb97f86a2a4689a877947ab8091ef5386a6ffbdd080f8e78cf7cb0cddd7b3"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "0033568ef7b2633c9696766cfa", adata: "63018f76dc8a1bcb", plaintext: "9020ea6f91bdd85afa0039ba4baff9bfb79c7028949cd0ec", ciphertext: "4ccb1e7ca981befaa0726c55d378061298c85c92814abc33c52ee81d7d77c08a"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "00103fe41336713c9696766cfa", adata: "aa6cfa36cae86b40", plaintext: "b916e0eacc1c00d7dcec68ec0b3bbb1a02de8a2d1aa346132e", ciphertext: "b1d23a2220ddc0ac900d9aa03c61fcf4a559a4417767089708a776796edb723506"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "00764c63b8058e3c9696766cfa", adata: "d0d0735c531e1becf049c244", plaintext: "12daac5630efa5396f770ce1a66b21f7b2101c", ciphertext: "14d253c3967b70609b7cbb7c499160283245269a6f49975bcadeaf"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "00f8b678094e3b3c9696766cfa", adata: "77b60f011c03e1525899bcae", plaintext: "e88b6a46c78d63e52eb8c546efb5de6f75e9cc0d", ciphertext: "5545ff1a085ee2efbf52b2e04bee1e2336c73e3f762c0c7744fe7e3c"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "00d560912d3f703c9696766cfa", adata: "cd9044d2b71fdb8120ea60c0", plaintext: "6435acbafb11a82e2f071d7ca4a5ebd93a803ba87f", ciphertext: "009769ecabdf48625594c59251e6035722675e04c847099e5ae0704551"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "0042fff8f1951c3c9696766cfa", adata: "d85bc7e69f944fb8", plaintext: "8a19b950bcf71a018e5e6701c91787659809d67dbedd18", ciphertext: "bc218daa947427b6db386a99ac1aef23ade0b52939cb6a637cf9bec2408897c6ba"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "00920f40e56cdc3c9696766cfa", adata: "74a0ebc9069f5b37", plaintext: "1761433c37c5a35fc1f39f406302eb907c6163be38c98437", ciphertext: "5810e6fd25874022e80361a478e3e9cf484ab04f447efff6f0a477cc2fc9bf548944"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "0027ca0c7120bc3c9696766cfa", adata: "44a3aa3aae6475ca", plaintext: "a434a8e58500c6e41530538862d686ea9e81301b5ae4226bfa", ciphertext: "f2beed7bc5098e83feb5b31608f8e29c38819a89c8e776f1544d4151a4ed3a8b87b9ce"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "005b8ccbcd9af83c9696766cfa", adata: "ec46bb63b02520c33c49fd70", plaintext: "b96b49e21d621741632875db7f6c9243d2d7c2", ciphertext: "31d750a09da3ed7fddd49a2032aabf17ec8ebf7d22c8088c666be5c197"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "003ebe94044b9a3c9696766cfa", adata: "47a65ac78b3d594227e85e71", plaintext: "e2fcfbb880442c731bf95167c8ffd7895e337076", ciphertext: "e882f1dbd38ce3eda7c23f04dd65071eb41342acdf7e00dccec7ae52987d"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "003ebe94044b9a3c9696766cfa", adata: "47a65ac78b3d594227e85e71", plaintext: "e2fcfbb880442c731bf95167c8ffd7895e337076", ciphertext: "e882f1dbd38ce3eda7c23f04dd65071eb41342acdf7e00dccec7ae52987d"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "003ebe94044b9a3c9696766cfa", adata: "47a65ac78b3d594227e85e71", plaintext: "e2fcfbb880442c731bf95167c8ffd7895e337076", ciphertext: "e882f1dbd38ce3eda7c23f04dd65071eb41342acdf7e00dccec7ae52987d"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "008d493b30ae8b3c9696766cfa", adata: "6e37a6ef546d955d34ab6059", plaintext: "abf21c0b02feb88f856df4a37381bce3cc128517d4", ciphertext: "f32905b88a641b04b9c9ffb58cc390900f3da12ab16dce9e82efa16da62059"},
		{key: "d7828d13b2b0bdc325a76236df93cc6b", nonce: "008d493b30ae8b3c9696766cfa", adata: "6e37a6ef546d955d34ab6059", plaintext: "abf21c0b02feb88f856df4a37381bce3cc128517d4", ciphertext: "f32905b88a641b04b9c9ffb58cc390900f3da12ab16dce9e82efa16da62059"},
	}

	decodeAndCheck := func(vv string, i int) (rv []byte) {
		var err error
		rv, err = hex.DecodeString(vv)
		if err != nil {
			t.Errorf("AesCCM FATAL ERROR: Unable to setup AES, input hex failed to parse, %v test:#%d", vv, i)
			return
		}
		return
	}

	for i, v := range testDataRfc3610 {
		godebug.Printf("Test: %d ---------------------------------------------------------------------------\n", i)

		key := decodeAndCheck(v.key, i)
		nonce := decodeAndCheck(v.nonce, i)
		adata := decodeAndCheck(v.adata, i)
		plaintext := decodeAndCheck(v.plaintext, i)
		Aes, err := aes.NewCipher(key)
		if err != nil {
			t.Errorf("AesCCM FATAL ERROR: Unable to setup AES with given key")
			return
		}

		TagLength := hex.DecodedLen(len(v.ciphertext)) - len(plaintext)
		AesCCM, err := NewCCM(Aes, TagLength, len(nonce))
		if err != nil {
			t.Fatal(err)
		}

		ct := AesCCM.Seal(nil, nonce, plaintext, adata)
		tmp := fmt.Sprintf("%x", ct)
		if strings.ToLower(v.ciphertext) != strings.ToLower(tmp) {
			t.Errorf("AesCCM Test #%d: got\t%s, expected\t%s", i, tmp, v.ciphertext)
			continue
		}

		plaintext2, err := AesCCM.Open(nil, nonce, ct, adata)
		if err != nil {
			t.Errorf("AesCCM Test #%d: Open failed when it should have succeded: %v", i, err)
			continue
		}

		if !bytes.Equal(plaintext, plaintext2) {
			t.Errorf("AesCCM Test #%d: got %x expected %x, failed to properly recover original data", i, plaintext2, plaintext)
			continue
		}

		for j := 0; j < 8; j++ {
			onebit := byte(1 << uint(j))
			for pos := 0; pos < len(nonce) || pos < len(ct); pos++ {
				if pos < len(nonce) {
					nonce[pos] ^= onebit
					if _, err := AesCCM.Open(nil, nonce, ct, adata); err == nil {
						t.Errorf("AesCCM Test #%d: Altered nonce, should have failed open, pos=%d j=%d", i, pos, j)
					}
					nonce[pos] ^= onebit
				}

				if pos < len(ct) {
					ct[pos] ^= onebit
					if _, err := AesCCM.Open(nil, nonce, ct, adata); err == nil {
						t.Errorf("AesCCM Test #%d: Altered ct, should have failed open, pos=%d j=%d", i, pos, j)
					}
					ct[pos] ^= onebit
				}

				if pos < len(adata) && len(adata) > 0 {
					adata[pos] ^= onebit
					if _, err := AesCCM.Open(nil, nonce, ct, adata); err == nil {
						t.Errorf("AesCCM Test #%d: Alterd adata, should have failed open, pos=%d j=%d", i, pos, j)
					}
					adata[pos] ^= onebit
				}

			}
		}
	}
}

/*
valid IV sizes:
	7, 8, 9, 10, 11, 12, 13
valid Tag sizes:
	4, 6, 8, 10, 12, 14, 16
*/

func Test_01(t *testing.T) {
	//var blk cipher.Block
	key := []byte("example key 1234")

	blk, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// func (c *CCMType) cbcOneBLock(mac, data []byte) {
	// c, err := NewCCM(blk cipher.Block, TagSize int, NonceSize int)
	// Nonce == 6 -> Failed
	// Nonce == 14 -> Failed
	// Nonce 8, 10, 12
	_, err = NewCCM(blk, CcmBlockSize, 12)
	if err != nil {
		t.Errorf("Failed to create NewCCM, err=%s", err)
		return
	}

	//var mac, data [CcmBlockSize]byte
	mac := make([]byte, CcmBlockSize, CcmBlockSize)
	// copy ( mac, []byte("0123456790abcdef")
	data := []byte("0123456790abcdef")

	cc, err := newCCMType(blk, CcmBlockSize, 12)
	if err != nil {
		t.Errorf("Failed to create NewCCM, err=%s", err)
		return
	}

	cc.cbcOneBLock(mac, data)
	// fmt.Printf("%x\n", mac)
	if "af278d089142971fe3009fd40bb879c8" != fmt.Sprintf("%x", mac) {
		t.Errorf("Failed to match previous encrypted ccm stuff")
	}

	// func (c *CCMType) cbcString(mac, data []byte) {
	cc.cbcString(mac, []byte(`Humpty Dumpty got Put Back Together Again - He Did! He Did!!`))
	// fmt.Printf("%x\n", mac)
	if "752163991a3c21905c825db9b17bb364" != fmt.Sprintf("%x", mac) {
		t.Errorf("Failed to match previous encrypted ccm/cbc stuff")
	}

}

func Test_NonceLength(t *testing.T) {
	var testData = []struct {
		in    int
		nonce int
	}{
		{nonce: 13, in: 20},
		{nonce: 13, in: 200},
		{nonce: 13, in: 2000},
		{nonce: 13, in: 20000},
		{nonce: 12, in: 200000},
		{nonce: 12, in: 2000000},
		{nonce: 11, in: 20000000},
		{nonce: 11, in: 200000000},
	}

	for ii, vv := range testData {
		if kk := CalculateNonceLengthFromMessageLength(vv.in); kk != vv.nonce {
			t.Errorf("Invalid NonceLength Test %d, Expected %d, got %d\n", ii, vv.nonce, kk)
		}
	}

}

func BenchmarkAESCCMSeal(b *testing.B) {
	var key [aes.BlockSize]byte
	var nonce [13]byte
	var out []byte

	key1, _ := hex.DecodeString("d7828d13b2b0bdc325a76236df93cc6b")
	copy(key[:], key1)

	Aes, _ := aes.NewCipher(key[:])
	AesCCM, _ := NewCCM(Aes, aes.BlockSize, 13)

	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))

	copy(nonce[:], "aaaaaaaaaaaaa"[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = AesCCM.Seal(out[:0], nonce[:], buf, nonce[:])
	}
}

func Test_maximumLengthForMessage(t *testing.T) {
	var testData = []struct {
		L       uint64
		TagSize uint64
		out     int
	}{
		// {out: 13, L: 20, TagSize: 12},
		// {out: 13, L: 200, TagSize: 12},
		// {out: 13, L: 2000, TagSize: 12},
		// {out: 13, L: 20000, TagSize: 12},
		// {out: 12, L: 200000, TagSize: 12},
		// {out: 12, L: 2000000, TagSize: 12},
		// {out: 11, L: 20000000, TagSize: 12},
		// {out: 11, L: 200000000, TagSize: 12},
		{out: 65535, L: 2, TagSize: 10},
		{out: 65535, L: 2, TagSize: 16},
		{out: 65535, L: 2, TagSize: 8},
		{out: 16777215, L: 3, TagSize: 16},
		{out: 4294967295, L: 4, TagSize: 16},
		{out: 1099511627775, L: 5, TagSize: 16},
		{out: 281474976710655, L: 6, TagSize: 16},
		{out: 72057594037927935, L: 7, TagSize: 16},
		{out: 9223372036854775791, L: 8, TagSize: 16},
	}

	for ii, vv := range testData {

		// func maximumLengthForMessage(L uint64, TagSize uint64) int {
		jj := maximumLengthForMessage(vv.L, vv.TagSize)

		godebug.Printf("L %d TagSize %d Out %d\n", vv.L, vv.TagSize, jj)

		if true {
			if kk := maximumLengthForMessage(vv.L, vv.TagSize); kk != vv.out {
				t.Errorf("Invalid NonceLength Test %d, Expected %d, got %d, test %d\n", ii, vv.out, vv.out, kk)
			}
		}
	}

}

/* vim: set noai ts=4 sw=4: */
