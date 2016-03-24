package sjcl

// Read and convert Stanford JavaScript Cryptography Libraries (SJCL) JSON format JSON structures into
// GO (golang) code.  This code is fairly specific to the aesccm/restful interface for SJCL.

// MIT Licensed.

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/pschlump/aesccm/base64data"
	"github.com/pschlump/json" //	"encoding/json"
)

type SJCL_DataStruct struct {
	InitilizationVector base64data.Base64Data `json:"iv"`     // initilization vector or nonce for CCM mode
	Version             int                   `json:"v"`      // should be constant 1 - version - only version suppoted
	Iter                int                   `json:"iter"`   // PBKDF2 iteration count
	KeySize             int                   `json:"ks"`     // keysize in bits - devide by 8 to get GO key size for pbkdf2
	TagSize             int                   `json:"ts"`     // CCM tag size in bits
	Mode                string                `json:"mode"`   // - should be constant "ccm" - only format supported
	AdditionalData      base64data.Base64Data `json:"adata"`  // additional authenticated data
	Cipher              string                `json:"cipher"` // - should be constant "aes" - only fomrat supported
	Salt                base64data.Base64Data `json:"salt"`   // PBKDF2 salt
	CipherText          base64data.Base64Data `json:"ct"`     // ciphertext
	TagSizeBytes        int                   `json:"-"`      // Tag size converted to bytes
	KeySizeBytes        int                   `json:"-"`      // Key size converted to bytes
	Status              string                `json:"status"` // Response messages include a status of success/error
	Msg                 string                `json:"msg"`    // Error response messages include a "msg"
}

func ReadSJCL(fn string) (eBlob SJCL_DataStruct) {
	file, err := ioutil.ReadFile(fn)
	if err != nil {
		log.Fatal("Reading:", err)
	}
	err = json.Unmarshal(file, &eBlob)
	if err != nil {
		log.Fatal("JSON decoder:", err)
	}

	// Valid input JSON data  ------------------------------------------------------------------------------------------------
	if eBlob.Cipher != "aes" {
		log.Fatalf("Only AES encryption is supported\n") // xyzzy - mod to return an error instad of exit
	}
	if eBlob.Mode != "ccm" {
		log.Fatalf("Only CCM authentication is supported\n")
	}
	if eBlob.Version != 1 {
		log.Fatalf("Only version 1 of SJCL is supported\n")
	}
	if eBlob.TagSize%8 != 0 {
		log.Fatalf("bad tag size TagSize=%d, not a multiple of 8", eBlob.TagSize)
	}
	eBlob.TagSizeBytes = eBlob.TagSize / 8
	eBlob.KeySizeBytes = eBlob.KeySize / 8
	return
}

var BadSJCLData = errors.New("Invalid data in SJCL JSON message")

func ConvertSJCL(file string) (eBlob SJCL_DataStruct, err error, msg string) {

	err = json.Unmarshal([]byte(file), &eBlob)
	if err != nil {
		msg = "JSON decoder error"
		return
	}

	// Valid input JSON data  ------------------------------------------------------------------------------------------------
	if eBlob.Cipher != "aes" {
		msg = "Only AES encryption is supported\n"
		err = BadSJCLData
		return
	}
	if eBlob.Mode != "ccm" {
		msg = "Only CCM authentication is supported\n"
		err = BadSJCLData
		return
	}
	if eBlob.Version != 1 {
		msg = "Only version 1 of SJCL is supported\n"
		err = BadSJCLData
		return
	}
	if eBlob.TagSize%8 != 0 {
		msg = fmt.Sprintf("bad tag size TagSize=%d, not a multiple of 8", eBlob.TagSize)
		err = BadSJCLData
		return
	}
	eBlob.TagSizeBytes = eBlob.TagSize / 8
	eBlob.KeySizeBytes = eBlob.KeySize / 8
	return
}
