package base64data

import (
	"encoding/base64"
	"fmt"

	tr "github.com/pschlump/godebug"
)

// Base64Data extends the JSON marshal/unmarshal interface to support Base64 data.
type Base64Data []byte

// MarshalText implements encoding.TextMarshaller - convert to Base64 on output.
func (b Base64Data) MarshalText() ([]byte, error) {
	text := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(text, b)
	return text, nil
}

// UnmarshalText implements encoding.TextUnmarshaller - convert from Base64 to byte.
func (b *Base64Data) UnmarshalText(text []byte) error {
	if n := base64.StdEncoding.DecodedLen(len(text)); cap(*b) < n {
		*b = make([]byte, n)
	}
	n, err := base64.StdEncoding.Decode(*b, text)
	*b = (*b)[:n]
	return err
}

// xyzzy-c

// int32Array is an hack used for some debug output to approximate
// what the JavaScript implementation will print/show when running
// it in a console.
func (b Base64Data) Int32Array() []int32 {
	n := len(b) / 4
	extra := len(b) % 4
	if extra > 0 {
		n++
	}
	a := make([]int32, n)
	// a := make([]int32, 0, len(b)+1)
	i, j := 0, 0
	for ; j < extra; j++ {
		a[i] <<= 8
		a[i] |= int32(b[j])
	}
	if j != 0 {
		i++
	}
	for ; i < len(a); i++ {
		a[i] = int32(b[j])<<24 | int32(b[j+1])<<16 | int32(b[j+2])<<8 | int32(b[j+3])
		j += 4
	}
	return a
}

// Implement an output conversion for debuging that matches what SJCL shows
// on the SJCL demo page.
func (b Base64Data) Uint32Array() []uint32 {
	n := len(b) / 4
	extra := len(b) % 4
	if extra > 0 {
		n++
	}
	a := make([]uint32, n)
	i, j := 0, 0
	for ; j < extra; j++ {
		a[i] <<= 8
		a[i] |= uint32(b[j])
	}
	if j != 0 {
		i++
	}
	for ; i < len(a); i++ {
		a[i] = uint32(b[j])<<24 | uint32(b[j+1])<<16 | uint32(b[j+2])<<8 | uint32(b[j+3])
		j += 4
	}
	return a
}

func (b Base64Data) Int64Array() []int64 {
	a := make([]int64, 0, (len(b)/4)+1)
	var tmp int64
	for i, bi := range b {
		tmp <<= 8
		tmp |= int64(bi)
		if i%4 == 3 {
			a = append(a, tmp)
			tmp = 0
		}
	}
	if i := uint(len(b) % 4); i != 0 {
		tmp <<= 8 * (4 - i)
		tmp |= int64(0x10000000000) * int64(i<<3)
		a = append(a, tmp)
	}
	return a
}

func (b Base64Data) Debug_dec(db bool, name string) {
	if db {
		fmt.Printf("%s: len=%d, 0x%x = %q = %v, %s\n", name, len(b), b, b.ConvToString(), b.Int32Array(), tr.LF(2))
	}
}

func (b Base64Data) Debug_hex(db bool, name string) {
	if db {
		fmt.Printf("%s: len=%d, 0x%x = %q = %x, %s\n", name, len(b), b, b.ConvToString(), b.Uint32Array(), tr.LF(2))
	}
}

func (b Base64Data) ConvToString() string {
	text := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(text, b)
	return string(text)
	//return fmt.Sprintf("%s = %v", text, b.int32Array())
}

func (b *Base64Data) CopyIn(text []byte) {
	if n := base64.StdEncoding.DecodedLen(len(text)); cap(*b) < n {
		*b = make([]byte, n)
	}
	copy(*b, text)
	// base64.StdEncoding.Encode(text, *b)
}

func (b Base64Data) IsEmpty() bool {
	if len(b) == 0 {
		return true
	}
	for _, ww := range b {
		if ww != 0 {
			return false
		}
	}
	return true
}
