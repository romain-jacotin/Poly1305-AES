package main

import "crypto/aes"
import "fmt"

// This long comment is a small extract from paper "Poly1305-AES message-authentication code"
// The complete paper written by Daniel J. Bernstein can be found here:
//
// http://cr.yp.to/mac/poly1305-20050329.pdf
// ------------------------------------------------------------------------------------------------
// Poly1305-AES computes a 16-byte authenticator Poly1305r(m,AESk(n)) of a variable-length message 'm', using
//   'k' a 16-byte AES key
//   'r' a 16-byte additional key
//   'n' a 16-byte nonce
//
// The Poly1305-AES formula is a straightforward polynomial evaluation modulo (2^130) − 5
// Most of the detail is in key format and message padding.
// ------------------------------------------------------------------------------------------------
// MESSAGES
// ------------------------------------------------------------------------------------------------
// Poly1305-AES authenticates messages.
// A message is any sequence of bytes m[0], m[1], ... , m[l − 1]
// A byte is any element of {0, 1, ... , 255}
// The length l can be any nonnegative integer, and can vary from one message to another.
// ------------------------------------------------------------------------------------------------
// KEYS
// ------------------------------------------------------------------------------------------------
// Poly1305-AES authenticates messages using a 32-byte secret key shared by the message sender and the message receiver.
//
// The key has two parts:
//   first,  a 16-byte AES key k
//   second, a 16-byte string r[0],r[1],...,r[15]
//
// The second part of the key represents a 128-bit integer r in unsigned little-endian form:
//   r = r[0] + 2^8*r[1] + . . . + 2^120*r[15].
//
// Certain bits of r are required to be 0:
//   r[3],r[7],r[11],r[15] are required to have their top four bits clear (i.e., to be in {0, 1, . . . , 15}),
//   and r[4], r[8], r[12] are required to have their bottom two bits clear (i.e., to be in {0, 4, 8, . . . , 252}).
// Thus there are 2^106 possibilities for r.
// In other words, r is required to have the form r0 + r1 + r2 + r3 where:
//   r0        is oneof {􏰂0, 1, 2, 3,  ..., 2^28 − 1􏰃}
//   r1 / 2^32 is oneof {􏰂0, 4, 8, 12, ..., 2^28 − 4}􏰃
//   r2 / 2^64 is oneof {􏰂0, 4, 8, 12, ..., 2^28 − 4}􏰃
//   r3 / 2^96 is oneof {􏰂0, 4, 8, 12, ..., 2^28 − 4􏰃}
// ------------------------------------------------------------------------------------------------
// NONCE
// ------------------------------------------------------------------------------------------------
// Poly1305-AES requires each message to be accompanied by a 16-byte nonce, i.e., a unique message number.
// Poly1305-AES feeds each nonce n through AESk to obtain the 16-byte string AESk(n).
// ------------------------------------------------------------------------------------------------
// CONVERSION AND PADDING
// ------------------------------------------------------------------------------------------------
// Let m[0], m[1], . . . , m[l − 1] be a message.
// Write q = ⌈l/16⌉.
// Define integers c1,c2,...,cq is oneof {1,2,3,...,2^129}􏰃 as follows:
//
// if 1 <= i <= ⌊l/16⌋ then
//   ci = m[16i−16]  + 2^8*m[16i−15]  + 2^16*m[16*i−14] + ··· + 2^120*m[16*i−1] + 2^128
//
// if l is not a multiple of 16 then
//   cq = m[16*q−16] + 2^8*m[16*q−15] + ··· + 2^8[(l%16)−8]*m[l−1] + 2^8*(l%16)
//
// In other words:
//   Pad each 16-byte chunk of a message to 17 bytes by appending a 1.
//   If the message has a final chunk between 1 and 15 bytes, append 1 to the chunk, and then zero-pad the chunk to 17 bytes.
//   Either way, treat the resulting 17-byte chunk as an unsigned little-endian integer.
// ------------------------------------------------------------------------------------------------
// AUTHENTICATORS
// ------------------------------------------------------------------------------------------------
// Poly1305r(m,AESk(n)), the Poly1305-AES authenticator of a message 'm' with nonce 'n' under secret key ('k', 'r'),
// is defined as the 16-byte unsigned little-endian representation of
//
//   ( ( ( c1*r^q + c2*r^(q−1) + ··· + cq*r^1 ) mod 2^(130 −5) ) + AESk(n) ) mod 2^128
//
// Here the 16-byte string AESk(n) is treated as an unsigned little-endian integer,
// and c1, c2, . . . , cq are the integers defined above.
// ------------------------------------------------------------------------------------------------
// SAMPLE CODE (but Go language do not support uint128 ...)
// ------------------------------------------------------------------------------------------------
/*

func Poly1305_AES( m *[]byte, k [16]byte, r [16]byte, n [16]byte ) {
    var rbar, h, p, c uint128
    var s, hash [16]byte
    var i, j, l int

    l = len(m)
    h = 0
    p = (1<<130) - 5

	// Consider 'r' as a Little Endian uint124
    for j = 0; j < 16; j++ {
        rbar += uint128(r[j]) << (8 * j)
    }

    i = 0
    for i < l {
        // Consider each consecutives 16 bytes of m as 'c' a Little Endian uint128
        // If the size of the last chunk of 16 bytes is less than 16:
        //    then consider the immediate missing byte as equal to 1 and consider the next missing bytes equals to zero
        // If the size of the chunk is 16 bytes:
        //    then consider the 17th bytes to be equal to 1
        c = 0
        for (j = 0;(j < 16) && ((i+j) < l);++j) {
            c += uint128(m[i+j]) << (8 * j)
        }
        i += j
        c += 1 << (8 * j)

        // Update the accumulator 'h' so at the end it is equal to (c1*r^q + c2*r^(q−1) + ··· + cq*r^1) mod 2^(130 −5)
        h = ((h + c) * rbar) % p
    }

	// Compute the AES128 value of the nonce 'n' by the AES key 'k'
    s = AES(k,n)

    // Consider 's' a Little Endian uint128 and add it to 'h'
    for j = 0; j < 16; j++ {
        h += (uint128(s[j]) << (8 * j)
    }

	// Write the final 'h' uint128 value in Little Endian
    for j = 0; j < 16; j++ {
		hash[j] = byte(h >> (j * 8))
    }
    return hash
}

*/
// ------------------------------------------------------------------------------------------------
// TEST VECTORS ( Extensive test suite can be found at http://cr.yp.to/mac/test.html )
// ------------------------------------------------------------------------------------------------
// m ￼                    f3 f6
// c1 ￼                   00000000000000000000000000001f6f3
// r ￼                    85 1f c4 0c 34 67 ac 0b e0 5c c2 04 04 f3 f7 00
// m(r) mod 2^130 − 5 ￼   321e58e25a69d7f8f27060770b3f8bb9c
// k ￼                    ec 07 4c 83 55 80 74 17 01 42 5b 62 32 35 ad d6
// n                  ￼   fb 44 73 50 c4 e8 68 c5 2a c3 27 5c f9 d4 32 7e
// AESk(n) ￼              58 0b 3b 0f 94 47 bb 1e 69 d0 95 b5 92 8b 6d bc
// Poly1305r(m,AESk(n))   f4 c6 33 c3 04 4f c1 45 f8 4f 33 5c b8 19 53 de
// ------------------------------------------------------------------------------------------------
// m                      (null message)
// r ￼                    a0 f3 08 00 00 f4 64 00 d0 c7 e9 07 6c 83 44 03
// m(r) mod 2^130 − 5￼    000000000000000000000000000000000
// k ￼                    75 de aa 25 c0 9f 20 8e 1d c4 ce 6b 5c ad 3f bf
// n ￼                    61 ee 09 21 8d 29 b0 aa ed 7e 15 4a 2c 55 09 cc
// AESk(n) ￼              dd 3f ab 22 51 f1 1a c7 59 f0 88 71 29 cc 2e e7
// Poly1305r(m,AESk(n))   dd 3f ab 22 51 f1 1a c7 59 f0 88 71 29 cc 2e e7
// ------------------------------------------------------------------------------------------------
// m ￼                    66 3c ea 19 0f fb 83 d8 95 93 f3 f4 76 b6 bc 24
//                        d7 e6 79 10 7e a2 6a db 8c af 66 52 d0 65 61 36
// c1 ￼                   124bcb676f4f39395d883fb0f19ea3c66
// c2 ￼                   1366165d05266af8cdb6aa27e1079e6d7
// r ￼                    48 44 3d 0b b0 d2 11 09 c8 9a 10 0b 5c e2 c2 08
// m(r) mod 2^130 − 5￼    1cfb6f98add6a0ea7c631de020225cc8b
// k ￼                    6a cb 5f 61 a7 17 6d d3 20 c5 c1 eb 2e dc dc 74
// n ￼                    ae 21 2a 55 39 97 29 59 5d ea 45 8b c6 21 ff 0e
// AESk(n) ￼              83 14 9c 69 b5 61 dd 88 29 8a 17 98 b1 07 16 ef
// Poly1305r(m,AESk(n))   0e e1 c1 6b b7 3f 0f 4f d1 98 81 75 3c 01 cd be
// ------------------------------------------------------------------------------------------------
// m ￼                    ab 08 12 72 4a 7f 1e 34 27 42 cb ed 37 4d 94 d1
//                        36 c6 b8 79 5d 45 b3 81 98 30 f2 c0 44 91 fa f0
//                        99 0c 62 e4 8b 80 18 b2 c3 e4 a0 fa 31 34 cb 67
//                        fa 83 e1 58 c9 94 d9 61 c4 cb 21 09 5c 1b f9
// c1 ￼                   1d1944d37edcb4227341e7f4a721208ab
// c2 ￼                   1f0fa9144c0f2309881b3455d79b8c636
// c3 ￼                   167cb3431faa0e4c3b218808be4620c99
// c4 ￼                   001f91b5c0921cbc461d994c958e183fa
// r ￼                    12 97 6a 08 c4 42 6d 0c e8 a8 24 07 c4 f4 82 07
// m(r) mod 2^130 − 5 ￼   0c3c4f37c464bbd44306c9f8502ea5bd1
// k ￼                    e1 a5 66 8a 4d 5b 66 a5 f6 8c c5 42 4e d5 98 2d
// n ￼                    9a e8 31 e7 43 97 8d 3a 23 52 7c 71 28 14 9e 3a
// AESk(n) ￼              80 f8 c2 0a a7 12 02 d1 e2 91 79 cb cb 55 5a 57
// Poly1305r(m,AESk(n)) ￼ 51 54 ad 0d 2c b2 6e 01 27 4f c5 11 48 49 1f 1b
// ------------------------------------------------------------------------------------------------

func Poly1305_AES(inputdata *[]byte, k_aes *[]byte, r_key *[]byte, nonce *[]byte) *[]byte {
	hash := make([]byte, 16)
	s := make([]byte, 16)

	cipher, err := aes.NewCipher(*k_aes)
	if err != nil {
		fmt.Printf("crypto.aes.NewCipher( []byte ) error\n")
		return nil
	}
	cipher.Encrypt(s, *nonce)
	fmt.Printf("AES-128(k,n)                  = [%v] %x\n", len(s), s)
	return &hash
}

func main() {
	data := []byte{0xab, 0x08, 0x12, 0x72, 0x4a, 0x7f, 0x1e, 0x34, 0x27, 0x42, 0xcb, 0xed, 0x37, 0x4d, 0x94, 0xd1,
		0x36, 0xc6, 0xb8, 0x79, 0x5d, 0x45, 0xb3, 0x81, 0x98, 0x30, 0xf2, 0xc0, 0x44, 0x91, 0xfa, 0xf0,
		0x99, 0x0c, 0x62, 0xe4, 0x8b, 0x80, 0x18, 0xb2, 0xc3, 0xe4, 0xa0, 0xfa, 0x31, 0x34, 0xcb, 0x67,
		0xfa, 0x83, 0xe1, 0x58, 0xc9, 0x94, 0xd9, 0x61, 0xc4, 0xcb, 0x21, 0x09, 0x5c, 0x1b, 0xf9}
	k_aes := []byte{0xe1, 0xa5, 0x66, 0x8a, 0x4d, 0x5b, 0x66, 0xa5, 0xf6, 0x8c, 0xc5, 0x42, 0x4e, 0xd5, 0x98, 0x2d}
	r_key := []byte{0x12, 0x97, 0x6a, 0x08, 0xc4, 0x42, 0x6d, 0x0c, 0xe8, 0xa8, 0x24, 0x07, 0xc4, 0xf4, 0x82, 0x07}
	nonce := []byte{0x9a, 0xe8, 0x31, 0xe7, 0x43, 0x97, 0x8d, 0x3a, 0x23, 0x52, 0x7c, 0x71, 0x28, 0x14, 0x9e, 0x3a}

	fmt.Printf("\ndata                          = [%v] %x\n", len(data), data)
	fmt.Printf("r                             = [%v] %x\n", len(r_key), r_key)
	fmt.Printf("k                             = [%v] %x\n", len(k_aes), k_aes)
	fmt.Printf("n                             = [%v] %x\n", len(nonce), nonce)
	poly1305 := Poly1305_AES(&data, &k_aes, &r_key, &nonce)
	fmt.Printf("Poly1305(data,r,AES-128(k,n)) = [%v] %x\n\n", len(*poly1305), *poly1305)
}
