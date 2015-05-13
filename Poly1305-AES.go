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
// m                      (null message)
// r ￼                    a0 f3 08 00 00 f4 64 00 d0 c7 e9 07 6c 83 44 03
// m(r) mod 2^130 − 5￼    00000000000 00000000000 00000000000
// k ￼                    75 de aa 25 c0 9f 20 8e 1d c4 ce 6b 5c ad 3f bf
// n ￼                    61 ee 09 21 8d 29 b0 aa ed 7e 15 4a 2c 55 09 cc
// AESk(n) ￼              dd 3f ab 22 51 f1 1a c7 59 f0 88 71 29 cc 2e e7
// Poly1305r(m,AESk(n))   dd 3f ab 22 51 f1 1a c7 59 f0 88 71 29 cc 2e e7
// ------------------------------------------------------------------------------------------------
// m ￼                    f3 f6
// c1 ￼                   00000000000 00000000000 0000001f6f3
// r ￼                    85 1f c4 0c 34 67 ac 0b e0 5c c2 04 04 f3 f7 00
// m(r) mod 2^130 − 5 ￼   321e58e25a6 9d7f8f27060 770b3f8bb9c
// k ￼                    ec 07 4c 83 55 80 74 17 01 42 5b 62 32 35 ad d6
// n                  ￼   fb 44 73 50 c4 e8 68 c5 2a c3 27 5c f9 d4 32 7e
// AESk(n) ￼              58 0b 3b 0f 94 47 bb 1e 69 d0 95 b5 92 8b 6d bc
// Poly1305r(m,AESk(n))   f4 c6 33 c3 04 4f c1 45 f8 4f 33 5c b8 19 53 de
// ------------------------------------------------------------------------------------------------
// m ￼                    66 3c ea 19 0f fb 83 d8 95 93 f3 f4 76 b6 bc 24
//                        d7 e6 79 10 7e a2 6a db 8c af 66 52 d0 65 61 36
// c1 ￼                   124bcb676f4 f39395d883f b0f19ea3c66
// c2 ￼                   1366165d052 66af8cdb6aa 27e1079e6d7
// r ￼                    48 44 3d 0b b0 d2 11 09 c8 9a 10 0b 5c e2 c2 08
// m(r) mod 2^130 − 5￼    1cfb6f98add 6a0ea7c631d e020225cc8b
// k ￼                    6a cb 5f 61 a7 17 6d d3 20 c5 c1 eb 2e dc dc 74
// n ￼                    ae 21 2a 55 39 97 29 59 5d ea 45 8b c6 21 ff 0e
// AESk(n) ￼              83 14 9c 69 b5 61 dd 88 29 8a 17 98 b1 07 16 ef
// Poly1305r(m,AESk(n))   0e e1 c1 6b b7 3f 0f 4f d1 98 81 75 3c 01 cd be
// ------------------------------------------------------------------------------------------------
// m ￼                    ab 08 12 72 4a 7f 1e 34 27 42 cb ed 37 4d 94 d1
//                        36 c6 b8 79 5d 45 b3 81 98 30 f2 c0 44 91 fa f0
//                        99 0c 62 e4 8b 80 18 b2 c3 e4 a0 fa 31 34 cb 67
//                        fa 83 e1 58 c9 94 d9 61 c4 cb 21 09 5c 1b f9
// c1 ￼                   1d1944d37ed cb4227341e7 f4a721208ab
// c2 ￼                   1f0fa9144c0 f2309881b34 55d79b8c636
// c3 ￼                   167cb3431fa a0e4c3b2188 08be4620c99
// c4 ￼                   001f91b5c09 21cbc461d99 4c958e183fa
// r ￼                    12 97 6a 08 c4 42 6d 0c e8 a8 24 07 c4 f4 82 07
// m(r) mod 2^130 − 5 ￼   0c3c4f37c46 4bbd44306c9 f8502ea5bd1
// k ￼                    e1 a5 66 8a 4d 5b 66 a5 f6 8c c5 42 4e d5 98 2d
// n ￼                    9a e8 31 e7 43 97 8d 3a 23 52 7c 71 28 14 9e 3a
// AESk(n) ￼              80 f8 c2 0a a7 12 02 d1 e2 91 79 cb cb 55 5a 57
// Poly1305r(m,AESk(n)) ￼ 51 54 ad 0d 2c b2 6e 01 27 4f c5 11 48 49 1f 1b
// ------------------------------------------------------------------------------------------------

func AES_128(k_aes, nonce *[]byte) *[]byte {
	s := make([]byte, 16)

	cipher, err := aes.NewCipher(*k_aes)
	if err != nil {
		fmt.Printf("crypto.aes.NewCipher( []byte ) error\n")
		return nil
	}
	cipher.Encrypt(s, *nonce)
	return &s
}

func mul_reg(dst *[4]uint64, a, b uint64) {
	a0 := a & 0xffffffff
	a1 := a >> 32
	b0 := b & 0xffffffff
	b1 := b >> 32
	dst0 := a0 * b0
	dst1 := dst0 >> 32
	dst[0] = dst0 & 0xffffffff
	dst1 += a1 * b0
	dst2 := dst1 >> 32
	dst1 &= 0xffffffff
	dst1 += a0 * b1
	dst2 += dst1 >> 32
	dst3 := dst2 >> 32
	dst2 &= 0xffffffff
	dst2 += a1 * b1
	dst3 += dst2 >> 32
	dst[1] = dst1 & 0xffffffff
	dst[2] = dst2 & 0xffffffff
	dst[3] = dst3 & 0xffffffff
}

func addlo_reg(dst *[4]uint64, a uint64) {
	dst0 := dst[0] + (a & 0xffffffff)
	dst1 := dst[1] + (a >> 32)
	dst1 += dst0 >> 32
	dst[0] = dst0 & 0xffffffff
	dst2 := dst[2] + (dst1 >> 32)
	dst[1] = dst1 & 0xffffffff
	dst3 := dst[3] + (dst2 >> 32)
	dst[2] = dst2 & 0xffffffff
	dst[3] = dst3 & 0xffffffff
}

func add_reg(dst, a *[4]uint64) {
	dst0 := dst[0] + a[0]
	dst1 := dst[1] + a[1]
	dst2 := dst[2] + a[2]
	dst3 := dst[3] + a[3]
	dst1 += dst0 >> 32
	dst[0] = dst0 & 0xffffffff
	dst2 = dst2 + (dst1 >> 32)
	dst[1] = dst1 & 0xffffffff
	dst3 += (dst2 >> 32)
	dst[2] = dst2 & 0xffffffff
	dst[3] = dst3 & 0xffffffff
}

func shr_reg(src *[4]uint64, bit uint) uint64 {
	return (src[1] >> (bit - 32)) + (src[2] << (64 - bit)) + (src[3] << (96 - bit))
}

func Poly1305(mac, data, r_key, s_key *[]byte) bool {
	var r0, r1, r2, h0, h1, h2, c, c0, c1, c2, s1, s2 uint64
	var i, j, l uint
	var d, d0, d1, d2 [4]uint64

	if (len(*mac) != 16) || (len(*r_key) != 16) || (len(*s_key) != 16) {
		return false
	}

	l = uint(len(*data))

	// Variables initialization: read 'r' and 's' as Little Endian unsigned int
	// r &= 0xffffffc0ffffffc0ffffffc0fffffff as required by the Poly1305 specifications
	//
	// NOTE: we need 'r', 'h' and 'c' to be uint130 because of the required modulus 2^130 - 5
	//       uint130(r) = 42 most significant bits(r2) + 44 middle bits(r1) + 44 less significant bits(r0)

	// r0 = LSB 44 bits of 'r' as uint130
	r0 = uint64((*r_key)[0]) |
		(uint64((*r_key)[1]) << 8) |
		(uint64((*r_key)[2]) << 16) |
		(uint64((*r_key)[3]) << 24) |
		(uint64((*r_key)[4]) << 32) |
		(uint64((*r_key)[5]) << 40)
	r0 &= 0xffc0fffffff

	// r1 = middle 44 bits of 'r' as uint130
	r1 = (uint64((*r_key)[5]) >> 4) |
		(uint64((*r_key)[6]) << 4) |
		(uint64((*r_key)[7]) << 12) |
		(uint64((*r_key)[8]) << 20) |
		(uint64((*r_key)[9]) << 28) |
		(uint64((*r_key)[10]) << 36)
	r1 &= 0xfffffc0ffff

	// r2 = MSB 42 bits of 'r' as uint130
	r2 = uint64((*r_key)[11]) |
		(uint64((*r_key)[12]) << 8) |
		(uint64((*r_key)[13]) << 16) |
		(uint64((*r_key)[14]) << 24) |
		(uint64((*r_key)[15]) << 32)
	r2 &= 0x00ffffffc0f

	s1 = (r1 * (5 << 2))
	s2 = (r2 * (5 << 2))

	// h = 0 --> zero is already the default value for h0, h1 and h2, so nothing to do :-)

	i = 0
	for i < l {
		// Read 'c' from a chunk of 16 bytes (or less if not enough data) as a Little Endian unsigned integer (uint130)
		// uint130(c) = 42 most significant bits(c2) + 44 middle bits(c1) + 44 less significant bits(c0)
		c0 = 0
		c1 = 0
		c2 = 0
		for j = 0; (j < 16) && (i < l); j++ {
			if j < 5 {
				c0 |= uint64((*data)[i]) << (j * 8)
			} else if j == 5 {
				c0 |= uint64((*data)[i]) << 40
				c1 |= uint64((*data)[i]) >> 4
			} else if j < 11 {
				c1 |= uint64((*data)[i]) << (4 + (j-6)*8)
			} else { // j >= 11
				c2 |= uint64((*data)[i]) << ((j - 11) * 8)
			}
			i++
		}
		c0 &= 0xfffffffffff
		c1 &= 0xfffffffffff
		c2 &= 0x3ffffffffff

		// if chunk'size == 16 bytes then add a 17th byte = 0x01
		// if chunk'size  < 16 bytes then add a last byte = 0x01, and bytes up to 17th are equals to 0
		if j < 6 {
			c0 |= 1 << (j * 8)
		} else if j < 11 {
			c1 |= 1 << (4 + (j-6)*8)
		} else { // j >= 11
			c2 |= 1 << ((j - 11) * 8)
		}

		// for each chunk 'c', update 'h' like this:      h = ((h + c) * r) % ((2^130)-5)

		// Calculate h = h + c
		h0 += c0
		h1 += c1
		h2 += c2

		// Calculate h = h * r --> MUST DEBUG !!!!

		// d0 = h0*r0 + h1*(r2*(5<<2)) + h2*(r1*(5<<2))
		mul_reg(&d0, h0, r0)
		mul_reg(&d, h1, s2)
		add_reg(&d0, &d)
		mul_reg(&d, h2, s1)
		add_reg(&d0, &d)

		// d1 = h0*r1 + h1*r0 + h2*(r2*(5<<2))
		mul_reg(&d1, h0, r1)
		mul_reg(&d, h1, r0)
		add_reg(&d1, &d)
		mul_reg(&d, h2, s2)
		add_reg(&d1, &d)

		// d2 = h0*r2 + h1*r1 + h2*r0
		mul_reg(&d2, h0, r2)
		mul_reg(&d, h1, r1)
		add_reg(&d2, &d)
		mul_reg(&d, h2, r0)
		add_reg(&d2, &d)

		// partial h %= ((2^130)-5)
		// In fact we don't calculate the complete modulo value, but the lowest value that is < 2^130

		// Convert d (= uint128 simulated with 4 uint64 that contains 32+32+32+32 bits)
		// into h (= uint130 simulated with 3 uint64 that contains 42+44+44) and propagate the carry ( = c )

		// h0 = LSB 44 bits of d0
		c = (d0[1] >> 12) + (d0[2] << 20) + (d0[3] << 52)
		h0 = (d0[0] + (d0[1] << 32)) & 0xfffffffffff

		// h1 = LSB 44 bits of d1
		addlo_reg(&d1, c)
		c = (d1[1] >> 12) + (d1[2] << 20) + (d1[3] << 52)
		h1 = (d1[0] + (d1[1] << 32)) & 0xfffffffffff

		// h1 = LSB 42 bits of d2
		addlo_reg(&d2, c)
		c = (d2[1] >> 10) + (d2[2] << 22) + (d2[3] << 54)
		h2 = (d2[0] + (d2[1] << 32)) & 0x3ffffffffff

		// Use the carry (= c) to calculate the partial modulo (2^130 - 5)
		// partial modulo = multiply the 130 bits value by the carry (the carry is the upper bit at the left of the 130 bits)
		h0 += c * 5
		c = (h0 >> 44)
		h0 = h0 & 0xfffffffffff
		h1 += c
		// Note: the carry is not fully propagated into h here, the full carry will be made after the last chunk (=after the 'chunk' loop)
	}

	// Fully carry h
	c = (h1 >> 44)
	h1 &= 0xfffffffffff
	h2 += c
	c = (h2 >> 42)
	h2 &= 0x3ffffffffff
	h0 += c * 5
	c = (h0 >> 44)
	h0 &= 0xfffffffffff
	h1 += c
	c = (h1 >> 44)
	h1 &= 0xfffffffffff
	h2 += c
	c = (h2 >> 42)
	h2 &= 0x3ffffffffff
	h0 += c * 5
	c = (h0 >> 44)
	h0 &= 0xfffffffffff
	h1 += c

	// Now it is the final step to compute h % ((2^130)-5)
	// We compare 'h' and 'p' :
	//   if h < p then h is the final modulus value
	//   if h >= p then the final value is h - p
	// Compute h - p = h - (2^130 - 5) = h + 5 - 2^130 = h + 5 - (1 << 130)
	c0 = h0 + 5
	c = c0 >> 44
	c0 &= 0xfffffffffff
	c1 = h1 + c
	c = c1 >> 44
	c1 &= 0xfffffffffff
	c2 = h2 + c - (1 << 42)

	// select h if h < p, or (h - p) if h >= p
	c = (c2 >> 63) - 1
	c0 &= c
	c1 &= c
	c2 &= c
	c = ^c
	h0 = (h0 & c) | c0
	h1 = (h1 & c) | c1
	h2 = (h2 & c) | c2

	// Read 's' as Little Endian uint128 (c0 = low 64 bits, c1 = high 64 bits)
	c0 = 0
	c1 = 0
	for i = 0; i < 8; i++ {
		c0 |= uint64((*s_key)[i]) << (i * 8)
		c1 |= uint64((*s_key)[i+8]) << (i * 8)
	}

	// h = h + s (in uint130)
	h0 += ((c0) & 0xfffffffffff)
	c = h0 >> 44
	h0 &= 0xfffffffffff

	h1 += (((c0 >> 44) | (c1 << 20)) & 0xfffffffffff) + c
	c = h1 >> 44
	h1 &= 0xfffffffffff

	h2 += ((c1 >> 24) & 0x3ffffffffff) + c
	h2 &= 0x3ffffffffff

	// Transform h in uint128: h = h % (2^128)
	h0 = h0 + (h1 << 44)
	h1 = ((h1 >> 20) + (h2 << 24))

	// Writing 'h' in Little Endian mode the 128 bits (=16 bytes)
	for i = 0; i < 8; i++ {
		(*mac)[i] = byte((h0 >> (i * 8)) & 0xff)
		(*mac)[i+8] = byte((h1 >> (i * 8)) & 0xff)
	}
	return true
}

func main() {
	mac := make([]byte, 16)

	var data []byte
	r_key := []byte{0xa0, 0xf3, 0x08, 0x00, 0x00, 0xf4, 0x64, 0x00, 0xd0, 0xc7, 0xe9, 0x07, 0x6c, 0x83, 0x44, 0x03}
	k_aes := []byte{0x75, 0xde, 0xaa, 0x25, 0xc0, 0x9f, 0x20, 0x8e, 0x1d, 0xc4, 0xce, 0x6b, 0x5c, 0xad, 0x3f, 0xbf}
	nonce := []byte{0x61, 0xee, 0x09, 0x21, 0x8d, 0x29, 0xb0, 0xaa, 0xed, 0x7e, 0x15, 0x4a, 0x2c, 0x55, 0x09, 0xcc}
	s := AES_128(&k_aes, &nonce)
	test_poly1305(&mac, &data, &r_key, s)
	fmt.Printf("                  Waiting MAC = [16] dd3fab2251f11ac759f0887129cc2ee7\n\n")

	data = []byte{0xf3, 0xf6}
	r_key = []byte{0x85, 0x1f, 0xc4, 0x0c, 0x34, 0x67, 0xac, 0x0b, 0xe0, 0x5c, 0xc2, 0x04, 0x04, 0xf3, 0xf7, 0x00}
	k_aes = []byte{0xec, 0x07, 0x4c, 0x83, 0x55, 0x80, 0x74, 0x17, 0x01, 0x42, 0x5b, 0x62, 0x32, 0x35, 0xad, 0xd6}
	nonce = []byte{0xfb, 0x44, 0x73, 0x50, 0xc4, 0xe8, 0x68, 0xc5, 0x2a, 0xc3, 0x27, 0x5c, 0xf9, 0xd4, 0x32, 0x7e}
	s = AES_128(&k_aes, &nonce)
	test_poly1305(&mac, &data, &r_key, s)
	fmt.Printf("                  Waiting MAC = [16] f4c633c3044fc145f84f335cb81953de\n\n")

	data = []byte{0x66, 0x3c, 0xea, 0x19, 0x0f, 0xfb, 0x83, 0xd8, 0x95, 0x93, 0xf3, 0xf4, 0x76, 0xb6, 0xbc, 0x24,
		0xd7, 0xe6, 0x79, 0x10, 0x7e, 0xa2, 0x6a, 0xdb, 0x8c, 0xaf, 0x66, 0x52, 0xd0, 0x65, 0x61, 0x36}
	r_key = []byte{0X48, 0x44, 0x3d, 0x0b, 0xb0, 0xd2, 0x11, 0x09, 0xc8, 0x9a, 0x10, 0x0b, 0x5c, 0xe2, 0xc2, 0x08}
	k_aes = []byte{0x6a, 0xcb, 0x5f, 0x61, 0xa7, 0x17, 0x6d, 0xd3, 0x20, 0xc5, 0xc1, 0xeb, 0x2e, 0xdc, 0xdc, 0x74}
	nonce = []byte{0xae, 0x21, 0x2a, 0x55, 0x39, 0x97, 0x29, 0x59, 0x5d, 0xea, 0x45, 0x8b, 0xc6, 0x21, 0xff, 0x0e}
	s = AES_128(&k_aes, &nonce)
	test_poly1305(&mac, &data, &r_key, s)
	fmt.Printf("                  Waiting MAC = [16] 0ee1c16bb73f0f4fd19881753c01cdbe\n\n")

	data = []byte{0xab, 0x08, 0x12, 0x72, 0x4a, 0x7f, 0x1e, 0x34, 0x27, 0x42, 0xcb, 0xed, 0x37, 0x4d, 0x94, 0xd1,
		0x36, 0xc6, 0xb8, 0x79, 0x5d, 0x45, 0xb3, 0x81, 0x98, 0x30, 0xf2, 0xc0, 0x44, 0x91, 0xfa, 0xf0,
		0x99, 0x0c, 0x62, 0xe4, 0x8b, 0x80, 0x18, 0xb2, 0xc3, 0xe4, 0xa0, 0xfa, 0x31, 0x34, 0xcb, 0x67,
		0xfa, 0x83, 0xe1, 0x58, 0xc9, 0x94, 0xd9, 0x61, 0xc4, 0xcb, 0x21, 0x09, 0x5c, 0x1b, 0xf9}
	k_aes = []byte{0xe1, 0xa5, 0x66, 0x8a, 0x4d, 0x5b, 0x66, 0xa5, 0xf6, 0x8c, 0xc5, 0x42, 0x4e, 0xd5, 0x98, 0x2d}
	r_key = []byte{0x12, 0x97, 0x6a, 0x08, 0xc4, 0x42, 0x6d, 0x0c, 0xe8, 0xa8, 0x24, 0x07, 0xc4, 0xf4, 0x82, 0x07}
	nonce = []byte{0x9a, 0xe8, 0x31, 0xe7, 0x43, 0x97, 0x8d, 0x3a, 0x23, 0x52, 0x7c, 0x71, 0x28, 0x14, 0x9e, 0x3a}
	s = AES_128(&k_aes, &nonce)
	test_poly1305(&mac, &data, &r_key, s)
	fmt.Printf("                  Waiting MAC = [16] 5154ad0d2cb26e01274fc51148491f1b\n\n")

	data = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	nonce = []byte{0x6b, 0x65, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x50, 0x6f, 0x6c, 0x79, 0x31, 0x33, 0x30, 0x35}
	r_key = []byte{0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20}
	test_poly1305(&mac, &data, &r_key, &nonce)
	fmt.Printf("                  Waiting MAC = [16] 49ec78090e481ec6c26b33b91ccc0307\n\n")

	data = []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21}
	nonce = []byte{0x6b, 0x65, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x50, 0x6f, 0x6c, 0x79, 0x31, 0x33, 0x30, 0x35}
	r_key = []byte{0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20}
	test_poly1305(&mac, &data, &r_key, &nonce)
	fmt.Printf("                  Waiting MAC = [16] a6f745008f81c916a20dcc74eef2b2f0\n\n")

	fmt.Printf("%x\n", 0xc0a8787e<<5)
}

func test_poly1305(mac, data, r_key, s *[]byte) {
	fmt.Printf("data                          = [%v] %x\n", len(*data), *data)
	if Poly1305(mac, data, r_key, s) {
		fmt.Printf("Poly1305(data,r,s)            = [%v] %x\n", len(*mac), *mac)
	} else {
		fmt.Printf("Poly1305(data,r,s) mac and keys size must be 16 bytes!\n\n", len(*mac), *mac)
	}
}
