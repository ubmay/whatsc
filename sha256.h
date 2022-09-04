#ifndef __SHA256_H__
#define __SHA256_H__

#include <stdlib.h>
#include <string.h>

typedef union {
	struct {
		uint32_t a, b, c, d, e, f, g, h;
	} s;
	uint32_t a[8];
	uint8_t b[32];
} sha256_t;

// Rotate a uint32_t `a' by `s' bits to the right.
#define __SHA256_H__rotr(a, s) (((a) >> (s)) | ((a) << (32 - (s))))

// Round constants.
const uint32_t __SHA256_H__k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


// Comparisons for sha256_t.
// Test if hash is equal to another hash.
static inline char sha256eq(sha256_t a, sha256_t b) {
	return
		(a.s.a == b.s.a)
		& (a.s.b == b.s.b)
		& (a.s.c == b.s.c)
		& (a.s.d == b.s.d)
		& (a.s.e == b.s.e)
		& (a.s.f == b.s.f)
		& (a.s.g == b.s.g)
		& (a.s.h == b.s.h);
}

// Tests if hash is not equal to another hash.
static inline char sha256ne(sha256_t a, sha256_t b) {
	return
		(a.s.a != b.s.a)
		| (a.s.b != b.s.b)
		| (a.s.c != b.s.c)
		| (a.s.d != b.s.d)
		| (a.s.e != b.s.e)
		| (a.s.f != b.s.f)
		| (a.s.g != b.s.g)
		| (a.s.h != b.s.h);
}

static inline char sha256gt(sha256_t a, sha256_t b) {
	if (a.s.a > b.s.a) return 1;
	if (a.s.a < b.s.a) return 0;

	if (a.s.b > b.s.b) return 1;
	if (a.s.b < b.s.b) return 0;

	if (a.s.c > b.s.c) return 1;
	if (a.s.c < b.s.c) return 0;

	if (a.s.d > b.s.d) return 1;
	if (a.s.d < b.s.d) return 0;

	if (a.s.e > b.s.e) return 1;
	if (a.s.e < b.s.e) return 0;

	if (a.s.f > b.s.f) return 1;
	if (a.s.f < b.s.f) return 0;

	if (a.s.g > b.s.g) return 1;
	if (a.s.g < b.s.g) return 0;

	if (a.s.h > b.s.h) return 1;
	if (a.s.h < b.s.h) return 0;

	return 0;
}

static inline char sha256lt(sha256_t a, sha256_t b) {
	if (a.s.a < b.s.a) return 1;
	if (a.s.a > b.s.a) return 0;

	if (a.s.b < b.s.b) return 1;
	if (a.s.b > b.s.b) return 0;

	if (a.s.c < b.s.c) return 1;
	if (a.s.c > b.s.c) return 0;

	if (a.s.d < b.s.d) return 1;
	if (a.s.d > b.s.d) return 0;

	if (a.s.e < b.s.e) return 1;
	if (a.s.e > b.s.e) return 0;

	if (a.s.f < b.s.f) return 1;
	if (a.s.f > b.s.f) return 0;

	if (a.s.g < b.s.g) return 1;
	if (a.s.g > b.s.g) return 0;

	if (a.s.h < b.s.h) return 1;
	if (a.s.h > b.s.h) return 0;

	return 0;
}

static inline char sha256ge(sha256_t a, sha256_t b) {
	return sha256gt(a, b) | sha256eq(a, b);
}

static inline char sha256le(sha256_t a, sha256_t b) {
	return sha256lt(a, b) | sha256eq(a, b);
}


// Hashes `_msg' of length `bytelen'.
// Not very safe, prone to out of bounds accesses.
sha256_t sha256(const void *_msg, uint64_t bytelen) {
	uint32_t
		h0 = 0x6a09e667,
		h1 = 0xbb67ae85,
		h2 = 0x3c6ef372,
		h3 = 0xa54ff53a,
		h4 = 0x510e527f,
		h5 = 0x9b05688c,
		h6 = 0x1f83d9ab,
		h7 = 0x5be0cd19;

	// Preprocess
	uint8_t *msg = (uint8_t*)_msg;
	uint64_t K = (64 - ((bytelen + 9) & 63)) & 63;

	// Convert `bytelen' from little-endian to big-endian.
	uint64_t blenr = bytelen << 3;
	{
		uint8_t *b = (uint8_t*)&blenr;
		uint8_t r[8] = {b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]};
		blenr = *(uint64_t*)r;
	}

	unsigned char *newm = (uint8_t*)calloc(1, bytelen + 9 + K);
	memcpy(newm, _msg, bytelen);
	newm[bytelen] = 128;
	memset(newm + (bytelen + 1), 0, K);
	memcpy(newm + (bytelen + 1 + K), &blenr, 8);
	
	// Process
	uint64_t cc = (bytelen + 9 + K) >> 6;	// chunk count
	for (uint64_t _i = 0; _i < cc; _i++) {
		unsigned char *caddr = newm + (_i << 6);		// current chunk address
		
		// Create a 64-entry message schedule array `w' of 32 bit words
		uint32_t w[64] = {0};

		// copy chunk into first 16 words of message schedule
		memcpy(w, caddr, 64);

		// Reverse byte order
		for (uint32_t i = 0; i < 16; i++) {
			uint8_t *b = (uint8_t*)(w+i);
			uint8_t r[4] = {b[3], b[2], b[1], b[0]};
			w[i] = *(uint32_t*)r;
		}
		
		for (uint32_t i = 16; i < 64; i++) {
			uint32_t s0 = 
				__SHA256_H__rotr(w[i-15], 7)
				^ __SHA256_H__rotr(w[i-15], 18)
				^ (w[i-15] >> 3);
			uint32_t s1 =
				__SHA256_H__rotr(w[i-2], 17)
				^ __SHA256_H__rotr(w[i-2], 19)
				^ (w[i-2] >> 10);
			w[i] = w[i-16] + s0 + w[i-7] + s1;
		}

		uint32_t a = h0,
				 b = h1,
				 c = h2,
				 d = h3,
				 e = h4,
				 f = h5,
				 g = h6,
				 h = h7;

		for (int i = 0; i < 64; i++) {
			uint32_t S1 = __SHA256_H__rotr(e, 6)
				^ __SHA256_H__rotr(e, 11)
				^ __SHA256_H__rotr(e, 25);
			uint32_t ch = (e & f) ^ ((~e) & g);
			uint32_t temp1 = h + S1 + ch + __SHA256_H__k[i] + w[i];

			uint32_t S0 = __SHA256_H__rotr(a, 2)
				^ __SHA256_H__rotr(a, 13)
				^ __SHA256_H__rotr(a, 22);
			uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint32_t temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
		h5 = h5 + f;
		h6 = h6 + g;
		h7 = h7 + h;
	}
	free(newm);
	{
		uint8_t *b = (uint8_t*)&h0;
		uint8_t r[4] = {b[3], b[2], b[1], b[0]};
		h0 = *(uint32_t*)r;
	}
	{
		uint8_t *b = (uint8_t*)&h1;
		uint8_t r[4] = {b[3], b[2], b[1], b[0]};
		h1 = *(uint32_t*)r;
	}
	{
		uint8_t *b = (uint8_t*)&h2;
		uint8_t r[4] = {b[3], b[2], b[1], b[0]};
		h2 = *(uint32_t*)r;
	}
	{
		uint8_t *b = (uint8_t*)&h3;
		uint8_t r[4] = {b[3], b[2], b[1], b[0]};
		h3 = *(uint32_t*)r;
	}
	{
		uint8_t *b = (uint8_t*)&h4;
		uint8_t r[4] = {b[3], b[2], b[1], b[0]};
		h4 = *(uint32_t*)r;
	}
	{
		uint8_t *b = (uint8_t*)&h5;
		uint8_t r[4] = {b[3], b[2], b[1], b[0]};
		h5 = *(uint32_t*)r;
	}
	{
		uint8_t *b = (uint8_t*)&h6;
		uint8_t r[4] = {b[3], b[2], b[1], b[0]};
		h6 = *(uint32_t*)r;
	}
	{
		uint8_t *b = (uint8_t*)&h7;
		uint8_t r[4] = {b[3], b[2], b[1], b[0]};
		h7 = *(uint32_t*)r;
	}
	sha256_t ret = {
		.s.a = h0,
		.s.b = h1,
		.s.c = h2,
		.s.d = h3,
		.s.e = h4,
		.s.f = h5,
		.s.g = h6,
		.s.h = h7,
	};
	return ret;
}

#endif
