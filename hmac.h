#ifndef __HMAC_SHA256_H__
#define __HMAC_SHA256_H__

#include <math.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "sha256.h"



// Creates a HMAC hash digest for SHA256.
sha256_t HMAC_sha256(const void* _K, const void* _m, uint32_t keylen, uint32_t msglen) {
	// HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
	// H is the hash function
	// m is the message
	// K is a secret key
	// K' is a block-sized key derived by
	//	padding to the right with zeros up to the block size if len(K) < block size
	//	hashing down to less than or equal to block size first and then padding to the right with zeroes
	// || denotes concatenation
	// ^ denotes XOR
	// opad is a block consisting of repeated 0x5c
	// ipad is a block consisting of repeated 0x36

	uint8_t* K = (uint8_t*)_K;
	uint8_t* m = (uint8_t*)_m;
	uint32_t b = 64;  // block size of hash function
	uint32_t L = 32;  // output size of hash function

	uint8_t* Kp = (uint8_t*)alloca(b * 3);  // Reusing Kp with offset for opad, ipad
	memset(Kp, 0, b * 3);
	uint8_t* opad = Kp + b;
	uint8_t* ipad = opad + b;
	memset(opad, 0x5c, b);
	memset(ipad, 0x36, b);

	if (keylen <= b) memcpy(Kp, K, keylen);
	else {
		sha256_t Kh = sha256(K, keylen);
		memcpy(Kp, &Kh, L);
	}

	// opad and ipad XOR
	for (uint32_t i = 0; i < b; i++) {
		opad[i] ^= Kp[i];
		ipad[i] ^= Kp[i];
	}

	uint8_t* ipad_II_msg = (uint8_t*)malloc(b + msglen);
	memcpy(ipad_II_msg, ipad, b);
	memcpy(ipad_II_msg + b, m, msglen);

	uint8_t* opad_II_hash = (uint8_t*)alloca(b + L);
	memcpy(opad_II_hash, opad, b);
	sha256_t hash = sha256(ipad_II_msg, b + msglen);
	memcpy(opad_II_hash + b, &hash, L);
	
	hash = sha256(opad_II_hash, b + L);

	free(ipad_II_msg);
	return hash;
}

#endif /* __HMAC_SHA256_H__ */
