#ifndef __HKDF_H__
#define __HKDF_H__

#include <math.h>
#include <stdlib.h>
#include <inttypes.h>

#include "sha256.h"
#include "hmac.h"

void HKDF_sha256(void* out, uint32_t length, void* _ikm, void* _salt, void* _info, uint32_t ikmlen, uint32_t saltlen, uint32_t infolen) {
	uint32_t L = 32;

	uint8_t* ikm = (uint8_t*)_ikm;
	uint8_t* info = (uint8_t*)_info;
	uint8_t* salt;
	uint8_t saltneedsfree = 0;
	if (_salt && saltlen != 0) {
		salt = (uint8_t*)_salt;
	} else {
		salt = (uint8_t*)malloc(L);
		saltlen = L;
		memcpy(salt, 0, L);
		saltneedsfree = 1;
	}
	
	sha256_t prk = HMAC_sha256(salt, ikm, saltlen, ikmlen);

	uint32_t count = length / L;
	if (length > count * L) count++;

	sha256_t t = {};
	uint32_t tempmsglen = L + infolen + 1;
	uint8_t* tempmsg = (uint8_t*)malloc(tempmsglen);
	uint8_t* okm = (uint8_t*)malloc(count * L);

	memcpy(tempmsg, info, infolen);
	tempmsg[infolen] = 1;
	t = HMAC_sha256(&prk, tempmsg, L, infolen + 1);
	memcpy(okm, &t, L);

	for (uint32_t i = 1; i < count; i++) {
		// t = hmac_sha256(prk, t + info + bytes([i + 1]))
        // okm += t
		memcpy(tempmsg, &t, L);
		memcpy(tempmsg + L, info, infolen);
		tempmsg[tempmsglen - 1] = i + 1;
		t = HMAC_sha256(&prk, tempmsg, L, tempmsglen);
		memcpy(okm + i * L, &t, L);
	}
	printf("%d\n", count);


	memcpy(out, okm, length);

	if (saltneedsfree) free(salt);
	free(okm);
	free(tempmsg);
}
#endif /* __HKDF_H__ */
