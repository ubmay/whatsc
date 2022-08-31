#include <stdio.h>
#include <stdlib.h>

#include "miniaes128_cbcext.h"
#include "sha256.h"
#include "hmac.h"
#include "hkdf.h"

int main() {
	char inFileName[1024] = {}, mediaKeyInput[1024] = {}, outFileName[1024] = {}, typeInput[16] = {};
	printf("Enter input file: ");
	scanf("%1023s", inFileName);
	printf("Enter media key: ");
	scanf("%1023s", mediaKeyInput);
	printf("Enter output file: ");
	scanf("%1023s", outFileName);
	printf("Enter video/document/image/audio: ");
	scanf("%15s", typeInput);

	uint8_t type = 255;
	if (!strcmp(typeInput, "video")) type = 0;
	else if (!strcmp(typeInput, "document")) type = 1;
	else if (!strcmp(typeInput, "image")) type = 2;
	else if (!strcmp(typeInput, "audio")) type = 3;

	if (type == 255) {
		fprintf(stderr, "decryptfile: type not found\n");
		return 1;
	}

	// Obtaining key
	uint8_t* iv = (uint8_t*)mediaKeyInput;
	uint8_t* cipherKey = ((uint8_t*)mediaKeyInput) + 16;
	uint8_t* macKey = ((uint8_t*)mediaKeyInput) + 48;
	// Omitting refKey
	
	// Getting data
	FILE* infile = fopen(inFileName, "rb");
	fseek(infile, 0, SEEK_END);
	uint64_t filelen = ftell(infile);
	fseek(infile, 0, SEEK_SET);
	uint8_t* fileData = (uint8_t*)malloc(filelen - 10);
	fread(fileData, filelen - 10, 1, infile);
	fclose(infile);

	// Decrypting data
	// TODO: implement AES256
	/* 
	uint64_t blockcount = (filelen - 10) >> 4;
	blockex_t prevstate = {};
	blockex_t state = {};
	blockex_t key = {};
	memcpy(&key, cipherKey, 
	if (blockcount > 0) {
		
	}
	for (uint64_t i = 1; i < blockcount; i++) {
		AES128EncryptCBC($`blockex_t state`, $`blockex_t key`, $`blockex_t cbcvec`)
	}
	*/
}
