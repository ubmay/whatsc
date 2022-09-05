#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include "../miniaes.h"
#include "../sha256.h"
#include "../hmac.h"
#include "../hkdf.h"

enum E2EMediaType {
	E2EMediaTypeVideo,
	E2EMediaTypeDocument,
	E2EMediaTypeImage,
	E2EMediaTypeAudio,
	E2EMediaTypeInvalid,
};

const char E2EMediaInfoVideo[] = "WhatsApp Video Keys";
const char E2EMediaInfoImage[] = "WhatsApp Image Keys";
const char E2EMediaInfoDocument[] = "WhatsApp Document Keys";
const char E2EMediaInfoAudio[] = "WhatsApp Audio Keys";
const char E2EMediaInfoSticker[] = "WhatsApp Image Keys";

unsigned int mreadline(char* buf, unsigned int maxcount) {
	char r = 0;
	unsigned int t = 0;
	ssize_t c = read(0, &r, 1);
	while (r != '\n' && t < maxcount - 1) {
		if (c != 1) break;
		buf[t++] = r;
		c = read(0, &r, 1);
	}
	buf[t] = 0;
	return t;
}

unsigned int mreadline_handleesc(char* buf, unsigned int maxcount) {
	char r = 0;
	unsigned int t = 0;
	ssize_t c = read(0, &r, 1);
	if (c) while (r != '\n' && t < maxcount - 1) {
		if (c != 1) break;
		if (r == '\\') {
			c = read(0, &r, 1);
			if (!c) {
				buf[t++] = r;
				break;
			}

			if (r == ' ' || r == '\\' || r == '"' || r == '\'' || r == '?') buf[t++] = r;
			else if (r == 'r') buf[t++] = '\r';
			else if (r == 't') buf[t++] = '\t';
			else if (r == 'v') buf[t++] = '\v';
			else if (r == 'n') buf[t++] = '\n';
			else if (r == '0') buf[t++] = '\0';
			else if (r == 'f') buf[t++] = '\f';
			else if (r == 'x') {
				char r0 = 0, r1 = 0;
				c = read(0, &r0, 1);
				if (!c) {
					buf[t++] = '\'';
					buf[t++] = 'x';
					break;
				}

				c = read(0, &r1, 1);
				if (!c) {
					buf[t++] = '\'';
					buf[t++] = 'x';
					buf[t++] = r0;
					break;
				}

				if (r0 >= 'a' && r0 <= 'f') r0 -= 'a' - '9' - 1;
				if (r1 >= 'a' && r1 <= 'f') r1 -= 'a' - '9' - 1;
				r0 -= '0';
				r1 -= '0';
				r = r0 * 16 + r1;
				buf[t++] = r;
			}
			c = read(0, &r, 1);
		} else {
			buf[t++] = r;
			c = read(0, &r, 1);
		}
	}
	buf[t] = 0;
	return t;
}

void trimright(char* str) {
	int a = strlen(str);
	while (isspace(str[a - 1]) && a) str[a--] = 0;
}

void trimleft(char* str) {
	int a = 0;
	int l = strlen(str);
	while (isspace(str[a]) && l) {
		str[a++] = 0;
		l--;
	}
	memcpy(str, str + a, l);
	memset(str + l, 0, a);
}

int main() {
	char inFileName[1024] = {}, mediaKeyInput[1024] = {}, outFileName[1024] = {}, typeInput[16] = {};
	printf("Enter input file: ");
	fflush(stdout);
	mreadline_handleesc(inFileName, 1024);
	trimright(inFileName);
	trimleft(inFileName);
	fflush(stdin);

	printf("Enter media key: ");
	fflush(stdout);
	mreadline(mediaKeyInput, 1024);
	fflush(stdin);

	printf("Enter output file: ");
	fflush(stdout);
	mreadline_handleesc(outFileName, 1024);
	trimright(inFileName);
	trimleft(inFileName);
	fflush(stdin);

	printf("Enter video/document/image/sticker/audio: ");
	fflush(stdout);
	mreadline(typeInput, 1024);
	fflush(stdin);

	enum E2EMediaType type = E2EMediaTypeInvalid;
	if (!strcmp(typeInput, "video")) type = E2EMediaTypeVideo;
	else if (!strcmp(typeInput, "document")) type = E2EMediaTypeDocument;
	else if (!strcmp(typeInput, "image")) type = E2EMediaTypeImage;
	else if (!strcmp(typeInput, "sticker")) type = E2EMediaTypeImage;
	else if (!strcmp(typeInput, "audio")) type = E2EMediaTypeAudio;


	if (type == 255) {
		fprintf(stderr, "decryptfile: fatal: invalid type %s\n", typeInput);
		return 1;
	}

	// Obtaining key
	uint8_t* mediaKey = (uint8_t*)alloca(32);
	int inputOff = 0;
	for (int i = 0; i < 32; i++) {
		char car = mediaKeyInput[inputOff++];
		if (car == '\\') {
			// Read next three bytes.
			char car0 = mediaKeyInput[inputOff++];
			if (car0 == 'x') {
				char car1 = mediaKeyInput[inputOff++];
				char car2 = mediaKeyInput[inputOff++];
				if (car1 >= 'a' && car1 <= 'f') car1 -= ('a' - '9' - 1);
				if (car2 >= 'a' && car2 <= 'f') car2 -= ('a' - '9' - 1);
				car1 -= '0';
				car2 -= '0';
				char o = car1 * 16 + car2;
				mediaKey[i] = o;
			} else if (car0 == '\\' || car0 == '"' || car0 == '\"' || car0 == '?') mediaKey[i] = car0;
			else if (car0 == 'r') mediaKey[i] = '\r';
			else if (car0 == 't') mediaKey[i] = '\t';
			else if (car0 == 'v') mediaKey[i] = '\v';
			else if (car0 == 'f') mediaKey[i] = '\f';
			else if (car0 == 'n') mediaKey[i] = '\n';
			else if (car0 == '0') mediaKey[i] = '\0';
			else {
				printf("decryptfile: fatal: unknown escape sequence \\%c when decoding mediaKeyInput\n", car0);
				return 2;
			}
		} else {
			mediaKey[i] = car;
		}
	}

	if (inputOff < strlen(mediaKeyInput)) {
		printf("decryptfile: warn: read less bytes from mediaKeyInput than expected\n");
	}
	if (inputOff > strlen(mediaKeyInput)) {
		printf("decryptfile: warn: mediaKeyInput decoded was less than 32 bytes\n");
	}

	printf("decryptfile: info: Decoded mediaKeyInput into mediaKey\n");

	// Obtaining key expandedd
	uint8_t* mediaKeyExpanded = (uint8_t*)alloca(112);
	switch (type) {
		case E2EMediaTypeVideo:
			HKDF_sha256(mediaKeyExpanded, 112, mediaKey, 0, E2EMediaInfoVideo, 32, 0, sizeof(E2EMediaInfoVideo) - 1);
			break;
		case E2EMediaTypeDocument:
			HKDF_sha256(mediaKeyExpanded, 112, mediaKey, 0, E2EMediaInfoDocument, 32, 0, sizeof(E2EMediaInfoDocument) - 1);
			break;
		case E2EMediaTypeImage:
			HKDF_sha256(mediaKeyExpanded, 112, mediaKey, 0, E2EMediaInfoImage, 32, 0, sizeof(E2EMediaInfoImage) - 1);
			break;
		case E2EMediaTypeAudio:
			HKDF_sha256(mediaKeyExpanded, 112, mediaKey, 0, E2EMediaInfoAudio, 32, 0, sizeof(E2EMediaInfoAudio) - 1);
			break;
		default:
			printf("decryptfile: fatal: invalid type %d\n", type);
			return 1;
			break;
	}

	printf("decryptfile: info: Expanded mediaKey into mediaKeyExpanded\n");

	aesblock128_t iv = *(aesblock128_t*)mediaKeyExpanded;
	aesblock256_t cipherKey = *(aesblock256_t*)(mediaKeyExpanded + 16);
	aesblock256_t macKey = *(aesblock256_t*)(mediaKeyExpanded + 48);
	// Omitting refKey
	
	// Getting data
	FILE* infile = fopen(inFileName, "rb");
	if (infile == 0) {
		printf("decryptfile: fatal: failed opening %s with errno %d\n", inFileName, errno);
		return 3;
	}
	fseek(infile, 0, SEEK_END);
	uint64_t filelen = ftell(infile);
	uint64_t blockcount = (filelen - 10) >> 4;
	fseek(infile, 0, SEEK_SET);
	uint8_t* fileData = (uint8_t*)calloc(blockcount, 4);
	fread(fileData, filelen - 10, 1, infile);
	fclose(infile);

	printf("decryptfile: info: Read %llu bytes of file data\n", blockcount << 4);

	// Decrypting data
	// TODO: implement AES256
	 
	aesblock128_t prevstate = {};
	aesblock128_t state = {};
	aesblock256_t key = {};
	memcpy(&key, &cipherKey, sizeof(aesblock256_t));
	aesblock128_t* inblocks = (aesblock128_t*)fileData;
	aesblock128_t* outblocks = (aesblock128_t*)malloc(blockcount << 4);
	aesblock128_t* roundKeys = 0;
	AES256GenerateRoundKeys(cipherKey, &roundKeys, 15);
	if (blockcount > 0) {
		prevstate = iv;
		for (uint64_t i = 0; i < blockcount; i++) {
			state = inblocks[i];
			outblocks[i] = AES256DecryptUPKCBC(state, roundKeys, prevstate);
			prevstate = state;
		}
	}
	free(roundKeys);
	
	printf("decryptfile: info: Decrypted data, writing to out file\n");
	FILE* outfile = fopen(outFileName, "wb");
	if (outfile == 0) {
		printf("decryptfile: fatal: failed opening output file with errno %d\n", errno);
		return 4;
	}
	fwrite(outblocks, 16, blockcount, outfile);
	fclose(outfile);

	printf("decryptfile: info: Written to output file\n");

	// Cleanup
	free(fileData);
	free(outblocks);
	return 0;
}
