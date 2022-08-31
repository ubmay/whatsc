#ifndef __MINIAES128_H__
#define __MINIAES128_H__
#include <stdlib.h>
typedef struct {
    unsigned char a, b, c, d;
} row_t;
typedef struct {
    unsigned int a, b, c, d;
} block_t;
typedef struct {
    row_t a, b, c, d;
} blockex_t;
typedef struct {
    int a, b;
} int128_t;

unsigned char sbox[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

unsigned char isbox[] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// rcon as well

row_t rcon[] = {
    {1}, {2}, {4}, {8}, {16},
    {32}, {64}, {128}, {27}, {54}
};

// and multiply tables

unsigned char gfmul2[] = {
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
    0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
    0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
    0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
    0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
    0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
    0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
    0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
    0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
    0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
    0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
    0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
    0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
    0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
    0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
    0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};

unsigned char gfmul3[] = {
    0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
    0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
    0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
    0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
    0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
    0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
    0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
    0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
    0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
    0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
    0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
    0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
    0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
    0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
    0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
    0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
};

unsigned char gfmul9[] = {
    0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77,
    0x90,0x99,0x82,0x8b,0xb4,0xbd,0xa6,0xaf,0xd8,0xd1,0xca,0xc3,0xfc,0xf5,0xee,0xe7,
    0x3b,0x32,0x29,0x20,0x1f,0x16,0x0d,0x04,0x73,0x7a,0x61,0x68,0x57,0x5e,0x45,0x4c,
    0xab,0xa2,0xb9,0xb0,0x8f,0x86,0x9d,0x94,0xe3,0xea,0xf1,0xf8,0xc7,0xce,0xd5,0xdc,
    0x76,0x7f,0x64,0x6d,0x52,0x5b,0x40,0x49,0x3e,0x37,0x2c,0x25,0x1a,0x13,0x08,0x01,
    0xe6,0xef,0xf4,0xfd,0xc2,0xcb,0xd0,0xd9,0xae,0xa7,0xbc,0xb5,0x8a,0x83,0x98,0x91,
    0x4d,0x44,0x5f,0x56,0x69,0x60,0x7b,0x72,0x05,0x0c,0x17,0x1e,0x21,0x28,0x33,0x3a,
    0xdd,0xd4,0xcf,0xc6,0xf9,0xf0,0xeb,0xe2,0x95,0x9c,0x87,0x8e,0xb1,0xb8,0xa3,0xaa,
    0xec,0xe5,0xfe,0xf7,0xc8,0xc1,0xda,0xd3,0xa4,0xad,0xb6,0xbf,0x80,0x89,0x92,0x9b,
    0x7c,0x75,0x6e,0x67,0x58,0x51,0x4a,0x43,0x34,0x3d,0x26,0x2f,0x10,0x19,0x02,0x0b,
    0xd7,0xde,0xc5,0xcc,0xf3,0xfa,0xe1,0xe8,0x9f,0x96,0x8d,0x84,0xbb,0xb2,0xa9,0xa0,
    0x47,0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x0f,0x06,0x1d,0x14,0x2b,0x22,0x39,0x30,
    0x9a,0x93,0x88,0x81,0xbe,0xb7,0xac,0xa5,0xd2,0xdb,0xc0,0xc9,0xf6,0xff,0xe4,0xed,
    0x0a,0x03,0x18,0x11,0x2e,0x27,0x3c,0x35,0x42,0x4b,0x50,0x59,0x66,0x6f,0x74,0x7d,
    0xa1,0xa8,0xb3,0xba,0x85,0x8c,0x97,0x9e,0xe9,0xe0,0xfb,0xf2,0xcd,0xc4,0xdf,0xd6,
    0x31,0x38,0x23,0x2a,0x15,0x1c,0x07,0x0e,0x79,0x70,0x6b,0x62,0x5d,0x54,0x4f,0x46
};

unsigned char gfmul11[] = {
    0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
    0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
    0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
    0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
    0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
    0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
    0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
    0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
    0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
    0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
    0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
    0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
    0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
    0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
    0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
    0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3
};

unsigned char gfmul13[] = {
    0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
    0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b,
    0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0,
    0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20,
    0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26,
    0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6,
    0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d,
    0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d,
    0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91,
    0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41,
    0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a,
    0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa,
    0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc,
    0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c,
    0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47,
    0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97
};

unsigned char gfmul14[] = {
    0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
    0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
    0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
    0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
    0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
    0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
    0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
    0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
    0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
    0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
    0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
    0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
    0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
    0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
    0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
    0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d
};

blockex_t SubBlockEx(blockex_t a) {
    blockex_t ret = {
        { sbox[a.a.a], sbox[a.a.b], sbox[a.a.c], sbox[a.a.d] },
        { sbox[a.b.a], sbox[a.b.b], sbox[a.b.c], sbox[a.b.d] },
        { sbox[a.c.a], sbox[a.c.b], sbox[a.c.c], sbox[a.c.d] },
        { sbox[a.d.a], sbox[a.d.b], sbox[a.d.c], sbox[a.d.d] }
    };
    return ret;
}

blockex_t InvSubBlockEx(blockex_t a) {
    blockex_t ret = {
        { isbox[a.a.a], isbox[a.a.b], isbox[a.a.c], isbox[a.a.d] },
        { isbox[a.b.a], isbox[a.b.b], isbox[a.b.c], isbox[a.b.d] },
        { isbox[a.c.a], isbox[a.c.b], isbox[a.c.c], isbox[a.c.d] },
        { isbox[a.d.a], isbox[a.d.b], isbox[a.d.c], isbox[a.d.d] }
    };
    return ret;
}

row_t SubRow(row_t a) {
    row_t ret = { sbox[a.a], sbox[a.b], sbox[a.c], sbox[a.d] };
    return ret;
}

row_t RotateRowRight(row_t _a, unsigned char _o) {
    unsigned char o = _o & 3;
    row_t leftover = {};
    row_t a = _a;

    memcpy(&leftover, (row_t*)((long long)&a + 4 - o), o);
    memcpy((row_t*)((long long)&a + o), &a, 4 - o);
    memcpy(&a, &leftover, o);
    return a;
}

row_t GetColumnEx(blockex_t a, unsigned char _o) {
    unsigned char o = _o & 3;
    row_t ret =  {
        *(unsigned char*)((long long)&a.a + o),
        *(unsigned char*)((long long)&a.b + o),
        *(unsigned char*)((long long)&a.c + o),
        *(unsigned char*)((long long)&a.d + o)
    };
    return ret;
}

blockex_t ShiftColumnsEx(blockex_t _a) {
    row_t c0 = GetColumnEx(_a, 0);
    row_t c1 = RotateRowRight(GetColumnEx(_a, 1), -1);
    row_t c2 = RotateRowRight(GetColumnEx(_a, 2), -2);
    row_t c3 = RotateRowRight(GetColumnEx(_a, 3), -3);
    blockex_t a = {
        { c0.a, c1.a, c2.a, c3.a },
        { c0.b, c1.b, c2.b, c3.b },
        { c0.c, c1.c, c2.c, c3.c },
        { c0.d, c1.d, c2.d, c3.d }
    };
    return a;
}

blockex_t InvShiftColumnsEx(blockex_t _a) {
    row_t c0 = GetColumnEx(_a, 0);
    row_t c1 = RotateRowRight(GetColumnEx(_a, 1), 1);
    row_t c2 = RotateRowRight(GetColumnEx(_a, 2), 2);
    row_t c3 = RotateRowRight(GetColumnEx(_a, 3), 3);
    blockex_t a = {
        { c0.a, c1.a, c2.a, c3.a },
        { c0.b, c1.b, c2.b, c3.b },
        { c0.c, c1.c, c2.c, c3.c },
        { c0.d, c1.d, c2.d, c3.d }
    };
    return a;
}

unsigned char sl1(unsigned char a) {
    return (a << 1) ^ (27 * (a >> 7));
}

blockex_t MixRowsEx(blockex_t a) {
    row_t o0 = {
        gfmul2[a.a.a] ^ gfmul3[a.a.b] ^ a.a.c ^ a.a.d,
        gfmul2[a.a.b] ^ gfmul3[a.a.c] ^ a.a.d ^ a.a.a,
        gfmul2[a.a.c] ^ gfmul3[a.a.d] ^ a.a.a ^ a.a.b,
        gfmul2[a.a.d] ^ gfmul3[a.a.a] ^ a.a.b ^ a.a.c,
    };
    row_t o1 = {
        gfmul2[a.b.a] ^ gfmul3[a.b.b] ^ a.b.c ^ a.b.d,
        gfmul2[a.b.b] ^ gfmul3[a.b.c] ^ a.b.d ^ a.b.a,
        gfmul2[a.b.c] ^ gfmul3[a.b.d] ^ a.b.a ^ a.b.b,
        gfmul2[a.b.d] ^ gfmul3[a.b.a] ^ a.b.b ^ a.b.c,
    };
    row_t o2 = {
        gfmul2[a.c.a] ^ gfmul3[a.c.b] ^ a.c.c ^ a.c.d,
        gfmul2[a.c.b] ^ gfmul3[a.c.c] ^ a.c.d ^ a.c.a,
        gfmul2[a.c.c] ^ gfmul3[a.c.d] ^ a.c.a ^ a.c.b,
        gfmul2[a.c.d] ^ gfmul3[a.c.a] ^ a.c.b ^ a.c.c,
    };
    row_t o3 = {
        gfmul2[a.d.a] ^ gfmul3[a.d.b] ^ a.d.c ^ a.d.d,
        gfmul2[a.d.b] ^ gfmul3[a.d.c] ^ a.d.d ^ a.d.a,
        gfmul2[a.d.c] ^ gfmul3[a.d.d] ^ a.d.a ^ a.d.b,
        gfmul2[a.d.d] ^ gfmul3[a.d.a] ^ a.d.b ^ a.d.c,
    };
    blockex_t ret = { o0, o1, o2, o3 };
    return ret;
}

blockex_t InvMixRowsEx(blockex_t a) {
    row_t o0 = {
        gfmul14[a.a.a] ^ gfmul11[a.a.b] ^ gfmul13[a.a.c] ^ gfmul9[a.a.d],
        gfmul14[a.a.b] ^ gfmul11[a.a.c] ^ gfmul13[a.a.d] ^ gfmul9[a.a.a],
        gfmul14[a.a.c] ^ gfmul11[a.a.d] ^ gfmul13[a.a.a] ^ gfmul9[a.a.b],
        gfmul14[a.a.d] ^ gfmul11[a.a.a] ^ gfmul13[a.a.b] ^ gfmul9[a.a.c],
    };
    row_t o1 = {
        gfmul14[a.b.a] ^ gfmul11[a.b.b] ^ gfmul13[a.b.c] ^ gfmul9[a.b.d],
        gfmul14[a.b.b] ^ gfmul11[a.b.c] ^ gfmul13[a.b.d] ^ gfmul9[a.b.a],
        gfmul14[a.b.c] ^ gfmul11[a.b.d] ^ gfmul13[a.b.a] ^ gfmul9[a.b.b],
        gfmul14[a.b.d] ^ gfmul11[a.b.a] ^ gfmul13[a.b.b] ^ gfmul9[a.b.c],
    };
    row_t o2 = {
        gfmul14[a.c.a] ^ gfmul11[a.c.b] ^ gfmul13[a.c.c] ^ gfmul9[a.c.d],
        gfmul14[a.c.b] ^ gfmul11[a.c.c] ^ gfmul13[a.c.d] ^ gfmul9[a.c.a],
        gfmul14[a.c.c] ^ gfmul11[a.c.d] ^ gfmul13[a.c.a] ^ gfmul9[a.c.b],
        gfmul14[a.c.d] ^ gfmul11[a.c.a] ^ gfmul13[a.c.b] ^ gfmul9[a.c.c],
    };
    row_t o3 = {
        gfmul14[a.d.a] ^ gfmul11[a.d.b] ^ gfmul13[a.d.c] ^ gfmul9[a.d.d],
        gfmul14[a.d.b] ^ gfmul11[a.d.c] ^ gfmul13[a.d.d] ^ gfmul9[a.d.a],
        gfmul14[a.d.c] ^ gfmul11[a.d.d] ^ gfmul13[a.d.a] ^ gfmul9[a.d.b],
        gfmul14[a.d.d] ^ gfmul11[a.d.a] ^ gfmul13[a.d.b] ^ gfmul9[a.d.c],
    };
    blockex_t ret = { o0, o1, o2, o3 };
    return ret;
}

blockex_t AddBlockEx(blockex_t a, blockex_t b) {
    blockex_t ret = {
        {
            (unsigned char)(a.a.a ^ b.a.a),
            (unsigned char)(a.a.b ^ b.a.b),
            (unsigned char)(a.a.c ^ b.a.c),
            (unsigned char)(a.a.d ^ b.a.d)
        },
        {
            (unsigned char)(a.b.a ^ b.b.a),
            (unsigned char)(a.b.b ^ b.b.b),
            (unsigned char)(a.b.c ^ b.b.c),
            (unsigned char)(a.b.d ^ b.b.d)
        },
        {
            (unsigned char)(a.c.a ^ b.c.a),
            (unsigned char)(a.c.b ^ b.c.b),
            (unsigned char)(a.c.c ^ b.c.c),
            (unsigned char)(a.c.d ^ b.c.d)
        },
        {
            (unsigned char)(a.d.a ^ b.d.a),
            (unsigned char)(a.d.b ^ b.d.b),
            (unsigned char)(a.d.c ^ b.d.c),
            (unsigned char)(a.d.d ^ b.d.d)
        }
    };
    return ret;
}

row_t AddRow(row_t a, row_t b) {
    row_t ret = {
        (unsigned char)(a.a ^ b.a),
        (unsigned char)(a.b ^ b.b),
        (unsigned char)(a.c ^ b.c),
        (unsigned char)(a.d ^ b.d)
    };
    return ret;
}

void GenerateRoundKeys(blockex_t key, blockex_t** outKeys, unsigned char countExclusive) {
    if (countExclusive > 0 && outKeys) {
        if (!*outKeys) *outKeys = (blockex_t*)malloc(sizeof(blockex_t) * countExclusive);
        {
            row_t r0 = key.a;
            row_t r1 = key.b;
            row_t r2 = key.c;
            row_t r3 = key.d;
            row_t o0 = AddRow(AddRow(r0, SubRow(RotateRowRight(r3, -1))), rcon[0]);
            row_t o1 = AddRow(r1, o0);
            row_t o2 = AddRow(r2, o1);
            row_t o3 = AddRow(r3, o2);
            blockex_t o = { o0, o1, o2, o3 };
            (*outKeys)[0] = o;
        }
        for (int i = 1; i < countExclusive; i++) {
            row_t r0 = (*outKeys)[i - 1].a;
            row_t r1 = (*outKeys)[i - 1].b;
            row_t r2 = (*outKeys)[i - 1].c;
            row_t r3 = (*outKeys)[i - 1].d;
            row_t o0 = AddRow(AddRow(r0, SubRow(RotateRowRight(r3, -1))), rcon[i]);
            row_t o1 = AddRow(r1, o0);
            row_t o2 = AddRow(r2, o1);
            row_t o3 = AddRow(r3, o2);
            blockex_t o = { o0, o1, o2, o3 };
            (*outKeys)[i] = o;
        }
    }
}

blockex_t AES128Encrypt(blockex_t state, blockex_t key) {
    blockex_t* roundKeys = 0;
    GenerateRoundKeys(key, &roundKeys, 10);

    // Initial round
    blockex_t output = AddBlockEx(state, key);

    // 9 main rounds
    for (int i = 0; i < 9; i++) {
        output = SubBlockEx(output);
        output = ShiftColumnsEx(output);
        output = MixRowsEx(output);
        output = AddBlockEx(output, roundKeys[i]);
    }

    // Final round
    output = SubBlockEx(output);
    output = ShiftColumnsEx(output);
    output = AddBlockEx(output, roundKeys[9]);

    return output;
}

blockex_t AES128Decrypt(blockex_t state, blockex_t key) {
    blockex_t* roundKeys = 0;
    GenerateRoundKeys(key, &roundKeys, 10);

    // Final round
    blockex_t output = AddBlockEx(state, roundKeys[9]);
    output = InvShiftColumnsEx(output);
    output = InvSubBlockEx(output);

    // 9 main rounds
    for (int i = 8; i >= 0; i--) {
        output = AddBlockEx(output, roundKeys[i]);
        output = InvMixRowsEx(output);
        output = InvShiftColumnsEx(output);
        output = InvSubBlockEx(output);
    }

    // Initial round
    output = AddBlockEx(output, key);

    return output;
}
#endif /* __MINIAES128_H__ */

#ifdef __MINIAES128_CBCEXT_H__
#define __MINIAES128_CBCEXT_H__

blockex_t AES128Encrypt(blockex_t state, blockex_t key, blockex_t cbcvec) {
    blockex_t* roundKeys = 0;
    GenerateRoundKeys(key, &roundKeys, 10);

    // Initial round
    blockex_t output = AddBlockEx(state, key);
	
	// CBC Encryption
	// (note that AddBlockEx is actually an XOR operation)
	output = AddBlockEx(output, cbcvec)

    // 9 main rounds
    for (int i = 0; i < 9; i++) {
        output = SubBlockEx(output);
        output = ShiftColumnsEx(output);
        output = MixRowsEx(output);
        output = AddBlockEx(output, roundKeys[i]);
    }

    // Final round
    output = SubBlockEx(output);
    output = ShiftColumnsEx(output);
    output = AddBlockEx(output, roundKeys[9]);

    return output;
}

blockex_t AES128CBCDecrypt(blockex_t state, blockex_t key, blockex_t cbcvec) {
    blockex_t* roundKeys = 0;
    GenerateRoundKeys(key, &roundKeys, 10);

    // Final round
    blockex_t output = AddBlockEx(state, roundKeys[9]);
    output = InvShiftColumnsEx(output);
    output = InvSubBlockEx(output);

    // 9 main rounds
    for (int i = 8; i >= 0; i--) {
        output = AddBlockEx(output, roundKeys[i]);
        output = InvMixRowsEx(output);
        output = InvShiftColumnsEx(output);
        output = InvSubBlockEx(output);
    }

    // Initial round
    output = AddBlockEx(output, key);

	// CBC Decryption
	// (note that AddBlockEx is actually an XOR operation)
	output = AddBlockEx(output, cbcvec)

    return output;
}

#endif /* __MINIAES128_CBCEXT_H */
