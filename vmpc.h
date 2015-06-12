#ifndef _VMPC_H
#define _VMPC_H

#ifndef uint8
#define uint8  unsigned char
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif

typedef struct
{
	unsigned char P[256];	// Tablica permutacji
	unsigned char s, n;
	unsigned char ivInited;	// Potem wyt³umaczê, o co chodzi
}VmpcState;


void VMPCInitKeyRound(unsigned char Data[], unsigned char Len, unsigned char Src , VmpcState *s);
void VMPCInitKeyRound16(unsigned char Data[], unsigned char Src);   //Dla kluczy i wektorow o rozmiarze 16 bajtow (128 bitow)
void VMPCInitKey(unsigned char Key[], unsigned char Vec[], unsigned char KeyLen, unsigned char VecLen);   //KeyLen, VecLen = 1,2,3,...,64
void VMPCInitKey16(unsigned char Key[], unsigned char Vec[]);   //Dla kluczy i wektorow o rozmiarze 16 bajtow (128 bitow)
void VMPCInitKeyBASIC(unsigned char Key[], unsigned char Vec[], unsigned char KeyLen, unsigned char VecLen);   //KeyLen, VecLen = 1,2,3,...,64
void VMPCInitKey16BASIC(unsigned char Key[], unsigned char Vec[]);   //Dla kluczy i wektorow o rozmiarze 16 bajtow (128 bitow)
void VMPCEncrypt(unsigned char *Data, unsigned int Len , VmpcState *s);
void VMPCInitMAC();
void VMPCEncryptMAC(unsigned char Data[], unsigned int Len , VmpcState *s);
void VMPCDecryptMAC(unsigned char Data[], unsigned int Len);
void VMPCOutputMAC();
void VMPCEraseKey();

#endif