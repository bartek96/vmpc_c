/*---------------------------------------------------------------------------------------------------

Implementacja szyfru strumieniowego VMPC 
oraz 
schematu uwierzytelnionego szyfrowania VMPC-MAC
w jêzyku C

Autor algorytmów:		Bartosz ¯ó³tak
Autor implementacji:	Bartosz ¯ó³tak

www.szyfrowanie.com 

-----------------------------------------------------------------------------------------------------
----------------------- Wykorzystanie algorytmów: ---------------------------------------------------
-----------------------------------------------------------------------------------------------------

unsigned char Klucz[64], Wektor[64]; Wiadomosc[1000]; WiadomoscMAC[20];

Szyfrowanie:

VMPCInitKey(Klucz, Wektor, 16, 16);
VMPCEncrypt(Wiadomosc, 1000);

Deszyfrowanie:

VMPCInitKey(Klucz, Wektor, 16, 16);
VMPCEncrypt(Wiadomosc, 1000);

(funkcja VMPCEncrypt s³u¿y do szyfrowania i deszyfrowania). 

Szyfrowanie z uwierzytelnianiem (z kodem MAC):

VMPCInitKey(Klucz, Wektor, 16, 16);
VMPCInitMAC();
VMPCEncryptMAC(Wiadomosc, 1000);
VMPCOutputMAC();                  //Kod MAC umieszczony zostaje w 20-bajtowej tablicy "MAC"
Move(MAC, WiadomoscMAC, 20);      //Zapamietaj wygenerowany MAC w tablicy "WiadomoscMAC"

Deszyfrowanie i weryfikacja kodu MAC:

VMPCInitKey(Klucz, Wektor, 16, 16);
VMPCInitMAC();
VMPCDecryptMAC(Wiadomosc, 1000);
VMPCOutputMAC();                  //Kod MAC umieszczony zostaje w 20-bajtowej tablicy "MAC"

Je?li 20-bajtowe tablice "MAC" i "WiadomoscMAC" sš identyczne, wiadomo?æ zosta³a poprawnie odszyfrowana -
u¿yty zosta³ w³a?ciwy klucz i wiadomo?æ nie zosta³a zmieniona.

----------------------------------------------------------------------------------------------------
Funkcje VMPCInitKey / VMPCInitKey16 (wykorzystujšce algorytm inicjowania klucza VMPC-KSA3)
zapewniajš wy¿szy poziom bezpieczeñstwa, ale o oko³o 1/3 ni¿szš wydajno?æ 
ni¿ podstawowe funkcje VMPCInitKeyBASIC / VMPCInitKey16BASIC.

Je?li tylko wydajno?æ systemu pozwala, autor zaleca stosowaæ funkcje VMPCInitKey / VMPCInitKey16.
Jednocze?nie funkcje VMPCInitKeyBASIC / VMPCInitKey16BASIC tak¿e pozostajš bezpieczne.

----------------------------------------------------------------------------------------------------
UWAGA! 
Do ka¿dego szyfrowania z tym samym kluczem ("Klucz") 
nale¿y u¿yæ INNEJ warto?ci wektora inicjujšcego "Wektor". 

Szyfrowanie dwóch wiadomo?ci TYM SAMYM kluczem i TYM SAMYM wektorem inicjujšcym
drastycznie obni¿a poziom bezpieczeñstwa!

Klucz jest warto?ciš tajnš. 
Wektor inicjujšcy jest warto?ciš jawnš - mo¿na go przekazaæ jawnie wraz z zaszyfrowanš wiadomo?ciš.
----------------------------------------------------------------------------------------------------*/


//---------------------------------------------------------------------------------------------------
//----------------------------------------- IMPLEMENTACJA: ------------------------------------------
//---------------------------------------------------------------------------------------------------

#include <string.h>
#include "Header/define_B12V0.h"
#include <plib.h>
#include "Header/vmpc.h"
//--- Typ danych "int" oznacza zmiennš 32-bitow¹


//----------- Zmienne szyfru VMPC: -----------

//VmpcState state;	// Stan automatu szyfruj¹cego

//----------- Zmienne schematu uwierzytelnionego szyfrowania VMPC-MAC: -----------
unsigned char MAC[32];
unsigned char m1, m2, m3, m4, mn;

//----------------- Dane testowe: -----------------
unsigned char TestKey[16]         = {0x96, 0x61, 0x41, 0x0A, 0xB7, 0x97, 0xD8, 0xA9, 0xEB, 0x76, 0x7C, 0x21, 0x17, 0x2D, 0xF6, 0xC7};
unsigned char TestVector[16]      = {0x4B, 0x5C, 0x2F, 0x00, 0x3E, 0x67, 0xF3, 0x95, 0x57, 0xA8, 0xD2, 0x6F, 0x3D, 0xA2, 0xB1, 0x55};

unsigned char TestOutPInd[8]      = {0, 1, 2, 3, 252, 253, 254, 255};
unsigned int  TestOutInd[16]      = {0, 1, 2, 3, 252, 253, 254, 255, 1020, 1021, 1022, 1023, 102396, 102397, 102398, 102399};


unsigned char TestOutPBASIC[8]    = {0x3F, 0xA5, 0x22, 0x67, 0x75, 0xB3, 0xD2, 0xC3};
unsigned char TestOutBASIC[16]    = {0xA8, 0x24, 0x79, 0xF5, 0xB8, 0xFC, 0x66, 0xA4, 0xE0, 0x56, 0x40, 0xA5, 0x81, 0xCA, 0x49, 0x9A};
//VMPCInitKeyBASIC(TestKey, TestVector, 16, 16);  LUB  VMPCInitKey16BASIC(TestKey, TestVector);
//P[TestOutPInd[x]]==TestOutPBASIC[x];  x=0,1,...,7
//Table[x]=0;  x=0,1,...,102399
//VMPCEncrypt(Table, 102400);  LUB  VMPCEncryptMAC(Table, 102400);
//Table[TestOutInd[x]]==TestOutBASIC[x];  x=0,1,...,15


unsigned char TestOutP[8]         = {0x1F, 0x00, 0xE2, 0x03, 0x5C, 0xEE, 0xC2, 0x2B};
unsigned char TestOut[16]         = {0xB6, 0xEB, 0xAE, 0xFE, 0x48, 0x17, 0x24, 0x73, 0x1D, 0xAE, 0xC3, 0x5A, 0x1D, 0xA7, 0xE1, 0xDC};
//VMPCInitKey(TestKey, TestVector, 16, 16);  LUB  VMPCInitKey16(TestKey, TestVector);
//P[TestOutPInd[x]]==TestOutP[x];  x=0,1,...,7
//Table[x]=0;  x=0,1,...,102399
//VMPCEncrypt(Table, 102400);  LUB  VMPCEncryptMAC(Table, 102400);
//Table[TestOutInd[x]]==TestOut[x];  x=0,1,...,15


unsigned char TestOutMACBASIC[20] = {0x9B, 0xDA, 0x16, 0xE2, 0xAD, 0x0E, 0x28, 0x47, 0x74, 0xA3, 0xAC, 0xBC, 0x88, 0x35, 0xA8, 0x32, 0x6C, 0x11, 0xFA, 0xAD};
//Table[x]=x;  x=0,1,2,...,254,255
//VMPCInitKeyBASIC(TestKey, TestVector, 16, 16);  LUB  VMPCInitKey16BASIC(TestKey, TestVector);
//VMPCInitMAC();
//VMPCEncryptMAC(Table, 256);
//VMPCOutputMAC();
//MAC[x]==TestOutMACBASIC[x];  x=0,1,...,19

unsigned char TestOutMAC[20]      = {0xA2, 0xB6, 0x0D, 0xB7, 0xB3, 0x90, 0x1D, 0x5C, 0x99, 0x61, 0x7C, 0xE2, 0xA3, 0x95, 0x02, 0x81, 0x75, 0x3A, 0x0C, 0x98};
//Table[x]=x & 255;  x=0,1,2,...,999998,999999;  (Table[0]=0; Table[1]=1; ...; Table[999998]=62; Table[999999]=63)
//VMPCInitKey(TestKey, TestVector, 16, 16);  LUB  VMPCInitKey16(TestKey, TestVector);
//VMPCInitMAC();
//VMPCEncryptMAC(Table, 1000000);
//VMPCOutputMAC();
//MAC[x]==TestOutMAC[x];  x=0,1,...,19

//-----------------------------------------------------------------------------------------------------------
/*
unsigned char Permut123[256]=   //Permut123[x]=x
{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,
72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,
109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,
139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,
169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,
199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,
228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255};
*/
//-----------------------------------------------------------------------------------------------------------


//---------- Szyfr strumieniowy VMPC: ----------


void VMPCInitKeyRound(unsigned char Data[], unsigned char Len, unsigned char Src , VmpcState *s)
/*Data: klucz lub wektor inicjujacy
Len=1,2,3,...,64: dlugosc klucza/wektora inicjujacego (w bajtach)
Src=0: pierwsze inicjowanie klucza (tablica P i zmienna s zostana najpierw przywrocone do stanu poczatkowego)
Src=1: ponowne inicjowanie klucza, np. wektorem inicjujacym*/
{
	unsigned char k;
	int x;
	unsigned char t;

	if (Src == 0) 
	{
		//memcpy(s ->P, Permut123, 256);
		k = 0;
		while(1){
			s ->P[k] = k;
			if(k == 255) break;
			k++;
		}

		s ->s = 0;
	}
	s ->n = 0;

	k = 0;
	for (x = 0; x < 768; x++)
	{
		s ->s = s ->P[ (s ->s + s ->P[s ->n] + Data[k]) & 255 ];

		t = s ->P[s ->n];
		s ->P[s ->n] = s ->P[s ->s];
		s ->P[s ->s] = t;

		k++;  
		if (k == Len) k = 0;
		s ->n++;
	}
}


/*
void VMPCInitKeyRound16(unsigned char Data[], unsigned char Src)   //Dla kluczy i wektorow o rozmiarze 16 bajtow (128 bitow)
//Data: klucz lub wektor inicjujacy
//Src=0: pierwsze inicjowanie klucza (tablica P i zmienna s zostana najpierw przywrocone do stanu poczatkowego)
//Src=1: ponowne inicjowanie klucza, np. wektorem inicjujacym
{
	int x;
	unsigned char t;
	unsigned char i;

	if (Src==0) 
	{
		memcpy(state.P, Permut123, 256);
		for(i = 0 ; i < 256 ; i++)
			s ->P[i] = i;
		state.s = 0;
	}
	unsigned char k=0;
	state.n = 0;

	for (x = 0; x < 768; x++)
	{
		state.s = state.P[ (state.s + state.P[state.n] + Data[k]) & 255 ];

		t = state.P[state.n];
		state.P[state.n] = state.P[state.s];  
		state.P[state.s] = t;

		k=++k & 15;
		state.n++;
	}
}



void VMPCInitKey(unsigned char Key[], unsigned char Vec[], unsigned char KeyLen, unsigned char VecLen)   //KeyLen, VecLen = 1,2,3,...,64
{
	VMPCInitKeyRound(Key, KeyLen, 0);
	VMPCInitKeyRound(Vec, VecLen, 1);
	VMPCInitKeyRound(Key, KeyLen, 1);
}



void VMPCInitKey16(unsigned char Key[], unsigned char Vec[])   //Dla kluczy i wektorow o rozmiarze 16 bajtow (128 bitow)
{
	VMPCInitKeyRound16(Key, 0);
	VMPCInitKeyRound16(Vec, 1);
	VMPCInitKeyRound16(Key, 1);
}


void VMPCInitKeyBASIC(unsigned char Key[], unsigned char Vec[], unsigned char KeyLen, unsigned char VecLen)   //KeyLen, VecLen = 1,2,3,...,64
{
	VMPCInitKeyRound(Key, KeyLen, 0);
	VMPCInitKeyRound(Vec, VecLen, 1);
}



void VMPCInitKey16BASIC(unsigned char Key[], unsigned char Vec[])   //Dla kluczy i wektorow o rozmiarze 16 bajtow (128 bitow)
{
	VMPCInitKeyRound16(Key, 0);
	VMPCInitKeyRound16(Vec, 1);
}

*/

void VMPCEncrypt(unsigned char *Data, unsigned int Len , VmpcState *s)
{
	int x;
	unsigned char t;
	for (x = 0; x < Len; x++)
	{
		s ->s = s ->P[ (s ->s + s ->P[s ->n]) & 255 ];
		Data[x] ^= s ->P[(s ->P[s ->P[ s ->s ]] + 1) & 255];
		t = s ->P[s ->n];  
		s ->P[s ->n] = s ->P[s ->s];
		s ->P[s ->s] = t;
		s ->n++;
	}
}


//---------- Schemat uwierzytelnionego szyfrowania VMPC-MAC: ----------

/*
void VMPCInitMAC()
{
	m1=m2=m3=m4=mn=0;
	memset(MAC, 0, sizeof(MAC));
}



void VMPCEncryptMAC(unsigned char Data[], unsigned int Len , VmpcState *s)
{
	unsigned int x;
	unsigned char t;

	for (x = 0; x < Len; x++)
	{
		s ->s = s ->P[ (s ->s + s ->P[s ->n]) & 255 ];

		Data[x] ^= s ->P[(s ->P[s ->P[ s ->s ]] + 1) & 255];

		m4 = s ->P[(m4 + m3) & 255];
		m3 = s ->P[(m3 + m2) & 255];
		m2 = s ->P[(m2 + m1) & 255];
		m1 = s ->P[(m1 + s ->s + Data[x]) & 255];

		MAC[mn]  ^=m1;
		MAC[mn+1]^=m2;
		MAC[mn+2]^=m3;
		MAC[mn+3]^=m4;

		t = s ->P[s ->n];  
		s ->P[s ->n] = s ->P[s ->s];  
		s ->P[s ->s]=t;

		mn = (mn+4) & 31;
		s ->n++;
	}
}



void VMPCDecryptMAC(unsigned char Data[], unsigned int Len , VmpcState *s)
{
	unsigned int x;
	unsigned char t;

	for (x = 0; x < Len; x++)
	{
		s ->s = s ->P[ (s ->s + s ->P[s ->n]) & 255 ];

		m4 = s ->P[(m4 + m3) & 255];
		m3 = s ->P[(m3 + m2) & 255];
		m2 = s ->P[(m2 + m1) & 255];
		m1 = s ->P[(m1 + s ->s + Data[x]) & 255];

		MAC[mn]  ^=m1;
		MAC[mn+1]^=m2;
		MAC[mn+2]^=m3;
		MAC[mn+3]^=m4;

		Data[x] ^= s ->P[(s ->P[s ->P[ s ->s ]]+1) & 255];

		t = s ->P[s ->n];  
		s ->P[s ->n] = s ->P[s ->s];  
		s ->P[s ->s] = t;

		mn=(mn+4) & 31;
		s ->n++;
	}
}



void VMPCOutputMAC()
{
	unsigned int x;
	for (x=1; x<=24; x++)
	{
		s=P[ (s + P[n]) & 255 ];

		m4=P[(m4 + m3 + x) & 255];
		m3=P[(m3 + m2 + x) & 255];
		m2=P[(m2 + m1 + x) & 255];
		m1=P[(m1 + s  + x) & 255];

		MAC[mn]  ^=m1;
		MAC[mn+1]^=m2;
		MAC[mn+2]^=m3;
		MAC[mn+3]^=m4;

		unsigned char t=P[n];  P[n]=P[s];  P[s]=t;

		mn=(mn+4) & 31;
		n++;
	}
	VMPCInitKeyRound(MAC, 32, 1);
	memset(MAC, 0, 20);
	VMPCEncrypt(MAC, 20);
}



void VMPCEraseKey()
{
	memset(P, 0, sizeof(P));
	memset(MAC, 0, sizeof(MAC));
	s=n=m1=m2=m3=m4=mn=0;
}

*/
//---------------------------------------------------------------------------------------------------
//--------------------------------------------- KONIEC ----------------------------------------------
//---------------------------------------------------------------------------------------------------

