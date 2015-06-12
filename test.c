#include <stdio.h>
#include "vmpc.h"


void test1(void)
{
	VmpcContext vc;
	unsigned char key[] = {0x96, 0x61, 0x41, 0x0A, 0xB7, 0x97, 0xD8, 0xA9, 0xEB, 0x76, 0x7C, 0x21, 0x17, 0x2D, 0xF6, 0xC7};
	unsigned char iv[]  = {0x4B, 0x5C, 0x2F, 0x00, 0x3E, 0x67, 0xF3, 0x95, 0x57, 0xA8, 0xD2, 0x6F, 0x3D, 0xA2, 0xB1, 0x55};
	unsigned char plainText[] = {'H' , 'e' , 'l' , 'l' , 'o' , ' ' , 'w' , 'o' , 'r' , 'l' , 'd' , ' ' , '!' , '!' , '!' };
	unsigned char encrypted[] = {0xE0, 0x41, 0x15, 0x99, 0x7D, 0xC6, 0x73, 0x7B, 0xFF, 0xDD, 0x30, 0xAC, 0xF0, 0xB5, 0x51};
	unsigned char i;


	VmpcInitKeyRound(key , 16 , 1 , &vc);
	VmpcInitKeyRound(iv  , 16 , 0 , &vc);
	// OR VmpcInitKeyBASIC(key , 16 , iv , 16 , &vc);

	VmpcEncrypt(plainText , sizeof(plainText) , &vc);	// Encrypt plainn text
	printf(plainText);

	for(i = 0 ; i < sizeof(plainText) ; i++)
	{
		if(plainText[i] != encrypted[i])
		{
			printf("Encryption failed , plainText[%d] = %02X encrypted[%d] = %02X" , i , plainText[i] , encrypted[i]);
		}
	}

	// Now, if you want decrypt message...
	VmpcInitKeyRound(key , 16 , 1 , &vc);
	VmpcInitKeyRound(iv  , 16 , 0 , &vc);
	// OR VmpcInitKeyBASIC(key , 16 , iv , 16 , &vc);

	// Remember, in plainText is encrypted message
	VmpcEncrypt(plainText , sizeof(plainText) , &vc);	// Encrypt plainn text

	printf(plainText);
}

void test2(void)
{
	// VMPC is a stream cipher, so you can encrypt/decrypt 
	VmpcContext vc;
	unsigned char key[] = {0x96, 0x61, 0x41, 0x0A, 0xB7, 0x97, 0xD8, 0xA9, 0xEB, 0x76, 0x7C, 0x21, 0x17, 0x2D, 0xF6, 0xC7};
	unsigned char iv[]  = {0x4B, 0x5C, 0x2F, 0x00, 0x3E, 0x67, 0xF3, 0x95, 0x57, 0xA8, 0xD2, 0x6F, 0x3D, 0xA2, 0xB1, 0x55};
	unsigned char c;

	VmpcInitKeyRound(key , 16 , 1 , &vc);
	VmpcInitKeyRound(iv  , 16 , 0 , &vc);
	// OR VmpcInitKeyBASIC(key , 16 , iv , 16 , &vc);

	printf("Enter characters...");

	while(1)
	{
		c = getchar();
		VmpcEncrypt(&c , 1 , &vc);
		putchar(c);
	}
}

int main(void)
{
	test1();
	//test2();

	return 0;
}