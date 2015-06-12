/*---------------------------------------------------------------------------------------------------

                 Implementation of the VMPC Stream Cipher
                                 and 
              the VMPC-MAC Authenticated Encryption Scheme
                                 in C

                Author of the algorithms: Bartosz Zoltak
              Author of the implementation: Bartosz Wawrzyniak

                         www.vmpcfunction.com 

-----------------------------------------------------------------------------------------------------
----------------------- Usage of the algorithms: ----------------------------------------------------
-----------------------------------------------------------------------------------------------------

unsigned char Key[64], Vector[64]; Message[1000]; MessageMAC[20];

Encryption:

   VMPCInitKey(Key, Vector, 16, 16);
   VMPCEncrypt(Message, 1000);

Decryption:

   VMPCInitKey(Key, Vector, 16, 16);
   VMPCEncrypt(Message, 1000);

   (the VMPCEncrypt function is used for both encryption and decryption). 

Authenticated Encryption (with the MAC tag):

   VMPCInitKey(Key, Vector, 16, 16);
   VMPCInitMAC();
   VMPCEncryptMAC(Message, 1000);
   VMPCOutputMAC();                  //The MAC tag is saved in the 20-byte "MAC" table
   Move(MAC, MessageMAC, 20);        //Save the generated MAC tag in the "MessageMAC" table

Decryption and verification of the MAC tag:

   VMPCInitKey(Key, Vector, 16, 16);
   VMPCInitMAC();
   VMPCDecryptMAC(Message, 1000);
   VMPCOutputMAC();                  //The MAC tag is saved in the 20-byte "MAC" table

   If the 20-byte tables "MAC" and "MessageMAC" are identical, the message was correctly decrypted -
   the correct key was used and the message was not corrupted.

----------------------------------------------------------------------------------------------------
The VMPCInitKey / VMPCInitKey16 functions (employing the VMPC-KSA3 key initialization algorithm)
provide higher security level but about 1/3 lower efficiency.
than the basic VMPCInitKeyBASIC / VMPCInitKey16BASIC functions.

If only the system efficiency allows, the author recommends to use the VMPCInitKey / VMPCInitKey16 functions.
At the same time the VMPCInitKeyBASIC / VMPCInitKey16BASIC functions also remain secure. 
----------------------------------------------------------------------------------------------------
CAUTION! 
A DIFFERENT value of the initialization vector ("Vector")
should be used for each encryption with the same key ("Key").

Encrypting two messages with THE SAME key and THE SAME initialization vector
drastically reduces security level!

The key is a secret value.
The initialization vector is not secret - it can be passed in plain form along with the encrypted message.
-----------------------------------------------------------------------------------------------------------*/


//---------------------------------------------------------------------------------------------------
//----------------------------------------- IMPLEMENTATION: -----------------------------------------
//---------------------------------------------------------------------------------------------------

//--- The "int" type denotes a 32-bit integer

#include <string.h>
#include "Header/vmpc.h"

//---------- VMPC Stream Cipher: ----------


void VmpcInitKeyRound(unsigned char *data, unsigned char len, unsigned char firstInit , VmpcContext *vc)
/*Data: key or initialization vector
  Len=1,2,3,...,64: key/initialization vector length (in bytes)
  Src=0: first initialization of the key (the P table and the s variable will be restored to their initial values first)
  Src=1: re-initialization of the key, e.g. with the initialization vector*/
{
	unsigned int i;
	unsigned char k;
	unsigned char tmp;

	if (firstInit != 0)
	{
		for(i = 0 ; i < 256 ; i++)
			vc->P[i] = i;
		vc->s = 0;
	}

	vc ->n = 0;
	k = 0;

	for (i = 0; i < 768; i++)
	{
		vc->s = vc->P[ (vc->s + vc->P[vc->n] + data[k]) & 0xFF];

		tmp = vc->P[vc->n];  
		vc->P[vc->n] = vc->P[vc->s];
		vc->P[vc->s] = tmp;

		k++;  
		if (k == len) k = 0;
		vc->n++;
	}
}


void VmpcInitKey(unsigned char *key, unsigned char keyLen, unsigned char *iv, unsigned char ivLen , VmpcContext *vc)   //KeyLen, VecLen = 1,2,3,...,64
{
	VmpcInitKeyRound(key, keyLen, 1 , vc);
	VmpcInitKeyRound(iv , ivLen , 0 , vc);
	VmpcInitKeyRound(key, keyLen, 0 , vc);
}


void VmpcInitKeyBASIC(unsigned char *key, unsigned char keyLen, unsigned char *iv, unsigned char ivLen , VmpcContext *vc)   //KeyLen, VecLen = 1,2,3,...,64
{
	VmpcInitKeyRound(key, keyLen, 1 , vc);
	VmpcInitKeyRound(iv , ivLen , 0 , vc);
}


void VmpcEncrypt(unsigned char *data, unsigned int len , VmpcContext *vc)
{
	unsigned int i;
	unsigned char tmp;

	for (i = 0; i < len; i++)
	{
		vc->s = vc->P[ (vc->s + vc->P[vc->n]) & 0xFF ];

		data[i] ^= vc->P[(vc->P[vc->P[ vc->s ]] + 1) & 0xFF];

		tmp = vc->P[vc->n];  
		vc->P[vc->n] = vc->P[vc->s];  
		vc->P[vc->s] = tmp;

		vc->n++;
	}
}


//---------- VMPC-MAC Authenticated Encryption Scheme: ----------


void VmpcInitMAC(VmpcContext *vc)
{
	vc->m1 = 0;
	vc->m2 = 0;
	vc->m3 = 0;
	vc->m4 = 0;
	vc->mn = 0;
	memset(vc->MAC, 0, sizeof(((VmpcContext *)0)->MAC));
}



void VmpcEncryptMAC(unsigned char *data, unsigned int len , VmpcContext *vc)
{
	unsigned int i;
	unsigned char tmp;
	for (i = 0; i < len; i++)
	{
		vc->s = vc->P[ (vc->s + vc->P[vc->n]) & 0xFF ];

		data[i] ^= vc->P[(vc->P[vc->P[ vc->s ]] + 1) & 0xFF];

		vc->m4 = vc->P[(vc->m4 + vc->m3) & 0xFF];
		vc->m3 = vc->P[(vc->m3 + vc->m2) & 0xFF];
		vc->m2 = vc->P[(vc->m2 + vc->m1) & 0xFF];
		vc->m1 = vc->P[(vc->m1 + vc->s + data[i]) & 0xFF];

		vc->MAC[vc->mn]     ^= vc->m1;
		vc->MAC[vc->mn + 1] ^= vc->m2;
		vc->MAC[vc->mn + 2] ^= vc->m3;
		vc->MAC[vc->mn + 3] ^= vc->m4;

		tmp = vc->P[vc->n];  
		vc->P[vc->n] = vc->P[vc->s];  
		vc->P[vc->s] = tmp;

		vc->mn = (vc->mn + 4) & 31;
		vc->n++;
	}
}



void VmpcDecryptMAC(unsigned char *data, unsigned int len , VmpcContext *vc)
{
	unsigned int i;
	unsigned char tmp;
	for (i = 0; i < len; i++)
	{
		vc->s = vc->P[ (vc->s + vc->P[vc->n]) & 0xFF ];

		vc->m4 = vc->P[(vc->m4 + vc->m3) & 0xFF];
		vc->m3 = vc->P[(vc->m3 + vc->m2) & 0xFF];
		vc->m2 = vc->P[(vc->m2 + vc->m1) & 0xFF];
		vc->m1 = vc->P[(vc->m1 + vc->s + data[i]) & 0xFF];

		vc->MAC[vc->mn]     ^= vc->m1;
		vc->MAC[vc->mn + 1] ^= vc->m2;
		vc->MAC[vc->mn + 2] ^= vc->m3;
		vc->MAC[vc->mn + 3] ^= vc->m4;

		data[i] ^= vc->P[(vc->P[vc->P[ vc->s ]] + 1) & 0xFF];

		tmp = vc->P[vc->n];  
		vc->P[vc->n] = vc->P[vc->s];  
		vc->P[vc->s] = tmp;

		vc->mn = (vc->mn + 4) & 31;
		vc->n++;
	}
}



void VmpcOutputMAC(VmpcContext *vc)
{
	unsigned int i;
	unsigned char tmp;
	for (i = 1; i <= 24; i++)
	{
		vc->s = vc->P[ (vc->s + vc->P[vc->n]) & 0xFF ];

		vc->m4 = vc->P[(vc->m4 + vc->m3 + i) & 0xFF];
		vc->m3 = vc->P[(vc->m3 + vc->m2 + i) & 0xFF];
		vc->m2 = vc->P[(vc->m2 + vc->m1 + i) & 0xFF];
		vc->m1 = vc->P[(vc->m1 + vc->s  + i) & 0xFF];

		vc->MAC[vc->mn]     ^= vc->m1;
		vc->MAC[vc->mn + 1] ^= vc->m2;
		vc->MAC[vc->mn + 2] ^= vc->m3;
		vc->MAC[vc->mn + 3] ^= vc->m4;

		tmp = vc->P[vc->n];  
		vc->P[vc->n] = vc->P[vc->s];  
		vc->P[vc->s] = tmp;

		vc->mn = (vc->mn + 4) & 31;
		vc->n++;
	}
	VmpcInitKeyRound(vc->MAC, 32, 0 , vc);
	memset(vc->MAC, 0, 20);
	VmpcEncrypt(vc->MAC, 20 , vc);
}



void VmpcEraseKey(VmpcContext *vc)
{
	memset(vc ->P, 0, sizeof(((VmpcContext *)0)->P));
	memset(vc ->MAC, 0, sizeof(((VmpcContext *)0)->MAC));
	vc ->s = 0;
	vc ->n = 0;
	vc ->m1 = 0;
	vc ->m2 = 0;
	vc ->m3 = 0;
	vc ->m4 = 0;
	vc ->mn = 0;
}



