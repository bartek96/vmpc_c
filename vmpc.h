#ifndef _VMPC_H_
#define _VMPC_H_

typedef struct
{
	//----------- VMPC Stream Cipher variables: -----------
	unsigned char P[256];
	unsigned char s, n;
	//----------- VMPC-MAC Authenticated Encryption Scheme variables: -----------
	unsigned char MAC[32];
	unsigned char m1, m2, m3, m4, mn;
	// bonus
	unsigned char ivInited;
}VmpcContext;


void VmpcInitKeyRound(unsigned char *data, unsigned char len, unsigned char firstInit , VmpcContext *vc);
void VmpcInitKey(unsigned char *key, unsigned char keyLen, unsigned char *iv, unsigned char ivLen , VmpcContext *vc);
void VmpcInitKeyBASIC(unsigned char *key, unsigned char keyLen, unsigned char *iv, unsigned char ivLen , VmpcContext *vc);
void VmpcEncrypt(unsigned char *data, unsigned int len , VmpcContext *vc);
void VmpcInitMAC(VmpcContext *vc);
void VmpcEncryptMAC(unsigned char *data, unsigned int len , VmpcContext *vc);
void VmpcDecryptMAC(unsigned char *data, unsigned int len , VmpcContext *vc);
void VmpcOutputMAC(VmpcContext *vc);
void VmpcEraseKey(VmpcContext *vc);



#endif //_VMPC_H_
