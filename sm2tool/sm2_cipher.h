#ifndef		SM2_CIPHER_H
#define		SM2_CIPHER_H

#ifdef		__cplusplus
extern "C"	{
#endif

	int sign_ecc(
		const char *dH,
		const char *xH,
		const char *yH,
		const char *id,
		const char *msg,
		const char *kH,
		char *rH,
		char *sH);
	int verify_ecc(
		const char *xH,
		const char *yH,
		const char *id,
		const char *msg,
		char *rH,
		char *sH);
	int enc_ecc(
		const char *xH,
		const char *yH,
		const char *kH,
		const char *plain,
		int plainLen,
		char *cipher,
		int *pCipherLen
		);
	int dec_ecc(
		const char *dH,
		const char *xH,
		const char *yH,
		const char *cipher,
		int cipherLen,
		char *plain,
		int *pPlainLen
		);

#ifdef		__cplusplus
			}
#endif


#endif