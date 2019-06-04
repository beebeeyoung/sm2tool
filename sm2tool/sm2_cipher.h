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


#ifdef		__cplusplus
			}
#endif


#endif