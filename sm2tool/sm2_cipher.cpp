#include "sm2_cipher.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "e_os.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/sm2.h>
#include "sm2_lcl.h"


RAND_METHOD fake_rand;
const RAND_METHOD *old_rand;

static const char rnd_seed[] =
	"string to make the random number generator think it has entropy";
static const char *rnd_number = NULL;

static int fbytes(unsigned char *buf, int num)
{
	int ret = 0;
	BIGNUM *bn = NULL;

	if (!BN_hex2bn(&bn, rnd_number)) {
		goto end;
	}
	if (BN_num_bytes(bn) > num) {
		goto end;
	}
	memset(buf, 0, num);
	if (!BN_bn2bin(bn, buf + num - BN_num_bytes(bn))) {
		goto end;
	}
	ret = 1;
end:
	BN_free(bn);
	return ret;
}

static int change_rand(const char *hex)
{
	if (!(old_rand = RAND_get_rand_method())) {
		return 0;
	}

	fake_rand.seed		= old_rand->seed;
	fake_rand.cleanup	= old_rand->cleanup;
	fake_rand.add		= old_rand->add;
	fake_rand.status	= old_rand->status;
	fake_rand.bytes		= fbytes;
	fake_rand.pseudorand	= old_rand->bytes;

	if (!RAND_set_rand_method(&fake_rand)) {
		return 0;
	}

	rnd_number = hex;
	return 1;
}

static int restore_rand(void)
{
	rnd_number = NULL;
	if (!RAND_set_rand_method(old_rand))
		return 0;
	else	return 1;
}

static EC_GROUP *new_ec_group(int is_prime_field,
	const char *p_hex, const char *a_hex, const char *b_hex,
	const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex)
{
	int ok = 0;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	EC_POINT *G = NULL;
	point_conversion_form_t form = SM2_DEFAULT_POINT_CONVERSION_FORM;
	int flag = 0;

	if (!(ctx = BN_CTX_new())) {
		goto err;
	}

	if (!BN_hex2bn(&p, p_hex) ||
	    !BN_hex2bn(&a, a_hex) ||
	    !BN_hex2bn(&b, b_hex) ||
	    !BN_hex2bn(&x, x_hex) ||
	    !BN_hex2bn(&y, y_hex) ||
	    !BN_hex2bn(&n, n_hex) ||
	    !BN_hex2bn(&h, h_hex)) {
		goto err;
	}

	if (is_prime_field) {
		if (!(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))) {
			goto err;
		}
		if (!(G = EC_POINT_new(group))) {
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GFp(group, G, x, y, ctx)) {
			goto err;
		}
	} else {
		if (!(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))) {
			goto err;
		}
		if (!(G = EC_POINT_new(group))) {
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GF2m(group, G, x, y, ctx)) {
			goto err;
		}
	}

	if (!EC_GROUP_set_generator(group, G, n, h)) {
		goto err;
	}

	EC_GROUP_set_asn1_flag(group, flag);
	EC_GROUP_set_point_conversion_form(group, form);

	ok = 1;
err:
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(x);
	BN_free(y);
	BN_free(n);
	BN_free(h);
	EC_POINT_free(G);
	if (!ok && group) {
		//ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		group = NULL;
	}

	return group;
}

static EC_KEY *new_ec_key(const EC_GROUP *group,
	const char *sk, const char *xP, const char *yP,
	const char *id, const EVP_MD *id_md)
{
	int ok = 0;
	EC_KEY *ec_key = NULL;
	BIGNUM *d = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	OPENSSL_assert(group);
	OPENSSL_assert(xP);
	OPENSSL_assert(yP);

	if (!(ec_key = EC_KEY_new())) {
		goto end;
	}
	if (!EC_KEY_set_group(ec_key, group)) {
		goto end;
	}

	if (sk) {
		if (!BN_hex2bn(&d, sk)) {
			goto end;
		}
		if (!EC_KEY_set_private_key(ec_key, d)) {
			goto end;
		}
	}

	if (xP && yP) {
		if (!BN_hex2bn(&x, xP)) {
			goto end;
		}
		if (!BN_hex2bn(&y, yP)) {
			goto end;
		}
		if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
			goto end;
		}
	}

	/*
	if (id) {
		if (!SM2_set_id(ec_key, id, id_md)) {
			goto end;
		}
	}
	*/

	ok = 1;
end:
	if (d) BN_free(d);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (!ok && ec_key) {
		//ERR_print_errors_fp(stderr);
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	return ec_key;
}

void dump_bin(char * title, unsigned char *data, int dataLen)
{
	int v1 = 16, v2 = 4, i = 0;
	if(!title || !data || dataLen <= 0)
		return;
	printf("begin dump: %s \n",title);
	for(i = 0; i < dataLen; i++)
	{
		printf("%02x",data[i]);
		if(v1 - 1 == i % v1)
		{
			printf("\n");
		}else if(v2 -1 == i % v2)
		{
			printf(" ");
		}
	}
	if(v1 - 1 != (dataLen - 1) % v1)
	{
			printf("\n");
	}
	printf("end dump:%s\n",title);
}
int sign_ecc(
		const char *dH,
		const char *xH,
		const char *yH,
		const char *id,
		const char *msg,
		const char *kH,
		char *rH,
		char *sH)
{
	int iRet = 0;
	EC_GROUP *group = NULL;
	const EVP_MD *md = EVP_sm3();
	unsigned char dgst[EVP_MAX_MD_SIZE] = {0}, Z[EVP_MAX_MD_SIZE] = {0};
	size_t dgstlen = 0;
	EC_KEY *ec_key = NULL;
	ECDSA_SIG *sm2sig = NULL;
	const BIGNUM *sig_r;
	const BIGNUM *sig_s;
	unsigned char sig[256] = {0};
	const unsigned char *p = NULL;
	char * str = NULL;
	unsigned int sigLen;

	change_rand(kH);
	if(!(group = new_ec_group(1,
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
		"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
		"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
		"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
		"1"))){
		goto ret;
	}
	if (!(ec_key = new_ec_key(group, dH, xH, yH, id, md))) {
		goto ret;
	}
	dgstlen = sizeof(Z);
	if (!SM2_compute_id_digest(md, id, strlen(id), Z, &dgstlen, ec_key)) {
		goto ret;
	}
	dump_bin("Z",Z,dgstlen);
	dgstlen = sizeof(dgst);
	if (!SM2_compute_message_digest(md, md,
		(const unsigned char *)msg, strlen(msg), id, strlen(id),
		dgst, &dgstlen, ec_key)) {
		goto ret;
	}
	dump_bin("e",dgst,dgstlen);

	sigLen = sizeof(sig);
	if (!SM2_sign(0, dgst, dgstlen, sig, &sigLen, ec_key)) {
		goto ret;
	}
	p = sig;
	if (!(sm2sig = d2i_ECDSA_SIG(NULL, &p, sigLen))) {
		goto ret;
	}
	ECDSA_SIG_get0(sm2sig, &sig_r, &sig_s);
	str = BN_bn2hex(sig_r);
	strcpy(rH,str);
	printf("r:%s\n",rH);
	OPENSSL_free(str);
	str = BN_bn2hex(sig_s);
	strcpy(sH,str);
	printf("s:%s\n",sH);
	OPENSSL_free(str);
	iRet = 1;
ret:
	restore_rand();
	if (ec_key) 
		EC_KEY_free(ec_key);
	if (sm2sig) 
		ECDSA_SIG_free(sm2sig);
	if (group)
		EC_GROUP_free(group);
	return iRet;
}
int verify_ecc(
		const char *xH,
		const char *yH,
		const char *id,
		const char *msg,
		char *rH,
		char *sH)
{
	int iRet = 0;
	EC_GROUP *group = NULL;
	const EVP_MD *md = EVP_sm3();
	unsigned char dgst[EVP_MAX_MD_SIZE] = {0}, Z[EVP_MAX_MD_SIZE] = {0};
	size_t dgstlen = 0;
	EC_KEY *ec_key = NULL;
	ECDSA_SIG *sm2sig = ECDSA_SIG_new();
	BIGNUM *sign_r = NULL;
	BIGNUM *sign_s = NULL;
	unsigned char *sig = NULL;
	unsigned int sigLen;

	if(!(group = new_ec_group(1,
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
		"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
		"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
		"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
		"1"))){
		goto ret;
	}
	if (!(ec_key = new_ec_key(group, NULL, xH, yH, id, md))) {
		goto ret;
	}
	dgstlen = sizeof(Z);
	if (!SM2_compute_id_digest(md, id, strlen(id), Z, &dgstlen, ec_key)) {
		goto ret;
	}
	dump_bin("Z",Z,dgstlen);
	dgstlen = sizeof(dgst);
	if (!SM2_compute_message_digest(md, md,
		(const unsigned char *)msg, strlen(msg), id, strlen(id),
		dgst, &dgstlen, ec_key)) {
		goto ret;
	}
	dump_bin("e",dgst,dgstlen);

	if (!BN_hex2bn(&sign_r, rH) || !BN_hex2bn(&sign_s, sH)) {
		goto ret;
	}
	ECDSA_SIG_set0(sm2sig,sign_r,sign_s);
	sigLen = i2d_ECDSA_SIG(sm2sig,&sig);
	if (1 != SM2_verify(0, dgst, dgstlen, sig, sigLen, ec_key)) {
		goto ret;
	}
	iRet = 1;
ret:
	if(sig)
		OPENSSL_clear_free(sig,sigLen);
	if (sm2sig) 
		ECDSA_SIG_free(sm2sig);
	if (ec_key) 
		EC_KEY_free(ec_key);
	if (group)
		EC_GROUP_free(group);
	return iRet;
}

int enc_ecc(
		const char *xH,
		const char *yH,
		const char *kH,
		const char *plain,
		int plainLen,
		char *cipher,
		int *pCipherLen
		)
{
	int iRet = 0;
	EC_GROUP *group = NULL;
	EC_KEY *ec_key = NULL;
	const EVP_MD *md = EVP_sm3();
	SM2CiphertextValue *cv = NULL;
	char *tbuf = NULL;
	long tlen;
	unsigned char mbuf[128] = {0};
	unsigned char cbuf[sizeof(mbuf) + 256] = {0};
	size_t mlen, clen;
	unsigned char *p;

	change_rand(kH);
	if(!(group = new_ec_group(1,
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
		"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
		"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
		"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
		"1"))){
		goto ret;
	}
	if (!(ec_key = new_ec_key(group, NULL, xH, yH, NULL, NULL))) {
		goto ret;
	}
	
	if (!(cv = SM2_do_encrypt(md, (unsigned char *)plain, plainLen, ec_key))) {
		goto ret;
	}

	p = (unsigned char *)cipher;
	if ((clen = i2o_SM2CiphertextValue(group, cv, &p)) <= 0) {
		goto ret;
	}
	tbuf = OPENSSL_buf2hexstr((unsigned char *)cipher,clen);
	strcpy(cipher,tbuf);
	*pCipherLen = strlen(tbuf);
	iRet = 1;
ret:
	restore_rand();
	EC_KEY_free(ec_key);
	SM2CiphertextValue_free(cv);
	OPENSSL_free(tbuf);
	EC_GROUP_free(group);
	return iRet;
	
}
int dec_ecc(
	const char *dH,
	const char *xH,
	const char *yH,
	const char *cipher,
	int cipherLen,
	char *plain,
	int *pPlainLen
	)
{
	int iRet = 0;
	EC_GROUP *group = NULL;
	EC_KEY *ec_key = NULL;
	const EVP_MD *md = EVP_sm3();
	SM2CiphertextValue *cv = NULL;
	long clen = 0;
	unsigned char *p = NULL, *p2 = NULL;

	if(!(group = new_ec_group(1,
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
		"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
		"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
		"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
		"1"))){
		goto ret;
	}
	if (!(ec_key = new_ec_key(group, dH, xH, yH, NULL, NULL))) {
		goto ret;
	}
	p = p2 = OPENSSL_hexstr2buf(cipher,&clen);
	if(!(cv = o2i_SM2CiphertextValue(group,md,&cv,(const unsigned char **)&p2,clen)) )
	{
		goto ret;
	}
	if (!(SM2_do_decrypt(md, cv,(unsigned char *)plain, (size_t *)pPlainLen, ec_key))) {
		goto ret;
	}
	iRet = 1;
ret:
	OPENSSL_free(p);
	SM2CiphertextValue_free(cv);
	EC_KEY_free(ec_key);
	EC_GROUP_clear_free(group);
	return iRet;

}