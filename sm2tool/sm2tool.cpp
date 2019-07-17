#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm2_cipher.h"
#ifdef WIN32
#include <Windows.h>
#include <time.h>

#endif

//#define printf(a) NULL
/*
	this example is based on gmssl(http://gmssl.org/) using GB data¡£
*/

unsigned int gOperationNum = 10000;
void test_s_sm2(void)
{
	int iRet = 0;
	char dH[] = {"3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"};//sm2 private key
	char xH[] = {"09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"};//sm2 public key x coordinate value
	char yH[] = {"CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"};//sm2 public key y coordinate value
	char id[] = {"1234567812345678"};//sm2 user ID
	char msg[] = {"message digest"};//msg 
	char kH[] = {"59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"};//sm2 random number in sign algorithm
	char rH[64+1] = {0};//"F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3"//sm2 sign result  component r
	char sH[64+1] = {0};//"B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA"//sm2 sign result  component s

	//while(1)
	{
		
		iRet = sign_ecc(dH,xH,yH,id,msg,kH,rH,sH);
		if(iRet)
		{
			printf("sign success\n");
		}
		else
		{
			printf("sign failed\n");
		}
		iRet = verify_ecc(xH,yH,id,msg,rH,sH);
		if(iRet)
		{
			printf("verify success\n");
		}
		else
		{
			printf("verify failed\n");
		}
		//system("pause");
	}
}

void test_c_sm2(void)
{
	int iRet = 0;
	char dH[] = {"3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"};//sm2 private key
	char xH[] = {"09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"};//sm2 public key x coordinate value
	char yH[] = {"CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"};//sm2 public key y coordinate value
	char plain[] = {"encryption standard"};//msg 
	char kH[] = {"59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"};//sm2 random number in sign algorithm
	char cipher[1024] = {0}, plain2[1024] = {0};//"F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3"//sm2 sign result  component r
	int plainLen = 0, cipherLen = 0, plain2Len = 0;
	
	plainLen = strlen(plain);
	cipherLen = sizeof(cipher);
	plain2Len = strlen(plain2);

	//while(1)
	{
		
		iRet = enc_ecc(xH,yH,kH,plain,plainLen,cipher,&cipherLen);
		if(iRet)
		{
			printf("enc_ecc success\n");
		}
		else
		{
			printf("enc_ecc failed\n");
		}

		iRet = dec_ecc(dH,xH,yH,cipher,cipherLen,plain2,&plain2Len);
		if(iRet && (plain2Len == plainLen) && (0 == memcmp(plain,plain2,plain2Len)) )
		{
			printf("dec_ecc success\n");
		}
		else
		{
			printf("dec_ecc failed\n");
		}
		//system("pause");
	}
}

int get_tick()
{
	int iRet = 0;
#define		MaxTimeVal		(0x7fffffff)

#ifdef WIN32
	iRet = GetTickCount() % MaxTimeVal;
#else
	struct timeval tm = {0};
	gettimeofday(&tm,NULL);
	iRet = (tm.tv_sec*1000 + tm.tv_usec/1000) % MaxTimeVal;
#endif
	return iRet;
}

void speed_sign_sm2(void)
{
	int iRet = 0,  i = 0, st = 0, et = 0;
	char dH[] = {"3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"};//sm2 private key
	char xH[] = {"09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"};//sm2 public key x coordinate value
	char yH[] = {"CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"};//sm2 public key y coordinate value
	char id[] = {"1234567812345678"};//sm2 user ID
	char msg[] = {"message digest"};//msg 
	char kH[] = {"59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"};//sm2 random number in sign algorithm
	char rH[64+1] = {0};//"F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3"//sm2 sign result  component r
	char sH[64+1] = {0};//"B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA"//sm2 sign result  component s

	st = get_tick();
	while(i++ < gOperationNum)
	{
		
		iRet = sign_ecc(dH,xH,yH,id,msg,kH,rH,sH);
		if(!iRet)
		{
			printf("sign failed\n");
			goto ret;
		}

	}
	et  = get_tick();
	iRet = verify_ecc(xH,yH,id,msg,rH,sH);
	if(!iRet)
	{
		printf("verify failed\n");
		goto ret;
	}
	printf("%s speed: %i tps within %i ms\n",__FUNCTION__, gOperationNum*1000/(et - st), et - st);
ret:
	return;

}

void speed_verify_sm2(void)
{
	int iRet = 0, i = 0, st = 0, et = 0;
	char dH[] = {"3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"};//sm2 private key
	char xH[] = {"09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"};//sm2 public key x coordinate value
	char yH[] = {"CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"};//sm2 public key y coordinate value
	char id[] = {"1234567812345678"};//sm2 user ID
	char msg[] = {"message digest"};//msg 
	char kH[] = {"59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"};//sm2 random number in sign algorithm
	char rH[64+1] = {0};//"F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3"//sm2 sign result  component r
	char sH[64+1] = {0};//"B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA"//sm2 sign result  component s

	iRet = sign_ecc(dH,xH,yH,id,msg,kH,rH,sH);
	if(iRet)
	{
		printf("sign success\n");
	}
	else
	{
		printf("sign failed\n");
	}
	st = get_tick();
	while(i++ < gOperationNum)
	{
		iRet = verify_ecc(xH,yH,id,msg,rH,sH);
		if(!iRet)
		{
			printf("verify failed\n");
			goto ret;
		}
	}
	et = get_tick();
	printf("%s speed: %i tps within %i ms\n",__FUNCTION__, gOperationNum*1000/(et - st), et - st);
ret:
	return;

}
int main(int argc, char* argv[])
{
	speed_sign_sm2();
	speed_verify_sm2();
	while(1)
	{
		test_s_sm2();
		test_c_sm2();
	}
	return 0;
}

