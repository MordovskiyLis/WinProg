// CentOS.cpp : Defines the entry point for the DLL application.
//
#include "stdafx.h"
#include "sha512.h"
#include "Modules.h"    // to stdfx

//#include <inttypes.h>

BOOL APIENTRY DllMain(HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	return TRUE;
}

extern "C" __declspec(dllexport) void GetInfo(MODULEINFO * info)
{
	info->dwFlags = MODULE_SALT_WITH_HASH | MODULE_HASH_BASE64;	// MODULE_HASH_BASE64
	info->szAbout = "Type of hashes: CentOS 8 v1.x \n$6$salt$hash \n(c)Vii";
	info->szHashType = "CentOS 8 v1.0.x";
}

extern "C" __declspec(dllexport) int GetHash(HASHINFO * info)
{
	/*
	typedef struct {
		unsigned char* pBuf; // Address of buffer to store generated hash
		char* szPassword;    // Password
		int nPasswordLen;    // Length of password
		char* szSalt;        // !Salt, HMAC-key or any other additional key for hashing
		int nSaltLen;        // Length of salt or key = 16
		char* szName;        // User name	! не используется при создании Хеша в CentOS !
		int nNameLen;        // Length of user name
		DWORD dwFlags;       // Combination of flags defining different modes of hashing
		DWORD dwReserved[8]; // Reserved for future usage
	} HASHINFO;
	*/

	static int sourceLen = 90 + info->nSaltLen;
	//unsigned char sizeBufer[sourceLen];	// hash=86 || $6$s$p=106
	//106	const char* infoMain = "$6$GsNKoAhykdO0B4Sb$e9fgGX8V.9yrpLGtaB55zuTo3CDUgI89tHS9xTmsjGaGVg6J2.7lQu3u3cHSal3oCVUq4t8VHJTC6qMB/hToY0";
	//100	const char* infoMain = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
	
	SHA512_CTX context;
	memset(&context.ctPassw, '\0', 256);
	memset(&context.ctSalt, '\0', 16);
	memcpy(&context.ctPassw, info->szPassword, info->nPasswordLen);
	memcpy(&context.ctSalt, info->szSalt, info->nSaltLen);
	context.ctPasswLen = info->nPasswordLen;
	context.ctSaltLen = info->nSaltLen;

	//SHA512Init(&context, (unsigned char*)info->szPassword, (unsigned char*)info->szSalt, info->nPasswordLen, info->nSaltLen);

	/*
	if (info->nPasswordLen <= sourceLen)
	{
		ZeroMemory(sizeBufer, sizeof(sizeBufer));
		memcpy(sizeBufer, info->szPassword, info->nPasswordLen);
		SHA512.update(&context, sizeBufer, sourceLen);
	}
	else
		SHA512.update(&context, (unsigned char *)info->szPassword, info->nPasswordLen);
	
	SHA512::final(info->pBuf, &context);

	memcpy(info->pBuf, context->state, 16);*/

	/*	Функция не из класса _SHA512_
	*/
	//sourceLen = 90 + info->nSaltLen;
	//info->pBuf = (unsigned char*)sha512_crypt(&context);	// , info->szPassword, info->szSalt);
	memcpy(info->pBuf, (const char*)sha512_crypt(&context), sourceLen);
	//memcpy(info->pBuf, infoMain, 100);
	//memcpy(&info->pBuf[(size_t)3], info->szSalt, 16);

	return sourceLen;	// или 86
}

extern "C" __declspec(dllexport) int GetSalt(SALTINFO* info) {
	/*
	typedef struct {
		char* pSalt;         // Address of buffer to store salt
		char* szHash;        // Hash (like "$1$12345678$tRy4cXc3kmcfRZVj4iFXr/")
		int nHashLen;        // Hash length = 86
		DWORD dwReserved[5]; // Reserved for future usage} SALTINFO;
	} SALTINFO;
	*/
	
	memcpy(info->pSalt, &info->szHash[(size_t)3], 16);	// &info->szHash[(size_t)3]

	//memcpy(info->pSalt, info->szHash, 106);
	return 16;
}
