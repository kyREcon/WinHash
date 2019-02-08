#include "WinHash.h"

LPCWSTR HashingAlgos[MAX_HASHING_ALGOS] = { L"MD2", L"MD4", L"MD5", L"SHA1", L"SHA256", L"SHA384", L"SHA512" };

//--------------------------------------------------------------------------------

BOOL WinHashInitHashInfoStruct(HashingAlgorithm HashingAlgId, PHASH_INFO pHashInfo)
{
	if (!pHashInfo)
		return FALSE;

	SecureZeroMemory(pHashInfo, sizeof(HASH_INFO));
	pHashInfo->HashingAlgId = HashingAlgId;
	pHashInfo->SizeOfStructure = sizeof(HASH_INFO);
	return TRUE;
}

//------------------------------------------------------------------------------------

BOOL WinHashInitReHashInfoStruct(HashingAlgorithm HashingAlgId, PHASH_INFO pHashInfo)
{
	if (!pHashInfo || pHashInfo->SizeOfStructure != sizeof(HASH_INFO))
		return FALSE;

	pHashInfo->HashingAlgId = HashingAlgId;
	pHashInfo->SizeOfStructure = sizeof(HASH_INFO);
	return TRUE;
}

//------------------------------------------------------------------------------

BOOL WinHashGetHash(PHASH_INFO pHashInfo, PBYTE pData, SIZE_T DataSize)
{
	BOOL bSuccess = FALSE;
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	PUCHAR pbHashObject = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	ULONG CryptObjLen = 0;
	ULONG pcbResult = 0;
	PBYTE HashDataRaw = NULL;
	PCHAR HashDataString = NULL;

	if (!pHashInfo)
		return bSuccess;

	if (DataSize > ULONG_MAX)
		return bSuccess;

	if (pHashInfo->SizeOfStructure != sizeof(HASH_INFO))
		return bSuccess;

	pHashInfo->pHashDataRaw = NULL;
	pHashInfo->pHashDataString = NULL;
	pHashInfo->RawHashSize = 0;
	pHashInfo->StringHashLength = 0;

	if ((ULONG)pHashInfo->HashingAlgId > (ULONG)MaxHashId)
		return bSuccess;

	if (!pData)
		return bSuccess;

	if (STATUS_SUCCESS != BCryptOpenAlgorithmProvider(&hAlgorithm, HashingAlgos[pHashInfo->HashingAlgId], NULL, 0))
		return bSuccess;

	if (STATUS_SUCCESS != BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&CryptObjLen, sizeof(CryptObjLen), &pcbResult, 0))
	{
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return bSuccess;
	}

	pbHashObject = new (std::nothrow)UCHAR[CryptObjLen];

	if (!pbHashObject)
	{
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return bSuccess;
	}

	SecureZeroMemory(pbHashObject, CryptObjLen);

	if (STATUS_SUCCESS != BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, CryptObjLen, NULL, 0, 0))
	{
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		delete[] pbHashObject;
		return bSuccess;
	}

	ULONG HashLength = 0;
	if (STATUS_SUCCESS != BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&HashLength, sizeof(HashLength), &pcbResult, 0))
		goto Cleanup;

	HashDataRaw = new (std::nothrow)UCHAR[HashLength]; //allocate memory to store the hash in raw hex format

	if (HashDataRaw == NULL)
		goto Cleanup;

	SecureZeroMemory(HashDataRaw, HashLength);

	if (STATUS_SUCCESS != BCryptHashData(hHash, pData, (ULONG)DataSize, 0))
		goto Cleanup;

	if (STATUS_SUCCESS != BCryptFinishHash(hHash, HashDataRaw, HashLength, 0))
		goto Cleanup;
	
	pHashInfo->pHashDataRaw = HashDataRaw;
	pHashInfo->RawHashSize = HashLength;

	CryptBinaryToStringA(HashDataRaw, HashLength, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, NULL, &pcbResult); //call with a NULL pointer to get the size required

	HashDataString = new (std::nothrow)CHAR[pcbResult]; //allocate memory to store the hash in string format

	if (HashDataString == NULL)
		goto Cleanup;

	SecureZeroMemory(HashDataString, pcbResult);

	if (CryptBinaryToStringA(HashDataRaw, HashLength, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, HashDataString, &pcbResult)) //do the conversion
	{
		pHashInfo->pHashDataString = HashDataString;
		pHashInfo->StringHashLength = pcbResult;
		bSuccess = TRUE;
	}

Cleanup:

	BCryptDestroyHash(hHash);
	BCryptCloseAlgorithmProvider(hAlgorithm, 0);

	if (pbHashObject)
		delete[] pbHashObject;

	if (!bSuccess)
	{
		if (HashDataRaw)
		{
			pHashInfo->pHashDataRaw = NULL;
			delete[] HashDataRaw;
		}

		if (HashDataString)
		{
			pHashInfo->pHashDataString = NULL;
			delete[] HashDataString;
		}
	}

	return bSuccess;
}

//-------------------------------------------------------------------------------

BOOL WinHashReHash(PHASH_INFO pHashInfo, ULONG HashingIterations)
{
	BOOL bSuccess = FALSE;
	PBYTE HashRawTmp = NULL;
	PCHAR HashStringTmp = NULL;
	HashingAlgorithm HashingAlgId = pHashInfo->HashingAlgId;
	HASH_INFO HashInfoTmp;

	if (!pHashInfo || HashingIterations == 0 || pHashInfo->SizeOfStructure != sizeof(HASH_INFO))
		return bSuccess;

	if (!WinHashInitHashInfoStruct(pHashInfo->HashingAlgId, &HashInfoTmp))
		return bSuccess;


	if (!WinHashGetHash(&HashInfoTmp, (PBYTE)pHashInfo->pHashDataString, pHashInfo->StringHashLength))
		goto Cleanup;

	HashingIterations--;

	SIZE_T StringHashLength = HashInfoTmp.StringHashLength;
	HashStringTmp = new (std::nothrow)CHAR[StringHashLength + 1];

	if (!HashStringTmp)
		goto Cleanup;

	SecureZeroMemory(HashStringTmp, StringHashLength + 1);
	memcpy(HashStringTmp, HashInfoTmp.pHashDataString, StringHashLength);


	for (ULONG i = 0; i < HashingIterations; i++)
	{	
		WinHashDeleteHash(&HashInfoTmp);

		if (!WinHashInitHashInfoStruct(HashingAlgId, &HashInfoTmp))
			goto Cleanup;

		if (!WinHashGetHash(&HashInfoTmp, (PBYTE)HashStringTmp, StringHashLength))
			goto Cleanup;

		memcpy(HashStringTmp, HashInfoTmp.pHashDataString, StringHashLength);
	}

	SIZE_T RawHashSize = HashInfoTmp.RawHashSize;
	HashRawTmp = new (std::nothrow)BYTE[RawHashSize];

	if (!HashRawTmp)
		goto Cleanup;

	memcpy(HashRawTmp, HashInfoTmp.pHashDataRaw, RawHashSize);

	bSuccess = TRUE;

Cleanup:

	WinHashDeleteHash(pHashInfo);
		
	if (bSuccess)
	{
		WinHashInitHashInfoStruct(HashingAlgId, pHashInfo);
		pHashInfo->pHashDataString = HashStringTmp;
		pHashInfo->StringHashLength = StringHashLength;
		pHashInfo->pHashDataRaw = HashRawTmp;
		pHashInfo->RawHashSize = RawHashSize;
	}
	else
	{	
		if (HashRawTmp)
		{
			SecureZeroMemory(HashRawTmp, RawHashSize);
			delete[] HashRawTmp;
		}

		WinHashDeleteHash(&HashInfoTmp);
	}

	return bSuccess;
}

//-------------------------------------------------------------------------------

void WinHashDeleteHash(PHASH_INFO pHashInfo)
{
	if (pHashInfo && pHashInfo->SizeOfStructure == sizeof(HASH_INFO))
	{
		if (pHashInfo->pHashDataRaw)
		{
			SecureZeroMemory(pHashInfo->pHashDataRaw, pHashInfo->RawHashSize);
			delete[] pHashInfo->pHashDataRaw;
		}
		if (pHashInfo->pHashDataString)
		{
			SecureZeroMemory(pHashInfo->pHashDataString, pHashInfo->StringHashLength);
			delete[] pHashInfo->pHashDataString;
		}

		SecureZeroMemory(pHashInfo, sizeof(HASH_INFO));
	}
}