/*
    WinHash
    -------

    A C++ Hashing wrapper around MS Cryptography API: Next Generation (CNG)

    This little project simplifies the usage of CNG hashing functions by hiding all the special API usage management from the user.

    It allows to retrieve with a single function call both the resulting hash value as raw data, and as a string.

    It also provides an easy way to recursively calculate the Hash of a Hash string value in a loop for cryptographic purposes when we want to apply a hashing function multiple times.

    Supported Hashing Algorithms: MD2, MD4, MD5, SHA1, SHA256, SHA384, SHA512

    Disclaimer
    ----------
    I wrote this for fun to use in other private projects. Use at your own risk.

    Author
    ------
    Kyriakos Economou (@kyREcon) / www.anti-reversing.com

    MIT License
    -----------
    Copyright (c) [2019] [Kyriakos Economou]

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/


#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <new>
#include <assert.h>

#include "WinHash.h"

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


LPCWSTR WinHash::pwzHashingAlgos[MAX_HASHING_ALG_IDS] = { L"MD2", L"MD4", L"MD5", L"SHA1", L"SHA256", L"SHA384", L"SHA512" };

//--------------------------------------------------------------------------------


static BOOL HashData(_In_ LPCWSTR& pcwzHashingAlgo, _In_ PBYTE& pbData, _In_ ULONG& DataSize, _Out_ PBYTE& pbHashHexRaw, _Out_ ULONG& cbHashHexRaw)
{

    BOOL bOK = FALSE;
    ULONG cbResult = 0;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;


    cbHashHexRaw = 0;
    pbHashHexRaw = NULL;

    NTSTATUS s = BCryptOpenAlgorithmProvider(&hAlgorithm, pcwzHashingAlgo, NULL, 0);

    if (NT_SUCCESS(s))
    {

        ULONG CryptObjLen = 0;
        s = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&CryptObjLen, sizeof(CryptObjLen), &cbResult, 0);

        if (NT_SUCCESS(s))
        {

            PBYTE pbHashObject = new (std::nothrow)UCHAR[CryptObjLen];
            assert(pbHashObject);

            if (NULL != pbHashObject)
            {

                SecureZeroMemory(pbHashObject, CryptObjLen);

                s = BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, CryptObjLen, NULL, 0, 0);

                if (NT_SUCCESS(s))
                {

                    s = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHashHexRaw, sizeof(cbHashHexRaw), &cbResult, 0);

                    if (NT_SUCCESS(s))
                    {

                        //allocate memory to store the hash in raw hex format
                        pbHashHexRaw = new (std::nothrow)BYTE[cbHashHexRaw];

                        if (NULL != pbHashHexRaw)
                        {

                            SecureZeroMemory(pbHashHexRaw, cbHashHexRaw);
                            s = BCryptHashData(hHash, pbData, (ULONG)DataSize, 0);

                            if (NT_SUCCESS(s))
                            {

                                s = BCryptFinishHash(hHash, pbHashHexRaw, cbHashHexRaw, 0);
                                bOK = NT_SUCCESS(s);

                            }


                            if (FALSE == bOK)
                            {
                                cbHashHexRaw = 0;

                                delete[] pbHashHexRaw;
                                pbHashHexRaw = NULL;
                            }

                        }

                    }

                    BCryptDestroyHash(hHash);
                }

                delete[] pbHashObject;
            }

        }

        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }


    return bOK;
}

//--------------------------------------------------------------------------------


BOOL WinHash::InitHashInfoStruct(_In_ HashingAlg AlgId, _In_ PHASH_INFO pHashInfo)
{

    assert(pHashInfo);

    if (pHashInfo)
    {
        return pHashInfo->Init(AlgId);
    }

    return FALSE;
}

//------------------------------------------------------------------------------------

BOOL WinHash::InitReHashInfoStruct(_In_ HashingAlg AlgId, _In_ PHASH_INFO pHashInfo)
{

    assert(pHashInfo);
    assert(pHashInfo->cbSizeOfStructure == sizeof(HASH_INFO));

    if (pHashInfo && pHashInfo->cbSizeOfStructure == sizeof(HASH_INFO))
    {
        pHashInfo->AlgId = AlgId;
        return TRUE;
    }

    return FALSE;

}

//------------------------------------------------------------------------------

BOOL WinHash::GetHash(_In_ PHASH_INFO pHashInfo, _In_ PBYTE pbData, _In_ ULONG DataSize)
{

    BOOL bOK = FALSE;

    assert(pHashInfo);

    if (NULL != pHashInfo)
    {

        assert(pbData);

        if (NULL != pbData)
        {

            assert(DataSize);

            if (DataSize)
            {

                assert(pHashInfo->cbSizeOfStructure == sizeof(HASH_INFO));

                if (pHashInfo->cbSizeOfStructure == sizeof(HASH_INFO))
                {

                    pHashInfo->InitHashingInfo();

                    assert(pHashInfo->AlgId < HashingAlgorithms::MaxHashId);

                    if (pHashInfo->AlgId < HashingAlgorithms::MaxHashId)
                    {

                        ULONG cbHashHexRawLength = 0;
                        PBYTE pbHashDataRaw = NULL;

                        bOK = HashData(pwzHashingAlgos[pHashInfo->AlgId], pbData, DataSize, pbHashDataRaw, cbHashHexRawLength);

                        if (bOK)
                        {

                            assert(pbHashDataRaw);
                            assert(cbHashHexRawLength);

                            ULONG cbResult = cbHashHexRawLength;
                            pHashInfo->pbHashDataRaw = pbHashDataRaw;
                            pHashInfo->cbHashDataRaw = cbHashHexRawLength;

                            // CALL WITH A NULL POINTER TO GET THE SIZE REQUIRED
                            bOK = CryptBinaryToStringA(pbHashDataRaw, cbHashHexRawLength, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, NULL, &cbResult);

                            if (bOK)
                            {

                                // ALLOCATE MEMORY TO STORE THE HASH IN STRING FORMAT.
                                // RETURNED SIZE INCLUDES THE REQUIRED NULL TERMINATION.
                                LPSTR pszHashDataString = new (std::nothrow)CHAR[cbResult];

                                if (NULL != pszHashDataString)
                                {

                                    // DO THE CONVERSION
                                    SecureZeroMemory(pszHashDataString, cbResult);
                                    bOK = CryptBinaryToStringA(pbHashDataRaw, cbHashHexRawLength, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, pszHashDataString, &cbResult);

                                    if (bOK)
                                    {
                                        pHashInfo->pszHashDataString = pszHashDataString;
                                        pHashInfo->cchStringHashLength = cbResult;
                                    }

                                }

                            }


                            if (FALSE == bOK)
                            {
                                pHashInfo->ResetHashingInfo();
                            }

                        }

                    }

                }

            }

        }

    }


    return bOK;
}

//-------------------------------------------------------------------------------

BOOL WinHash::ReHash(_In_ PHASH_INFO pHashInfo, _In_ ULONG HashingIterations)
{

    BOOL bOK = FALSE;
    PCHAR pszHashStringTmp = NULL;

    HASH_INFO HashInfoTmp;
    ULONG cchStringHashLength = 0;
    HashingAlg AlgId = pHashInfo->AlgId;

    assert(pHashInfo);
    assert(HashingIterations);
    assert(pHashInfo->cbSizeOfStructure == sizeof(HASH_INFO));

    if (pHashInfo && HashingIterations && pHashInfo->cbSizeOfStructure == sizeof(HASH_INFO))
    {

        if (InitHashInfoStruct(pHashInfo->AlgId, &HashInfoTmp))
        {

            if (GetHash(&HashInfoTmp, (PBYTE)pHashInfo->pszHashDataString, (ULONG)pHashInfo->cchStringHashLength))
            {

                cchStringHashLength = HashInfoTmp.cchStringHashLength;
                pszHashStringTmp = new (std::nothrow)CHAR[cchStringHashLength + 1];

                bOK = NULL != pszHashStringTmp;

                if (bOK)
                {

                    SecureZeroMemory(pszHashStringTmp, cchStringHashLength + 1);
                    memcpy(pszHashStringTmp, HashInfoTmp.pszHashDataString, cchStringHashLength);

                    for (ULONG i = 0; ++i < HashingIterations;)
                    {

                        DeleteHash(&HashInfoTmp);

                        bOK = InitHashInfoStruct(AlgId, &HashInfoTmp);

                        if (bOK)
                        {

                            bOK = GetHash(&HashInfoTmp, (PBYTE)pszHashStringTmp, cchStringHashLength);

                            if (bOK)
                            {
                                memcpy(pszHashStringTmp, HashInfoTmp.pszHashDataString, cchStringHashLength);
                            }

                        }

                    }

                }

            }

        }


        DeleteHash(pHashInfo);

        if (bOK)
        {
            InitHashInfoStruct(AlgId, pHashInfo);
            pHashInfo->pszHashDataString = HashInfoTmp.pszHashDataString;
            pHashInfo->cchStringHashLength = HashInfoTmp.cchStringHashLength;
            pHashInfo->pbHashDataRaw = HashInfoTmp.pbHashDataRaw;
            pHashInfo->cbHashDataRaw = HashInfoTmp.cbHashDataRaw;
        }
        else
        {
            DeleteHash(&HashInfoTmp);
        }


        if (pszHashStringTmp)
        {
            SecureZeroMemory(pszHashStringTmp, cchStringHashLength);
            delete[] pszHashStringTmp;
        }

    }

    return bOK;
}

//-------------------------------------------------------------------------------

VOID WinHash::DeleteHash(_In_ PHASH_INFO pHashInfo)
{

    assert(pHashInfo);
    assert(pHashInfo->cbSizeOfStructure == sizeof(HASH_INFO));

    if (pHashInfo && pHashInfo->cbSizeOfStructure == sizeof(HASH_INFO))
    {
        pHashInfo->Reset();
    }

}

//-------------------------------------------------------------------------------