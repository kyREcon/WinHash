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



#ifndef WIN_HASH_H_
#define WIN_HASH_H_


#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <assert.h>


class WinHash
{

public:
    static CONST ULONG MAX_HASHING_ALG_IDS = 7;
    static LPCWSTR pwzHashingAlgos[MAX_HASHING_ALG_IDS];

public:

    struct _HashingAlgorithms
    {

       typedef enum : ULONG
        {
            MD2,
            MD4,
            MD5,
            SHA1,
            SHA256,
            SHA384,
            SHA512,

            // keep always last
            MaxHashId
        }alg;

    };

    typedef _HashingAlgorithms HashingAlgorithms;
    typedef _HashingAlgorithms::alg HashingAlg;


public:
    struct _HASH_INFO
    {

        _HASH_INFO()
        {
            AlgId = HashingAlg::MaxHashId;

            pbHashDataRaw = NULL;
            cbHashDataRaw = 0;

            pszHashDataString = NULL;
            cchStringHashLength = 0;

            cbSizeOfStructure = 0;
        }


        BOOL Init(HashingAlg Id)
        {
            BOOL bOK = FALSE;

            assert(Id < HashingAlg::MaxHashId);
            bOK = Id < HashingAlg::MaxHashId;

            if (bOK)
            {
                Reset();
                AlgId = Id;
                cbSizeOfStructure = sizeof(*this);
            }

            return bOK;
        }


        VOID Reset()
        {
            ResetHashingInfo();

            cbSizeOfStructure = 0;
            AlgId = HashingAlg::MaxHashId;
        }


        VOID ResetHashingInfo()
        {
            if (pbHashDataRaw)
            {
                SecureZeroMemory(pbHashDataRaw, cbHashDataRaw);
                delete[] pbHashDataRaw;

                cbHashDataRaw = 0;
                pbHashDataRaw = NULL;
            }

            if (pszHashDataString)
            {
                SecureZeroMemory(pszHashDataString, cchStringHashLength);
                delete[] pszHashDataString;

                cchStringHashLength = 0;
                pszHashDataString = NULL;
            }
        }


        VOID InitHashingInfo()
        {
            cbHashDataRaw = 0;
            cchStringHashLength = 0;

            pbHashDataRaw = NULL;
            pszHashDataString = NULL;
        }


        HashingAlg AlgId;
        PBYTE pbHashDataRaw;
        ULONG cbHashDataRaw;
        LPSTR pszHashDataString;
        ULONG cchStringHashLength;
        ULONG cbSizeOfStructure;
    };


    typedef _HASH_INFO HASH_INFO;
    typedef _HASH_INFO* PHASH_INFO;


public:
    WinHash() {}
    ~WinHash(){}


public:

    /*
        Call this function to intialize a HASH_INFO structure before calling GetHash.

        1. HashingAlgorithm AlgId: A hash algo id from the HashingAlgorithm enumeration data structure.

        2. Pointer to a HashInfo structure to initialize.
        This will be used as an argument later with GetHash.

        Remarks
        -------
        If pHashInfo is NULL, the function fails and returns FALSE, otherwise it initializes 
        the structure and returns TRUE;
   */
    static BOOL InitHashInfoStruct(_In_ HashingAlg AlgId, _In_ PHASH_INFO pHashInfo);




    /*
        Get hash of data in raw hex and string format.

        1. PHASH_INFO HashInfo: Pointer to a HASH_INFO structure.

        2. PBYTE pData: Pointer to the data to calculate desired hash value.

        This must be a valid pointer to the data that we will be hashing.
        If it's NULL, the function returns FALSE.
        If it points to a valid address other than the data that we need to hash,
        the result is unpredictable.

        3. SIZE_T DataSize: Size of data to calculate the hash for.
        This can either be the entire buffer pointed by pData, or a part of
        it, but it should not exceed the the bounds of the data buffer.
        If it does, then the result is unpredictable.

        If DataSize value is bigger than ULONG_MAX (0xFFFFFFFF), the function returns FALSE;

        If the function succeeds, you must call DeleteHash once you have finished processing
        the returned data in order to free the memory that was allocated to store the hashes.

        If you want to perform subsequent hashing over the resulting string hash pHashDataString, do not
        call DeleteHash at this stage. See: InitReHashInfoStruct, ReHash

        Remarks
        --------
        If the functions succeeds, then it returns TRUE and valid pointers to pbHashDataRaw and pHashDataString 
        members, of the HASH_INFO structure (first parameter).

        HashInfo.RawHashDataSize: will be set to the size of the raw calculated hash format.

        HashInfo.StringHashDataLength: will be set to the length of the string format of the hash.
        The terminating null character is not included. Keep this in mind if you need to safely
        copy this string to another buffer.

        In order to avoid accidental string concatenations use (HashInfo.StringHashDataLength + 1) as the 
        size  of your buffer, and initialize your buffer to 0s before copying over the string hash.
    */
    static BOOL GetHash(_In_ PHASH_INFO HashInfo, _In_ PBYTE pbData, _In_ ULONG DataSize);




    /*
        Re-Initializes a HASH_INFO structure that was previously used with GetHash function,
        with the same or different HashingAlgoId for a subsequent call to ReHash function.

        1. HashingAlgorithm AlgId: Hashing Alogorithm id to use for Re-Hashing.
        2. PHASH_INFO pHashInfo: Pointer to a HASH_INFO structure.

        If the function succeeds returns TRUE, otherwise returns FALSE.

        If the function returns FALSE, and you no longer need to process the previously calculated hash,
        call DeleteHash to free any memory allocated with a previous call to GetHash
   */
    static BOOL InitReHashInfoStruct(_In_ HashingAlg AlgId, _In_ PHASH_INFO pHashInfo);




    /*
        This function applies the same or a different hashing algorithm over the previous
        calculated string hash format (pHashDataString) for specified number of iterations.

        1. PHASH_INFO HashInfo: Pointer to a HASH_INFO structure.
        2. Number of times to hash pHashInfo->pHashDataString.

        If the function succeeds returns TRUE and the HASH_INFO structure referenced by pHashInfo
        will contain the resulting hash calculation.

        You must call DeleteHash once you have finished processing the returned data in order
        to free the memory that was allocated to store the hashes.

        If the function fails, returns FALSE. In this case there is no need to call DeleteHash, as
        any memory buffer that was previously allocated is freed by this function.
    */
    static BOOL ReHash(_In_ PHASH_INFO pHashInfo, _In_ ULONG HashingIterations);



    /*
        Deletes hashes and frees memory allocated that stores the hashes during a previous call to GetHash.
        If HashInfo.pbHashDataRaw and/or HashInfo.pHashDataString are NULL the rest of the structure will be 
        sanitized.
    */
    static VOID DeleteHash(_In_ PHASH_INFO pHashInfo);

};

#endif