
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <string>

#include "WinHash.h"

int main()
{

    printf("\nWrite something: ");
    std::string test = "";
    std::getline(std::cin, test);
    printf("\n\n\n");


    WinHash winhash;
    WinHash::HASH_INFO HashInfo;


    /*Print MD5 string hash*/
    if (winhash.WinHashInitHashInfoStruct(WinHash::HashingAlgorithms::MD5, &HashInfo))
    {

        if (winhash.WinHashGetHash(&HashInfo, (PBYTE)test.c_str(), (ULONG)strlen(test.c_str())))
        {

            printf("MD5: %s\n\n\n", HashInfo.pszHashDataString);


            /*Re-Hash MD5 string with SHA256*/
            //if this fails, we must call WinHashDeleteHash to free memory allocated from WinHashGetHash
            if (winhash.WinHashInitReHashInfoStruct(WinHash::HashingAlgorithms::SHA256, &HashInfo))
            {
                if (winhash.WinHashReHash(&HashInfo, 2)) //if WinHashReHash fails we don't need to call WinHashDeleteHash
                {
                    printf("SHA256(MD5): %s\n\n\n", HashInfo.pszHashDataString);
                    winhash.WinHashDeleteHash(&HashInfo);
                }
            }
            else
            {
                winhash.WinHashDeleteHash(&HashInfo);
            }
        }

        /*Print all supported hashes for user input string.*/
        for (ULONG i = 0; i < WinHash::HashingAlgorithms::MaxHashId; i++)
        {
            if (winhash.WinHashInitHashInfoStruct((WinHash::HashingAlg)i, &HashInfo))
            {
                if (winhash.WinHashGetHash(&HashInfo, (PBYTE)test.c_str(), (ULONG)strlen(test.c_str())))
                {
                    printf("%ws: %s\n", WinHash::pwzHashingAlgos[i], HashInfo.pszHashDataString);
                    winhash.WinHashDeleteHash(&HashInfo);
                }
            }
        }

    }

    (VOID)getchar();
    return 0;

}

