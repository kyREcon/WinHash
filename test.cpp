
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



    WinHash::HASH_INFO HashInfo;


    /*Print MD5 string hash*/
    if (WinHash::WinHashInitHashInfoStruct(WinHash::HashingAlgorithms::MD5, &HashInfo))
    {

        if (WinHash::WinHashGetHash(&HashInfo, (PBYTE)test.c_str(), (ULONG)strlen(test.c_str())))
        {

            printf("MD5: %s\n\n\n", HashInfo.pszHashDataString);


            /*Re-Hash MD5 string with SHA256*/
            //if this fails, we must call WinHashDeleteHash to free memory allocated from WinHashGetHash
            if (WinHash::WinHashInitReHashInfoStruct(WinHash::HashingAlgorithms::SHA256, &HashInfo))
            {

                //if WinHashReHash fails we don't need to call WinHashDeleteHash
                if (WinHash::WinHashReHash(&HashInfo, 1))
                {
                    printf("SHA256(MD5): %s\n\n\n", HashInfo.pszHashDataString);
                    WinHash::WinHashDeleteHash(&HashInfo);
                }
            }
            else
            {
                WinHash::WinHashDeleteHash(&HashInfo);
            }
        }

        /*Print all supported hashes for user input string.*/
        for (ULONG i = 0; i < WinHash::HashingAlgorithms::MaxHashId; i++)
        {
            if (WinHash::WinHashInitHashInfoStruct((WinHash::HashingAlg)i, &HashInfo))
            {
                if (WinHash::WinHashGetHash(&HashInfo, (PBYTE)test.c_str(), (ULONG)strlen(test.c_str())))
                {
                    printf("%ws: %s\n", WinHash::pwzHashingAlgos[i], HashInfo.pszHashDataString);
                    WinHash::WinHashDeleteHash(&HashInfo);
                }
            }
        }

    }

    (VOID)getchar();
    return 0;
}