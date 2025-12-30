
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
    if (WinHash::InitHashInfoStruct(WinHash::HashingAlgorithms::MD5, &HashInfo))
    {

        if (WinHash::GetHash(&HashInfo, (PBYTE)test.c_str(), (ULONG)strlen(test.c_str())))
        {

            printf("MD5: %s\n\n\n", HashInfo.pszHashDataString);


            /*Re-Hash MD5 string with SHA256*/
            //if this fails, we must call DeleteHash to free memory allocated from GetHash
            if (WinHash::InitReHashInfoStruct(WinHash::HashingAlgorithms::SHA256, &HashInfo))
            {

                //if ReHash fails we don't need to call DeleteHash
                if (WinHash::ReHash(&HashInfo, 1))
                {
                    printf("SHA256(MD5): %s\n\n\n", HashInfo.pszHashDataString);
                    WinHash::DeleteHash(&HashInfo);
                }
            }
            else
            {
                WinHash::DeleteHash(&HashInfo);
            }
        }

        /*Print all supported hashes for user input string.*/
        for (ULONG i = 0; i < WinHash::HashingAlgorithms::MaxHashId; i++)
        {
            if (WinHash::InitHashInfoStruct((WinHash::HashingAlg)i, &HashInfo))
            {
                if (WinHash::GetHash(&HashInfo, (PBYTE)test.c_str(), (ULONG)strlen(test.c_str())))
                {
                    printf("%ws: %s\n", WinHash::pwzHashingAlgos[i], HashInfo.pszHashDataString);
                    WinHash::DeleteHash(&HashInfo);
                }
            }
        }

    }

    (VOID)getchar();
    return 0;
}