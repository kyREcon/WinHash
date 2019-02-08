#include "WinHash.h"
#include <iostream>
#include <string>

using namespace std;

int main()
{
	cout << "Write something: ";
	string test = "";
	getline(cin, test);
	cout << endl << endl << endl;

	HASH_INFO HashInfo;

	/*Print MD5 string hash */
	if (WinHashInitHashInfoStruct(MD5, &HashInfo))
	{
		if (WinHashGetHash(&HashInfo, (PBYTE)test.c_str(), strlen(test.c_str())))
			cout << "MD5:" << HashInfo.pHashDataString << endl << endl << endl;
		else
			return 1;


		/*Re-Hash MD5 string with SHA256 */
		if (WinHashInitReHashInfoStruct(SHA256, &HashInfo))
		{
			if (WinHashReHash(&HashInfo, 1))
			{
				cout << "SHA256(MD5):" << HashInfo.pHashDataString << endl << endl << endl;
				WinHashDeleteHash(&HashInfo);
			}
		}
		else
		{
			WinHashDeleteHash(&HashInfo);
		}
	}


	/*Print all supported hashes for user input string.*/
	for (ULONG i = 0; i < MaxHashId;  i++)
	{
		if (WinHashInitHashInfoStruct((HashingAlgorithm)i, &HashInfo))
		{
			if (WinHashGetHash(&HashInfo, (PBYTE)test.c_str(), strlen(test.c_str())))
			{
				wcout << HashingAlgos[i] << ":" << HashInfo.pHashDataString << endl;				
				WinHashDeleteHash(&HashInfo);
			}
		}
	}

	cin.get();
	return 0;
}