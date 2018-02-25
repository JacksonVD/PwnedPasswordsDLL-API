/*
* DLLMain.cpp is the code for the custom password filter that is to be utilised by
* LSA to check the validity of password requests.
* The DLL sends an API request to the PwnedPasswords API, and subsequently selects
* whether or not the password is valid, based on whether or not it exists as a
* previously breached password.
* The code utilises k-Anonymity by querying the API with the first five characters of the
* prospective password hash, then checks to see if the remaining suffix exists in the
* return from the API. This way, any external system can only possibly receive the first
* five characters in an SHA1 hash.
*
* Content Author:  JacksonVD
* Contact: jacksonvd.com
* Date Written:    25-02-18
*/

#include "stdafx.h"

#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <SubAuth.h>

#include <curl.h>
#include <sha.h>
#include <filters.h>
#include <hex.h>

#pragma comment(lib, "Ws2_32.lib")


// Visual Studio DLL Boilerplate

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

/*
* Quick and dirty function callback function for writing with cURL - append to string rather than using fwrite
*/

size_t cURL_Callback(void *contents, size_t size, size_t nmemb, std::string *s)
{
	((std::string*)s)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

/*
* This function will be called by LSA - the function imports calling account information, including the prospective password
* and exports a Boolean value (either TRUE or FALSE). This return value is then used by LSA in determining whether or not
* the password has passed the in-place password policy.
*/

extern "C" __declspec(dllexport) BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING accountName,
	PUNICODE_STRING fullName,
	PUNICODE_STRING password,
	BOOLEAN operation) {
	// Declare and initialise the returnValue Boolean expresion as true by default - allow the password change by default
	BOOLEAN returnValue = TRUE;

	// Declare the String to hold the SHA1 hash
	std::string hash = "";

	// Long and convoluted way of getting password String from PUNICODE_STRING
	std::wstring wStrBuffer(password->Buffer, password->Length / sizeof(WCHAR));
	const wchar_t *wideChar = wStrBuffer.c_str();
	std::wstring wStr(wideChar);
	std::string str(wStr.begin(), wStr.end());

	// Generate an SHA1 hash of the requesting password string through Crypto++
	CryptoPP::SHA1 sha1;
	CryptoPP::StringSource(str, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));

	// Declare and initialise cURL
	CURL *curl = curl_easy_init();

	// Initialise URL String as being the API address, as well as the first 5 letters of the password hash
	std::string URL("https://api.pwnedpasswords.com/range/" + hash.substr(0, 5));

	// Declare String for the API response
	std::string APIResponse;

	int http_status_code; // Declare the http_status_code variable
	if (curl) { // If cURL has been initialised..
		CURLcode res;
		curl_easy_setopt(curl, CURLOPT_URL, URL.c_str()); // Set the URL for CURL to the URL string
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "API Scraper/1.0"); // Troy requires a user-agent when calling API
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cURL_Callback); // Set the write function for cURL to cURL_Callback
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &APIResponse); // Set up cURL to write the API response to the APIResponse String

		res = curl_easy_perform(curl); // Perform the request on the above URL with the above user-agent

		if (res == CURLE_OK) { // If no errors occurred..

			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status_code); // Retrieve the HTTP status code

			if (http_status_code == 404) { // If the status code is 404 (i.e. password doesn't exist in pwned passwords data) THEN..
				returnValue = TRUE; // Set returnValue Boolean to true (password is fine to use as it doesn't exist as a previously breached password)
			}
			else // If there was a response from the API
			{
				std::size_t found = APIResponse.find(hash.substr(5)); // Attempt to find the hash suffix

				if (found != std::string::npos) // The find function will return string::npos if the requested string was no found
				{
					returnValue = FALSE; // If the hash exists, then set the return value to false (i.e. don't allow the password to be changed)
				}
			}
		}
		curl_easy_cleanup(curl); // Clean-up for cURL
	}

	return returnValue; // Return the Boolean value to LSA

}
