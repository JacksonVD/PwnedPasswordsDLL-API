# Introduction

PwnedPasswordsDLL is a DLL that allows password requests through any form of Active Directory integration to be checked against over 500 million previously breached passwords using Troy Hunt's Pwned Passwords API and k-Anonymity.

Check out https://jacksonvd.com/checking-for-breached-passwords-ad-using-k-anonymity/ for more information on the background of the tool.

# Compiling the Code (Visual Studio)

1. Download the PwnedPasswordsDLL-API source from here
2. Download Crypto++ from the following link (https://www.cryptopp.com/#download)
3. Build Crypto++ as a library in x64 mode – the following link is a good resource on compiling it for use in Visual Studio (http://programmingknowledgeblog.blogspot.com.au/2013/04/compiling-and-integrating-crypto-into.html)
4. Include the Crypto++ header directories through Project –> PwnedPasswordsDLL-API Properties –> Configuration Properties –> VC++ Directories. Edit the Include Directories and add the include directory
5. Then, edit the Library Directories and add the Debug directory from the x64\Output directory.
6. Add cryptlib.lib to your Additional Dependencies list under Project –> PwnedPasswordsDLL-API Properties –> Configuration Properties -> Linker –>Input –> Additional Dependencies
7. Build libCurl as a library in x64 mode – this is a great resource from Github that will build libcurl on Windows (https://github.com/blackrosezy/build-libcurl-windows)
8. Include the libCurl header directories through Project –> PwnedPasswordsDLL-API Properties –> Configuration Properties –> VC++ Directories. 
9. Edit the Include Directories and add the include directory
10. Then, edit the Library Directories and add the relevant libCurl library directory.
11. Add libcurl_a.lib to your Additional Dependencies list under Project –> PwnedPasswordsDLL-API Properties –> Configuration Properties –> Linker –>Input –> Additional Dependencies
12. Add  CURL_STATICLIB to your Preprocessor Definitions under  Project –> PwnedPasswordsDLL-API Properties –> Configuration Properties –>  C/C++ -> Preprocessor
13. Change Runtime Library to Multi-threaded Debug (/MTd) under Project –> PwnedPasswordsDLL-API Properties –> Configuration Properties –>  C/C++ –> Code Generation
14. All that’s left now is to Build and then test out the DLL!

# Implementing the DLL

The implementation of the DLL is the easy part - just download or build the DLL, place it in system32 and add a registry key!

Note: These instructions need to be followed on all Domain Controllers in the domain if you wish to implement this for Active Directory, as any of them may end up servicing a password change request.

1. Download or build the DLL
2. The DLL itself needs to be placed in your system root directory (generally C:\Windows\System32).
3. The DLL name needs to be added to the multi-string “Notification Packages” registry subkey under HKLM\System\CurrentControlSet\Control\LSA – note that you only need to add the name of the DLL, not including the file extension.
4. To ensure that the DLL works alongside your Group Policy password filtering settings,  ensure that the Passwords must meet complexity requirements policy setting is enabled through your relevant GPO(s).
5. Reboot the DC(s). Any password change request should now be filtered through the DLL.
