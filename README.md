# WinEventSubsystem
Program to retrieve event data from Windows Event Subsystem

Curl Dependencies in Visual Studio
1. Configuration->C/C++->Addtional Include Directories (C:\Users\SSingh\Code\buildtools\Debug_x64\boost\include\boost-1_65;C:\local\curl-7.20.0\curl-7.20.0\include\curl;%(AdditionalIncludeDirectories)

2. C\C++->Preprocessor - > CURL_STATICLIB;%(PreprocessorDefinitions)

3. Linker-> Input-> Additional Dependencies
libcurl.lib
ws2_32.lib
wldap32.lib
