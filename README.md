# WinEventSubsystem
Program to retrieve event data from Windows Event Subsystem

Curl Dependencies in Visual Studio
1. Configuration->C/C++->Addtional Include Directories (C:\Users\SSingh\Code\buildtools\Debug_x64\boost\include\boost-1_65;C:\local\curl-7.20.0\curl-7.20.0\include\curl;%(AdditionalIncludeDirectories)

2. C\C++->Preprocessor - > CURL_STATICLIB;%(PreprocessorDefinitions)

3. Linker-> Input-> Additional Dependencies
libcurl.lib
ws2_32.lib
wldap32.lib

Elastic Index Utility commands
1. Delete index -  curl -XDELETE 'localhost:9200/event?pretty'
2. Create index - curl -XPUT 'localhost:9200/event?pretty&pretty'
3. Add sample Data - 
curl -XPUT 'http://localhost:9200/event/doc/4346?pretty&pretty' -H 'Content-Type: application/json' -d'
{"event_id":4346,"event_count":6393,"Source":"Microsoft-Windows-NlaSvc/OperationalMicrosoft-Windows-NlaSvc","username":"AUTHORITYSYSTEM","Date/Time":"Wed, 2017-Dec-20 13:36:43 UTC+10:30","System":"SSingh-HP","Strings":"LDAP authentication on interface {1F552EB7-4540-4038-8604-95C47BA6CCB3} (192.168.56.1) failed with error 0x51"}'

Starting ElasticSearch
Start in cmd 
C:\Program Files\Elastic\Elasticsearch\6.1.1\bin\ElasticSearch.exe

Run Kibana
cd C:\local\kibana-6.1.0-windows-x86_64\kibana-6.1.0-windows-x86_64\bin\Kibana.bat

Open Web UI
http://localhost:5601/app/kibana#/home?_g=()

1. In Management console - Create Index Pattern define Index as event* and do not forget to select @timestamp field as timefilter field.
2. In Discover - Select event* and select time period as "Last 5 years" depending on the windows events created.
3. You should see a page that looks like file attached in ElasticKibanaUI.jpeg
