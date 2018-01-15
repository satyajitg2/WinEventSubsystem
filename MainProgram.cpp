#include <windows.h>
#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <winevt.h>
#include <iostream>
#include <locale>
#include <codecvt>
#include <Sddl.h>
#include <curl.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace pt = boost::property_tree;
static int eventCount = 0;

//CRITICAL_SECTION to protect curl use
// Global variable
CRITICAL_SECTION CriticalSection;


#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "Advapi32.lib")

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);
DWORD PrintEventSystemData(EVT_HANDLE hEvent);
bool eventFormatMessageTask(EVT_HANDLE publisher, EVT_HANDLE evtHandle, pt::ptree& event_ptree);
bool eventFormatMessage(EVT_HANDLE publisher, EVT_HANDLE evtHandle, pt::ptree& event_ptree);
bool detailEventData(EVT_HANDLE evtHandle, const PEVT_VARIANT pValues, pt::ptree& event_ptree);
bool simpleCurlTest();
bool sendCurlRequest(pt::ptree event_ptree);
std::string wcharStringToString(wchar_t* buffer, PEVT_VARIANT& pRenderedValues, EVT_SYSTEM_PROPERTY_ID id);
bool findUserFromSid(PSID sid, std::string& str);

struct windowsEventStruct {
	WCHAR hostName[100];
	int criticality;
	DWORD sCounter;
	TCHAR submissionTime[26];
	DWORD shortEventId;
	DWORD eventLogLevel;
	UINT64 eventKeyWord;
	char sourceName[256];
	WCHAR eventLogSourceName[256];
	TCHAR userName[256];
	TCHAR sidType[100];
	TCHAR eventLogType[60];
	TCHAR eventCategoryString[256];
	char dateTime[100];
	char eventDetailString[500];
	DWORD eventLogCounter;
	wchar_t	bookMark[200];
};

std::string wcharStringToString(wchar_t* buffer, PEVT_VARIANT& pRenderedValues, EVT_SYSTEM_PROPERTY_ID id)
{
	char charBuf[500];
	swprintf(buffer, 500, L"%s", pRenderedValues[id].StringVal);
	size_t convertedChars = 0;
	wcstombs_s(&convertedChars, charBuf, wcslen(buffer) + 1, buffer, _TRUNCATE);
	std::string str(charBuf);
	return str;
}

std::string wcharIntToString(wchar_t* buffer, PEVT_VARIANT& pRenderedValues, EVT_SYSTEM_PROPERTY_ID id)
{
	char charBuf[500];
	swprintf(buffer, 500, L"%I64u", pRenderedValues[id].UInt64Val);
	size_t convertedChars = 0;
	wcstombs_s(&convertedChars, charBuf, wcslen(buffer) + 1, buffer, _TRUNCATE);
	std::string str(charBuf);
	return str;
}

bool sendCurlRequest(pt::ptree event_ptree)
{
	CURL *curl;
	CURLcode res;
	// Request ownership of the critical section.
	EnterCriticalSection(&CriticalSection);
	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	if (curl) {
		std::stringstream ss;
		pt::write_json(ss, event_ptree);
		std::string s = ss.str();

		/*First set the URL this is about to receive our POST. This URL can
		just as well be a https:// URL if that is what should receive the data.*/
		std::string url_init = "http://localhost:9200/event/doc/";
		std::string urlEventCount = url_init.append(std::to_string(eventCount++));
		std::string url = urlEventCount.append("?pretty&pretty");

		struct curl_slist *headers = NULL;
		headers = curl_slist_append(headers, "Accept: application/json");
		headers = curl_slist_append(headers, "Content-Type: application/json");
		headers = curl_slist_append(headers, "charsets: utf-8");

		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

		/* HTTP PUT please */
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, s.c_str());

		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */
		if (res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		/* always cleanup */
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();
	// Release ownership of the critical section.
	LeaveCriticalSection(&CriticalSection);
	return 0;
}


void main(void)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hSubscription = NULL;
	LPWSTR pwsPath[] = { L"Application", L"Setup", L"Security", L"System" };
	LPWSTR pwsQuery = L"*";

	// Initialize the critical section one time only.
	if (!InitializeCriticalSectionAndSpinCount(&CriticalSection, 0x00000400))
		return;

	// Subscribe to events beginning with the oldest event in the channel. The subscription
	// will return all current events in the channel and any future events that are raised
	// while the application is active.
	for (unsigned int i = 0; i < sizeof(pwsPath) / sizeof(pwsPath[0]); i++)
	{
		hSubscription = EvtSubscribe(NULL, NULL, pwsPath[i], pwsQuery, NULL, NULL,
			(EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, EvtSubscribeStartAtOldestRecord);
		if (NULL == hSubscription)
		{
			status = GetLastError();

			if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
				wprintf(L"Channel %s was not found.\n", pwsPath);
			else if (ERROR_EVT_INVALID_QUERY == status)
				// You can call EvtGetExtendedStatus to get information as to why the query is not valid.
				wprintf(L"The query \"%s\" is not valid.\n", pwsQuery);
			else
				wprintf(L"EvtSubscribe failed with %lu.\n", status);

			goto cleanup;
		}

	}
	wprintf(L"Hit any key to quit\n\n");
	while (!_kbhit())
		Sleep(10);
	
cleanup:
	// Release resources used by the critical section object.
	DeleteCriticalSection(&CriticalSection);
	if (hSubscription)
		EvtClose(hSubscription);


}

// The callback that receives the events that match the query criteria. 
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent)
{
	UNREFERENCED_PARAMETER(pContext);

	DWORD status = ERROR_SUCCESS;

	switch (action)
	{
		// You should only get the EvtSubscribeActionError action if your subscription flags 
		// includes EvtSubscribeStrict and the channel contains missing event records.
	case EvtSubscribeActionError:
		if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
		{
			wprintf(L"The subscription callback was notified that event records are missing.\n");
			// Handle if this is an issue for your application.
		}
		else
		{
			wprintf(L"The subscription callback received the following Win32 error: %lu\n", (DWORD)hEvent);
		}
		break;

	case EvtSubscribeActionDeliver:
		if (ERROR_SUCCESS != (status = PrintEventSystemData(hEvent)))
		{
			goto cleanup;
		}
		break;

	default:
		wprintf(L"SubscriptionCallback: Unknown action.\n");
	}

cleanup:

	if (ERROR_SUCCESS != status)
	{
		// End subscription - Use some kind of IPC mechanism to signal
		// your application to close the subscription handle.
	}

	return status; // The service ignores the returned status.
}

DWORD PrintEventSystemData(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hContext = NULL;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
	WCHAR wsGuid[50];
	LPSTR pwsSid = NULL;
	ULONGLONG ullTimeStamp = 0;
	ULONGLONG ullNanoseconds = 0;
	SYSTEMTIME st;
	FILETIME ft;
	std::string str;
	pt::ptree event_ptree;
	wchar_t buffer[500];


	// Identify the components of the event that you want to render. In this case,
	// render the system section of the event.
	hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
	if (NULL == hContext)
	{
		wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
		goto cleanup;
	}

	// When you render the user data or system section of the event, you must specify
	// the EvtRenderEventValues flag. The function returns an array of variant values 
	// for each element in the user data or system section of the event. For user data
	// or event data, the values are returned in the same order as the elements are 
	// defined in the event. For system data, the values are returned in the order defined
	// in the EVT_SYSTEM_PROPERTY_ID enumeration.
	if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
	{
		if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
		{
			dwBufferSize = dwBufferUsed;
			pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
			if (pRenderedValues)
			{
				EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
			}
			else
			{
				wprintf(L"malloc failed\n");
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			wprintf(L"EvtRender failed with %d\n", GetLastError());
			goto cleanup;
		}
	}
	DWORD EventID = pRenderedValues[EvtSystemEventID].UInt16Val;
	if (EvtVarTypeNull != pRenderedValues[EvtSystemQualifiers].Type)
	{
		EventID = MAKELONG(pRenderedValues[EvtSystemEventID].UInt16Val, pRenderedValues[EvtSystemQualifiers].UInt16Val);
	}
	wprintf(L"EventID: %lu\n", EventID);
	swprintf(buffer, 500, L"%lu", EventID);
	char buf[500];
	size_t convertedChars = 0;
	wcstombs_s(&convertedChars, buf, wcslen(buffer) + 1, buffer, _TRUNCATE);
	event_ptree.put("EventID", buf);

	// Print the values from the System section of the element.
	wprintf(L"Provider Name: %s\n", pRenderedValues[EvtSystemProviderName].StringVal);
	swprintf(buffer, 100, L"%s", pRenderedValues[EvtSystemProviderName].StringVal);
	event_ptree.put("Source", wcharStringToString(buffer, pRenderedValues, EvtSystemProviderName).c_str());

	if (NULL != pRenderedValues[EvtSystemProviderGuid].GuidVal)
	{
		StringFromGUID2(*(pRenderedValues[EvtSystemProviderGuid].GuidVal), wsGuid, sizeof(wsGuid) / sizeof(WCHAR));
		wprintf(L"Provider Guid: %s\n", wsGuid);
	}
	else
	{
		wprintf(L"Provider Guid: NULL\n");
	}


	wprintf(L"Version: %u\n", (EvtVarTypeNull == pRenderedValues[EvtSystemVersion].Type) ? 0 : pRenderedValues[EvtSystemVersion].ByteVal);
	wprintf(L"Level: %u\n", (EvtVarTypeNull == pRenderedValues[EvtSystemLevel].Type) ? 0 : pRenderedValues[EvtSystemLevel].ByteVal);
	wprintf(L"Task: %hu\n", (EvtVarTypeNull == pRenderedValues[EvtSystemTask].Type) ? 0 : pRenderedValues[EvtSystemTask].UInt16Val);
	wprintf(L"Opcode: %u\n", (EvtVarTypeNull == pRenderedValues[EvtSystemOpcode].Type) ? 0 : pRenderedValues[EvtSystemOpcode].ByteVal);
	wprintf(L"Keywords: 0x%I64x\n", pRenderedValues[EvtSystemKeywords].UInt64Val);

	ullTimeStamp = pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
	ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
	ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);

	FileTimeToSystemTime(&ft, &st);
	ullNanoseconds = (ullTimeStamp % 10000000) * 100; // Display nanoseconds instead of milliseconds for higher resolution
	wprintf(L"TimeCreated SystemTime: %02d/%02d/%02d %02d:%02d:%02d.%I64u)\n",
		st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond, ullNanoseconds);

	swprintf(buffer, 500, L"TimeCreated SystemTime: %02d/%02d/%02d %02d:%02d:%02d.%I64u)",
		st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond, ullNanoseconds);

	char dateBuf[500];
	convertedChars = 0;
	wcstombs_s(&convertedChars, dateBuf, wcslen(buffer) + 1, buffer, _TRUNCATE);
	event_ptree.put("Date/Time", dateBuf);


	wprintf(L"EventRecordID: %I64u\n", pRenderedValues[EvtSystemEventRecordId].UInt64Val);
	event_ptree.put("EventID", wcharIntToString(buffer, pRenderedValues, EvtSystemEventRecordId).c_str());

	event_ptree.put("System", wcharStringToString(buffer, pRenderedValues, EvtSystemComputer));
	event_ptree.put("Channel", wcharStringToString(buffer, pRenderedValues, EvtSystemChannel));

	if (EvtVarTypeNull != pRenderedValues[EvtSystemActivityID].Type)
	{
		StringFromGUID2(*(pRenderedValues[EvtSystemActivityID].GuidVal), wsGuid, sizeof(wsGuid) / sizeof(WCHAR));
		wprintf(L"Correlation ActivityID: %s\n", wsGuid);
	}

	if (EvtVarTypeNull != pRenderedValues[EvtSystemRelatedActivityID].Type)
	{
		StringFromGUID2(*(pRenderedValues[EvtSystemRelatedActivityID].GuidVal), wsGuid, sizeof(wsGuid) / sizeof(WCHAR));
		wprintf(L"Correlation RelatedActivityID: %s\n", wsGuid);
	}

	wprintf(L"Execution ProcessID: %lu\n", pRenderedValues[EvtSystemProcessID].UInt32Val);
	wprintf(L"Execution ThreadID: %lu\n", pRenderedValues[EvtSystemThreadID].UInt32Val);
	wprintf(L"Channel: %s\n", (EvtVarTypeNull == pRenderedValues[EvtSystemChannel].Type) ? L"" : pRenderedValues[EvtSystemChannel].StringVal);
	wprintf(L"Computer: %s\n", pRenderedValues[EvtSystemComputer].StringVal);


	if (EvtVarTypeNull != pRenderedValues[EvtSystemUserID].Type)
	{
		char ch[5000];
		char DefChar = ' ';
		if (ConvertSidToStringSid(pRenderedValues[EvtSystemUserID].SidVal, &pwsSid))
		{
			//PROBLEM STRING *********************************
			wprintf(L"Security UserID: %s\n", pwsSid);
			wprintf(L"Security UserID: %s\n", pRenderedValues[EvtSystemUserID].SidVal);
			char charBuf[100];
			swprintf(buffer, 100, L"%s", pwsSid);

			size_t convertedChars = 0;
			//WideCharToMultiByte(CP_ACP, 0, pwsSid, -1, ch, 5000, &DefChar, NULL);
			//_snprintf_s(&DefChar, sizeof(&DefChar), _TRUNCATE, "%s", pwsSid);
			std::string uName;
			findUserFromSid(pRenderedValues[EvtSystemUserID].SidVal, uName);
			event_ptree.put("UserID", uName.c_str());
			LocalFree(pwsSid);
		}
	}

	detailEventData(hEvent, pRenderedValues, event_ptree);
cleanup:

	if (hContext)
		EvtClose(hContext);

	if (pRenderedValues)
		free(pRenderedValues);

	return status;
}

bool findUserFromSid(PSID sid, std::string& str)
{
	char userName[256];
	try {
		if (IsValidSid(sid)) {
			char szName[257] = "";
			char szDomain[257] = "";
			DWORD cbName = 256;
			DWORD cbDomain = 256;
			SID_NAME_USE snu;
			DWORD dwRC = LookupAccountSid(NULL, sid, szName, &cbName, szDomain, &cbDomain, &snu);
			if (strlen(szName)) {
				if (strlen(szDomain)) {
					_snprintf_s(userName, 256, _TRUNCATE, "%s\\%s", szDomain, szName);
				}
				else {
					_snprintf_s(userName, 256, _TRUNCATE, "%s", szName);
				}
			}
		}
		else {
			return false;
		}
	}
	catch (...) {

		LPSTR psSid = NULL;

		if (ConvertSidToStringSid(sid, &psSid)) {
			strncpy_s(userName, 256, psSid, _TRUNCATE);
			LocalFree(psSid);
		}
	}
	str.assign(userName);
	return true;
}

bool detailEventData(EVT_HANDLE evtHandle, const PEVT_VARIANT pValues, pt::ptree& event_ptree)
{
	pt::ptree eventPtree;
	EVT_HANDLE publisher = NULL;
	publisher = EvtOpenPublisherMetadata(NULL, pValues[EvtSystemProviderName].StringVal, NULL, NULL, 0);
	if (publisher == NULL)
	{
		DWORD dwRes = GetLastError();
		std::cout << dwRes << std::endl;
		return false;
	}
	if (EvtVarTypeNull != pValues[EvtSystemTask].Type && pValues[EvtSystemTask].UInt16Val) {
		if (eventFormatMessageTask(publisher, evtHandle, event_ptree) == false){
			EvtClose(publisher);
			return false;
		}
	}

	if (eventFormatMessage(publisher, evtHandle, event_ptree) == false){
		EvtClose(publisher);
		return false;
	}

	pt::ptree curlPtree = event_ptree;
	sendCurlRequest(curlPtree);
	// We no londer need the publisher.
	EvtClose(publisher);
	return true;
}

bool eventFormatMessage(EVT_HANDLE publisher, EVT_HANDLE evtHandle, pt::ptree& event_ptree)
{
	DWORD dwBuffSize = 0;
	DWORD dwBuffUsed = 0;
	char ch[5000];
	char DefChar = ' ';

	BOOL bRet = EvtFormatMessage(publisher, evtHandle, NULL, 0, NULL, EvtFormatMessageEvent, dwBuffSize, NULL, &dwBuffUsed);
	//only supplying system values isn't enough to populate the whole event
	if (!bRet) {
		DWORD dwRes = GetLastError();
		if (dwRes == ERROR_INSUFFICIENT_BUFFER) {
			// Allocate the buffer size needed to for the XML event.
			dwBuffSize = dwBuffUsed;
			WCHAR *pBuff = new WCHAR[dwBuffSize];
			if (pBuff == NULL) {
				return false;
			}
			bRet = EvtFormatMessage(publisher, evtHandle, NULL, 0, NULL, EvtFormatMessageEvent, dwBuffSize, pBuff, &dwBuffUsed);
			//only supplying system values isn't enough to populate the whole event
			//PROBLEM conversion**************************

			WideCharToMultiByte(CP_ACP, 0, pBuff, -1, ch, 5000, &DefChar, NULL);

			std::string str(ch);
			event_ptree.put("String", str.c_str());

			delete[] pBuff;
		}
		else {
			std::cout << "EvtFormatMessageEvent Error: " << dwRes << std::endl;
			return false;
		}
		if (!bRet)
		{
			dwRes = GetLastError();
			std::cout << "EvtFormatMessageEvent Error 2: " << dwRes << std::endl;
			if (dwRes == ERROR_EVT_UNRESOLVED_VALUE_INSERT) {
				std::cout << "EvtFormatMessageEvent Error 2: Unresolved value insert, ignoring" << std::endl;
			}
			else if (dwRes == ERROR_INSUFFICIENT_BUFFER && dwBuffSize >= dwBuffUsed) {
				//WTF?  The buffer is the right size, but there isn't enough buffer space... mmmkay
				// ignore the error and proceed as normal, cleanup everything else
				std::cout << "EvtFormatMessageEvent Error 2: IGNORED, buffer looks ok" << std::endl;
			}
			else {
				return false;
			}
		}
	}

	return true;
}

bool eventFormatMessageTask(EVT_HANDLE publisher, EVT_HANDLE evtHandle, pt::ptree& event_ptree)
{
	////category				= XML
	DWORD dwBuffSize = 0;
	DWORD dwBuffUsed = 0;
	TCHAR* eventTempString = new TCHAR[200];

	BOOL bRet = EvtFormatMessage(publisher, evtHandle, NULL, 0, NULL, EvtFormatMessageTask, dwBuffSize, NULL, &dwBuffUsed);
	if (!bRet)
	{
		DWORD dwRes = GetLastError();
		if (dwRes == ERROR_INSUFFICIENT_BUFFER) {
			// Allocate the buffer size needed to for the XML event.
			dwBuffSize = dwBuffUsed;
			WCHAR *pBuff = new WCHAR[dwBuffSize];
			if (pBuff == NULL) {
				std::cout << "Insufficent memory to obtain full event data" << std::endl;
				return false;
			}

			bRet = EvtFormatMessage(publisher, evtHandle, NULL, 0, NULL, EvtFormatMessageTask, dwBuffSize, pBuff, &dwBuffUsed);
			// XXX What about !bRet?
			WideCharToMultiByte(CP_UTF8, 0, pBuff, -1, eventTempString, sizeof(eventTempString), NULL, NULL);
			delete[] pBuff;
		}
	}

	return true;

}
