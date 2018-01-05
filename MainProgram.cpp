#include <windows.h>
#include <conio.h>
#include <stdio.h>
#include <winevt.h>
#include <iostream>
#include <locale>
#include <codecvt>
#include <Sddl.h>


#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "Advapi32.lib")

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);
DWORD PrintEvent(EVT_HANDLE hEvent);
DWORD PrintEventSystemData(EVT_HANDLE hEvent);
DWORD PrintEventValues(EVT_HANDLE hEvent);
bool populateEventData(PEVT_VARIANT bufValue);

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


void main(void)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hSubscription = NULL;
	LPWSTR pwsPath = L"Application";
	LPWSTR pwsQuery = L"*";

	// Subscribe to events beginning with the oldest event in the channel. The subscription
	// will return all current events in the channel and any future events that are raised
	// while the application is active.
	hSubscription = EvtSubscribe(NULL, NULL, pwsPath, pwsQuery, NULL, NULL,
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

	wprintf(L"Hit any key to quit\n\n");
	while (!_kbhit())
		Sleep(10);

cleanup:

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
DWORD PrintEventValues(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hContext = NULL;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
	LPWSTR ppValues[] = { L"Event/System/Provider/@Name", L"Event/System/Channel" };
	DWORD count = sizeof(ppValues) / sizeof(LPWSTR);

	// Identify the components of the event that you want to render. In this case,
	// render the provider's name and channel from the system section of the event.
	// To get user data from the event, you can specify an expression such as
	// L"Event/EventData/Data[@Name=\"<data name goes here>\"]".
	hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
	if (NULL == hContext)
	{
		wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
		goto cleanup;
	}

	// The function returns an array of variant values for each element or attribute that
	// you want to retrieve from the event. The values are returned in the same order as 
	// you requested them.
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

	// Print the selected values.
	wprintf(L"\nProvider Name: %s\n", pRenderedValues[0].StringVal);
	wprintf(L"Channel: %s\n", (EvtVarTypeNull == pRenderedValues[1].Type) ? L"" : pRenderedValues[1].StringVal);

cleanup:

	if (hContext)
		EvtClose(hContext);

	if (pRenderedValues)
		free(pRenderedValues);

	return status;
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

	// Print the values from the System section of the element.
	wprintf(L"Provider Name: %s\n", pRenderedValues[EvtSystemProviderName].StringVal);
	if (NULL != pRenderedValues[EvtSystemProviderGuid].GuidVal)
	{
		StringFromGUID2(*(pRenderedValues[EvtSystemProviderGuid].GuidVal), wsGuid, sizeof(wsGuid) / sizeof(WCHAR));
		wprintf(L"Provider Guid: %s\n", wsGuid);
	}
	else
	{
		wprintf(L"Provider Guid: NULL");
	}


	DWORD EventID = pRenderedValues[EvtSystemEventID].UInt16Val;
	if (EvtVarTypeNull != pRenderedValues[EvtSystemQualifiers].Type)
	{
		EventID = MAKELONG(pRenderedValues[EvtSystemEventID].UInt16Val, pRenderedValues[EvtSystemQualifiers].UInt16Val);
	}
	wprintf(L"EventID: %lu\n", EventID);

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

	wprintf(L"EventRecordID: %I64u\n", pRenderedValues[EvtSystemEventRecordId].UInt64Val);

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
		if (ConvertSidToStringSid(pRenderedValues[EvtSystemUserID].SidVal, &pwsSid))
		{
			wprintf(L"Security UserID: %s\n", pwsSid);
			LocalFree(pwsSid);
		}
	}

cleanup:

	if (hContext)
		EvtClose(hContext);

	if (pRenderedValues)
		free(pRenderedValues);

	return status;
}


// Render the event as an XML string and print it.
DWORD PrintEvent(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	LPWSTR pRenderedContent = NULL;

	PEVT_VARIANT bufValue = NULL;
	/*
	BOOL bRet = ProcEvtRender(
	renderContext,		// Session.
	evtHandle,			// HANDLE.
	EvtRenderEventValues,	// Flags.
	dwValueSize,		// BufferSize.
	NULL,			// Send NULL to get buffersize needed
	&dwValueSize,		// Buffersize that is used or required.
	&dwPropertyCount);


	*/
	EVT_HANDLE renderContext;

	renderContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
	//if (!EvtRender(renderContext, hEvent, EvtRenderEventValues, dwBufferSize, NULL, &dwBufferUsed, &dwPropertyCount))
	if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
	{
		if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
		{
			dwBufferSize = dwBufferUsed;
			pRenderedContent = (LPWSTR)malloc(dwBufferSize);
			bufValue = new EVT_VARIANT[dwBufferSize];


			//pValues = new EVT_VARIANT[dwBufferUsed];
			if (pRenderedContent)
			{
				EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
				//EvtRender(renderContext, hEvent, EvtRenderEventValues, dwBufferSize, bufValue, &dwBufferUsed, &dwPropertyCount);
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
			wprintf(L"EvtRender failed with %d\n", status);
			goto cleanup;
		}
	}

	wprintf(L"%s\n\n", pRenderedContent);
	//populateEventData(bufValue);

cleanup:

	if (pRenderedContent)
		free(pRenderedContent);

	return status;
}

bool populateEventData(PEVT_VARIANT pValues)
{
	windowsEventStruct structObj;
	windowsEventStruct *eventPtr = &structObj;
	memset(eventPtr, 0, sizeof(windowsEventStruct));
	/*
	std::cout << pValues[EvtSystemChannel].StringVal;
	std::cout << pValues[EvtSystemProviderName].StringVal;
	std::cout << pValues[EvtSystemKeywords].UInt64Val;
	std::cout << pValues[EvtSystemLevel].ByteVal;
	std::cout << pValues[EvtSystemTimeCreated].FileTimeVal;
	std::cout << pValues[EvtSystemUserID].SidVal;
	std::cout << pValues[EvtSystemComputer].StringVal;

	std::cout << pValues[EvtSystemProviderName].StringVal;
	std::cout << pValues[EvtSystemTask].UInt16Val << std::endl;
	*/
	
	eventPtr->shortEventId = pValues[EvtSystemEventID].UInt16Val;
	if (pValues[EvtSystemChannel].StringVal)
	{
		wcsncpy_s(eventPtr->eventLogSourceName, sizeof(eventPtr->eventLogSourceName), pValues[EvtSystemChannel].StringVal, _TRUNCATE);
	}
	std::string strSourceName;
	typedef std::codecvt_utf8<wchar_t> convert_typeX;
	std::wstring_convert<convert_typeX, wchar_t> converterX;
	try {
		strSourceName = converterX.to_bytes(pValues[EvtSystemProviderName].StringVal);
		std::cout << strSourceName << std::endl;
		if (strSourceName.empty()) {
			throw std::range_error("EvtSystemProviderName converted to empty string");
		}
		strncpy_s(eventPtr->sourceName, sizeof(eventPtr->sourceName), strSourceName.c_str(), _TRUNCATE);
	}
	catch (const std::range_error &e) {
		LPCWSTR val = pValues[EvtSystemProviderName].StringVal;
		while (*val) {
			val++;
		}
		val = pValues[EvtSystemProviderName].StringVal;
		strncpy_s(eventPtr->sourceName, sizeof(eventPtr->sourceName), "", _TRUNCATE);
		while (*val) {
			_snprintf_s(eventPtr->sourceName, sizeof(eventPtr->sourceName), _TRUNCATE, "%s%x ", eventPtr->sourceName, *val); 
			val++;
		}

	}
	wprintf(L"%s ", eventPtr->sourceName);
	wprintf(L"%s \n\n",  eventPtr->eventLogSourceName);
	
	return true;
}
