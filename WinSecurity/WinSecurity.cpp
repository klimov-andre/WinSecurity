#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <psapi.h>
#include <sddl.h>
#include <winbase.h>
#include <aclapi.h>

#define CONSOLE
#define PROCESS_CNT 512
#define BUF_LEN 512

#ifdef CONSOLE
  #define PRINT_STR_CONSOLE(x) printf(x" line: %d, err: %lu\n", __LINE__, GetLastError())
#else
  #define PRINT_STR_CONSOLE(x)
#endif


BOOL ListProcessModules(DWORD dwPID);
BOOL GetProcessList();
INT Is_64(DWORD PID);
VOID GetMitigationInfo(DWORD PID, BOOL* policyDep, BOOL* policyAslr);
DWORD GetOwnerNamenSID(DWORD PID, LPWSTR wstrName, DWORD dwNameLen, LPSTR* strSID);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);


INT Is_64(DWORD PID)
{
  HANDLE hProcess;
  BOOL bIs64;
  INT res;
  hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID);
  if ( hProcess == INVALID_HANDLE_VALUE )
  {
    return -1;
  }

  if ( IsWow64Process(hProcess, &bIs64) )
  {
    if ( !bIs64 )
    {
      res = 1;
    }
    else
    {
      res = 0;
    }
  }
  else
  {
    res = -1;
  }
  CloseHandle(hProcess);
  return res;
}


BOOL GetProcessList()
{
  HANDLE hProcessSnap;
  HANDLE hProcess;
  HANDLE hParentProcess;
  PROCESSENTRY32 pe32;
  DWORD dwPriorityClass;
  DWORD dwPathLen;
  DWORD dwCopiedBufLen;
  WCHAR wstrExePath[MAX_PATH];

  pe32.dwSize = sizeof(PROCESSENTRY32);

  /*
    Сделать снимок текущих процессов
  */
  hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hProcessSnap == INVALID_HANDLE_VALUE)
  {
    PRINT_STR_CONSOLE("Error: CreateToolhelp32Snapshot");
    return FALSE;
  }

  /*
    Получение информации о первом процессе снимка
  */
  if (!Process32First(hProcessSnap, &pe32))
  {
    PRINT_STR_CONSOLE("Error: Process32First");
    CloseHandle(hProcessSnap);
    return FALSE;
  }

  /*
    Пройтись по всем процессам из списка
  */
  do
  {
    dwPathLen = MAX_PATH;
    dwPriorityClass = 0;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
    if (hProcess == INVALID_HANDLE_VALUE)
    {
      printf(" invalid ");
    }
    
    // PID И НАЗАВАНИЕ
    _tprintf(TEXT("\n%ld %s "), pe32.th32ProcessID, pe32.szExeFile);

    // ПУТЬ  К ФАЙЛУ
    dwCopiedBufLen = GetModuleFileNameExW(hProcess, NULL, wstrExePath, dwPathLen);
    if (dwCopiedBufLen > 0)
    {
      wprintf(L"%s ", wstrExePath);
    }
    else
    {
      wprintf(L"N/a");
    }

    //PID РОДИТЕЛЯ
    wprintf(L" %d", pe32.th32ParentProcessID);

    //ИМЯ РОДИТЕЛЯ
    hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ParentProcessID);
    if (hParentProcess == INVALID_HANDLE_VALUE)
    {
      wprintf(L" N/a\n");
    }
    else
    {
      HMODULE hMod;
      DWORD dwLen;
      DWORD dwRes;
      CHAR szProcessName[MAX_PATH];
      dwRes = GetProcessImageFileNameA(hParentProcess, szProcessName, MAX_PATH);
      if (dwRes > 0)
      {
        printf(" %s \n",szProcessName);
      }
      else
      {
        printf(" N/a\n");
      }
    }

    // МОДУЛИ
    ListProcessModules(pe32.th32ProcessID);

    // ТИП (РАЗРЯДНОСТЬ)
    switch ( Is_64 ( pe32.th32ProcessID ) )
    {
    case 1:
      wprintf(L"type x64\n");
      break;
    case 0:
      wprintf(L"type x86\n");
      break;
    case -1:
      wprintf(L"N/a\n");
      break;
    }

    //ASLR & DEP
    BOOL bDep;
    BOOL bAslr;
    GetMitigationInfo(pe32.th32ProcessID, &bDep, &bAslr);
    if (bDep)
    {
      wprintf(L"\nDEP enabled");
    }
    else
    {
      wprintf(L"\nDEP disabled");
    }
    if (bAslr)
    {
      wprintf(L"\nASLR enabled\n");
    }
    else
    {
      wprintf(L"\nASLR disabled\n");
    }

    // ИМЯ ВЛАДЕЛЬЦА И ЕГО СИД
    DWORD dwNameLen = 256;
    LPSTR strSID = (LPSTR)malloc(dwNameLen * sizeof(CHAR));;
    LPWSTR wstrName = (LPWSTR)malloc(dwNameLen*sizeof(WCHAR));

    DWORD dwRes = GetOwnerNamenSID(pe32.th32ProcessID, wstrName, dwNameLen, &strSID);
    if (0 != dwRes)
    {
      // можно просто ничего не печатать
      printf("errrrrrroooor: %lu\n", dwRes);
    }
    else
    {
      wprintf(L"%s\n", wstrName);
      printf("%s\n", strSID);
    }

    CloseHandle(hProcess);

  } while (Process32Next(hProcessSnap, &pe32));

  CloseHandle(hProcessSnap);
  return(TRUE);
}


BOOL ListProcessModules(DWORD PID)
{
  HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
  MODULEENTRY32 me32;
  wprintf(L"MODULI: ");

  // Take a snapshot of all modules in the specified process.
  hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
  if (hModuleSnap == INVALID_HANDLE_VALUE)
  {
    PRINT_STR_CONSOLE("CreateToolhelp32Snapshot");
    return(FALSE);
  }

  // Set the size of the structure before using it.
  me32.dwSize = sizeof(MODULEENTRY32);

  // Retrieve information about the first module,
  // and exit if unsuccessful
  if (!Module32First(hModuleSnap, &me32))
  {
    PRINT_STR_CONSOLE("Module32First");
    CloseHandle(hModuleSnap);
    return(FALSE);
  }

  // Now walk the module list of the process,
  // and display information about each module
  do
  {
    _tprintf(TEXT("%s\n"), me32.szModule);
  } while (Module32Next(hModuleSnap, &me32));
  wprintf(L"\n ");
  CloseHandle(hModuleSnap);
  return(TRUE);
}


VOID GetMitigationInfo(DWORD PID, BOOL* bDep, BOOL* bAslr)
{
  HANDLE hProcess;
  PROCESS_MITIGATION_DEP_POLICY policyDep = { 0 };
  PROCESS_MITIGATION_ASLR_POLICY policyAslr = { 0 };
  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
  if (hProcess == INVALID_HANDLE_VALUE)
  {
    return;
  }

  *bDep = GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &policyDep, sizeof(policyDep));
  *bAslr = GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &policyAslr, sizeof(policyAslr));
  CloseHandle(hProcess);
  return;
}


DWORD GetOwnerNamenSID(DWORD PID, LPWSTR wstrName, DWORD dwNameLen, LPSTR* strSID)
{
  HANDLE hProcess;
  HANDLE hToken;
  PTOKEN_OWNER ptokenOwner;
  DWORD dwSize = 0;
  DWORD dwDomLen = 256;
  
  LPWSTR strDomain = (LPWSTR)calloc(dwDomLen, 256);
  SID_NAME_USE suseUse;

  hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
  if (0 == OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
  {
    return GetLastError();
  }
  GetTokenInformation(hToken, TokenOwner, NULL, dwSize, &dwSize);
  ptokenOwner = (PTOKEN_OWNER)GlobalAlloc(GPTR, dwSize);
  GetTokenInformation(hToken, TokenOwner, ptokenOwner, dwSize, &dwSize);

  if (NULL == ptokenOwner)
  {
    return GetLastError();
  }
  if (0 == ConvertSidToStringSidA(ptokenOwner->Owner, strSID))
  {
    return GetLastError();
  }

  suseUse = SidTypeUnknown;
  if (0 == LookupAccountSidW(NULL, ptokenOwner->Owner, wstrName, &dwNameLen, strDomain, &dwDomLen, &suseUse))
  {
    return GetLastError();
  }
  return 0;
}

// ПЕЧАТАЕТ ИМЯ владельца файла
DWORD GetFileOwnerName(CHAR *path)
{
  SE_OBJECT_TYPE obj_type = SE_FILE_OBJECT;

#if 0 
  CHAR *path = new CHAR[BUF_LEN];
  memcpy(path, "C:\\Users\\Андрей\\Documents\\test.c", sizeof("C:\\Users\\Андрей\\Documents\\test.c"));
#endif

  PSID pSID = NULL;
  PSECURITY_DESCRIPTOR SD;
  CHAR name[BUF_LEN] = "", domain[BUF_LEN] = "";
  DWORD userLen = BUF_LEN, domainLen = BUF_LEN;
  SID_NAME_USE sidName;

  // Получить sid владельца
  if (!GetNamedSecurityInfoA(path, obj_type, OWNER_SECURITY_INFORMATION, &pSID, NULL, NULL, NULL, &SD) == ERROR_SUCCESS)
  {
    return GetLastError();
  }

  if (!LookupAccountSidA(NULL, pSID, name, &userLen, domain, &domainLen, &sidName))
  {
    DWORD err = GetLastError();
    if (err == ERROR_NONE_MAPPED)
    {
      strcpy(name, "NONE_MAPPED");
    }
    else
    {
      return GetLastError();
    }
  }

  printf("%s\n", name);
  return 0;
}



// Выводит запись контроля доступа в нормальном виде (исп-ся в PrintACLs)
VOID PrintAce( CHAR* name, INT ace_type, SID_NAME_USE suse, ACCESS_MASK mask)
{
  printf("Name: %s\n", name);
  switch (ace_type)
  {
  case ACCESS_ALLOWED_ACE_TYPE:
    printf("ACCESS_ALLOWED_ACE_TYPE\n");
    break;
  case ACCESS_DENIED_ACE_TYPE:
    printf("ACCESS_DENIED_ACE_TYPE\n");
    break;
  case SYSTEM_AUDIT_ACE_TYPE:
    printf("SYSTEM_AUDIT_ACE_TYPE\n");
    break;
  }

  // это просто может понадобиться и не хочется комментить
#if 0
  printf("SID type: ");
  switch (suse)
  {
  case SidTypeUser:
    printf("SidTypeUser\n");
    break;
  case SidTypeGroup:
    printf("SidTypeGroup\n");
    break;
  case SidTypeDomain:
    printf("SidTypeDomain\n");
    break;
  case SidTypeAlias:
    printf("SidTypeAlias\n");
    break;
  case SidTypeWellKnownGroup:
    printf("SidTypeWellKnownGroup\n");
    break;
  case SidTypeDeletedAccount:
    printf("SidTypeDeletedAccount\n");
    break;
  case SidTypeInvalid:
    printf("SidTypeInvalid\n");
    break;
  case SidTypeUnknown:
    printf("SidTypeUnknown\n");
    break;
  case SidTypeComputer:
    printf("SidTypeComputer\n");
    break;
  case SidTypeLabel:
    printf("SidTypeLabel\n");
    break;
  case SidTypeLogonSession:
    printf("SidTypeLogonSession\n");
    break;
  }
#endif

  printf("Mask: %x\n", mask);
  printf("Mask values:\n");
  if (mask&DELETE)
    printf("  DELETE\n");
  if (mask&READ_CONTROL)
    printf("  READ_CONTROL\n");
  if (mask&WRITE_DAC)
    printf("  WRITE_DAC\n");
  if (mask&WRITE_OWNER)
    printf("  WRITE_OWNER\n");
  if (mask&SYNCHRONIZE)
    printf("  WRITE_DAC\n");
  if (mask&SPECIFIC_RIGHTS_ALL)
    printf("  SPECIFIC_RIGHTS_ALL\n");
  if (mask&ACCESS_SYSTEM_SECURITY)
    printf("  ACCESS_SYSTEM_SECURITY\n");
  if (mask&GENERIC_READ)
    printf("  GENERIC_READ\n");
  if (mask&GENERIC_WRITE)
    printf("  GENERIC_WRITE\n");
  if (mask&GENERIC_EXECUTE)
    printf("  GENERIC_EXECUTE\n");
  if (mask&GENERIC_ALL)
    printf("  GENERIC_ALL\n");
  printf("\n");
}



DWORD PrintACLs(CHAR *path)
{
  SE_OBJECT_TYPE obj_type = SE_FILE_OBJECT;

#if 0
  CHAR *path = new CHAR[BUF_LEN];
  memcpy(path, "C:\\Users\\Андрей\\Documents\\test.c",sizeof("C:\\Users\\Андрей\\Documents\\test.c"));
#endif

  PACL Dacl = NULL;
  PSECURITY_DESCRIPTOR SD;
  SID p;
  ACL_SIZE_INFORMATION acl_size;

  // Извлечь список доступа
  if (!GetNamedSecurityInfoA(path, obj_type, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &SD) == ERROR_SUCCESS)
  {
    printf("GetNamedSecurityInfoA\n");
    return GetLastError();
  }

  // Узнать число элементов в списке
  if (!GetAclInformation(Dacl, &acl_size, sizeof(acl_size), AclSizeInformation))
  {
    printf("GetAclInformation\n");
    return GetLastError();
  }

  // прогнать по списку и вывести записи
  for (int i = 0; i < acl_size.AceCount; i++)
  {
    LPVOID pAce;
    PSID pSID;
    CHAR name[1024] = "", domain[1024] = "";
    DWORD userLen = 1024, domainLen = 1024;
    SID_NAME_USE suse;

    if (!GetAce(Dacl, i, &pAce))
    {
      return GetLastError();
    }
    pSID = (PSID)(&((ACCESS_ALLOWED_ACE*)pAce)->SidStart);
    
    if (!LookupAccountSidA(NULL, pSID, name, &userLen, domain, &domainLen, &suse))
    {
      DWORD err = GetLastError();
      if (err == ERROR_NONE_MAPPED)
      {
        strcpy(name, "NONE_MAPPED");
      }
      else
      {
        return GetLastError();
      }
    }
    PrintAce(name, (*(ACCESS_ALLOWED_ACE*)pAce).Header.AceType, suse, ((ACCESS_ALLOWED_ACE*)pAce)->Mask);
  }
}


// Изменить владельца указанного файла
DWORD SetNewOwner(CHAR* strFilename, CHAR* strNewOwner)
{
  HANDLE hToken = NULL;
  PSID pSID = NULL;
  PSECURITY_DESCRIPTOR pSecurityDesc = NULL;
  DWORD dwLen = 0;
  DWORD dwSidLen = 0;
  CHAR strBuf[BUF_LEN];
  SID_NAME_USE suse;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
  {
    return GetLastError();
  }
  else
  {
    SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, 1);
    SetPrivilege(hToken, SE_SECURITY_NAME, 1);
    SetPrivilege(hToken, SE_BACKUP_NAME, 1);
    SetPrivilege(hToken, SE_RESTORE_NAME, 1);
  }

  GetFileSecurityA(strFilename, OWNER_SECURITY_INFORMATION, pSecurityDesc, 0, &dwLen);
  pSecurityDesc = (PSECURITY_DESCRIPTOR)malloc(dwLen);
  if (!InitializeSecurityDescriptor(pSecurityDesc, SECURITY_DESCRIPTOR_REVISION))
  {
    return GetLastError();
  }

  dwLen = BUF_LEN;
  LookupAccountNameA(NULL, strNewOwner, NULL, &dwSidLen, NULL, &dwLen, &suse);
  pSID = (PSID)malloc(dwSidLen);
  if (!LookupAccountNameA(NULL, strNewOwner, pSID, &dwSidLen, strBuf, &dwLen, &suse))
  {
    return GetLastError();
  }

  if (SetSecurityDescriptorOwner(pSecurityDesc, pSID, 0))
  {
    DWORD dwRes = SetFileSecurityA(strFilename, OWNER_SECURITY_INFORMATION, pSecurityDesc);
    SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, 0);
    SetPrivilege(hToken, SE_SECURITY_NAME, 0);
    SetPrivilege(hToken, SE_BACKUP_NAME, 0);
    SetPrivilege(hToken, SE_RESTORE_NAME, 0);
    free(pSID);
    free(pSecurityDesc);
    return dwRes;
  }
}


// Включает/Отключает привилегию процессу 
// bEnablePrivilege = 0 - отключить
// bEnablePrivilege = 1 - включить
// hToken - токен процесса
// lpszPrivilege - название привилегии
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
  TOKEN_PRIVILEGES tp;
  LUID luid;

  if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
  {
    return FALSE;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  if (bEnablePrivilege)
  {
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  }
  else
  {
    tp.Privileges[0].Attributes = 0;
  }

  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
  {
    return FALSE;
  }

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
  {
    printf("The token does not have the specified privilege. \n");
    return FALSE;
  }
  return TRUE;
}


int main()
{
  setlocale(LC_ALL, "Rus");
  DWORD dwRes = SetNewOwner((CHAR*)"C:\\Virtual\\ddd.txt", (CHAR*)"Userok");
  printf("%lu\n", dwRes);
  GetFileOwnerName((CHAR*)"C:\\Virtual\\ddd.txt");
}

