#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <psapi.h>

#define CONSOLE
#define PROCESS_CNT 512


#ifdef CONSOLE
  #define PRINT_STR_CONSOLE(x) printf(x" line: %d, err: %lu\n", __LINE__, GetLastError())
#else
  #define PRINT_STR_CONSOLE(x)
#endif


BOOL ListProcessModules(DWORD dwPID);
BOOL GetProcessList();
INT Is_64(DWORD PID);


INT Is_64(DWORD PID)
{
  HANDLE hProcess;
  BOOL bIs64;
  hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID);
  if ( hProcess == INVALID_HANDLE_VALUE )
  {
    return -1;
  }
  if ( IsWow64Process(hProcess, &bIs64) )
  {
    if ( !bIs64 )
    {
      return 1;
    }
    else
    {
      return 0;
    }
  }
  return -1;
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

    CloseHandle(hProcess);

  } while (Process32Next(hProcessSnap, &pe32));

  CloseHandle(hProcessSnap);
  return(TRUE);
}





BOOL ListProcessModules(DWORD dwPID)
{
  HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
  MODULEENTRY32 me32;
  wprintf(L"MODULI: ");
  // Take a snapshot of all modules in the specified process.
  hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
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
  //me32.ex
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


int main()
{
  setlocale(LC_ALL, "Rus");
  GetProcessList();
}

