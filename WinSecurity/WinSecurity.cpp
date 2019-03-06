#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <psapi.h>

#define CONSOLE

#ifdef CONSOLE
  #define PRINT_STR_CONSOLE(x) printf(x" line: %d, err: %lu\n", __LINE__, GetLastError())
#else
  #define PRINT_STR_CONSOLE(x)
#endif

BOOL ListProcessModules(DWORD dwPID);
BOOL GetProcessList();

BOOL GetProcessList()
{
  HANDLE hProcessSnap;
  HANDLE hProcess;
  HANDLE hParentProcess;
  PROCESSENTRY32 pe32;
  DWORD dwPriorityClass;
  DWORD dwPathLen;
  WCHAR wstrExePath[MAX_PATH];

  pe32.dwSize = sizeof(PROCESSENTRY32);
  //pwstrExePath = (LPWSTR)malloc(sizeof(CHAR)*1024);

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
      //PRINT_STR_CONSOLE("OpenProcess");
      printf(" invalid ");
    }
    else
    {
      dwPriorityClass = GetPriorityClass(hProcess);
      if (!dwPriorityClass)
      {
        //PRINT_STR_CONSOLE("GetPriorityClass");
      }
    }
    
    // id и название
    _tprintf(TEXT("\n%ld %s "), pe32.th32ProcessID, pe32.szExeFile);
    if (QueryFullProcessImageNameW(hProcess, PROCESS_NAME_NATIVE, (LPWSTR)wstrExePath, &dwPathLen))
    {
      wprintf(L"%s ", wstrExePath);
    }
    else
    {
      wprintf(L"pizda ");
    }

    hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ParentProcessID);
    // родитель и его пид
    if (hParentProcess == INVALID_HANDLE_VALUE)
    {
      wprintf(L" %d none \n", pe32.th32ParentProcessID);
    }
    else
    {
      HMODULE hMod;
      DWORD cbNeeded;
      CHAR szProcessName[MAX_PATH];

      if (EnumProcessModules(hParentProcess, &hMod, sizeof(hMod), &cbNeeded))
      {
        GetModuleBaseNameA(hParentProcess, hMod, szProcessName, MAX_PATH);
        printf(" %d %s \n", pe32.th32ParentProcessID, szProcessName);
      }
      
    }
    /// МОДУЛИ
    ListProcessModules(pe32.th32ProcessID);
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
  int p = 0;
  int i = 99;
  i += i += p += i;
  setlocale(LC_ALL, "Rus");
  PRINT_STR_CONSOLE("hello");
  GetProcessList();
}

