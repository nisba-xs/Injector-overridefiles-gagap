#include "cccccc.h"
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <ctype.h>
#include <stdio.h>
#include <conio.h>
#include <string.h>
#include <stdlib.h>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ostream>
#include <time.h>
#include <string>
#include <ctime>
#include <psapi.h>
#include <sddl.h>
#include <accctrl.h>
#include <aclapi.h>
#include <tchar.h>
#include <wininet.h>
#include <winsock.h>
#include <urlmon.h>
#include <time.h>
#include <cstdlib> //Declare "system()"

#include "XorStr.h"

#include "Console.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wsock32.lib")
#pragma comment (lib,"wininet.lib")
#pragma comment (lib, "urlmon.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "GODGUARD.lib")
#pragma warning(disable : 4715)
#pragma warning(disable : 4552)

using namespace std;
using std::cout;
#include "DllData.h"
template <class SupSibzxyClass>
SupSibzxyClass addCrap(SupSibzxyClass a, SupSibzxyClass b)
{
	return a + b;
}

class SupSibzxyClass {
public:
	template<class type>
	bool ENDGAME(DWORD dwBase, type Value) {
		__try {
			*(type*)(dwBase) = Value;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}
	template<class type>
	bool PointBlank(DWORD dwBase, type Value) {
		__try {
			*(type*)(dwBase) += Value;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}
	template<class type>
	bool NOOB(DWORD dwBase, type Value) {
		__try {
			*(type*)(dwBase) -= Value;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}
	template<class type>
	bool Sorry(DWORD dwBase, type Value) {
		__try {
			*(type*)(dwBase) *= Value;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}
	template<class type>
	bool DriveCar(DWORD dwBase, type Value) {
		__try {
			*(type*)(dwBase) /= Value;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}
	struct settings_t {
		bool openclose;
		DWORD PLEASEEIEI;
	}Options;
};

SupSibzxyClass* memory;
#define PH_MAINWND_CLASSNAME L"SupSibzxyClass" // phapppub

DWORD WINAPI AVENGERS(LPVOID) {
	while (true) {
		if (GetAsyncKeyState(VK_END) & 1) {
			memory->Options.openclose != memory->Options.openclose;
			if (memory->Options.openclose) {
				memory->ENDGAME<DWORD>(0x11907722, 0x74);
			}
			else {
				memory->ENDGAME<DWORD>(0x11907722, 0x74);
			}
		}
	}
	return NULL;
}

BOOL WINAPI DllMain(HMODULE hDll, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		//MessageBeep(MB_ICONINFORMATION);
		CreateThread(0, 0, AVENGERS, 0, 0, &memory->Options.PLEASEEIEI);
		return true;
	}
	return false;
}

char MUAYTHAI(DWORD pid, uint64_t loc) {
	HANDLE PHD;
	SYSTEM_INFO si;
	MEMORY_BASIC_INFORMATION MMBBII;
	LPVOID IM;
	DWORD ret, TTR;
	HANDLE CRP = OpenProcess(PROCESS_ALL_ACCESS, TRUE, GetCurrentProcessId());
	HANDLE CRTK = NULL;

	LUID PVL;

	TOKEN_PRIVILEGES TP[1];
	TP[0].PrivilegeCount = 1;

	OpenProcessToken(CRP, TOKEN_ADJUST_PRIVILEGES, &CRTK);
	LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &PVL);

	TP[0].Privileges[0].Luid = PVL;
	TP[0].Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(CRTK, FALSE, TP, 0, NULL, NULL);

	PHD = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (PHD == NULL) {
		return false;
	}

	IM = (void*)loc;

	char WHAT;
	ReadProcessMemory(PHD, IM, (LPVOID)(&WHAT), 1, &TTR);

	CloseHandle(PHD);
	return WHAT;
}

DWORD protectprocess(void)
{
	HANDLE hProcess = GetCurrentProcess();
	PACL pEmptyDacl;
	DWORD dwErr;

	// using malloc guarantees proper alignment
	pEmptyDacl = (PACL)malloc(sizeof(ACL));

	if (!InitializeAcl(pEmptyDacl, sizeof(ACL), ACL_REVISION))
	{
		dwErr = GetLastError();
	}
	else
	{
		dwErr = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
			DACL_SECURITY_INFORMATION, NULL, NULL, pEmptyDacl, NULL);
	}

	free(pEmptyDacl);
	return dwErr;
}

typedef HINSTANCE(*fpLoadLibrary)(char*);


//---------------------------------------------------------------------------------------//
void ClassRegOpenKeyEx()
{
	int Windows32 = 1;
	HKEY hIESettings01 = NULL;
	HKEY hIESettings1 = NULL;

	if (Windows32)
	{
		protectprocess();
		Sleep(10);
		//MessageBoxA(0,/*กด Ok แล้ว เข้าเกมได้เลย*/XorStr<0xea, 16, 0x1b50821d>("\xe\x50\x29\x35\x2c\x4e\x21\x48\x12\x36\x36\x37\x34\x35\x3a" + 0x1b50821d).s, /*Villain_Blade*/XorStr<0x44, 14, 0x41dd43de>("\x1e\x20\x14\x28\x1c\x1e\x5\x66\xf\x25\x2b\x2e\x24" + 0x41dd43de).s, MB_OK);
		MessageBox(NULL, "กดokหน้ารันเชอร์แล้วเขาเกมส์", "== GaGaap. ==", MB_ICONERROR);

		// 64 BIT
		LONG lRes01 = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", NULL, KEY_READ | KEY_WRITE, &hIESettings01);
		lRes01 = RegSetValueExA(hIESettings01, "AppInit_DLLs", NULL, REG_SZ,
			(BYTE*)"C:\\Windows\\SysWOW64\\XAPOFX1_6.dll", strlen("C:\\Windows\\SysWOW64\\XAPOFX1_6.dll") + 1);;
		DWORD value01 = 1;

		LONG lRes1 = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", NULL, KEY_READ | KEY_WRITE, &hIESettings1);
		lRes1 = RegSetValueEx(hIESettings1, "LoadAppInit_DLLs", NULL, REG_DWORD,
			(BYTE*)"0x1", strlen("0x1"));
		DWORD value1 = 1;


	}
}


#include <cstdio>
#include "Xorstr.h"
string random(int len)
{
	string a = /*abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*/XorStr<0x76, 63, 0x784652B1>("\x17\x15\x1B\x1D\x1F\x1D\x1B\x15\x17\x15\xEB\xED\xEF\xED\xEB\xF5\xF7\xF5\xFB\xFD\xFF\xFD\xFB\xF5\xF7\xF5\xD1\xD3\xD1\xD7\xD1\xD3\xD1\xDF\xD1\xD3\xD1\xD7\xD1\xD3\xD1\xCF\xF1\xF3\xF1\xF7\xF1\xF3\xF1\xFF\xF1\xF3\x9A\x9A\x9E\x9E\x9A\x9A\x86\x86\x8A\x8A" + 0x784652B1).s;
	string r;
	srand(time(NULL));
	for (int i = 0; i < len; i++) r.push_back(a.at(size_t(rand() % 62)));
	return r;
}
int main(int argc, char* argv[])
{
	protectprocess();
	char pa[999];
	sprintf(pa, "%s", argv[1]);
	TCHAR CopyFileName1[2048] = { 0 };
	if (strcmp(pa, "(null)") == 0)
	{
		TCHAR CopyFileName[2048] = { 0 };

		GetModuleFileName(NULL, CopyFileName, MAX_PATH);

		GetModuleFileName(NULL, CopyFileName1, MAX_PATH);

		char* End;

		End = strrchr(CopyFileName, ('\\')) + 1;

		if (!End)
			return FALSE;

		*End = ('\0');

		char txt[999];
		sprintf(txt, "%sGaGaap.exe", CopyFileName);
		protectprocess();
		SetConsoleTitle(TEXT("== GaGaap. ==\n"));
		DoSome();
		system("color F");
		Sleep(1500);
		DoSome();
		system("color F");
		Sleep(1500);
		_cprintf("[+]"" Please enter the game.\n");
		Sleep(3000);

		char txt1[999];
		sprintf(txt1, "\"%s\"", CopyFileName1);

		CopyFile(CopyFileName1, txt, false);
		//MessageBox(0,txt,"",0);

		ShellExecute(NULL, "open", txt, txt1, NULL, SW_SHOW);
		return 0;
	}
	else
	{
		Sleep(300);
		char Delete[999];
		strcpy(Delete, argv[1]);
		remove(Delete);
		protectprocess();
		HWND hWnd = GetConsoleWindow();//ซ่อน Console
		ShowWindow(hWnd, SW_HIDE);//ซ่อน Console
		int cols;

		const int result = remove("C:\\Windows\\SysWOW64\\XAPOFX1_6.dll");
		Sleep(300);
		HANDLE _File = CreateFileA("C:\\Windows\\SysWOW64\\XAPOFX1_6.dll", GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		WriteFile(_File, (PVOID)rawData, sizeof(rawData), new ULONG, NULL);
		CloseHandle(_File);

		ClassRegOpenKeyEx();

	}
}