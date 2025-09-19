#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <map>
#include <string>
#include <psapi.h>
class Process;
class Cloner;
class RemoteModule {
private:
	uintptr_t m_pSize;
	uintptr_t m_pBase;
	Process* m_pProc;
	std::string m_szDll{};
	bool m_bIsValid{};
	bool m_bAllocated{};
public:
	RemoteModule(uintptr_t pBase, uintptr_t pSize, Process* pProc, std::string szDll = "") :
		m_pSize(pSize),
		m_pBase(pBase),
		m_pProc(pProc),
		m_szDll(szDll),
		m_bIsValid(true) {
	}

	RemoteModule() :
		m_pSize(0x0),
		m_pBase(0x0),
		m_pProc(nullptr),
		m_szDll("Invalid"),
		m_bIsValid(false) {

	}
	bool Sync();
	uintptr_t GetAddr() { return m_pBase; };
	uint8_t* ScanMemory(const char* signature);
};

class Process {
public:
	HANDLE m_hProc;
private:
	DWORD pProcId;
	std::string m_szProcName;
	std::map<std::string, RemoteModule*> remoteModuleList{};

private:
	inline void GetProcHandle() {

		::PROCESSENTRY32 entry = { };
		entry.dwSize = sizeof(::PROCESSENTRY32);

		const HANDLE snapShot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		while (::Process32Next(snapShot, &entry))
		{
			if (!m_szProcName.compare(entry.szExeFile))
			{
				pProcId = entry.th32ProcessID;
				m_hProc = ::OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pProcId);

				break;
			}
		}
		// FreeSchemaSystem handle
		if (snapShot)
			::CloseHandle(snapShot);

		if (!m_hProc) {
			printf("Couldn't find Process %s\n", m_szProcName.c_str());
			exit(1);
		}
	}

	inline MODULEINFO GetModuleInfoEx(std::string m_Name)
	{

		HMODULE m_Modules[1337];
		DWORD m_Needed = 0x0;
		// printf("0x%p\n", Memory::remoteHandleMap[processName]);
		if (!K32EnumProcessModules(m_hProc, m_Modules, sizeof(m_Modules), &m_Needed)) {
			printf("Error: 0x%x\n", GetLastError());
			return {};
		}

		DWORD m_Count = (m_Needed / sizeof(HMODULE));
		for (DWORD i = 0; m_Count > i; ++i)
		{
			char m_ModuleFileName[MAX_PATH] = { 0 };
			if (!K32GetModuleFileNameExA(m_hProc, m_Modules[i], m_ModuleFileName, sizeof(m_ModuleFileName)))
				continue;

			if (strstr(m_ModuleFileName, ("\\" + m_Name).c_str()))
			{
				MODULEINFO m_ModuleInfo = { 0 };
				if (!K32GetModuleInformation(m_hProc, m_Modules[i], &m_ModuleInfo, sizeof(MODULEINFO)))
					return {};
				return m_ModuleInfo;
			}
		}

		return {};
	}

public:
	Process(std::string szProcName) : m_szProcName(szProcName) {
		GetProcHandle();
	};

	template <typename T>
	inline bool Read(uintptr_t m_Address, T* m_Buffer, SIZE_T m_Size)
	{
		SIZE_T bytesRead;
		auto res = ReadProcessMemory(m_hProc, reinterpret_cast<LPCVOID>(m_Address), m_Buffer, m_Size, &bytesRead);
		return res;
	}

	RemoteModule *GetRemoteModule(std::string szModuleName);
	Cloner* GetClonerForAddr(uintptr_t pAddr, bool bIsPtr = false);
};