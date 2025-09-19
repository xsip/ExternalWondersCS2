#pragma once
#include <Windows.h>
#include <map>
#include <string>
#include <TlHelp32.h>
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
	void GetProcHandle();

	MODULEINFO GetModuleInfoEx(std::string m_Name);

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