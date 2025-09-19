#pragma once
#include <Windows.h>
#include <memory>
class Process;
class Cloner {
private:
	uintptr_t m_pAddr;
	uintptr_t m_pPtr{};
	LPVOID m_pAllocationBase{};
	uintptr_t m_pSize{};

	bool m_bIsPtr;
	
	Process* m_pProc;

	std::unique_ptr<uint8_t[]> m_pBytes;

public:
	Cloner(uintptr_t pAddr, Process* proc, bool isPtr): m_pAddr(pAddr), m_pProc(proc), m_bIsPtr(isPtr) {}

	bool CopyMemoryRegion(bool bRefresh = false);
};