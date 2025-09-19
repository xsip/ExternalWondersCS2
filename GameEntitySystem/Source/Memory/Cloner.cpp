#include <Memory/Cloner.h>
#include <Memory/Process.h>
bool Cloner::CopyMemoryRegion(bool bRefresh) {
	
	if (bRefresh) {
		if(m_pPtr)
			VirtualFree(reinterpret_cast<LPVOID>(m_pPtr), static_cast<SIZE_T>(m_pSize), MEM_RELEASE);
		m_pAllocationBase = nullptr;
		m_pPtr = NULL;
		m_pSize = NULL;
	}

	if (!m_pPtr) {

		if (m_bIsPtr)
			m_pPtr = m_pAddr;
		else
			m_pProc->Read(m_pAddr, &m_pPtr, sizeof(uintptr_t));

		MEMORY_BASIC_INFORMATION mBI;
		SIZE_T vQe = VirtualQueryEx(m_pProc->m_hProc, reinterpret_cast<void*>(m_pPtr), &mBI, sizeof(MEMORY_BASIC_INFORMATION));

		if (!vQe)
			return false;

		m_pPtr = reinterpret_cast<uintptr_t>(mBI.BaseAddress);
		m_pSize = mBI.RegionSize;
	}


	if (!m_pAllocationBase) {
		DWORD oldprotect;
		VirtualProtect(reinterpret_cast<LPVOID>(m_pPtr), static_cast<SIZE_T>(m_pSize), PAGE_EXECUTE_READWRITE, &oldprotect);

		VirtualAlloc(reinterpret_cast<LPVOID>(m_pPtr), static_cast<SIZE_T>(m_pSize), MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		m_pAllocationBase = VirtualAlloc(reinterpret_cast<LPVOID>(m_pPtr), static_cast<SIZE_T>(m_pSize), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!m_pAllocationBase) {
			return false;
		}

		VirtualProtect(reinterpret_cast<LPVOID>(m_pPtr), static_cast<SIZE_T>(m_pSize), PAGE_EXECUTE_READWRITE, &oldprotect);
	}

	m_pBytes = std::make_unique<uint8_t[]>(m_pSize);

	if (!m_pProc->Read(m_pPtr, m_pBytes.get(), m_pSize)) {
		return false;
	}

	memcpy(reinterpret_cast<void*>(m_pPtr), reinterpret_cast<void*>(m_pBytes.get()), static_cast<size_t>(m_pSize));

	if (m_pBytes.get()) {
		m_pBytes.reset();
		m_pBytes.release();
	}

	return true;
}