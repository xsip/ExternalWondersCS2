#include <Memory/Process.h>
#include <Memory/Cloner.h>
#include <vector>
#include <stdexcept>

bool RemoteModule::Sync() {
	uint8_t* _ModuleBytes = new uint8_t[m_pSize];
	if (!this->m_pProc->Read(m_pBase, _ModuleBytes, m_pSize)) {
		delete[] _ModuleBytes;
		return false;
	}
	
	if (!m_bAllocated) {
		DWORD oldprotect;
		auto lpvResult = VirtualAlloc(reinterpret_cast<void*>(m_pBase), m_pSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpvResult == NULL) {
			delete[] _ModuleBytes;
			return false;
		}
		VirtualProtect(reinterpret_cast<void*>(m_pBase), m_pSize, PAGE_EXECUTE_READWRITE, &oldprotect);
		m_bAllocated = true;
	}

	memcpy(reinterpret_cast<void*>(m_pBase), reinterpret_cast<void*>(_ModuleBytes), static_cast<size_t>(m_pSize));
	delete[] _ModuleBytes;
	return true;
}

uint8_t* RemoteModule::ScanMemory(const char* signature) {

	static auto pattern_to_byte = [](const char* pattern) {
		auto bytes = std::vector<int>{};
		auto start = const_cast<char*>(pattern);
		auto end = const_cast<char*>(pattern) + std::strlen(pattern);

		for (auto current = start; current < end; ++current) {
			if (*current == '?') {
				++current;

				if (*current == '?')
					++current;

				bytes.push_back(-1);
			}
			else {
				bytes.push_back(std::strtoul(current, &current, 16));
			}
		}
		return bytes;
		};


	auto pattern_bytes = pattern_to_byte(signature);
	auto scan_bytes = reinterpret_cast<std::uint8_t*>(m_pBase);

	auto s = pattern_bytes.size();
	auto d = pattern_bytes.data();

	for (auto i = 0ul; i < m_pSize- s; ++i) {
		bool found = true;

		for (auto j = 0ul; j < s; ++j) {
			if (scan_bytes[i + j] != d[j] && d[j] != -1) {
				found = false;
				break;
			}
		}

		if (found) {
			return &scan_bytes[i];
		}
	}

	throw std::runtime_error(std::string("Wrong signature: ") + signature);
}



RemoteModule *Process::GetRemoteModule(std::string szModuleName) {
	if (remoteModuleList.contains(szModuleName)) {
		return remoteModuleList[szModuleName];
	}

	auto moduleInfo = GetModuleInfoEx(szModuleName);

	if (!moduleInfo.lpBaseOfDll)
		return {};

	auto mod = new RemoteModule((uintptr_t)moduleInfo.lpBaseOfDll, (uintptr_t)moduleInfo.SizeOfImage, this, szModuleName);
	remoteModuleList.insert({ szModuleName , mod });
	if (!remoteModuleList[szModuleName]->Sync()) {
		return {};
	}

	return remoteModuleList[szModuleName];
}


Cloner* Process::GetClonerForAddr(uintptr_t pAddr, bool bIsPtr) {
	return new Cloner(pAddr, this, bIsPtr);
}