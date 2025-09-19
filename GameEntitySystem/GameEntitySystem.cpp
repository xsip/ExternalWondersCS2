#include <Windows.h>
#include <iostream>
#include <Memory/Process.h>
#include <Memory/Cloner.h>


template <typename T>
using GetEntityByIdDef = T(*)(uintptr_t pGameEntitySystem, int idx);


int main() {
	
	Process proc{ "cs2.exe" };
	
	auto mClient = proc.GetRemoteModule("client.dll");

	auto pGameEntitySystem = *(uintptr_t*)(mClient->GetAddr() + 0x1E149E0);
	auto pGameEntitySystemCloner = proc.GetClonerForAddr(pGameEntitySystem, true);

	if (!pGameEntitySystemCloner->CopyMemoryRegion()) {
		return 0;
	}
	
	auto pGameEntitySystemEntities = pGameEntitySystem +0x10;
	auto pGameEntitySystemEntitiesCloner = proc.GetClonerForAddr(pGameEntitySystemEntities, false);
	
	if (!pGameEntitySystemEntitiesCloner->CopyMemoryRegion()) {
		return 0;
	}
	
	auto GetEntityByIdx = reinterpret_cast<GetEntityByIdDef<uintptr_t>>(mClient->ScanMemory("4C 8D 49 10 81 FA"));
	
	printf("CWorld: 0x%p\n", GetEntityByIdx(pGameEntitySystem, 0));
	
}