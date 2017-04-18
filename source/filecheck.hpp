#pragma once

#include <stdint.h>

namespace GarrysMod
{
	namespace Lua
	{
		class ILuaBase;
	}
}

namespace filecheck
{

void Initialize( GarrysMod::Lua::ILuaBase *LUA );
int32_t PostInitialize( GarrysMod::Lua::ILuaBase *LUA );
void Deinitialize( GarrysMod::Lua::ILuaBase *LUA );

}
