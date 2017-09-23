#pragma once

#include <stdint.h>

namespace GarrysMod
{
	namespace Lua
	{
		class ILuaBase;
	}
}

namespace netfilter
{

void Initialize( GarrysMod::Lua::ILuaBase *LUA );
void Deinitialize( GarrysMod::Lua::ILuaBase *LUA );

}
