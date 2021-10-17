#pragma once

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
	void Deinitialize( );
}
