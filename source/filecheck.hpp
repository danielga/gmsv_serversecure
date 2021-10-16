#pragma once

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
	void Deinitialize( );
}
