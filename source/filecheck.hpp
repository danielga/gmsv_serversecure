#ifndef FILECHECK_HPP
#define FILECHECK_HPP

#pragma once

namespace GarrysMod::Lua {
class ILuaBase;
} // namespace GarrysMod::Lua

namespace filecheck {
void Initialize(GarrysMod::Lua::ILuaBase *LUA);
void Deinitialize();
} // namespace filecheck

#endif // FILECHECK_HPP
