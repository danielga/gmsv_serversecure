#ifndef NETFILTER_CORE_HPP
#define NETFILTER_CORE_HPP

#pragma once

namespace GarrysMod::Lua {
class ILuaBase;
} // namespace GarrysMod::Lua

namespace netfilter {
void Initialize(GarrysMod::Lua::ILuaBase *LUA);
void Deinitialize();
} // namespace netfilter

#endif // NETFILTER_CORE_HPP
