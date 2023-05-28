#include "filecheck.hpp"
#include "netfilter/core.hpp"

#include <GarrysMod/InterfacePointers.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <Platform.hpp>

#include <iserver.h>

#include <cstdint>
#include <string>

namespace global {
static constexpr std::string_view Version = "serversecure 1.5.42";
// version num follows LuaJIT style, xxyyzz
static constexpr uint32_t VersionNum = 10542;

static IServer *server = nullptr;

LUA_FUNCTION_STATIC(GetClientCount) {
  LUA->PushNumber(server->GetClientCount());
  return 1;
}

static void PreInitialize(GarrysMod::Lua::ILuaBase *LUA) {
  server = InterfacePointers::Server();
  if (server == nullptr) {
    LUA->ThrowError("failed to dereference IServer");
  }

  LUA->CreateTable();

  LUA->PushString(Version.data());
  LUA->SetField(-2, "Version");

  LUA->PushNumber(VersionNum);
  LUA->SetField(-2, "VersionNum");

  LUA->PushCFunction(GetClientCount);
  LUA->SetField(-2, "GetClientCount");
}

static void Initialize(GarrysMod::Lua::ILuaBase *LUA) {
  LUA->SetField(GarrysMod::Lua::INDEX_GLOBAL, "serversecure");
}

static void Deinitialize(GarrysMod::Lua::ILuaBase *LUA) {
  LUA->PushNil();
  LUA->SetField(GarrysMod::Lua::INDEX_GLOBAL, "serversecure");
}
} // namespace global

GMOD_MODULE_OPEN() {
  global::PreInitialize(LUA);
  netfilter::Initialize(LUA);
  filecheck::Initialize(LUA);
  global::Initialize(LUA);
  return 1;
}

GMOD_MODULE_CLOSE() {
  filecheck::Deinitialize();
  netfilter::Deinitialize();
  global::Deinitialize(LUA);
  return 0;
}
