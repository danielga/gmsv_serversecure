#include "filecheck.hpp"

#include <GarrysMod/FunctionPointers.hpp>
#include <GarrysMod/InterfacePointers.hpp>
#include <GarrysMod/Lua/Helpers.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <Platform.hpp>

#include <detouring/classproxy.hpp>
#include <scanning/symbolfinder.hpp>

#include <dbg.h>
#include <networkstringtabledefs.h>
#include <strtools.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace filecheck {
enum class ValidationMode { None, Fixed, Lua };

static constexpr std::string_view file_hook_name = "IsValidFileForTransfer";
static constexpr std::string_view downloads_dir =
    "downloads" CORRECT_PATH_SEPARATOR_S;
static ValidationMode validation_mode = ValidationMode::None;
static GarrysMod::Lua::ILuaInterface *lua_interface = nullptr;
static INetworkStringTable *downloads = nullptr;
static Detouring::Hook hook;

inline bool SetFileDetourStatus(ValidationMode mode) {
  if (mode != ValidationMode::None ? hook.Enable() : hook.Disable()) {
    validation_mode = mode;
    return true;
  }

  return false;
}

LUA_FUNCTION_STATIC(EnableFileValidation) {
  if (LUA->Top() < 1) {
    LUA->ArgError(1, "boolean or number expected, got nil");
  }

  ValidationMode mode = ValidationMode::Fixed;
  if (LUA->IsType(1, GarrysMod::Lua::Type::Bool)) {
    mode = LUA->GetBool(1) ? ValidationMode::Fixed : ValidationMode::None;
  } else if (LUA->IsType(1, GarrysMod::Lua::Type::Number)) {
    auto num = static_cast<int32_t>(LUA->GetNumber(1));
    if (num < 0 || num > 2) {
      LUA->ArgError(1, "invalid mode value, must be 0, 1 or 2");
    }

    mode = static_cast<ValidationMode>(num);
  } else {
    LUA->ArgError(1, "boolean or number expected");
  }

  LUA->PushBool(SetFileDetourStatus(mode));
  return 1;
}

inline bool Call(const char *filepath) {
  return hook
      .GetTrampoline<FunctionPointers::CNetChan_IsValidFileForTransfer_t>()(
          filepath);
}

inline bool BlockDownload(const char *filepath) {
  DevWarning("[ServerSecure] Blocking download of \"%s\"\n", filepath);
  return false;
}

static bool CNetChan_IsValidFileForTransfer_detour(const char *filepath) {
  if (filepath == nullptr) {
    return BlockDownload("string pointer was NULL");
  }

  std::string nicefile(filepath);
  if (nicefile.empty()) {
    return BlockDownload("path length was 0");
  }

  if (validation_mode == ValidationMode::Lua) {
    if (LuaHelpers::PushHookRun(lua_interface, file_hook_name.data()) == 0) {
      return Call(filepath);
    }

    lua_interface->PushString(filepath);

    bool valid = true;
    if (LuaHelpers::CallHookRun(lua_interface, 1, 1)) {
      if (lua_interface->IsType(-1, GarrysMod::Lua::Type::Bool)) {
        valid = lua_interface->GetBool(-1);
      }

      lua_interface->Pop(1);
    }

    return valid;
  }

  if (!V_RemoveDotSlashes(&nicefile[0])) {
    return BlockDownload(filepath);
  }

  nicefile.resize(std::strlen(nicefile.c_str()));
  filepath = nicefile.c_str();

  DevMsg("[ServerSecure] Checking file \"%s\"\n", filepath);

  if (!Call(filepath)) {
    return BlockDownload(filepath);
  }

  int32_t index = downloads->FindStringIndex(filepath);
  if (index != INVALID_STRING_INDEX) {
    return true;
  }

  if (nicefile.size() == 22 &&
      std::strncmp(filepath, downloads_dir.data(), downloads_dir.size()) == 0 &&
      std::strncmp(filepath + nicefile.size() - 4, ".dat", 4) == 0) {
    return true;
  }

  return BlockDownload(filepath);
}

void Initialize(GarrysMod::Lua::ILuaBase *LUA) {
  lua_interface = dynamic_cast<GarrysMod::Lua::ILuaInterface *>(LUA);

  const auto CNetChan_IsValidFileForTransfer =
      FunctionPointers::CNetChan_IsValidFileForTransfer();
  if (CNetChan_IsValidFileForTransfer == nullptr) {
    LUA->ThrowError("unable to find CNetChan::IsValidFileForTransfer");
  }

  if (!hook.Create(
          reinterpret_cast<void *>(CNetChan_IsValidFileForTransfer),
          reinterpret_cast<void *>(&CNetChan_IsValidFileForTransfer_detour))) {
    LUA->ThrowError(
        "unable to create detour for CNetChan::IsValidFileForTransfer");
  }

  INetworkStringTableContainer *networkstringtable =
      InterfacePointers::NetworkStringTableContainerServer();
  if (networkstringtable == nullptr) {
    LUA->ThrowError("unable to get INetworkStringTableContainer");
  }

  downloads = networkstringtable->FindTable("downloadables");
  if (downloads == nullptr) {
    LUA->ThrowError("missing \"downloadables\" string table");
  }

  LUA->PushCFunction(EnableFileValidation);
  LUA->SetField(-2, "EnableFileValidation");
}

void Deinitialize() { hook.Destroy(); }
} // namespace filecheck
