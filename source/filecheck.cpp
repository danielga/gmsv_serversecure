#include <filecheck.hpp>
#include <main.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/LuaHelpers.hpp>
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <networkstringtabledefs.h>
#include <cstring>
#include <strtools.h>
#include <scanning/symbolfinder.hpp>
#include <detouring/classproxy.hpp>

namespace filecheck
{

class CNetChanProxy
{
private:
	enum ValidationMode
	{
		ValidationModeNone,
		ValidationModeFixed,
		ValidationModeLua
	};

public:
	void Initialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		lua_interface = static_cast<GarrysMod::Lua::ILuaInterface *>( LUA );

		{
			SymbolFinder symfinder;

			IsValidFileForTransfer_original =
				reinterpret_cast<IsValidFileForTransfer_t>( symfinder.ResolveOnBinary(
					global::engine_binary.c_str( ),
					IsValidFileForTransfer_sig,
					IsValidFileForTransfer_siglen
				) );
		}

		if( IsValidFileForTransfer_original == nullptr )
			LUA->ThrowError( "unable to find CNetChan::IsValidFileForTransfer" );

		if( !hook.Create( IsValidFileForTransfer_original, &CNetChanProxy::IsValidFileForTransfer ) )
			LUA->ThrowError( "unable to create detour for CNetChan::IsValidFileForTransfer" );

		INetworkStringTableContainer *networkstringtable =
			global::engine_loader.GetInterface<INetworkStringTableContainer>(
				INTERFACENAME_NETWORKSTRINGTABLESERVER
			);
		if( networkstringtable == nullptr )
			LUA->ThrowError( "unable to get INetworkStringTableContainer" );

		downloads = networkstringtable->FindTable( "downloadables" );
		if( downloads == nullptr )
			LUA->ThrowError( "missing \"downloadables\" string table" );
	}

	int32_t PostInitialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		LUA->PushCFunction( EnableFileValidation );
		LUA->SetField( -2, "EnableFileValidation" );
		return 0;
	}

	void Deinitialize( GarrysMod::Lua::ILuaBase * )
	{
		hook.Disable( );
	}

	static bool SetFileDetourStatus( ValidationMode mode )
	{
		if( mode != ValidationModeNone ? hook.Enable( ) : hook.Disable( ) )
		{
			validation_mode = mode;
			return true;
		}

		return false;
	}

	LUA_FUNCTION_STATIC_DECLARE( EnableFileValidation )
	{
		GarrysMod::Lua::ILuaBase *LUA = L->luabase;
		LUA->SetState( L );

		if( LUA->Top( ) < 1 )
			LUA->ArgError( 1, "boolean or number expected, got nil" );

		ValidationMode mode = ValidationModeFixed;
		if( LUA->IsType( 1, GarrysMod::Lua::Type::BOOL ) )
		{
			mode = LUA->GetBool( 1 ) ? ValidationModeFixed : ValidationModeNone;
		}
		else if( LUA->IsType( 1, GarrysMod::Lua::Type::NUMBER ) )
		{
			int32_t num = static_cast<int32_t>( LUA->GetNumber( 1 ) );
			if( num < 0 || num > 2 )
				LUA->ArgError( 1, "invalid mode value, must be 0, 1 or 2" );

			mode = static_cast<ValidationMode>( num );
		}
		else
		{
			LUA->ArgError( 1, "boolean or number expected" );
		}

		LUA->PushBool( SetFileDetourStatus( mode ) );
		return 1;
	}

	static bool Call( const char *filepath )
	{
		return hook.GetTrampoline<IsValidFileForTransfer_t>( )( filepath );
	}

	static bool BlockDownload( const char *filepath )
	{
		DebugWarning( "[ServerSecure] Blocking download of \"%s\"\n", filepath );
		return false;
	}

	static bool IsValidFileForTransfer( const char *filepath )
	{
		if( filepath == nullptr )
			return BlockDownload(
				"[ServerSecure] Invalid file to download (string pointer was NULL)\n"
			);

		std::string nicefile( filepath );
		if( nicefile.empty( ) )
			return BlockDownload(
				"[ServerSecure] Invalid file to download (path length was 0)\n"
			);

		if( validation_mode == ValidationModeLua )
		{
			if( !LuaHelpers::PushHookRun( lua_interface, file_hook_name ) )
				return Call( filepath );

			lua_interface->PushString( filepath );

			bool valid = true;
			if( LuaHelpers::CallHookRun( lua_interface, 1, 1 ) )
			{
				if( lua_interface->IsType( -1, GarrysMod::Lua::Type::BOOL ) )
					valid = lua_interface->GetBool( -1 );

				lua_interface->Pop( 1 );
			}

			return valid;
		}

		if( !V_RemoveDotSlashes( &nicefile[0] ) )
			return BlockDownload( filepath );

		nicefile.resize( std::strlen( nicefile.c_str( ) ) );
		filepath = nicefile.c_str( );

		DebugWarning( "[ServerSecure] Checking file \"%s\"\n", filepath );

		if( !Call( filepath ) )
			return BlockDownload( filepath );

		int32_t index = downloads->FindStringIndex( filepath );
		if( index != INVALID_STRING_INDEX )
			return true;

		if( nicefile.size( ) == 22 &&
			std::strncmp( filepath, downloads_dir, 10 ) == 0 &&
			std::strncmp( filepath + nicefile.size( ) - 4, ".dat", 4 ) == 0 )
			return true;

		return BlockDownload( filepath );
	}

	static ValidationMode validation_mode;

private:
	typedef bool ( *IsValidFileForTransfer_t )( const char *file );

	IsValidFileForTransfer_t IsValidFileForTransfer_original;

	static const char IsValidFileForTransfer_sig[];
	static const size_t IsValidFileForTransfer_siglen;
	static const char file_hook_name[];
	static const char downloads_dir[];

	static GarrysMod::Lua::ILuaInterface *lua_interface;
	static INetworkStringTable *downloads;
	static Detouring::Hook hook;
};

#if defined _WIN32

const char CNetChanProxy::IsValidFileForTransfer_sig[] =
	"\x55\x8B\xEC\x53\x8B\x5D\x08\x85\xDB\x0F\x84\x2A\x2A\x2A\x2A\x80\x3B";
const size_t CNetChanProxy::IsValidFileForTransfer_siglen =
	sizeof( CNetChanProxy::IsValidFileForTransfer_sig ) - 1;

#elif defined __linux

const char CNetChanProxy::IsValidFileForTransfer_sig[] =
	"@_ZN8CNetChan22IsValidFileForTransferEPKc";
const size_t CNetChanProxy::IsValidFileForTransfer_siglen = 0;

#elif defined __APPLE__

const char CNetChanProxy::IsValidFileForTransfer_sig[] =
	"@__ZN8CNetChan22IsValidFileForTransferEPKc";
const size_t CNetChanProxy::IsValidFileForTransfer_siglen = 0;

#endif

const char CNetChanProxy::file_hook_name[] = "IsValidFileForTransfer";
const char CNetChanProxy::downloads_dir[] = "downloads" CORRECT_PATH_SEPARATOR_S;
CNetChanProxy::ValidationMode CNetChanProxy::validation_mode = ValidationModeNone;

GarrysMod::Lua::ILuaInterface *CNetChanProxy::lua_interface = nullptr;
INetworkStringTable *CNetChanProxy::downloads = nullptr;
Detouring::Hook CNetChanProxy::hook;

static CNetChanProxy netchan_proxy;

void Initialize( GarrysMod::Lua::ILuaBase *LUA )
{
	netchan_proxy.Initialize( LUA );
}

int32_t PostInitialize( GarrysMod::Lua::ILuaBase *LUA )
{
	return netchan_proxy.PostInitialize( LUA );
}

void Deinitialize( GarrysMod::Lua::ILuaBase *LUA )
{
	netchan_proxy.Deinitialize( LUA );
}

}
