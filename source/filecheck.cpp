#include <filecheck.hpp>
#include <main.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/Lua/Helpers.hpp>
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <networkstringtabledefs.h>
#include <cstring>
#include <strtools.h>
#include <scanning/symbolfinder.hpp>
#include <detouring/classproxy.hpp>
#include <Platform.hpp>

namespace filecheck
{
	enum ValidationMode
	{
		ValidationModeNone,
		ValidationModeFixed,
		ValidationModeLua
	};

	typedef bool( *CNetChan__IsValidFileForTransfer_t )( const char *filepath );

#if defined SYSTEM_WINDOWS

	static const char CNetChan__IsValidFileForTransfer_sig[] =
		"\x55\x8B\xEC\x53\x8B\x5D\x08\x56\x57\x85\xDB\x0F\x84";
	static const size_t CNetChan__IsValidFileForTransfer_siglen =
		sizeof( CNetChan__IsValidFileForTransfer_sig ) - 1;

#elif defined SYSTEM_LINUX || defined SYSTEM_MACOSX

	static const char CNetChan__IsValidFileForTransfer_sig[] =
		"@_ZN8CNetChan22IsValidFileForTransferEPKc";
	static const size_t CNetChan__IsValidFileForTransfer_siglen = 0;

#endif

	static CNetChan__IsValidFileForTransfer_t CNetChan__IsValidFileForTransfer_original = nullptr;
	static const char file_hook_name[] = "IsValidFileForTransfer";
	static const char downloads_dir[] = "downloads" CORRECT_PATH_SEPARATOR_S;
	static ValidationMode validation_mode = ValidationModeNone;
	static GarrysMod::Lua::ILuaInterface *lua_interface = nullptr;
	static INetworkStringTable *downloads = nullptr;
	static Detouring::Hook hook;

	inline bool SetFileDetourStatus( ValidationMode mode )
	{
		if( mode != ValidationModeNone ? hook.Enable( ) : hook.Disable( ) )
		{
			validation_mode = mode;
			return true;
		}

		return false;
	}

	LUA_FUNCTION_STATIC( EnableFileValidation )
	{
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

	inline bool Call( const char *filepath )
	{
		return hook.GetTrampoline<CNetChan__IsValidFileForTransfer_t>( )( filepath );
	}

	inline bool BlockDownload( const char *filepath )
	{
		DebugWarning( "[ServerSecure] Blocking download of \"%s\"\n", filepath );
		return false;
	}

	static bool CNetChan_IsValidFileForTransfer_detour( const char *filepath )
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

	void Initialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		lua_interface = static_cast<GarrysMod::Lua::ILuaInterface *>( LUA );

		{
			SymbolFinder symfinder;

			CNetChan__IsValidFileForTransfer_original =
				reinterpret_cast<CNetChan__IsValidFileForTransfer_t>( symfinder.ResolveOnBinary(
					global::engine_binary.c_str( ),
					CNetChan__IsValidFileForTransfer_sig,
					CNetChan__IsValidFileForTransfer_siglen
				) );
		}

		if( CNetChan__IsValidFileForTransfer_original == nullptr )
			LUA->ThrowError( "unable to find CNetChan::IsValidFileForTransfer" );

		if( !hook.Create( reinterpret_cast<void *>( CNetChan__IsValidFileForTransfer_original ),
			reinterpret_cast<void *>( &CNetChan_IsValidFileForTransfer_detour ) ) )
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

		LUA->PushCFunction( EnableFileValidation );
		LUA->SetField( -2, "EnableFileValidation" );
	}

	void Deinitialize( GarrysMod::Lua::ILuaBase * )
	{
		hook.Disable( );
	}
}
