#include <main.hpp>
#include <netfilter.hpp>
#include <filecheck.hpp>
#include <GarrysMod/Lua/Interface.h>

#if defined _WIN32 && _MSC_VER != 1600

#error The only supported compilation platform for this project on Windows is Visual Studio 2010 (for ABI reasons).

#endif

namespace global
{

SourceSDK::FactoryLoader engine_loader( "engine", false, true, "bin/" );
std::string engine_lib = helpers::GetBinaryFileName( "engine", false, true, "bin/" );

static void PreInitialize( lua_State *state )
{
	if( !engine_loader.IsValid( ) )
		LUA->ThrowError( "unable to get engine factory" );

	LUA->CreateTable( );

	LUA->PushString( "serversecure 1.3.5" );
	LUA->SetField( -2, "Version" );

	// version num follows LuaJIT style, xxyyzz
	LUA->PushNumber( 10305 );
	LUA->SetField( -2, "VersionNum" );
}

static void Initialize( lua_State *state )
{
	LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, "serversecure" );
}

static void Deinitialize( lua_State *state )
{
	LUA->PushNil( );
	LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, "serversecure" );
}

}

GMOD_MODULE_OPEN( )
{
	global::PreInitialize( state );
	netfilter::Initialize( state );
	filecheck::Initialize( state );
	global::Initialize( state );
	return 1;
}

GMOD_MODULE_CLOSE( )
{
	filecheck::Deinitialize( state );
	netfilter::Deinitialize( state );
	global::Deinitialize( state );
	return 0;
}
