#include <main.hpp>
#include <interfaces.hpp>
#include <netfilter.hpp>
#include <filecheck.hpp>

namespace global
{

SourceSDK::FactoryLoader engine_loader( "engine", false, true, "bin/" );
std::string engine_lib = helpers::GetBinaryFileName( "engine", false, true, "bin/" );

static void Initialize( lua_State *state )
{
	if( !engine_loader.IsValid( ) )
		LUA->ThrowError( "unable to get engine factory" );

	LUA->CreateTable( );

	LUA->PushString( "serversecure 1.1.0" );
	LUA->SetField( -2, "Version" );

	// version num follows LuaJIT style, xxyyzz
	LUA->PushNumber( 10100 );
	LUA->SetField( -2, "VersionNum" );

	LUA->Push( -1 );
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
	global::Initialize( state );
	netfilter::Initialize( state );
	filecheck::Initialize( state );
	return 1;
}

GMOD_MODULE_CLOSE( )
{
	filecheck::Deinitialize( state );
	netfilter::Deinitialize( state );
	global::Deinitialize( state );
	return 0;
}
