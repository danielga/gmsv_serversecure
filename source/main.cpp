#include <main.hpp>
#include <interfaces.hpp>
#include <netfilter.hpp>
#include <filecheck.hpp>
#include <convar.h>
#include <networkstringtabledefs.h>

namespace global
{

static SourceSDK::FactoryLoader icvar_loader( "vstdlib" );
static SourceSDK::FactoryLoader engine_loader( "engine", false );

INetworkStringTableContainer *networkstringtable = nullptr;
std::string engine_lib = helpers::GetBinaryFileName( "engine", false, true, "bin/" );

static void Initialize( lua_State *state )
{
	if( !icvar_loader.IsValid( ) )
		LUA->ThrowError( "unable to get vstdlib factory" );

	if( !engine_loader.IsValid( ) )
		LUA->ThrowError( "unable to get engine factory" );

	g_pCVar = icvar_loader.GetInterface<ICvar>( CVAR_INTERFACE_VERSION );
	if( g_pCVar == nullptr )
		LUA->ThrowError( "unable to get ICvar" );

	networkstringtable = engine_loader.GetInterface<INetworkStringTableContainer>(
		INTERFACENAME_NETWORKSTRINGTABLESERVER
	);
	if( networkstringtable == nullptr )
		LUA->ThrowError( "unable to get INetworkStringTableContainer" );

	LUA->CreateTable( );

	LUA->PushString( "serversecure 1.0.0" );
	LUA->SetField( -2, "Version" );

	// version num follows LuaJIT style, xxyyzz
	LUA->PushNumber( 10000 );
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
	global::Initialize( state );
	return 0;
}
