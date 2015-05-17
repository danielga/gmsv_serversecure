#include <main.hpp>
#include <interfaces.hpp>
#include <netfilter.hpp>
#include <filecheck.hpp>
#include <interface.h>
#include <convar.h>
#include <networkstringtabledefs.h>

namespace Global
{

static SourceSDK::FactoryLoader icvar_loader( "vstdlib" );
static SourceSDK::FactoryLoader engine_loader( "engine", false );

INetworkStringTableContainer *networkstringtable = nullptr;

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

	LUA->PushSpecial( GarrysMod::Lua::SPECIAL_GLOB );

	LUA->CreateTable( );
	LUA->Push( -1 );
	LUA->SetField( -3, "serversecure" );

	LUA->Remove( -2 );
}

static void Deinitialize( lua_State *state )
{
	LUA->PushSpecial( GarrysMod::Lua::SPECIAL_GLOB );

	LUA->PushNil( );
	LUA->SetField( -2, "serversecure" );

	LUA->Pop( 1 );
}

}

GMOD_MODULE_OPEN( )
{
	Global::Initialize( state );
	NetFilter::Initialize( state );
	//FileCheck::Initialize( state );
	return 0;
}

GMOD_MODULE_CLOSE( )
{
	//FileCheck::Deinitialize( state );
	NetFilter::Deinitialize( state );
	Global::Initialize( state );
	return 0;
}