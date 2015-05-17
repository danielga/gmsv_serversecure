#include <main.hpp>
#include <netfilter.hpp>
#include <filecheck.hpp>
#include <interface.h>
#include <convar.h>
#include <networkstringtabledefs.h>
#include <interfaces.hpp>

namespace Global
{

static SourceSDK::FactoryLoader icvar_loader( "vstdlib" );
static SourceSDK::FactoryLoader engine_loader( "engine" );

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
}

static void Deinitialize( lua_State * )
{ }

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