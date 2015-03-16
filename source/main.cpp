#include <main.hpp>
#include <netfilter.hpp>
#include <filecheck.hpp>
#include <interface.h>
#include <convar.h>
#include <networkstringtabledefs.h>

namespace Global
{

#if defined _WIN32

static CDllDemandLoader icvar_loader( "vstdlib.dll" );
static CDllDemandLoader engine_loader( "engine.dll" );

#elif defined __linux

static CDllDemandLoader icvar_loader( "libvstdlib_srv.so" );
static CDllDemandLoader engine_loader( "engine_srv.so" );

#elif defined __APPLE__

static CDllDemandLoader icvar_loader( "libvstdlib.dylib" );
static CDllDemandLoader engine_loader( "engine.dylib" );

#endif

INetworkStringTableContainer *networkstringtable = nullptr;

static void Initialize( lua_State *state )
{
	CreateInterfaceFn vstdlibfactory = icvar_loader.GetFactory( );
	if( vstdlibfactory == nullptr )
		LUA->ThrowError( "unable to get vstdlib factory" );

	g_pCVar = reinterpret_cast<ICvar *>( vstdlibfactory( CVAR_INTERFACE_VERSION, nullptr ) );
	if( g_pCVar == nullptr )
		LUA->ThrowError( "unable to get ICvar" );

	CreateInterfaceFn enginefactory = engine_loader.GetFactory( );
	if( enginefactory == nullptr )
		LUA->ThrowError( "unable to get engine factory" );

	networkstringtable = reinterpret_cast<INetworkStringTableContainer *>(
		enginefactory( INTERFACENAME_NETWORKSTRINGTABLESERVER, nullptr )
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