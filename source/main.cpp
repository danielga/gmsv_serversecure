#include <main.hpp>
#include <netfilter/core.hpp>
#include <filecheck.hpp>
#include <GarrysMod/Lua/Interface.h>

#if defined _WIN32 && _MSC_VER != 1600

#error The only supported compilation platform for this project on Windows is Visual Studio 2010 (for ABI reasons).

#elif defined __linux && (__GNUC__ != 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 4))

#error The only supported compilation platforms for this project on Linux are GCC 4.4 to 4.9 (for ABI reasons).

#elif defined __APPLE__

#include <AvailabilityMacros.h>

#if MAC_OS_X_VERSION_MIN_REQUIRED > 1050

#error The only supported compilation platform for this project on Mac OS X is GCC with Mac OS X 10.5 SDK (for ABI reasons).

#endif

#endif

namespace global
{

SourceSDK::FactoryLoader engine_loader( "engine", false, true, "bin/" );
std::string engine_lib = helpers::GetBinaryFileName( "engine", false, true, "bin/" );
static bool post_initialized = false;

LUA_FUNCTION_STATIC( PostInitialize )
{
	if( !post_initialized )
	{
		LUA->GetField( GarrysMod::Lua::INDEX_GLOBAL, "serversecure" );
		if( !LUA->IsType( -1, GarrysMod::Lua::Type::TABLE ) )
			LUA->ThrowError( "EVEN NOW, THE EVIL SEED OF WHAT YOU'VE DONE GERMINATES WITHIN YOU" );

		int32_t nrets = netfilter::PostInitialize( state );
		if( nrets != 0 )
			return nrets;

		nrets = filecheck::PostInitialize( state );
		if( nrets != 0 )
			return nrets;

		post_initialized = true;
	}

	LUA->PushBool( true );
	return 1;
}

static void PreInitialize( lua_State *state )
{
	if( !engine_loader.IsValid( ) )
		LUA->ThrowError( "unable to get engine factory" );

	LUA->CreateTable( );

	LUA->PushString( "serversecure 1.5.1" );
	LUA->SetField( -2, "Version" );

	// version num follows LuaJIT style, xxyyzz
	LUA->PushNumber( 10501 );
	LUA->SetField( -2, "VersionNum" );

	LUA->PushCFunction( PostInitialize );
	LUA->SetField( -2, "PostInitialize" );
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
