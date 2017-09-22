#include <main.hpp>
#include <netfilter/core.hpp>
#include <filecheck.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <scanning/symbolfinder.hpp>
#include <iserver.h>

namespace global
{

#if defined _WIN32

static const char IServer_sig[] =
	"\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\xD8\x6D\x24\x83\x4D\xEC\x10";
static const size_t IServer_siglen = sizeof( IServer_sig ) - 1;

#elif defined __linux

static const char IServer_sig[] = "@sv";
static const size_t IServer_siglen = 0;

#elif defined __APPLE__

static const char IServer_sig[] = "@_sv";
static const size_t IServer_siglen = 0;

#endif

SourceSDK::FactoryLoader engine_loader( "engine", false, true, "bin/" );
std::string engine_binary = Helpers::GetBinaryFileName( "engine", false, true, "bin/" );
IServer *server = nullptr;
static bool post_initialized = false;

LUA_FUNCTION_STATIC( GetClientCount )
{
	LUA->PushNumber( server->GetClientCount( ) );
	return 1;
}

LUA_FUNCTION_STATIC( PostInitialize )
{
	if( !post_initialized )
	{
		LUA->GetField( GarrysMod::Lua::INDEX_GLOBAL, "serversecure" );
		if( !LUA->IsType( -1, GarrysMod::Lua::Type::TABLE ) )
			LUA->ThrowError( "EVEN NOW, THE EVIL SEED OF WHAT YOU'VE DONE GERMINATES WITHIN YOU" );

		LUA->PushCFunction( GetClientCount );
		LUA->SetField( -2, "GetClientCount" );

		int32_t nrets = netfilter::PostInitialize( LUA );
		if( nrets != 0 )
			return nrets;

		nrets = filecheck::PostInitialize( LUA );
		if( nrets != 0 )
			return nrets;

		post_initialized = true;
	}

	LUA->PushBool( true );
	return 1;
}

static void PreInitialize( GarrysMod::Lua::ILuaBase *LUA )
{
	{
		SymbolFinder symfinder;

		server =

#if defined __linux || defined __APPLE__

			reinterpret_cast<IServer *>

#else

			*reinterpret_cast<IServer **>

#endif

			( symfinder.ResolveOnBinary(
				engine_binary.c_str( ),
				IServer_sig,
				IServer_siglen
			) );
	}

	if( server == nullptr )
		LUA->ThrowError( "failed to locate IServer" );

	LUA->CreateTable( );

	LUA->PushString( "serversecure 1.5.12" );
	LUA->SetField( -2, "Version" );

	// version num follows LuaJIT style, xxyyzz
	LUA->PushNumber( 10512 );
	LUA->SetField( -2, "VersionNum" );

	LUA->PushCFunction( PostInitialize );
	LUA->SetField( -2, "PostInitialize" );

	post_initialized = false;
}

static void Initialize( GarrysMod::Lua::ILuaBase *LUA )
{
	LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, "serversecure" );
}

static void Deinitialize( GarrysMod::Lua::ILuaBase *LUA )
{
	LUA->PushNil( );
	LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, "serversecure" );
}

}

GMOD_MODULE_OPEN( )
{
	global::PreInitialize( LUA );
	netfilter::Initialize( LUA );
	filecheck::Initialize( LUA );
	global::Initialize( LUA );
	return 1;
}

GMOD_MODULE_CLOSE( )
{
	filecheck::Deinitialize( LUA );
	netfilter::Deinitialize( LUA );
	global::Deinitialize( LUA );
	return 0;
}
