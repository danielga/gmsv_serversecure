#include <main.hpp>
#include <netfilter/core.hpp>
#include <filecheck.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <scanning/symbolfinder.hpp>
#include <iserver.h>
#include <Platform.hpp>

namespace global
{

#if defined SYSTEM_WINDOWS

static const char IServer_sig[] =
	"\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\xD8\x6D\x24\x83\x4D\xEC\x10";
static const size_t IServer_siglen = sizeof( IServer_sig ) - 1;

#elif defined SYSTEM_LINUX

static const char IServer_sig[] = "@sv";
static const size_t IServer_siglen = 0;

#elif defined SYSTEM_MACOSX

static const char IServer_sig[] = "@_sv";
static const size_t IServer_siglen = 0;

#endif

SourceSDK::FactoryLoader engine_loader( "engine", false, true, "bin/" );
std::string engine_binary = Helpers::GetBinaryFileName( "engine", false, true, "bin/" );
IServer *server = nullptr;

LUA_FUNCTION_STATIC( GetClientCount )
{
	LUA->PushNumber( server->GetClientCount( ) );
	return 1;
}

static void PreInitialize( GarrysMod::Lua::ILuaBase *LUA )
{
	{
		SymbolFinder symfinder;

		server =

#if defined SYSTEM_POSIX

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

	LUA->PushString( "serversecure 1.5.16" );
	LUA->SetField( -2, "Version" );

	// version num follows LuaJIT style, xxyyzz
	LUA->PushNumber( 10516 );
	LUA->SetField( -2, "VersionNum" );

	LUA->PushCFunction( GetClientCount );
	LUA->SetField( -2, "GetClientCount" );
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
