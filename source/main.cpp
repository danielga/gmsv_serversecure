#include <main.hpp>
#include <netfilter/core.hpp>
#include <filecheck.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <scanning/symbolfinder.hpp>
#include <iserver.h>
#include <Platform.hpp>

Symbol::Symbol( const std::string &nam, size_t len ) :
	name( nam ), length( len ) { }

Symbol Symbol::FromSignature( const std::string &signature )
{
	return Symbol( signature, signature.size( ) );
}

Symbol Symbol::FromName( const std::string &name )
{
	return Symbol( "@" + name );
}

namespace global
{
	static const std::string CGameServer_sym = "sv";

#if defined SYSTEM_WINDOWS

	static const Symbol IServer_sym = Symbol::FromSignature( "\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\xD8\x6D\x24\x83\x4D\xEC\x10" );

#elif defined SYSTEM_POSIX

	static const Symbol IServer_sym = Symbol::FromName( "sv" );

#endif

	SourceSDK::FactoryLoader engine_loader( "engine" );
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

			server = reinterpret_cast<IServer *>(
				engine_loader.GetSymbol( CGameServer_sym )
			);
			if( server == nullptr )
			{
				void *temp_server = symfinder.Resolve(
					engine_loader.GetModule( ),
					IServer_sym.name.c_str( ),
					IServer_sym.length
				);
				if( temp_server == nullptr )
					LUA->ThrowError( "failed to locate IServer" );

				server =

#if defined SYSTEM_POSIX

					reinterpret_cast<IServer *>

#else

					*reinterpret_cast<IServer **>

#endif

					( temp_server );
			}
		}

		if( server == nullptr )
			LUA->ThrowError( "failed to dereference IServer" );

		LUA->CreateTable( );

		LUA->PushString( "serversecure 1.5.26" );
		LUA->SetField( -2, "Version" );

		// version num follows LuaJIT style, xxyyzz
		LUA->PushNumber( 10526 );
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
