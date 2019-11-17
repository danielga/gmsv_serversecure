#pragma once

#include <string>
#include <GarrysMod/FactoryLoader.hpp>

#if defined DEBUG

#include <dbg.h>
#include <Color.h>

#define _DebugMsg( ... ) Msg( __VA_ARGS__ )
#define _DebugWarning( ... ) ConColorMsg( 1, global::__yellow, __VA_ARGS__ )

#else

#define _DebugMsg( ... )
#define _DebugWarning( ... )

#endif

class IServer;

struct Symbol
{
	std::string name;
	size_t length;

	Symbol( const std::string &nam, size_t len = 0 );

	static Symbol FromSignature( const std::string &signature );
	static Symbol FromName( const std::string &name );
};

namespace global
{
	extern SourceSDK::FactoryLoader engine_loader;
	extern IServer *server;

#if defined DEBUG

	static Color __yellow( 255, 255, 0, 255 );

#endif

}
