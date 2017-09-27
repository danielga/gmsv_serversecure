#pragma once

#include <string>
#include <GarrysMod/Interfaces.hpp>

#if defined DEBUG

#include <dbg.h>
#include <Color.h>

#define DebugMsg( ... ) Msg( __VA_ARGS__ )
#define DebugWarning( ... ) ConColorMsg( 1, global::__yellow, __VA_ARGS__ )

#else

#define DebugMsg( arg, ... ) (void)( arg, __VA_ARGS__ )
#define DebugWarning( arg, ... ) (void)( arg, __VA_ARGS__ )

#endif

class IServer;

namespace global
{
	extern SourceSDK::FactoryLoader engine_loader;
	extern std::string engine_binary;
	extern IServer *server;

#if defined DEBUG

	static Color __yellow( 255, 255, 0, 255 );

#endif

}
