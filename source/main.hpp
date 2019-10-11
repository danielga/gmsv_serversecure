#pragma once

#include <string>
#include <GarrysMod/FactoryLoader.hpp>

#if defined DEBUG

#include <dbg.h>
#include <Color.h>

#define DebugMsg( ... ) Msg( __VA_ARGS__ )
#define DebugWarning( ... ) ConColorMsg( 1, global::__yellow, __VA_ARGS__ )

#else

#define DebugMsg( ... )
#define DebugWarning( ... )

#endif

class IServer;

namespace global
{
	extern SourceSDK::FactoryLoader engine_loader;
	extern IServer *server;

#if defined DEBUG

	static Color __yellow( 255, 255, 0, 255 );

#endif

}
