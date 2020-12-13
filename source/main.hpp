#pragma once

#include <GarrysMod/FactoryLoader.hpp>

#include <string>
#include <vector>

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

namespace global
{
	extern IServer *server;

#if defined DEBUG

	static Color __yellow( 255, 255, 0, 255 );

#endif

}
