#pragma once

#include <GarrysMod/FactoryLoader.hpp>

#include <string>
#include <vector>

#if defined DEBUG

#include <dbg.h>
#include <Color.h>

#define _DebugMsg( ... ) Msg( __VA_ARGS__ )
#define _DebugWarning( ... ) ConColorMsg( 1, Color( 255, 255, 0, 255 ), __VA_ARGS__ )

#else

#define _DebugMsg( ... )
#define _DebugWarning( ... )

#endif

class IServer;

namespace global
{
	extern IServer *server;
}
