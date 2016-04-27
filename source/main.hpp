#pragma once

#include <string>
#include <GarrysMod/Interfaces.hpp>

#if defined DEBUG

#include <dbg.h>
#include <Color.h>

static Color __yellow( 255, 255, 0, 255 );
#define DebugMsg( ... ) Msg( __VA_ARGS__ )
#define DebugWarning( ... ) ConColorMsg( 1, __yellow, __VA_ARGS__ )

#else

#define DebugMsg( arg, ... ) (void)arg
#define DebugWarning( arg, ... ) (void)arg

#endif

namespace global
{

extern SourceSDK::FactoryLoader engine_loader;
extern std::string engine_lib;

}
