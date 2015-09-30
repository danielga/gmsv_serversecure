#pragma once

#include <string>
#include <interfaces.hpp>

#if defined DEBUG

#include <dbg.h>
#include <color.h>

static Color __yellow( 255, 255, 0, 255 );
#define DebugMsg( ... ) Msg( __VA_ARGS__ )
#define DebugWarning( ... ) ConColorMsg( 1, __yellow, __VA_ARGS__ )

#else

#define DebugMsg
#define DebugWarning

#endif

namespace global
{

extern SourceSDK::FactoryLoader engine_loader;
extern std::string engine_lib;

}
