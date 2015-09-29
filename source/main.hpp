#pragma once

#include <string>
#include <interfaces.hpp>
#include <dbg.h>

#if defined DEBUG

#define DebugMsg( ... ) Msg( __VA_ARGS__ )
#define DebugWarning( ... ) Warning( __VA_ARGS__ )

#else

#define DebugMsg
#define DebugWarning

#endif

namespace global
{

extern SourceSDK::FactoryLoader engine_loader;
extern std::string engine_lib;

}
