#pragma once

#include <string>
#include <interfaces.hpp>
#include <dbg.h>

#if defined _DEBUG

#define DebugWarning( ... ) Warning( __VA_ARGS__ )

#else

#define DebugWarning

#endif

namespace global
{

extern SourceSDK::FactoryLoader engine_loader;
extern std::string engine_lib;

}
