#pragma once

#include <cstdint>

struct lua_State;

namespace netfilter
{

void Initialize( lua_State *state );
int32_t PostInitialize( lua_State *state );
void Deinitialize( lua_State *state );

}
