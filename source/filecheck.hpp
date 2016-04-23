#pragma once

struct lua_State;

namespace filecheck
{

void Initialize( lua_State *state );
void Deinitialize( lua_State *state );

}
