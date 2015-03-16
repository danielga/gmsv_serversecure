#include <netfilter.hpp>
#include <convar.h>
#include <unordered_set>
#include <symbolfinder.hpp>

#if defined _WIN32

#include <winsock2.h>

#elif defined __linux || defined __APPLE__

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#endif

#include <detours.h>

namespace NetFilter
{

/*#if defined _WIN32

static const char *engine_lib = "engine.dll";

static const char *NET_SendTo_sym = "\x55\x8B\xEC\x51\x8B\x0D\x2A\x2A\x2A\x2A\x83\xB9\x0C\x10\x00\x00";
static const size_t NET_SendTo_symlen = 16;

static const char *NET_SendToImpl_sym = "\x55\x8B\xEC\x8B\x45\x18\x8B\x4D\x14\x8B\x55\x10\x50\x8B\x45\x0C";
static const size_t NET_SendToImpl_symlen = 16;

#elif defined __linux

static const char *engine_lib = "bin/engine_srv.so";

static const char *NET_SendTo_sym = "_Z10NET_SendTobiPKciPK8sockaddrii";
static const size_t NET_SendTo_symlen = 0;

static const char *NET_SendToImpl_sym = "_Z14NET_SendToImpliPKciPK8sockaddrii";
static const size_t NET_SendToImpl_symlen = 0;

#elif defined __APPLE__

static const char *engine_lib = "engine.dylib";

static const char *NET_SendTo_sym = "__Z10NET_SendTobiPKciPK8sockaddrii";
static const size_t NET_SendTo_symlen = 0;

static const char *NET_SendToImpl_sym = "__Z14NET_SendToImpliPKciPK8sockaddrii";
static const size_t NET_SendToImpl_symlen = 0;

#endif*/

typedef int32_t ( *Hook_recvfrom_t )(
	int32_t s,
	char *buf,
	int32_t len,
	int32_t flags,
	sockaddr *from,
	int32_t *fromlen
);

/*typedef int32_t ( *NET_SendTo_t )(
	bool verbose,
	SOCKET s,
	const char *buf,
	int32_t len,
	const sockaddr *to,
	int32_t tolen,
	int32_t iGameDataLength
);

typedef int32_t ( *NET_SendToImpl_t )(
	SOCKET s,
	const char *buf,
	int32_t len,
	const sockaddr *to,
	int32_t tolen,
	int32_t iGameDataLength
);*/

struct Packet_t
{
	uint32 channel;
	uint8 type;
};

static ConVar ss_show_oob( "ss_show_oob", "0", 0, "Display any OOB messages received" );
static ConVar ss_oob_conservative( "ss_oob_conservative", "0", 0, "Use CPU conservation" );

static ConVarRef sv_max_queries_sec_global( "sv_max_queries_sec_global", true );
static ConVarRef sv_max_queries_window( "sv_max_queries_window", true );

static Hook_recvfrom_t Hook_recvfrom = nullptr;
/*static NET_SendTo_t NET_SendTo = nullptr;
static MologieDetours::Detour<NET_SendTo_t> *NET_SendTo_detour = nullptr;
static NET_SendToImpl_t NET_SendToImpl = nullptr;
static MologieDetours::Detour<NET_SendToImpl_t> *NET_SendToImpl_detour = nullptr;*/
static std::unordered_set<uint32_t> filter;

static bool IsDataValid( char *data, int32_t len, sockaddr_in *from )
{
	if( len == 0 )
		return false;

	if( len < 5 )
		return true;

	Packet_t *packet = reinterpret_cast<Packet_t *>( data );
	if( packet->channel == -2 )
		return false;

	if( packet->channel != -1 )
		return true;

	switch( packet->type )
	{
		case 's': // master server challenge
		{
			if( len > 100 )
			{
				if( ss_show_oob.GetBool( ) )
					Msg(
						"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
						len,
						packet->channel,
						packet->type,
						inet_ntoa( from->sin_addr )
					);

				return false;
			}

			if( len >= 18 )
			{
				if( V_strncmp( data + 4, "statusResponse", 14 ) == 0 )
				{
					if( ss_show_oob.GetBool( ) )
						Msg(
							"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
							len,
							packet->channel,
							packet->type,
							inet_ntoa( from->sin_addr )
						);

					return false;
				}
			}

			return true;
		}

		case 'T': // server info request
		case 'q': // connection handshake init
		case 'W': // server challenge request
		case 'U': // player info request
		case 'V': // rules request
		case 'k': // steam auth packet
		{
			if( ss_show_oob.GetBool( ) )
				Msg(
					"[ServerSecure] Good OOB! len: %d, channel: 0x%X, type: %c from %s\n",
					len,
					packet->channel,
					packet->type,
					inet_ntoa( from->sin_addr )
				);

			return true;
		}
	}

	if( ss_show_oob.GetBool( ) )
		Msg(
			"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
			len,
			packet->channel,
			packet->type,
			inet_ntoa( from->sin_addr )
		);

	return false;

}

#if defined _WIN32

inline int32_t SetNetError( )
{
	WSASetLastError( WSAEWOULDBLOCK );
	return -1;
}

#elif defined __linux || defined __APPLE__

inline int32_t SetNetError( )
{
	errno = EWOULDBLOCK;
	return -1;
}

#endif

inline bool IsAddressWhitelisted( const sockaddr_in *addr )
{
	return filter.find( ntohl( addr->sin_addr.s_addr ) ) != filter.end( );
}

static int32_t Hook_recvfrom_d(
	int32_t s,
	char *buf,
	int32_t len,
	int32_t flags,
	sockaddr *from,
	int32_t *fromlen
)
{
	for( int32_t i = 0; i < 2 || !ss_oob_conservative.GetBool( ); ++i )
	{
		int32_t dataLen = Hook_recvfrom( s, buf, len, flags, from, fromlen );
		if( dataLen == -1 )
			return SetNetError( );

		if( !IsAddressWhitelisted( reinterpret_cast<sockaddr_in *>( from ) ) )
			return SetNetError( );

		if( IsDataValid( buf, dataLen, reinterpret_cast<sockaddr_in *>( from ) ) )
			return dataLen;
	}

	return SetNetError( );
}

/*static int32_t NET_SendTo_d(
	bool verbose,
	SOCKET s,
	const char *buf,
	int32_t len,
	const sockaddr *to,
	int32_t tolen,
	int32_t iGameDataLength
)
{
	if( !IsAddressWhitelisted( reinterpret_cast<const sockaddr_in *>( to ) ) )
		return SetNetError( );

	return NET_SendTo( verbose, s, buf, len, to, tolen, iGameDataLength );
}

static int32_t NET_SendToImpl_d(
	SOCKET s,
	const char *buf,
	int32_t len,
	const sockaddr *to,
	int32_t tolen,
	int32_t iGameDataLength
)
{
	if( !IsAddressWhitelisted( reinterpret_cast<const sockaddr_in *>( to ) ) )
		return SetNetError( );

	return NET_SendToImpl( s, buf, len, to, tolen, iGameDataLength );
}*/

LUA_FUNCTION_STATIC( EnableFirewallWhitelist )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );

	if( LUA->GetBool( 1 ) )
	{
		g_pVCR->Hook_recvfrom = Hook_recvfrom_d;

/*		if( NET_SendTo_detour == nullptr )
		{
			NET_SendTo_detour = new( std::nothrow ) MologieDetours::Detour<NET_SendTo_t>(
				NET_SendTo, NET_SendTo_d
			);
			if( NET_SendTo_detour == nullptr )
				LUA->ThrowError( "failed to detour NET_SendTo" );
		}

		if( NET_SendToImpl_detour == nullptr )
		{
			NET_SendToImpl_detour = new( std::nothrow ) MologieDetours::Detour<NET_SendToImpl_t>(
				NET_SendToImpl, NET_SendToImpl_d
				);
			if( NET_SendToImpl_detour == nullptr )
				LUA->ThrowError( "failed to detour NET_SendToImpl" );
		}*/
	}
	else
	{
		g_pVCR->Hook_recvfrom = Hook_recvfrom;

/*		if( NET_SendTo_detour != nullptr )
		{
			delete NET_SendTo_detour;
			NET_SendTo_detour = nullptr;
		}

		if( NET_SendToImpl_detour != nullptr )
		{
			delete NET_SendToImpl_detour;
			NET_SendToImpl_detour = nullptr;
		}*/
	}

	return 0;
}

LUA_FUNCTION_STATIC( WhitelistIP )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
	filter.insert( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
	return 0;
}

LUA_FUNCTION_STATIC( RemoveIP )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
	filter.erase( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
	return 0;
}

LUA_FUNCTION_STATIC( WhitelistReset )
{
	filter.swap( std::unordered_set<uint32_t>( ) );
	return 0;
}

void Initialize( lua_State *state )
{
/*	SymbolFinder symfinder;

	NET_SendTo = reinterpret_cast<NET_SendTo_t>(
		symfinder.ResolveOnBinary( engine_lib, NET_SendTo_sym, NET_SendTo_symlen )
	);
	if( NET_SendTo == nullptr )
		LUA->ThrowError( "unable to get NET_SendTo" );

	NET_SendToImpl = reinterpret_cast<NET_SendToImpl_t>(
		symfinder.ResolveOnBinary( engine_lib, NET_SendToImpl_sym, NET_SendToImpl_symlen )
	);
	if( NET_SendToImpl == nullptr )
		LUA->ThrowError( "unable to get NET_SendToImpl" );*/

	g_pCVar->RegisterConCommand( &ss_show_oob );
	g_pCVar->RegisterConCommand( &ss_oob_conservative );

	sv_max_queries_sec_global.Init( "sv_max_queries_sec_global", false );
	sv_max_queries_sec_global.SetValue( 99999999 );

	sv_max_queries_window.Init( "sv_max_queries_window", false );
	sv_max_queries_window.SetValue( 1 );

	Hook_recvfrom = g_pVCR->Hook_recvfrom;

	LUA->PushSpecial( GarrysMod::Lua::SPECIAL_GLOB );

	LUA->PushCFunction( EnableFirewallWhitelist );
	LUA->SetField( -2, "EnableFirewallWhitelist" );

	LUA->PushCFunction( WhitelistIP );
	LUA->SetField( -2, "WhitelistIP" );

	LUA->PushCFunction( RemoveIP );
	LUA->SetField( -2, "RemoveIP" );

	LUA->PushCFunction( WhitelistReset );
	LUA->SetField( -2, "WhitelistReset" );

	LUA->Pop( 1 );
}

void Deinitialize( lua_State *state )
{
	LUA->PushSpecial( GarrysMod::Lua::SPECIAL_GLOB );

	LUA->PushNil( );
	LUA->SetField( -2, "EnableFirewallWhitelist" );

	LUA->PushNil( );
	LUA->SetField( -2, "WhitelistIP" );

	LUA->PushNil( );
	LUA->SetField( -2, "RemoveIP" );

	LUA->PushNil( );
	LUA->SetField( -2, "WhitelistReset" );

	LUA->Pop( 1 );

	g_pVCR->Hook_recvfrom = Hook_recvfrom;

	g_pCVar->UnregisterConCommand( &ss_show_oob );
	g_pCVar->UnregisterConCommand( &ss_oob_conservative );

/*	if( NET_SendTo_detour != nullptr )
	{
		delete NET_SendTo_detour;
		NET_SendTo_detour = nullptr;
	}

	if( NET_SendToImpl_detour != nullptr )
	{
		delete NET_SendToImpl_detour;
		NET_SendToImpl_detour = nullptr;
	}*/
}

}