#include <netfilter.hpp>
#include <convar.h>

#if defined _WIN32

#include <winsock2.h>

#elif defined __linux || defined __APPLE__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#endif

#if defined __linux || defined __APPLE__

#undef min
#undef max

#endif

#include <detours.h>
#include <symbolfinder.hpp>
#include <unordered_set>

namespace NetFilter
{

typedef int32_t ( *Hook_recvfrom_t )(
	int32_t s,
	char *buf,
	int32_t len,
	int32_t flags,
	sockaddr *from,
	int32_t *fromlen
);

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
static std::unordered_set<uint32_t> filter;
static bool check_packets = false;
static bool check_addresses = false;

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

inline bool IsAddressWhitelisted( const sockaddr_in *addr )
{
	return filter.find( ntohl( addr->sin_addr.s_addr ) ) != filter.end( );
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

static int32_t Hook_recvfrom_d(
	int32_t s,
	char *buf,
	int32_t len,
	int32_t flags,
	sockaddr *from,
	int32_t *fromlen
)
{
	sockaddr_in *infrom = reinterpret_cast<sockaddr_in *>( from );
	for( int32_t i = 0; i < 2 || !ss_oob_conservative.GetBool( ); ++i )
	{
		int32_t dataLen = Hook_recvfrom( s, buf, len, flags, from, fromlen );
		if( dataLen == -1 || ( check_addresses && !IsAddressWhitelisted( infrom ) ) )
			return SetNetError( );

		if( !check_packets || IsDataValid( buf, dataLen, infrom ) )
			return dataLen;
	}

	return SetNetError( );
}

inline void EnableDetour( bool enable )
{
	if( enable )
		g_pVCR->Hook_recvfrom = Hook_recvfrom_d;
	else if( !check_addresses && !check_packets )
		g_pVCR->Hook_recvfrom = Hook_recvfrom;
}

LUA_FUNCTION_STATIC( EnableFirewallWhitelist )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
	check_addresses = LUA->GetBool( 1 );
	EnableDetour( check_addresses );
	return 0;
}

LUA_FUNCTION_STATIC( EnablePacketValidation )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
	check_packets = LUA->GetBool( 1 );
	EnableDetour( check_packets );
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
	std::unordered_set<uint32_t>( ).swap( filter );
	return 0;
}

void Initialize( lua_State *state )
{
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
}

}