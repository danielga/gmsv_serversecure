#include <netfilter.hpp>
#include <detours.h>
#include <symbolfinder.hpp>
#include <unordered_set>
#include <thread>
#include <queue>
#include <chrono>
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

namespace NetFilter
{

typedef int32_t ( *Hook_recvfrom_t )(
	int32_t s,
	char *buf,
	int32_t buflen,
	int32_t flags,
	sockaddr *from,
	int32_t *fromlen
);

struct packet_t
{
	uint32 channel;
	uint8 type;
};

struct packet
{
	packet( ) :
		address_size( sizeof( address ) )
	{ }

	sockaddr address;
	int32_t address_size;
	std::vector<char> buffer;
};

static ConVar ss_show_oob( "ss_show_oob", "0", 0, "Display any OOB messages received" );
static ConVar ss_oob_conservative( "ss_oob_conservative", "1", 0, "Use CPU conservation" );

static ConVarRef sv_max_queries_sec_global( "sv_max_queries_sec_global", true );
static ConVarRef sv_max_queries_window( "sv_max_queries_window", true );

static Hook_recvfrom_t Hook_recvfrom = nullptr;
static int32_t game_socket = -1;

static bool check_packets = false;
static bool check_addresses = false;
static std::unordered_set<uint32_t> filter;

static void Hook_recvfrom_thread( );
static std::thread thread_socket( Hook_recvfrom_thread );
static std::queue<packet> packet_queue;
static bool threaded_socket = false;
static bool thread_execute = true;

static bool IsDataValid( const char *data, int32_t len, sockaddr_in *from )
{
	if( len == 0 )
		return false;

	if( len < 5 )
		return true;

	const packet_t *p = reinterpret_cast<const packet_t *>( data );
	if( p->channel == -2 )
		return false;

	if( p->channel != -1 )
		return true;

	switch( p->type )
	{
		case 's': // master server challenge
		{
			if( len > 100 )
			{
				if( ss_show_oob.GetBool( ) )
					Msg(
						"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
						len,
						p->channel,
						p->type,
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
							p->channel,
							p->type,
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
					p->channel,
					p->type,
					inet_ntoa( from->sin_addr )
				);

			return true;
		}
	}

	if( ss_show_oob.GetBool( ) )
		Msg(
			"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
			len,
			p->channel,
			p->type,
			inet_ntoa( from->sin_addr )
		);

	return false;

}

inline bool IsAddressWhitelisted( const sockaddr_in *addr )
{
	return filter.find( ntohl( addr->sin_addr.s_addr ) ) != filter.end( );
}

inline int32_t SetNetError( )
{

#if defined _WIN32

	WSASetLastError( WSAEWOULDBLOCK );

#elif defined __linux || defined __APPLE__

	errno = EWOULDBLOCK;

#endif

	return -1;
}

static int32_t Hook_recvfrom_d(
	int32_t s,
	char *buf,
	int32_t buflen,
	int32_t flags,
	sockaddr *from,
	int32_t *fromlen
)
{
	if( game_socket == -1 )
		game_socket = s;

	sockaddr_in *infrom = reinterpret_cast<sockaddr_in *>( from );
	for( int32_t i = 0; i < 2 || !ss_oob_conservative.GetBool( ); ++i )
	{
		if( !threaded_socket && packet_queue.empty( ) )
		{
			int32_t len = Hook_recvfrom( s, buf, buflen, flags, from, fromlen );
			if( len == -1 || ( check_addresses && !IsAddressWhitelisted( infrom ) ) )
				continue;

			if( check_packets && !IsDataValid( buf, len, infrom ) )
				continue;

			return len;
		}

		if( packet_queue.empty( ) )
			break;

		packet p = packet_queue.front( );
		packet_queue.pop( );

		int32_t len = static_cast<int32_t>( p.buffer.size( ) );
		if( len > buflen )
			len = buflen;

		memcpy( buf, p.buffer.data( ), len );
		*from = p.address;
		*fromlen = p.address_size;

		return len;
	}

	return SetNetError( );
}

static void Hook_recvfrom_thread( )
{
	std::chrono::milliseconds ms100 = std::chrono::milliseconds( 100 );
	timeval cms100 = { 0, 100000 };
	fd_set readables;
	char tempbuf[65535] = { 0 };
	while( thread_execute )
	{
		if( !threaded_socket )
		{
			std::this_thread::sleep_for( ms100 );
			continue;
		}

		FD_ZERO( &readables );
		FD_SET( static_cast<uint32_t>( game_socket ), &readables );
		if( select( 1, &readables, nullptr, nullptr, &cms100 ) == -1 )
			continue;

		packet p;
		sockaddr_in *infrom = reinterpret_cast<sockaddr_in *>( &p.address );
		int32_t len = Hook_recvfrom( game_socket, tempbuf, sizeof( tempbuf ), 0, &p.address, &p.address_size );
		if( len == -1 || ( check_addresses && !IsAddressWhitelisted( infrom ) ) )
			continue;

		if( check_packets && !IsDataValid( p.buffer.data( ), len, infrom ) )
			continue;

		p.buffer.assign( tempbuf, tempbuf + len );
		packet_queue.push( p );
	}
}

inline void SetDetourStatus( bool enabled )
{
	if( enabled )
		g_pVCR->Hook_recvfrom = Hook_recvfrom_d;
	else if( !check_addresses && !check_packets && !threaded_socket )
		g_pVCR->Hook_recvfrom = Hook_recvfrom;
}

LUA_FUNCTION_STATIC( EnableFirewallWhitelist )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
	check_addresses = LUA->GetBool( 1 );
	SetDetourStatus( check_addresses );
	return 0;
}

LUA_FUNCTION_STATIC( EnablePacketValidation )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
	check_packets = LUA->GetBool( 1 );
	SetDetourStatus( check_packets );
	return 0;
}

LUA_FUNCTION_STATIC( EnableThreadedSocket )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
	threaded_socket = LUA->GetBool( 1 );
	SetDetourStatus( threaded_socket );
	return 1;
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

	LUA->PushCFunction( EnableFirewallWhitelist );
	LUA->SetField( -2, "EnableFirewallWhitelist" );

	LUA->PushCFunction( EnablePacketValidation );
	LUA->SetField( -2, "EnablePacketValidation" );

	LUA->PushCFunction( EnableThreadedSocket );
	LUA->SetField( -2, "EnableThreadedSocket" );

	LUA->PushCFunction( WhitelistIP );
	LUA->SetField( -2, "WhitelistIP" );

	LUA->PushCFunction( RemoveIP );
	LUA->SetField( -2, "RemoveIP" );

	LUA->PushCFunction( WhitelistReset );
	LUA->SetField( -2, "WhitelistReset" );
}

void Deinitialize( lua_State *state )
{
	thread_execute = false;
	thread_socket.join( );

	g_pVCR->Hook_recvfrom = Hook_recvfrom;

	g_pCVar->UnregisterConCommand( &ss_show_oob );
	g_pCVar->UnregisterConCommand( &ss_oob_conservative );
}

}