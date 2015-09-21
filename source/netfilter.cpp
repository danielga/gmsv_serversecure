#include <netfilter.hpp>
#include <cstdint>
#include <unordered_set>
#include <queue>
#include <convar.h>
#include <threadtools.h>
#include <utlvector.h>
#include <helpers.hpp>
#include <symbolfinder.hpp>

#if defined _WIN32

#include <winsock2.h>

#elif defined __linux || defined __APPLE__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#endif

namespace netfilter
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

	sockaddr_in address;
	int32_t address_size;
	std::vector<char> buffer;
};

typedef struct
{
	int32_t nPort;
	bool bListening;
	int32_t hUDP;
	int32_t hTCP;
} netsocket_t;

typedef CUtlVector<netsocket_t> netsockets_t;

#if defined _WIN32

static const char *NET_ProcessListen_sig = "\x55\x8b\xec\x83\xec\x34\x56\x57\x8b\x7d\x08\x8b\xf7\xc1\xe6\x04";
static size_t NET_ProcessListen_siglen = 16;

static size_t net_sockets_offset = 18;

#elif defined __linux

static const char *NET_ProcessListen_sig = "@_Z17NET_ProcessListeni";
static size_t NET_ProcessListen_siglen = 0;

static size_t net_sockets_offset = 36;

#elif defined __APPLE__

static const char *NET_ProcessListen_sig = "@__Z17NET_ProcessListeni";
static size_t NET_ProcessListen_siglen = 0;

static size_t net_sockets_offset = 23;

#endif

static ConVar ss_show_oob( "ss_show_oob", "0", 0, "Display any OOB messages received" );

static std::string engine_lib = helpers::GetBinaryFileName( "engine", false, true, "bin/" );

static Hook_recvfrom_t Hook_recvfrom = nullptr;
static int32_t game_socket = -1;

static bool check_packets = false;
static bool check_addresses = false;
static std::unordered_set<uint32_t> filter;

static ThreadHandle_t thread_socket = nullptr;
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
				if( strncmp( data + 4, "statusResponse", 14 ) == 0 )
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
	return filter.find( addr->sin_addr.s_addr ) != filter.end( );
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
	sockaddr_in *infrom = reinterpret_cast<sockaddr_in *>( from );
	if( !threaded_socket && packet_queue.empty( ) )
	{
		int32_t len = Hook_recvfrom( s, buf, buflen, flags, from, fromlen );
		if( len == -1 || ( check_addresses && !IsAddressWhitelisted( infrom ) ) )
			return SetNetError( );

		if( check_packets && !IsDataValid( buf, len, infrom ) )
			return SetNetError( );

		return len;
	}

	if( packet_queue.empty( ) )
		return SetNetError( );

	packet p = packet_queue.front( );
	packet_queue.pop( );

	int32_t len = static_cast<int32_t>( p.buffer.size( ) );
	if( len > buflen )
		len = buflen;

	size_t addrlen = static_cast<size_t>( *fromlen );
	if( addrlen > sizeof( p.address ) )
		addrlen = sizeof( p.address );

	memcpy( buf, p.buffer.data( ), len );
	memcpy( from, &p.address, addrlen );
	*fromlen = p.address_size;

	return len;
}

static uint32_t Hook_recvfrom_thread( void *param )
{
	timeval ms100 = { 0, 100000 };
	char tempbuf[65535] = { 0 };
	fd_set readables;
	FD_ZERO( &readables );
	FD_SET( game_socket, &readables );

	while( thread_execute )
	{
		if( !threaded_socket )
		{
			ThreadSleep( 100 );
			continue;
		}

		if( select( game_socket + 1, &readables, nullptr, nullptr, &ms100 ) == -1 )
			continue;

		packet p;
		sockaddr_in *infrom = reinterpret_cast<sockaddr_in *>( &p.address );
		int32_t len = Hook_recvfrom(
			game_socket,
			tempbuf,
			sizeof( tempbuf ),
			0,
			reinterpret_cast<sockaddr *>( &p.address ),
			&p.address_size
		);
		if( len == -1 || ( check_addresses && !IsAddressWhitelisted( infrom ) ) )
			continue;

		if( check_packets && !IsDataValid( tempbuf, len, infrom ) )
			continue;

		p.buffer.assign( tempbuf, tempbuf + len );
		packet_queue.push( p );
	}

	return 0;
}

inline void SetDetourStatus( bool enabled )
{
	if( enabled )
		VCRHook_recvfrom = Hook_recvfrom_d;
	else if( !check_addresses && !check_packets && !threaded_socket )
		VCRHook_recvfrom = Hook_recvfrom;
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

	if( threaded_socket )
		Msg( "[ServerSecure] Threaded socket reading was enabled! This is a rather untested feature! Use it with caution!\n" );

	return 1;
}

// Whitelisted IPs bytes need to be in network order (big endian)
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
	SymbolFinder symfinder;
	uint8_t *net_sockets_pointer = reinterpret_cast<uint8_t *>( symfinder.ResolveOnBinary(
		engine_lib.c_str( ),
		NET_ProcessListen_sig,
		NET_ProcessListen_siglen
	) );
	if( net_sockets_pointer == nullptr )
		LUA->ThrowError( "unable to sigscan for net_sockets" );

	netsockets_t *net_sockets = *reinterpret_cast<netsockets_t **>(
		net_sockets_pointer + net_sockets_offset
	);
	if( net_sockets == nullptr )
		LUA->ThrowError( "got an invalid pointer to net_sockets" );

	game_socket = net_sockets->Element( 1 ).hUDP;
	if( game_socket == -1 )
		LUA->ThrowError( "got an invalid server socket" );

	thread_execute = true;
	thread_socket = CreateSimpleThread( Hook_recvfrom_thread, nullptr );
	if( thread_socket == nullptr )
		LUA->ThrowError( "unable to create thread" );

	g_pCVar->RegisterConCommand( &ss_show_oob );

	Hook_recvfrom = VCRHook_recvfrom;

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

void Deinitialize( lua_State * )
{
	thread_execute = false;
	ThreadJoin( thread_socket );
	ReleaseThreadHandle( thread_socket );
	thread_socket = nullptr;

	VCRHook_recvfrom = Hook_recvfrom;

	g_pCVar->UnregisterConCommand( &ss_show_oob );
}

}
