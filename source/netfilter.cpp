#include <netfilter.hpp>
#include <main.hpp>
#include <cstdint>
#include <unordered_set>
#include <queue>
#include <string>
#include <ctime>
#include <eiface.h>
#include <filesystem_stdio.h>
#include <iserver.h>
#include <threadtools.h>
#include <utlvector.h>
#include <bitbuf.h>
#include <steam/steamclientpublic.h>
#include <steam/steam_gameserver.h>
#include <interfaces.hpp>
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

struct netsocket_t
{
	int32_t nPort;
	bool bListening;
	int32_t hUDP;
	int32_t hTCP;
};

typedef CUtlVector<netsocket_t> netsockets_t;

#if defined _WIN32

static const char *FileSystemFactory_sym = "\x55\x8B\xEC\x56\x8B\x75\x08\x68\x2A\x2A\x2A\x2A\x56\xE8";
static const size_t FileSystemFactory_symlen = 14;

static const char *NET_ProcessListen_sig = "\x55\x8b\xec\x83\xec\x34\x56\x57\x8b\x7d\x08\x8b\xf7\xc1\xe6\x04";
static size_t NET_ProcessListen_siglen = 16;

static const char *IServer_sig = "\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\xD8\x6D\x24\x83\x4D\xEC\x10";
static const size_t IServer_siglen = 16;

static uintptr_t GetGamemode_offset = 12;

static size_t net_sockets_offset = 18;

typedef uintptr_t ( __thiscall *GetGamemode_t )( uintptr_t );

#elif defined __linux

static const char *FileSystemFactory_sym = "@_Z17FileSystemFactoryPKcPi";
static const size_t FileSystemFactory_symlen = 0;

static const char *NET_ProcessListen_sig = "@_Z17NET_ProcessListeni";
static size_t NET_ProcessListen_siglen = 0;

static size_t net_sockets_offset = 36;

/*static const char *IServer_sig = "@sv";
static const size_t IServer_siglen = 0;*/
static const char *IServer_sig = "\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\xF3\x0F\x10\x8D\xA8\xFE\xFF";
static const size_t IServer_siglen = 16;

static uintptr_t GetGamemode_offset = 12;

typedef uintptr_t ( *GetGamemode_t )( uintptr_t );

#elif defined __APPLE__

static const char *FileSystemFactory_sym = "@__Z17FileSystemFactoryPKcPi";
static const size_t FileSystemFactory_symlen = 0;

static const char *NET_ProcessListen_sig = "@__Z17NET_ProcessListeni";
static size_t NET_ProcessListen_siglen = 0;

static size_t net_sockets_offset = 23;

static const char *IServer_sig = "\x2A\x2A\x2A\x2A\x8B\x08\x89\x04\x24\xFF\x51\x28\xD9\x9D\x9C\xFE";
static const size_t IServer_siglen = 16;

static uintptr_t GetGamemode_offset = 20;

typedef uintptr_t ( *GetGamemode_t )( uintptr_t );

#endif

static std::string dedicated_binary = helpers::GetBinaryFileName( "dedicated", false, true, "bin/" );
static SourceSDK::FactoryLoader server_loader( "server", false, true, "garrysmod/bin/" );

static Hook_recvfrom_t Hook_recvfrom = VCRHook_recvfrom;
static int32_t game_socket = -1;

static bool check_packets = false;
static bool check_addresses = false;
static std::unordered_set<uint32_t> filter;

static ThreadHandle_t thread_socket = nullptr;
static std::queue<packet> packet_queue;
static bool threaded_socket = false;
static bool thread_execute = true;

static const char *default_game_version = "15.08.10";
static uint8_t default_proto_version = 17;
static struct
{
	char game_dir[256];
	char game_desc[256];
	char game_version[256];
	int32_t appid;
	int32_t max_clients;
	int32_t proto_version;
	uint64_t steamid;
	int32_t udp_port;
	bool vac_secure;
	std::string tags;
} reply_info;
static char reply_buffer[1024] = { 0 };
static bf_write reply_packet( reply_buffer, sizeof( reply_buffer ) );
static time_t a2s_last_time = 0;
static bool info_cache = false;
static uint32_t info_cache_time = 5;

static IVEngineServer *engine_server = nullptr;
static IServer *server = nullptr;
static IServerGameDLL *gamedll = nullptr;
static IFileSystem *filesystem = nullptr;

// VS2015 compatible (possibly gcc compatible too)
struct gamemode
{
	std::string name;
	std::string path;
	std::string filters;
	std::string base;
	std::string workshopid;
};

static void BuildStaticReplyInfo( )
{
	strncpy( reply_info.game_desc, gamedll->GetGameDescription( ), sizeof( reply_info.game_desc ) );

	const CSteamID *steamid = engine_server->GetGameServerSteamID( );
	if( steamid != nullptr )
		reply_info.steamid = steamid->ConvertToUint64( );
	else
		reply_info.steamid = 0;

	reply_info.appid = engine_server->GetAppID( );

	reply_info.max_clients = server->GetMaxClients( );

	reply_info.udp_port = server->GetUDPPort( );

	reply_info.vac_secure = SteamGameServer_BSecure( );

	{
		uintptr_t gms = reinterpret_cast<CFileSystem_Stdio *>( filesystem )->Gamemodes( );
		GetGamemode_t getgm = *reinterpret_cast<GetGamemode_t *>(
			*reinterpret_cast<uintptr_t *>( gms ) + GetGamemode_offset
		);
		gamemode *gm = reinterpret_cast<gamemode *>( getgm( gms ) );

		reply_info.tags = " gm:";
		reply_info.tags += gm->path;

		if( !gm->workshopid.empty( ) )
		{
			reply_info.tags += " gmws:";
			reply_info.tags += gm->workshopid;
		}
	}

	{
		FileHandle_t file = filesystem->Open( "steam.inf", "r", "GAME" );
		if( file == nullptr )
		{
			strncpy( reply_info.game_version, default_game_version, sizeof( reply_info.game_version ) );
			Warning( "[ServerSecure] Error opening steam.inf\n" );
			return;
		}

		char buff[sizeof( reply_info.game_version )] = { 0 };
		if( filesystem->ReadLine( buff, sizeof( reply_info.game_version ), file ) == nullptr )
		{
			strncpy( reply_info.game_version, default_game_version, sizeof( reply_info.game_version ) );
			Warning( "[ServerSecure] Failed reading steam.inf\n" );
			filesystem->Close( file );
			return;
		}

		filesystem->Close( file );

		size_t len = strlen( buff );
		if( buff[len - 1] == '\n' )
			buff[len - 1] = '\0';

		strncpy( reply_info.game_version, &buff[13], sizeof( reply_info.game_version ) );
	}
}

static void BuildReplyInfo( )
{
	reply_packet.Reset( );

	reply_packet.WriteLong( -1 );
	reply_packet.WriteByte( 'I' );
	reply_packet.WriteByte( default_proto_version );
	reply_packet.WriteString( server->GetName( ) );
	reply_packet.WriteString( server->GetMapName( ) );
	reply_packet.WriteString( reply_info.game_dir );
	reply_packet.WriteString( reply_info.game_desc );
	reply_packet.WriteShort( reply_info.appid );
	reply_packet.WriteByte( server->GetNumClients( ) );
	reply_packet.WriteByte( reply_info.max_clients );
	reply_packet.WriteByte( server->GetNumFakeClients( ) );
	reply_packet.WriteByte( 'd' );

#if defined _WIN32

	reply_packet.WriteByte( 'w' );

#elif defined __linux

	reply_packet.WriteByte( 'l' );

#elif defined __APPLE__

	reply_packet.WriteByte( 'm' );

#endif

	reply_packet.WriteByte( server->GetPassword( ) != nullptr ? 1 : 0 );
	reply_packet.WriteByte( reply_info.vac_secure );
	reply_packet.WriteString( reply_info.game_version );

	if( reply_info.tags.empty( ) )
	{
		reply_packet.WriteByte( 0x80 | 0x10 );
		reply_packet.WriteShort( reply_info.udp_port );
		reply_packet.WriteLongLong( reply_info.steamid );
	}
	else
	{
		reply_packet.WriteByte( 0x80 | 0x20 | 0x10 );
		reply_packet.WriteShort( reply_info.udp_port );
		reply_packet.WriteLongLong( reply_info.steamid );
		reply_packet.WriteString( reply_info.tags.c_str( ) );
	}

	a2s_last_time = time( nullptr );
}

static bool IsDataValid( const char *data, int32_t len, const sockaddr_in &from )
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
		case 'W': // server challenge request
		case 's': // master server challenge
		{
			if( len > 100 )
			{
				DebugWarning(
					"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
					len,
					p->channel,
					p->type,
					inet_ntoa( from.sin_addr )
				);
				return false;
			}

			if( len >= 18 )
			{
				if( strncmp( &data[5], "statusResponse", 14 ) == 0 )
				{
					DebugWarning(
						"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
						len,
						p->channel,
						p->type,
						inet_ntoa( from.sin_addr )
					);
					return false;
				}
			}

			return true;
		}

		case 'T': // server info request
		{
			if( len == 25 && strncmp( &data[5], "Source Engine Query", 19 ) == 0 )
			{
				if( !info_cache )
					return true;

				if( time( nullptr ) - a2s_last_time >= info_cache_time )
					BuildReplyInfo( );

				sendto(
					game_socket,
					reinterpret_cast<char *>( reply_packet.GetData( ) ),
					reply_packet.GetNumBytesWritten( ),
					0,
					reinterpret_cast<const sockaddr *>( &from ),
					sizeof( from )
				);
			}

			return false;
		}

		case 'U': // player info request
		{
			return len == 9;
		}

		case 'V': // rules request
		{
			return len == 9;
		}

		case 'q': // connection handshake init
		case 'k': // steam auth packet
		{

#if defined _DEBUG

			Msg(
				"[ServerSecure] Good OOB! len: %d, channel: 0x%X, type: %c from %s\n",
				len,
				p->channel,
				p->type,
				inet_ntoa( from.sin_addr )
			);

#endif

			return true;
		}
	}

	DebugWarning(
		"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
		len,
		p->channel,
		p->type,
		inet_ntoa( from.sin_addr )
	);
	return false;

}

inline bool IsAddressWhitelisted( const sockaddr_in &addr )
{
	return filter.find( addr.sin_addr.s_addr ) != filter.end( );
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
	sockaddr_in infrom = { 0 };
	memcpy( &infrom, from, *fromlen > sizeof( infrom ) ? sizeof( infrom ) : *fromlen );
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

	while( thread_execute )
	{
		if( !threaded_socket )
		{
			ThreadSleep( 100 );
			continue;
		}

		FD_ZERO( &readables );
		FD_SET( game_socket, &readables );
		if( select( game_socket + 1, &readables, nullptr, nullptr, &ms100 ) == -1 || !FD_ISSET( game_socket, &readables ) )
			continue;

		packet p;
		int32_t len = Hook_recvfrom(
			game_socket,
			tempbuf,
			sizeof( tempbuf ),
			0,
			reinterpret_cast<sockaddr *>( &p.address ),
			&p.address_size
		);
		if( len == -1 || ( check_addresses && !IsAddressWhitelisted( p.address ) ) )
			continue;

		if( check_packets && !IsDataValid( tempbuf, len, p.address ) )
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
	return 0;
}

LUA_FUNCTION_STATIC( EnableInfoCache )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
	info_cache = LUA->GetBool( 1 );
	return 0;
}

LUA_FUNCTION_STATIC( SetInfoCacheTime )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
	info_cache_time = static_cast<uint32_t>( LUA->GetNumber( 1 ) );
	return 0;
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
	if( !server_loader.IsValid( ) )
		LUA->ThrowError( "unable to get server factory" );

	engine_server = global::engine_loader.GetInterface<IVEngineServer>(
		INTERFACEVERSION_VENGINESERVER_VERSION_21
	);
	if( engine_server == nullptr )
		LUA->ThrowError( "failed to load required IVEngineServer interface" );

	gamedll = server_loader.GetInterface<IServerGameDLL>( INTERFACEVERSION_SERVERGAMEDLL );
	if( gamedll == nullptr )
		LUA->ThrowError( "failed to load required IServerGameDLL interface" );

	SymbolFinder symfinder;

	CreateInterfaceFn factory = reinterpret_cast<CreateInterfaceFn>( symfinder.ResolveOnBinary(
		dedicated_binary.c_str( ), FileSystemFactory_sym, FileSystemFactory_symlen
	) );
	if( factory == nullptr )
		LUA->ThrowError( "unable to retrieve dedicated factory" );

	filesystem = static_cast<IFileSystem *>( factory( FILESYSTEM_INTERFACE_VERSION, nullptr ) );
	if( filesystem == nullptr )
		LUA->ThrowError( "failed to initialize IFileSystem" );

	IServer **pserver = reinterpret_cast<IServer **>( symfinder.ResolveOnBinary(
		global::engine_lib.c_str( ),
		IServer_sig,
		IServer_siglen
	) );
	if( pserver == nullptr )
		LUA->ThrowError( "failed to locate IServer pointer" );

	server = *pserver;
	if( server == nullptr )
		LUA->ThrowError( "failed to locate IServer" );

	uint8_t *net_sockets_pointer = reinterpret_cast<uint8_t *>( symfinder.ResolveOnBinary(
		global::engine_lib.c_str( ),
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

	BuildStaticReplyInfo( );

	LUA->PushCFunction( EnableFirewallWhitelist );
	LUA->SetField( -2, "EnableFirewallWhitelist" );

	LUA->PushCFunction( EnablePacketValidation );
	LUA->SetField( -2, "EnablePacketValidation" );

	LUA->PushCFunction( EnableThreadedSocket );
	LUA->SetField( -2, "EnableThreadedSocket" );

	LUA->PushCFunction( EnableInfoCache );
	LUA->SetField( -2, "EnableInfoCache" );

	LUA->PushCFunction( SetInfoCacheTime );
	LUA->SetField( -2, "SetInfoCacheTime" );

	LUA->PushCFunction( WhitelistIP );
	LUA->SetField( -2, "WhitelistIP" );

	LUA->PushCFunction( RemoveIP );
	LUA->SetField( -2, "RemoveIP" );

	LUA->PushCFunction( WhitelistReset );
	LUA->SetField( -2, "WhitelistReset" );
}

void Deinitialize( lua_State * )
{
	if( thread_socket != nullptr )
	{
		thread_execute = false;
		ThreadJoin( thread_socket );
		ReleaseThreadHandle( thread_socket );
		thread_socket = nullptr;
	}

	VCRHook_recvfrom = Hook_recvfrom;
}

}
