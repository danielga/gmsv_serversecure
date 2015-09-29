#include <netfilter.hpp>
#include <main.hpp>
#include <cstdint>
#include <set>
#include <unordered_set>
#include <queue>
#include <string>
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
#include <game/server/iplayerinfo.h>

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
	packet_t( ) :
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

struct reply_info_t
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
};

// VS2015 compatible (possibly gcc compatible too)
struct gamemode_t
{
	std::string name;
	std::string path;
	std::string filters;
	std::string base;
	std::string workshopid;
};

struct query_client_t
{
	bool operator<( const query_client_t &rhs ) const
	{
		return address < rhs.address;
	}

	bool operator==( const query_client_t &rhs ) const
	{
		return address == rhs.address;
	}

	uint32_t address;
	uint32_t last_reset;
	uint32_t count;
};

typedef CUtlVector<netsocket_t> netsockets_t;

#if defined _WIN32

static const char *FileSystemFactory_sym = "\x55\x8B\xEC\x56\x8B\x75\x08\x68\x2A\x2A\x2A\x2A\x56\xE8";
static const size_t FileSystemFactory_symlen = 14;

static const char *NET_ProcessListen_sig = "\x55\x8B\xEC\x83\xEC\x34\x56\x57\x8B\x7D\x08\x8B\xF7\xC1\xE6\x04";
static size_t NET_ProcessListen_siglen = 16;

static const size_t net_sockets_offset = 18;

static const char *IServer_sig = "\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\xD8\x6D\x24\x83\x4D\xEC\x10";
static const size_t IServer_siglen = 16;

static const uintptr_t GetGamemode_offset = 12;

typedef uintptr_t ( __thiscall *GetGamemode_t )( uintptr_t );

#elif defined __linux

static const char *FileSystemFactory_sym = "@_Z17FileSystemFactoryPKcPi";
static const size_t FileSystemFactory_symlen = 0;

static const char *NET_ProcessListen_sig = "@_Z17NET_ProcessListeni";
static const size_t NET_ProcessListen_siglen = 0;

static const size_t net_sockets_offset = 36;

/*static const char *IServer_sig = "@sv";
static const size_t IServer_siglen = 0;*/
static const char *IServer_sig = "\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\xF3\x0F\x10\x8D\xA8\xFE\xFF";
static const size_t IServer_siglen = 16;

static const uintptr_t GetGamemode_offset = 12;

typedef uintptr_t ( *GetGamemode_t )( uintptr_t );

#elif defined __APPLE__

static const char *FileSystemFactory_sym = "@__Z17FileSystemFactoryPKcPi";
static const size_t FileSystemFactory_symlen = 0;

static const char *NET_ProcessListen_sig = "@__Z17NET_ProcessListeni";
static const size_t NET_ProcessListen_siglen = 0;

static const size_t net_sockets_offset = 23;

static const char *IServer_sig = "\x2A\x2A\x2A\x2A\x8B\x08\x89\x04\x24\xFF\x51\x28\xD9\x9D\x9C\xFE";
static const size_t IServer_siglen = 16;

static const uintptr_t GetGamemode_offset = 20;

typedef uintptr_t ( *GetGamemode_t )( uintptr_t );

#endif

static std::string dedicated_binary = helpers::GetBinaryFileName( "dedicated", false, true, "bin/" );
static SourceSDK::FactoryLoader server_loader( "server", false, true, "garrysmod/bin/" );

static Hook_recvfrom_t Hook_recvfrom = VCRHook_recvfrom;
static int32_t game_socket = -1;

static bool packet_validation_enabled = false;

static bool firewall_enabled = false;
static std::unordered_set<uint32_t> firewall_whitelist;

static bool threaded_socket_enabled = false;
static bool threaded_socket_execute = true;
static ThreadHandle_t threaded_socket_handle = nullptr;
static std::queue<packet_t> threaded_socket_queue;

static const char *default_game_version = "15.08.10";
static const uint8_t default_proto_version = 17;
static bool info_cache_enabled = false;
static reply_info_t reply_info;
static char info_cache_buffer[1024] = { 0 };
static bf_write info_cache_packet( info_cache_buffer, sizeof( info_cache_buffer ) );
static uint32_t info_cache_last_update = 0;
static uint32_t info_cache_time = 5;

static const uint32_t query_limiter_max_clients = 4096;
static const uint32_t query_limiter_prune_clients = query_limiter_max_clients * 2 / 3;
static const uint32_t query_limiter_timeout_clients = 120;
static bool query_limiter_enabled = false;
static uint32_t query_limiter_global_count = 0;
static uint32_t query_limiter_global_last_reset = 0;
static std::set<query_client_t> query_limiter_clients;
static uint32_t query_limiter_max_window = 60;
static uint32_t query_limiter_max_sec = 1;
static uint32_t query_limiter_global_max_sec = 50;

static IServer *server = nullptr;
static CGlobalVars *globalvars = nullptr;

static void BuildStaticReplyInfo(
	IServerGameDLL *gamedll,
	IVEngineServer *engine_server,
	IFileSystem *filesystem
)
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
		uintptr_t gamemodes = reinterpret_cast<CFileSystem_Stdio *>( filesystem )->Gamemodes( );
		GetGamemode_t GetGamemode = *reinterpret_cast<GetGamemode_t *>(
			*reinterpret_cast<uintptr_t *>( gamemodes ) + GetGamemode_offset
		);
		gamemode_t *gamemode = reinterpret_cast<gamemode_t *>( GetGamemode( gamemodes ) );

		reply_info.tags = " gm:";
		reply_info.tags += gamemode->path;

		if( !gamemode->workshopid.empty( ) )
		{
			reply_info.tags += " gmws:";
			reply_info.tags += gamemode->workshopid;
		}
	}

	{
		FileHandle_t file = filesystem->Open( "steam.inf", "r", "GAME" );
		if( file == nullptr )
		{
			strncpy( reply_info.game_version, default_game_version, sizeof( reply_info.game_version ) );
			DebugWarning( "[ServerSecure] Error opening steam.inf\n" );
			return;
		}

		char buff[sizeof( reply_info.game_version )] = { 0 };
		if( filesystem->ReadLine( buff, sizeof( reply_info.game_version ), file ) == nullptr )
		{
			strncpy( reply_info.game_version, default_game_version, sizeof( reply_info.game_version ) );
			DebugWarning( "[ServerSecure] Failed reading steam.inf\n" );
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
	info_cache_packet.Reset( );

	info_cache_packet.WriteLong( -1 );
	info_cache_packet.WriteByte( 'I' );
	info_cache_packet.WriteByte( default_proto_version );
	info_cache_packet.WriteString( server->GetName( ) );
	info_cache_packet.WriteString( server->GetMapName( ) );
	info_cache_packet.WriteString( reply_info.game_dir );
	info_cache_packet.WriteString( reply_info.game_desc );
	info_cache_packet.WriteShort( reply_info.appid );
	info_cache_packet.WriteByte( server->GetNumClients( ) );
	info_cache_packet.WriteByte( reply_info.max_clients );
	info_cache_packet.WriteByte( server->GetNumFakeClients( ) );
	info_cache_packet.WriteByte( 'd' );

#if defined _WIN32

	info_cache_packet.WriteByte( 'w' );

#elif defined __linux

	reply_packet.WriteByte( 'l' );

#elif defined __APPLE__

	reply_packet.WriteByte( 'm' );

#endif

	info_cache_packet.WriteByte( server->GetPassword( ) != nullptr ? 1 : 0 );
	info_cache_packet.WriteByte( reply_info.vac_secure );
	info_cache_packet.WriteString( reply_info.game_version );

	if( reply_info.tags.empty( ) )
	{
		info_cache_packet.WriteByte( 0x80 | 0x10 );
		info_cache_packet.WriteShort( reply_info.udp_port );
		info_cache_packet.WriteLongLong( reply_info.steamid );
	}
	else
	{
		info_cache_packet.WriteByte( 0x80 | 0x20 | 0x10 );
		info_cache_packet.WriteShort( reply_info.udp_port );
		info_cache_packet.WriteLongLong( reply_info.steamid );
		info_cache_packet.WriteString( reply_info.tags.c_str( ) );
	}
}

inline bool CheckIPRate( uint32_t address, uint32_t time )
{
	if( query_limiter_clients.size( ) >= query_limiter_max_clients )
	{
		for( auto it = query_limiter_clients.begin( ); it != query_limiter_clients.end( ); ++it )
		{
			const query_client_t &client = *it;
			if( client.last_reset - time >= query_limiter_timeout_clients && client.address != address )
			{
				query_limiter_clients.erase( it );

				if( query_limiter_clients.size( ) <= query_limiter_prune_clients )
					break;
			}
		}
	}

	query_client_t client = { address, time, 1 };
	auto it = query_limiter_clients.find( client );
	if( it != query_limiter_clients.end( ) )
	{
		client = *it;
		query_limiter_clients.erase( it );

		if( time - client.last_reset >= query_limiter_max_window )
		{
			client.last_reset = time;
		}
		else
		{
			++client.count;
			if( client.count / query_limiter_max_window >= query_limiter_max_sec )
			{
				query_limiter_clients.insert( client );
				return false;
			}
		}
	}

	query_limiter_clients.insert( client );

	if( time - query_limiter_global_last_reset > query_limiter_max_window )
	{
		query_limiter_global_last_reset = time;
		query_limiter_global_count = 1;
	}
	else
	{
		++query_limiter_global_count;
		if( query_limiter_global_count / query_limiter_max_window >= query_limiter_global_max_sec )
			return false;
	}

	return true;
}

inline bool SendInfoCache( const sockaddr_in &from, uint32_t time )
{
	if( time - info_cache_last_update >= info_cache_time )
	{
		BuildReplyInfo( );
		info_cache_last_update = time;
	}

	sendto(
		game_socket,
		reinterpret_cast<char *>( info_cache_packet.GetData( ) ),
		info_cache_packet.GetNumBytesWritten( ),
		0,
		reinterpret_cast<const sockaddr *>( &from ),
		sizeof( from )
	);

	return false; // we've handled it
}

static bool IsDataValid( const char *data, int32_t len, const sockaddr_in &from )
{
	if( len == 0 )
		return false;

	if( len < 5 )
		return true;

	int32_t channel = *reinterpret_cast<const int32_t *>( data );
	if( channel == -2 )
		return false;

	if( channel != -1 )
		return true;

	uint8_t type = *reinterpret_cast<const uint8_t *>( data + 4 );
	switch( type )
	{
		case 'W': // server challenge request
		case 's': // master server challenge
		{
			if( len > 100 )
			{
				DebugWarning(
					"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
					len,
					channel,
					type,
					inet_ntoa( from.sin_addr )
				);
				return false;
			}

			if( len >= 18 )
			{
				if( strncmp( data + 5, "statusResponse", 14 ) == 0 )
				{
					DebugWarning(
						"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
						len,
						channel,
						type,
						inet_ntoa( from.sin_addr )
					);
					return false;
				}
			}

			return true;
		}

		case 'T': // server info request
		{
			if( len == 25 && strncmp( data + 5, "Source Engine Query", 19 ) == 0 )
			{
				uint32_t time = static_cast<uint32_t>( globalvars->realtime );
				if( query_limiter_enabled && !CheckIPRate( from.sin_addr.s_addr, time ) )
					return false;

				if( info_cache_enabled )
					return SendInfoCache( from, time );

				return true; // the query is valid, continue
			}

			return false; // the query is invalid, stop processing
		}

		case 'U': // player info request
		case 'V': // rules request
		{
			return len == 9;
		}

		case 'q': // connection handshake init
		case 'k': // steam auth packet
		{
			DebugMsg(
				"[ServerSecure] Good OOB! len: %d, channel: 0x%X, type: %c from %s\n",
				len,
				channel,
				type,
				inet_ntoa( from.sin_addr )
			);
			return true;
		}
	}

	DebugWarning(
		"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
		len,
		channel,
		type,
		inet_ntoa( from.sin_addr )
	);
	return false;
}

inline bool IsAddressWhitelisted( const sockaddr_in &addr )
{
	return firewall_whitelist.find( addr.sin_addr.s_addr ) != firewall_whitelist.end( );
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

inline packet_t GetPacket( )
{
	bool full = threaded_socket_queue.size( ) >= 1000;

	packet_t p = threaded_socket_queue.front( );
	threaded_socket_queue.pop( );

	if( full )
	{
		
	}

	return p;
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
	if( !threaded_socket_enabled && threaded_socket_queue.empty( ) )
	{
		int32_t len = Hook_recvfrom( s, buf, buflen, flags, from, fromlen );
		if( len == -1 || ( firewall_enabled && !IsAddressWhitelisted( infrom ) ) )
			return SetNetError( );

		if( packet_validation_enabled && !IsDataValid( buf, len, infrom ) )
			return SetNetError( );

		return len;
	}

	if( threaded_socket_queue.empty( ) )
		return SetNetError( );

	packet_t p = GetPacket( );
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

	while( threaded_socket_execute )
	{
		if( !threaded_socket_enabled || threaded_socket_queue.size( ) >= 1000 ) // testing for maximum queue size
		// this is a very cheap "fix", the socket itself has a queue too but will start dropping packets
		{
			ThreadSleep( 100 );
			continue;
		}

		FD_ZERO( &readables );
		FD_SET( game_socket, &readables );
		if( select( game_socket + 1, &readables, nullptr, nullptr, &ms100 ) == -1 || !FD_ISSET( game_socket, &readables ) )
			continue;

		packet_t p;
		int32_t len = Hook_recvfrom(
			game_socket,
			tempbuf,
			sizeof( tempbuf ),
			0,
			reinterpret_cast<sockaddr *>( &p.address ),
			&p.address_size
		);
		if( len == -1 || ( firewall_enabled && !IsAddressWhitelisted( p.address ) ) )
			continue;

		if( packet_validation_enabled && !IsDataValid( tempbuf, len, p.address ) )
			continue;

		p.buffer.assign( tempbuf, tempbuf + len );
		threaded_socket_queue.push( p );
	}

	return 0;
}

inline void SetDetourStatus( bool enabled )
{
	if( enabled )
		VCRHook_recvfrom = Hook_recvfrom_d;
	else if( !firewall_enabled && !packet_validation_enabled && !threaded_socket_enabled )
		VCRHook_recvfrom = Hook_recvfrom;
}

LUA_FUNCTION_STATIC( EnableFirewallWhitelist )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
	firewall_enabled = LUA->GetBool( 1 );
	SetDetourStatus( firewall_enabled );
	return 0;
}

// Whitelisted IPs bytes need to be in network order (big endian)
LUA_FUNCTION_STATIC( WhitelistIP )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
	firewall_whitelist.insert( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
	return 0;
}

LUA_FUNCTION_STATIC( RemoveIP )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
	firewall_whitelist.erase( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
	return 0;
}

LUA_FUNCTION_STATIC( WhitelistReset )
{
	std::unordered_set<uint32_t>( ).swap( firewall_whitelist );
	return 0;
}

LUA_FUNCTION_STATIC( EnablePacketValidation )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
	packet_validation_enabled = LUA->GetBool( 1 );
	SetDetourStatus( packet_validation_enabled );
	return 0;
}

LUA_FUNCTION_STATIC( EnableThreadedSocket )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
	threaded_socket_enabled = LUA->GetBool( 1 );
	SetDetourStatus( threaded_socket_enabled );
	return 0;
}

LUA_FUNCTION_STATIC( EnableInfoCache )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
	info_cache_enabled = LUA->GetBool( 1 );
	return 0;
}

LUA_FUNCTION_STATIC( SetInfoCacheTime )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
	info_cache_time = static_cast<uint32_t>( LUA->GetNumber( 1 ) );
	return 0;
}

LUA_FUNCTION_STATIC( EnableQueryLimiter )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
	query_limiter_enabled = LUA->GetBool( 1 );
	return 0;
}

LUA_FUNCTION_STATIC( SetMaxQueriesWindow )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
	query_limiter_max_window = static_cast<uint32_t>( LUA->GetNumber( 1 ) );
	return 0;
}

LUA_FUNCTION_STATIC( SetMaxQueriesPerSecond )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
	query_limiter_max_sec = static_cast<uint32_t>( LUA->GetNumber( 1 ) );
	return 0;
}

LUA_FUNCTION_STATIC( SetGlobalMaxQueriesPerSecond )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
	query_limiter_global_max_sec = static_cast<uint32_t>( LUA->GetNumber( 1 ) );
	return 0;
}

void Initialize( lua_State *state )
{
	if( !server_loader.IsValid( ) )
		LUA->ThrowError( "unable to get server factory" );

	IServerGameDLL *gamedll = server_loader.GetInterface<IServerGameDLL>( INTERFACEVERSION_SERVERGAMEDLL );
	if( gamedll == nullptr )
		LUA->ThrowError( "failed to load required IServerGameDLL interface" );

	IVEngineServer *engine_server = global::engine_loader.GetInterface<IVEngineServer>(
		INTERFACEVERSION_VENGINESERVER_VERSION_21
	);
	if( engine_server == nullptr )
		LUA->ThrowError( "failed to load required IVEngineServer interface" );

	IPlayerInfoManager *playerinfo = server_loader.GetInterface<IPlayerInfoManager>(
		INTERFACEVERSION_PLAYERINFOMANAGER
	);
	if( playerinfo == nullptr )
		LUA->ThrowError( "failed to load required IPlayerInfoManager interface" );

	globalvars = playerinfo->GetGlobalVars( );
	if( globalvars == nullptr )
		LUA->ThrowError( "failed to load required CGlobalVars interface" );

	SymbolFinder symfinder;

	CreateInterfaceFn factory = reinterpret_cast<CreateInterfaceFn>( symfinder.ResolveOnBinary(
		dedicated_binary.c_str( ), FileSystemFactory_sym, FileSystemFactory_symlen
	) );
	if( factory == nullptr )
		LUA->ThrowError( "unable to retrieve dedicated factory" );

	IFileSystem *filesystem = static_cast<IFileSystem *>( factory(
		FILESYSTEM_INTERFACE_VERSION,
		nullptr
	) );
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

	threaded_socket_execute = true;
	threaded_socket_handle = CreateSimpleThread( Hook_recvfrom_thread, nullptr );
	if( threaded_socket_handle == nullptr )
		LUA->ThrowError( "unable to create thread" );

	BuildStaticReplyInfo( gamedll, engine_server, filesystem );

	LUA->PushCFunction( EnableFirewallWhitelist );
	LUA->SetField( -2, "EnableFirewallWhitelist" );

	LUA->PushCFunction( WhitelistIP );
	LUA->SetField( -2, "WhitelistIP" );

	LUA->PushCFunction( RemoveIP );
	LUA->SetField( -2, "RemoveIP" );

	LUA->PushCFunction( WhitelistReset );
	LUA->SetField( -2, "WhitelistReset" );

	LUA->PushCFunction( EnablePacketValidation );
	LUA->SetField( -2, "EnablePacketValidation" );

	LUA->PushCFunction( EnableThreadedSocket );
	LUA->SetField( -2, "EnableThreadedSocket" );

	LUA->PushCFunction( EnableInfoCache );
	LUA->SetField( -2, "EnableInfoCache" );

	LUA->PushCFunction( SetInfoCacheTime );
	LUA->SetField( -2, "SetInfoCacheTime" );

	LUA->PushCFunction( EnableQueryLimiter );
	LUA->SetField( -2, "EnableQueryLimiter" );

	LUA->PushCFunction( SetMaxQueriesWindow );
	LUA->SetField( -2, "SetMaxQueriesWindow" );

	LUA->PushCFunction( SetMaxQueriesPerSecond );
	LUA->SetField( -2, "SetMaxQueriesPerSecond" );

	LUA->PushCFunction( SetGlobalMaxQueriesPerSecond );
	LUA->SetField( -2, "SetGlobalMaxQueriesPerSecond" );
}

void Deinitialize( lua_State * )
{
	if( threaded_socket_handle != nullptr )
	{
		threaded_socket_execute = false;
		ThreadJoin( threaded_socket_handle );
		ReleaseThreadHandle( threaded_socket_handle );
		threaded_socket_handle = nullptr;
	}

	VCRHook_recvfrom = Hook_recvfrom;
}

}
