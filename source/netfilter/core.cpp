#include "core.hpp"
#include "clientmanager.hpp"
#include "main.hpp"

#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/InterfacePointers.hpp>
#include <GarrysMod/FunctionPointers.hpp>
#include <Platform.hpp>

#include <detouring/hook.hpp>

#include <eiface.h>
#include <filesystem_stdio.h>
#include <iserver.h>
#include <threadtools.h>
#include <utlvector.h>
#include <bitbuf.h>
#include <steam/steam_gameserver.h>
#include <game/server/iplayerinfo.h>

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <queue>
#include <string>

#if defined SYSTEM_WINDOWS

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SERVERSECURE_CALLING_CONVENTION __stdcall

#include <WinSock2.h>
#include <Ws2tcpip.h>

#include <unordered_set>
#include <atomic>

typedef int32_t ssize_t;
typedef int32_t recvlen_t;

#elif defined SYSTEM_LINUX

#define SERVERSECURE_CALLING_CONVENTION

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <unordered_set>
#include <atomic>

typedef int32_t SOCKET;
typedef size_t recvlen_t;

static const SOCKET INVALID_SOCKET = -1;

#elif defined SYSTEM_MACOSX

#define SERVERSECURE_CALLING_CONVENTION

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <unordered_set>
#include <atomic>

typedef int32_t SOCKET;
typedef size_t recvlen_t;

static const SOCKET INVALID_SOCKET = -1;

#endif

class CBaseServer;

struct netsocket_t
{
	int32_t nPort;
	bool bListening;
	int32_t hUDP;
	int32_t hTCP;
};

namespace netfilter
{
	struct packet_t
	{
		packet_t( ) :
			address( ),
			address_size( sizeof( address ) )
		{ }

		sockaddr_in address;
		socklen_t address_size;
		std::vector<uint8_t> buffer;
	};

	struct server_tags_t
	{
		std::string gm;
		std::string gmws;
		std::string gmc;
		std::string loc;
		std::string ver;
	};

	struct reply_info_t
	{
		std::string game_dir;
		std::string game_version;
		std::string game_desc;
		int32_t max_clients = 0;
		int32_t udp_port = 0;
		server_tags_t tags;
	};

	enum class PacketType
	{
		Invalid = -1,
		Good,
		Info
	};

#if defined SYSTEM_WINDOWS

	static constexpr char operating_system_char = 'w';

#elif defined SYSTEM_POSIX

	static constexpr char operating_system_char = 'l';

#elif defined SYSTEM_MACOSX

	static constexpr char operating_system_char = 'm';

#endif

	static CSteamGameServerAPIContext gameserver_context;
	static bool gameserver_context_initialized = false;

	static SourceSDK::FactoryLoader icvar_loader( "vstdlib" );
	static ConVar *sv_visiblemaxplayers = nullptr;
	static ConVar *sv_location = nullptr;

	static SourceSDK::ModuleLoader dedicated_loader( "dedicated" );
	static SourceSDK::FactoryLoader server_loader( "server" );

	static ssize_t SERVERSECURE_CALLING_CONVENTION recvfrom_detour(
		SOCKET s,
		void *buf,
		recvlen_t buflen,
		int32_t flags,
		sockaddr *from,
		socklen_t *fromlen
	);
	typedef decltype( recvfrom_detour ) *recvfrom_t;

#ifdef PLATFORM_WINDOWS

	static Detouring::Hook recvfrom_hook( "ws2_32", "recvfrom", reinterpret_cast<void *>( recvfrom_detour ) );

#else

	static Detouring::Hook recvfrom_hook( "recvfrom", reinterpret_cast<void *>( recvfrom_detour ) );

#endif

	static SOCKET game_socket = INVALID_SOCKET;

	static bool packet_validation_enabled = false;

	static bool firewall_whitelist_enabled = false;
	static std::unordered_set<uint32_t> firewall_whitelist;

	static bool firewall_blacklist_enabled = false;
	static std::unordered_set<uint32_t> firewall_blacklist;

	static constexpr size_t threaded_socket_max_buffer = 8192;
	static constexpr size_t threaded_socket_max_queue = 1000;
	static std::atomic_bool threaded_socket_execute( true );
	static ThreadHandle_t threaded_socket_handle = nullptr;
	static std::queue<packet_t> threaded_socket_queue;
	static CThreadFastMutex threaded_socket_mutex;

	static constexpr char default_game_version[] = "2020.10.14";
	static constexpr uint8_t default_proto_version = 17;
	static bool info_cache_enabled = false;
	static reply_info_t reply_info;
	static char info_cache_buffer[1024] = { 0 };
	static bf_write info_cache_packet( info_cache_buffer, sizeof( info_cache_buffer ) );
	static uint32_t info_cache_last_update = 0;
	static uint32_t info_cache_time = 5;

	static ClientManager client_manager;

	static constexpr size_t packet_sampling_max_queue = 50;
	static bool packet_sampling_enabled = false;
	static std::queue<packet_t> packet_sampling_queue;
	static CThreadFastMutex packet_sampling_mutex;

	static IServerGameDLL *gamedll = nullptr;
	static IVEngineServer *engine_server = nullptr;
	static IFileSystem *filesystem = nullptr;

	inline const char *IPToString( const in_addr &addr )
	{
		static char buffer[16] = { };
		const char *str =
			inet_ntop( AF_INET, const_cast<in_addr *>( &addr ), buffer, sizeof( buffer ) );
		if( str == nullptr )
			return "unknown";

		return str;
	}

	static void BuildStaticReplyInfo( const char *game_version )
	{
		reply_info.game_desc = gamedll->GetGameDescription( );

		{
			reply_info.game_dir.resize( 256 );
			engine_server->GetGameDir( &reply_info.game_dir[0], static_cast<int32_t>( reply_info.game_dir.size( ) ) );
			reply_info.game_dir.resize( std::strlen( reply_info.game_dir.c_str( ) ) );

			size_t pos = reply_info.game_dir.find_last_of( "\\/" );
			if( pos != reply_info.game_dir.npos )
				reply_info.game_dir.erase( 0, pos + 1 );
		}

		reply_info.max_clients = global::server->GetMaxClients( );

		reply_info.udp_port = global::server->GetUDPPort( );

		{
			const IGamemodeSystem::Information &gamemode =
				static_cast<CFileSystem_Stdio *>( filesystem )->Gamemodes( )->Active( );

			if( !gamemode.name.empty( ) )
				reply_info.tags.gm = gamemode.name;
			else
				reply_info.tags.gm.clear( );

			if( gamemode.workshopid != 0 )
				reply_info.tags.gmws = std::to_string( gamemode.workshopid );
			else
				reply_info.tags.gmws.clear( );

			if( !gamemode.category.empty( ) )
				reply_info.tags.gmc = gamemode.category;
			else
				reply_info.tags.gmc.clear( );

			if( game_version != nullptr )
				reply_info.tags.ver = game_version;
		}

		{
			FileHandle_t file = filesystem->Open( "steam.inf", "r", "GAME" );
			if( file == nullptr )
			{
				reply_info.game_version = default_game_version;
				_DebugWarning( "[ServerSecure] Error opening steam.inf\n" );
				return;
			}

			char buff[256] = { 0 };
			bool failed = filesystem->ReadLine( buff, sizeof( buff ), file ) == nullptr;
			filesystem->Close( file );
			if( failed )
			{
				reply_info.game_version = default_game_version;
				_DebugWarning( "[ServerSecure] Failed reading steam.inf\n" );
				return;
			}

			reply_info.game_version = &buff[13];

			size_t pos = reply_info.game_version.find_first_of( "\r\n" );
			if( pos != reply_info.game_version.npos )
				reply_info.game_version.erase( pos );
		}
	}

	static std::string ConcatenateTags( const server_tags_t &tags )
	{
		std::string strtags;

		if( !tags.gm.empty( ) )
		{
			strtags += "gm:";
			strtags += tags.gm;
		}

		if( !tags.gmws.empty( ) )
		{
			strtags += strtags.empty( ) ? "gmws:" : " gmws:";
			strtags += tags.gmws;
		}

		if( !tags.gmc.empty( ) )
		{
			strtags += strtags.empty( ) ? "gmc:" : " gmc:";
			strtags += tags.gmc;
		}

		if( !tags.loc.empty( ) )
		{
			strtags += strtags.empty( ) ? "loc:" : " loc:";
			strtags += tags.loc;
		}

		if( !tags.ver.empty( ) )
		{
			strtags += strtags.empty( ) ? "ver:" : " ver:";
			strtags += tags.ver;
		}

		return strtags;
	}

	static void BuildReplyInfo( )
	{
		const char *server_name = global::server->GetName( );
		
		const char *map_name = global::server->GetMapName( );

		const char *game_dir = reply_info.game_dir.c_str( );

		const char *game_desc = reply_info.game_desc.c_str( );

		const int32_t appid = engine_server->GetAppID( );

		const int32_t num_clients = global::server->GetNumClients( );

		int32_t max_players =
			sv_visiblemaxplayers != nullptr ? sv_visiblemaxplayers->GetInt( ) : -1;
		if( max_players <= 0 || max_players > reply_info.max_clients )
			max_players = reply_info.max_clients;

		const int32_t num_fake_clients = global::server->GetNumFakeClients( );

		const bool has_password = global::server->GetPassword( ) != nullptr;

		if( !gameserver_context_initialized )
			gameserver_context_initialized = gameserver_context.Init( );

		bool vac_secure = false;
		if( gameserver_context_initialized )
		{
			ISteamGameServer *steamGS = gameserver_context.SteamGameServer( );
			if( steamGS != nullptr )
				vac_secure = steamGS->BSecure( );
		}

		const char *game_version = reply_info.game_version.c_str( );

		const int32_t udp_port = reply_info.udp_port;

		const CSteamID *sid = engine_server->GetGameServerSteamID( );
		const uint64_t steamid = sid != nullptr ? sid->ConvertToUint64( ) : 0;

		if( sv_location != nullptr )
			reply_info.tags.loc = sv_location->GetString( );
		else
			reply_info.tags.loc.clear( );

		const std::string tags = ConcatenateTags( reply_info.tags );
		const bool has_tags = !tags.empty( );

		info_cache_packet.Reset( );

		info_cache_packet.WriteLong( -1 ); // connectionless packet header
		info_cache_packet.WriteByte( 'I' ); // packet type is always 'I'
		info_cache_packet.WriteByte( default_proto_version );
		info_cache_packet.WriteString( server_name );
		info_cache_packet.WriteString( map_name );
		info_cache_packet.WriteString( game_dir );
		info_cache_packet.WriteString( game_desc );
		info_cache_packet.WriteShort( appid );
		info_cache_packet.WriteByte( num_clients );
		info_cache_packet.WriteByte( max_players );
		info_cache_packet.WriteByte( num_fake_clients );
		info_cache_packet.WriteByte( 'd' ); // dedicated server identifier
		info_cache_packet.WriteByte( operating_system_char );
		info_cache_packet.WriteByte( has_password ? 1 : 0 );
		info_cache_packet.WriteByte( vac_secure );
		info_cache_packet.WriteString( game_version );
		// 0x80 - port number is present
		// 0x10 - server steamid is present
		// 0x20 - tags are present
		// 0x01 - game long appid is present
		info_cache_packet.WriteByte( 0x80 | 0x10 | ( has_tags ? 0x20 : 0x00 ) | 0x01 );
		info_cache_packet.WriteShort( udp_port );
		info_cache_packet.WriteLongLong( steamid );
		if( has_tags )
			info_cache_packet.WriteString( tags.c_str( ) );
		info_cache_packet.WriteLongLong( appid );
	}

	inline PacketType SendInfoCache( const sockaddr_in &from, uint32_t time )
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

		_DebugWarning( "[ServerSecure] Handled %s info request using cache\n", IPToString( from.sin_addr ) );

		return PacketType::Invalid; // we've handled it
	}

	inline PacketType HandleInfoQuery( const sockaddr_in &from )
	{
		const uint32_t time = static_cast<uint32_t>( Plat_FloatTime( ) );
		if( !client_manager.CheckIPRate( from.sin_addr.s_addr, time ) )
		{
			_DebugWarning( "[ServerSecure] Client %s hit rate limit\n", IPToString( from.sin_addr ) );
			return PacketType::Invalid;
		}

		if( info_cache_enabled )
			return SendInfoCache( from, time );

		return PacketType::Good;
	}

	static PacketType ClassifyPacket( const uint8_t *data, int32_t len, const sockaddr_in &from )
	{
		if( len == 0 )
		{
			_DebugWarning(
				"[ServerSecure] Bad OOB! len: %d from %s\n",
				len,
				IPToString( from.sin_addr )
			);
			return PacketType::Invalid;
		}

		if( len < 5 )
			return PacketType::Good;

		const int32_t channel = *reinterpret_cast<const int32_t *>( data );
		if( channel == -2 )
		{
			_DebugWarning(
				"[ServerSecure] Bad OOB! len: %d, channel: 0x%X from %s\n",
				len,
				channel,
				IPToString( from.sin_addr )
			);
			return PacketType::Invalid;
		}

		if( channel != -1 )
			return PacketType::Good;

		const uint8_t type = *( data + 4 );
		if( packet_validation_enabled )
		{
			switch( type )
			{
			case 'W': // server challenge request
			case 's': // master server challenge
				if( len > 100 )
				{
					_DebugWarning(
						"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
						len,
						channel,
						type,
						IPToString( from.sin_addr )
					);
					return PacketType::Invalid;
				}

				if( len >= 18 && strncmp( reinterpret_cast<const char *>( data + 5 ), "statusResponse", 14 ) == 0 )
				{
					_DebugWarning(
						"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
						len,
						channel,
						type,
						IPToString( from.sin_addr )
					);
					return PacketType::Invalid;
				}

				return PacketType::Good;

			case 'T': // server info request (A2S_INFO)
				if( ( len != 25 && len != 1200 ) || strncmp( reinterpret_cast<const char *>( data + 5 ), "Source Engine Query", 19 ) != 0 )
				{
					_DebugWarning(
						"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
						len,
						channel,
						type,
						IPToString( from.sin_addr )
					);
					return PacketType::Invalid;
				}

				return PacketType::Info;

			case 'U': // player info request (A2S_PLAYER)
			case 'V': // rules request (A2S_RULES)
				if( len != 9 && len != 1200 )
				{
					_DebugWarning(
						"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
						len,
						channel,
						type,
						IPToString( from.sin_addr )
					);
					return PacketType::Invalid;
				}

				return PacketType::Good;

			case 'q': // connection handshake init
			case 'k': // steam auth packet
				_DebugMsg(
					"[ServerSecure] Good OOB! len: %d, channel: 0x%X, type: %c from %s\n",
					len,
					channel,
					type,
					IPToString( from.sin_addr )
				);
				return PacketType::Good;
			}

			_DebugWarning(
				"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
				len,
				channel,
				type,
				IPToString( from.sin_addr )
			);
			return PacketType::Invalid;
		}

		return type == 'T' ? PacketType::Info : PacketType::Good;
	}

	inline bool IsAddressAllowed( const sockaddr_in &addr )
	{
		return
			(
				!firewall_whitelist_enabled ||
				firewall_whitelist.find( addr.sin_addr.s_addr ) != firewall_whitelist.end( )
			) &&
			(
				!firewall_blacklist_enabled ||
				firewall_blacklist.find( addr.sin_addr.s_addr ) == firewall_blacklist.end( )
			);
	}

	inline int32_t HandleNetError( int32_t value )
	{
		if( value == -1 )

#if defined SYSTEM_WINDOWS

			WSASetLastError( WSAEWOULDBLOCK );

#elif defined SYSTEM_POSIX

			errno = EWOULDBLOCK;

#endif

		return value;
	}

	inline bool IsPacketQueueFull( )
	{
		AUTO_LOCK( threaded_socket_mutex );
		return threaded_socket_queue.size( ) >= threaded_socket_max_queue;
	}

	inline bool PopPacketFromQueue( packet_t &p )
	{
		AUTO_LOCK( threaded_socket_mutex );

		if( threaded_socket_queue.empty( ) )
			return false;

		p = std::move( threaded_socket_queue.front( ) );
		threaded_socket_queue.pop( );
		return true;
	}

	inline void PushPacketToQueue( packet_t &&p )
	{
		AUTO_LOCK( threaded_socket_mutex );
		threaded_socket_queue.emplace( std::move( p ) );
	}

	inline void PushPacketToSamplingQueue( packet_t &&p )
	{
		AUTO_LOCK( packet_sampling_mutex );

		if( packet_sampling_queue.size( ) >= packet_sampling_max_queue )
			packet_sampling_queue.pop( );

		packet_sampling_queue.emplace( std::move( p ) );
	}

	inline bool PopPacketFromSamplingQueue( packet_t &p )
	{
		AUTO_LOCK( packet_sampling_mutex );

		if( packet_sampling_queue.empty( ) )
			return false;

		p = std::move( packet_sampling_queue.front( ) );
		packet_sampling_queue.pop( );
		return true;
	}

	static ssize_t ReceiveAndAnalyzePacket(
		SOCKET s,
		void *buf,
		recvlen_t buflen,
		int32_t flags,
		sockaddr *from,
		socklen_t *fromlen
	)
	{
		auto trampoline = recvfrom_hook.GetTrampoline<recvfrom_t>( );
		if( trampoline == nullptr )
			return -1;

		const ssize_t len = trampoline( s, buf, buflen, flags, from, fromlen );
		_DebugWarning( "[ServerSecure] Called recvfrom on socket %d and received %d bytes\n", s, len );
		if( len == -1 )
			return -1;

		const uint8_t *buffer = reinterpret_cast<uint8_t *>( buf );
		if( packet_sampling_enabled )
		{
			packet_t p;
			std::memcpy( &p.address, from, *fromlen );
			p.address_size = *fromlen;
			p.buffer.assign( buffer, buffer + len );

			PushPacketToSamplingQueue( std::move( p ) );
		}

		const sockaddr_in &infrom = *reinterpret_cast<sockaddr_in *>( from );
		if( !IsAddressAllowed( infrom ) )
			return -1;

		_DebugWarning( "[ServerSecure] Address %s was allowed\n", IPToString( infrom.sin_addr ) );

		PacketType type = ClassifyPacket( buffer, len, infrom );
		if( type == PacketType::Info )
			type = HandleInfoQuery( infrom );

		return type != PacketType::Invalid ? len : -1;
	}

	static ssize_t SERVERSECURE_CALLING_CONVENTION recvfrom_detour(
		SOCKET s,
		void *buf,
		recvlen_t buflen,
		int32_t flags,
		sockaddr *from,
		socklen_t *fromlen
	)
	{
		if( s != game_socket )
		{
			_DebugWarning( "[ServerSecure] recvfrom detour called with socket %d, passing through\n", s );
			auto trampoline = recvfrom_hook.GetTrampoline<recvfrom_t>( );
			return trampoline != nullptr ? trampoline( s, buf, buflen, flags, from, fromlen ) : -1;
		}

		_DebugWarning( "[ServerSecure] recvfrom detour called with socket %d, detouring\n", s );
		
		packet_t p;
		const bool has_packet = PopPacketFromQueue( p );
		if( !has_packet )
			return HandleNetError( -1 );

		const ssize_t len = std::min( static_cast<ssize_t>( p.buffer.size( ) ), static_cast<ssize_t>( buflen ) );
		p.buffer.resize( static_cast<size_t>( len ) );
		std::copy( p.buffer.begin( ), p.buffer.end( ), static_cast<uint8_t *>( buf ) );

		const socklen_t addrlen = std::min( *fromlen, p.address_size );
		std::memcpy( from, &p.address, static_cast<size_t>( addrlen ) );
		*fromlen = addrlen;

		return len;
	}

	static uintp PacketReceiverThread( void * )
	{
		while( threaded_socket_execute )
		{
			if( IsPacketQueueFull( ) )
			{
				_DebugWarning( "[ServerSecure] Packet queue is full, sleeping for 100ms\n" );
				ThreadSleep( 100 );
				continue;
			}

			fd_set readables;
			FD_ZERO( &readables );
			FD_SET( game_socket, &readables );
			timeval timeout = { 0, 100000 };
			const int32_t res = select( game_socket + 1, &readables, nullptr, nullptr, &timeout );
			if( res == -1 || !FD_ISSET( game_socket, &readables ) )
				continue;

			_DebugWarning( "[ServerSecure] Select passed\n" );

			packet_t p;
			p.buffer.resize( threaded_socket_max_buffer );
			const ssize_t len = ReceiveAndAnalyzePacket(
				game_socket,
				p.buffer.data( ),
				static_cast<recvlen_t>( threaded_socket_max_buffer ),
				0,
				reinterpret_cast<sockaddr *>( &p.address ),
				&p.address_size
			);
			if( len == -1 )
				continue;

			_DebugWarning( "[ServerSecure] Pushing packet to queue\n" );

			p.buffer.resize( static_cast<size_t>( len ) );

			PushPacketToQueue( std::move( p ) );
		}

		return 0;
	}

	LUA_FUNCTION_STATIC( EnableFirewallWhitelist )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Bool );
		firewall_whitelist_enabled = LUA->GetBool( 1 );
		return 0;
	}

	// Whitelisted IPs bytes need to be in network order (big endian)
	LUA_FUNCTION_STATIC( AddWhitelistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		firewall_whitelist.insert( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( RemoveWhitelistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		firewall_whitelist.erase( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( ResetWhitelist )
	{
		std::unordered_set<uint32_t>( ).swap( firewall_whitelist );
		return 0;
	}

	LUA_FUNCTION_STATIC( EnableFirewallBlacklist )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Bool );
		firewall_blacklist_enabled = LUA->GetBool( 1 );
		return 0;
	}

	// Blacklisted IPs bytes need to be in network order (big endian)
	LUA_FUNCTION_STATIC( AddBlacklistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		firewall_blacklist.insert( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( RemoveBlacklistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		firewall_blacklist.erase( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( ResetBlacklist )
	{
		std::unordered_set<uint32_t>( ).swap( firewall_blacklist );
		return 0;
	}

	LUA_FUNCTION_STATIC( EnablePacketValidation )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Bool );
		packet_validation_enabled = LUA->GetBool( 1 );
		return 0;
	}

	LUA_FUNCTION_STATIC( EnableInfoCache )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Bool );
		info_cache_enabled = LUA->GetBool( 1 );
		return 0;
	}

	LUA_FUNCTION_STATIC( SetInfoCacheTime )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		info_cache_time = static_cast<uint32_t>( LUA->GetNumber( 1 ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( RefreshInfoCache )
	{
		BuildStaticReplyInfo( nullptr );
		BuildReplyInfo( );
		return 0;
	}

	LUA_FUNCTION_STATIC( EnableQueryLimiter )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Bool );
		client_manager.SetState( LUA->GetBool( 1 ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( SetMaxQueriesWindow )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		client_manager.SetMaxQueriesWindow( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( SetMaxQueriesPerSecond )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		client_manager.SetMaxQueriesPerSecond( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( SetGlobalMaxQueriesPerSecond )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		client_manager.SetGlobalMaxQueriesPerSecond(
			static_cast<uint32_t>( LUA->GetNumber( 1 ) )
		);
		return 0;
	}

	LUA_FUNCTION_STATIC( EnablePacketSampling )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Bool );

		packet_sampling_enabled = LUA->GetBool( 1 );
		if( !packet_sampling_enabled )
		{
			AUTO_LOCK( packet_sampling_mutex );
			std::queue<packet_t>( ).swap( packet_sampling_queue );
		}

		return 0;
	}

	LUA_FUNCTION_STATIC( GetSamplePacket )
	{
		packet_t p;
		if( !PopPacketFromSamplingQueue( p ) )
			return 0;

		LUA->PushNumber( p.address.sin_addr.s_addr );
		LUA->PushNumber( p.address.sin_port );
		LUA->PushString( reinterpret_cast<const char *>( &p.buffer[0] ), static_cast<unsigned int>( p.buffer.size( ) ) );
		return 3;
	}

	void Initialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		if( !server_loader.IsValid( ) )
			LUA->ThrowError( "unable to get server factory" );

		{
			ICvar *icvar = InterfacePointers::Cvar( );
			if( icvar != nullptr )
			{
				sv_visiblemaxplayers = icvar->FindVar( "sv_visiblemaxplayers" );
				sv_location = icvar->FindVar( "sv_location" );
			}
		}

		gamedll = InterfacePointers::ServerGameDLL( );
		if( gamedll == nullptr )
			LUA->ThrowError( "failed to load required IServerGameDLL interface" );

		engine_server = InterfacePointers::VEngineServer( );
		if( engine_server == nullptr )
			LUA->ThrowError( "failed to load required IVEngineServer interface" );

		filesystem = InterfacePointers::FileSystem( );
		if( filesystem == nullptr )
			LUA->ThrowError( "failed to initialize IFileSystem" );

		{
			const FunctionPointers::GMOD_GetNetSocket_t GetNetSocket = FunctionPointers::GMOD_GetNetSocket( );
			if( GetNetSocket != nullptr )
			{
				const netsocket_t *net_socket = GetNetSocket( 1 );
				if( net_socket != nullptr )
					game_socket = net_socket->hUDP;
			}
		}

		if( game_socket == INVALID_SOCKET )
			LUA->ThrowError( "got an invalid server socket" );

		if( !recvfrom_hook.Enable( ) )
			LUA->ThrowError( "failed to detour recvfrom" );

		threaded_socket_execute = true;
		threaded_socket_handle = CreateSimpleThread( PacketReceiverThread, nullptr );
		if( threaded_socket_handle == nullptr )
			LUA->ThrowError( "unable to create thread" );

		{
			LUA->GetField( GarrysMod::Lua::INDEX_GLOBAL, "VERSION" );
			const char *game_version = LUA->CheckString( -1 );
			BuildStaticReplyInfo( game_version );
			LUA->Pop( 1 );
		}

		LUA->PushCFunction( EnableFirewallWhitelist );
		LUA->SetField( -2, "EnableFirewallWhitelist" );

		LUA->PushCFunction( AddWhitelistIP );
		LUA->SetField( -2, "AddWhitelistIP" );

		LUA->PushCFunction( RemoveWhitelistIP );
		LUA->SetField( -2, "RemoveWhitelistIP" );

		LUA->PushCFunction( ResetWhitelist );
		LUA->SetField( -2, "ResetWhitelist" );

		LUA->PushCFunction( EnableFirewallBlacklist );
		LUA->SetField( -2, "EnableFirewallBlacklist" );

		LUA->PushCFunction( AddBlacklistIP );
		LUA->SetField( -2, "AddBlacklistIP" );

		LUA->PushCFunction( RemoveBlacklistIP );
		LUA->SetField( -2, "RemoveBlacklistIP" );

		LUA->PushCFunction( ResetBlacklist );
		LUA->SetField( -2, "ResetBlacklist" );

		LUA->PushCFunction( EnablePacketValidation );
		LUA->SetField( -2, "EnablePacketValidation" );

		LUA->PushCFunction( EnableInfoCache );
		LUA->SetField( -2, "EnableInfoCache" );

		LUA->PushCFunction( SetInfoCacheTime );
		LUA->SetField( -2, "SetInfoCacheTime" );

		LUA->PushCFunction( RefreshInfoCache );
		LUA->SetField( -2, "RefreshInfoCache" );

		LUA->PushCFunction( EnableQueryLimiter );
		LUA->SetField( -2, "EnableQueryLimiter" );

		LUA->PushCFunction( SetMaxQueriesWindow );
		LUA->SetField( -2, "SetMaxQueriesWindow" );

		LUA->PushCFunction( SetMaxQueriesPerSecond );
		LUA->SetField( -2, "SetMaxQueriesPerSecond" );

		LUA->PushCFunction( SetGlobalMaxQueriesPerSecond );
		LUA->SetField( -2, "SetGlobalMaxQueriesPerSecond" );

		LUA->PushCFunction( EnablePacketSampling );
		LUA->SetField( -2, "EnablePacketSampling" );

		LUA->PushCFunction( GetSamplePacket );
		LUA->SetField( -2, "GetSamplePacket" );
	}

	void Deinitialize( GarrysMod::Lua::ILuaBase * )
	{
		if( threaded_socket_handle != nullptr )
		{
			threaded_socket_execute = false;
			ThreadJoin( threaded_socket_handle );
			ReleaseThreadHandle( threaded_socket_handle );
			threaded_socket_handle = nullptr;
		}

		recvfrom_hook.Destroy( );
	}
}
