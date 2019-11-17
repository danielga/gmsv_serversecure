#include "core.hpp"
#include "clientmanager.hpp"
#include "main.hpp"

#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/FactoryLoader.hpp>
#include <detouring/hook.hpp>
#include <cstdint>
#include <cstddef>
#include <queue>
#include <string>
#include <eiface.h>
#include <filesystem_stdio.h>
#include <iserver.h>
#include <threadtools.h>
#include <utlvector.h>
#include <bitbuf.h>
#include <steam/steam_gameserver.h>
#include <game/server/iplayerinfo.h>
#include <scanning/symbolfinder.hpp>
#include <Platform.hpp>

#if defined SYSTEM_WINDOWS

#define WIN32_LEAN_AND_MEAN

#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <unordered_set>
#include <atomic>

typedef int32_t ssize_t;
typedef int32_t socklen_t;
typedef int32_t recvlen_t;

#elif defined SYSTEM_LINUX

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unordered_set>
#include <atomic>

typedef int32_t SOCKET;
typedef int32_t recvlen_t;

static const SOCKET INVALID_SOCKET = -1;

#elif defined SYSTEM_MACOSX

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unordered_set>
#include <atomic>

typedef int32_t SOCKET;
typedef int32_t recvlen_t;

static const SOCKET INVALID_SOCKET = -1;

#endif

class CBaseServer;

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

	struct netsocket_t
	{
		int32_t nPort;
		bool bListening;
		int32_t hUDP;
		int32_t hTCP;
	};

	struct reply_info_t
	{
		std::string game_dir;
		std::string game_version;
		std::string game_desc;
		int32_t max_clients = 0;
		int32_t udp_port = 0;
		std::string tags;
	};

	enum PacketType
	{
		PacketTypeInvalid = -1,
		PacketTypeGood,
		PacketTypeInfo
	};

	class CSteamGameServerAPIContext
	{
	public:
		ISteamClient *m_pSteamClient;
		ISteamGameServer *m_pSteamGameServer;
		ISteamUtils *m_pSteamGameServerUtils;
		ISteamNetworking *m_pSteamGameServerNetworking;
		ISteamGameServerStats *m_pSteamGameServerStats;
		ISteamHTTP *m_pSteamHTTP;
		ISteamInventory *m_pSteamInventory;
		ISteamUGC *m_pSteamUGC;
		ISteamApps *m_pSteamApps;
	};

	typedef CUtlVector<netsocket_t> netsockets_t;

	typedef netsocket_t *( *GetNetSocket_t )( int idx );

#if defined SYSTEM_WINDOWS

	static const std::string CSteamGameServerAPIContext_sym =
		"?s_SteamGameServerAPIContext@@3VCSteamGameServerAPIContext@@A";
	static const Symbol SteamGameServerAPIContext_sym =
		Symbol::FromSignature("\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\x6A\x00\x68\x2A\x2A\x2A\x2A\xFF\x55\x08\x83\xC4\x08\xA3");

	static const std::vector<Symbol> FileSystemFactory_syms = {
		Symbol::FromName( "?FileSystemFactory@@YAPAXPBDPAH@Z" ),
		Symbol::FromSignature( "\x55\x8B\xEC\x68\x2A\x2A\x2A\x2A\xFF\x75\x08\xE8" )
	};

	static const Symbol g_pFullFileSystem_sym = Symbol::FromName( "g_pFullFileSystem" );

	static const std::string GetNetSocket_sym = "?GMOD_GetNetSocket@@YAPAUnetsocket_t@@H@Z";
	static const Symbol net_sockets_sym = Symbol::FromSignature(
		"\x2A\x2A\x2A\x2A\x80\x7E\x04\x00\x0F\x84\x2A\x2A\x2A\x2A\xA1\x2A\x2A\x2A\x2A\xC7\x45\xF8\x10" );

	static const char operating_system_char = 'w';

#elif defined SYSTEM_POSIX

	static const std::string CSteamGameServerAPIContext_sym = "s_SteamGameServerAPIContext";
	static const Symbol SteamGameServerAPIContext_sym =
		Symbol::FromName( "_ZL27s_SteamGameServerAPIContext" );

	static const std::vector<Symbol> FileSystemFactory_syms = {
		Symbol::FromName( "_Z17FileSystemFactoryPKcPi" )
	};

	static const Symbol g_pFullFileSystem_sym = Symbol::FromName( "g_pFullFileSystem" );

	static const std::string GetNetSocket_sym = "_Z17GMOD_GetNetSocketi";
	static const Symbol net_sockets_sym = Symbol::FromName( "_ZL11net_sockets" );

#if defined SYSTEM_LINUX
	static const char operating_system_char = 'l';
#elif defined SYSTEM_MACOSX
	static const char operating_system_char = 'm';
#endif

#endif

	static CSteamGameServerAPIContext *gameserver_context = nullptr;

	static SourceSDK::FactoryLoader icvar_loader( "vstdlib" );
	static ConVar *sv_visiblemaxplayers = nullptr;

	static SourceSDK::ModuleLoader dedicated_loader( "dedicated" );
	static SourceSDK::FactoryLoader server_loader( "server" );

	static ssize_t recvfrom_detour(
		SOCKET s,
		void *buf,
		recvlen_t buflen,
		int32_t flags,
		sockaddr *from,
		socklen_t *fromlen
	);
	typedef decltype( recvfrom_detour ) *recvfrom_t;

	static Detouring::Hook recvfrom_hook( "recvfrom", reinterpret_cast<void *>( recvfrom_detour ) );

	static SOCKET game_socket = INVALID_SOCKET;

	static bool packet_validation_enabled = false;

	static bool firewall_whitelist_enabled = false;
	static std::unordered_set<uint32_t> firewall_whitelist;

	static bool firewall_blacklist_enabled = false;
	static std::unordered_set<uint32_t> firewall_blacklist;

	static const size_t threaded_socket_max_queue = 1000;
	static std::atomic_bool threaded_socket_enabled( false );
	static std::atomic_bool threaded_socket_execute( true );
	static ThreadHandle_t threaded_socket_handle = nullptr;
	static std::queue<packet_t> threaded_socket_queue;
	static CThreadFastMutex threaded_socket_mutex;

	static const char *default_game_version = "16.12.01";
	static const uint8_t default_proto_version = 17;
	static bool info_cache_enabled = false;
	static reply_info_t reply_info;
	static char info_cache_buffer[1024] = { 0 };
	static bf_write info_cache_packet( info_cache_buffer, sizeof( info_cache_buffer ) );
	static uint32_t info_cache_last_update = 0;
	static uint32_t info_cache_time = 5;

	static ClientManager client_manager;

	static const size_t packet_sampling_max_queue = 50;
	static std::atomic_bool packet_sampling_enabled( false );
	static std::deque<packet_t> packet_sampling_queue;
	static CThreadFastMutex packet_sampling_mutex;

	static CGlobalVars *globalvars = nullptr;
	static IServerGameDLL *gamedll = nullptr;
	static IVEngineServer *engine_server = nullptr;
	static IFileSystem *filesystem = nullptr;

	static void BuildStaticReplyInfo( )
	{
		reply_info.game_desc = gamedll->GetGameDescription( );

		{
			reply_info.game_dir.resize( 256 );
			engine_server->GetGameDir( &reply_info.game_dir[0], static_cast<int32_t>( reply_info.game_dir.size( ) ) );
			reply_info.game_dir.resize( strlen( reply_info.game_dir.c_str( ) ) );

			size_t pos = reply_info.game_dir.find_last_of( "\\/" );
			if( pos != reply_info.game_dir.npos )
				reply_info.game_dir.erase( 0, pos + 1 );
		}

		reply_info.max_clients = global::server->GetMaxClients( );

		reply_info.udp_port = global::server->GetUDPPort( );

		{
			const IGamemodeSystem::Information &gamemode =
				static_cast<CFileSystem_Stdio *>( filesystem )->Gamemodes( )->Active( );

			reply_info.tags = " gm:";
			reply_info.tags += gamemode.name;

			if( !gamemode.workshopid.empty( ) )
			{
				reply_info.tags += " gmws:";
				reply_info.tags += gamemode.workshopid;
			}
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

	// maybe divide into low priority and high priority data?
	// low priority would be VAC protection status for example
	// updated on a much bigger period
	static void BuildReplyInfo( )
	{
		info_cache_packet.Reset( );

		info_cache_packet.WriteLong( -1 ); // connectionless packet header
		info_cache_packet.WriteByte( 'I' ); // packet type is always 'I'
		info_cache_packet.WriteByte( default_proto_version );
		info_cache_packet.WriteString( global::server->GetName( ) );
		info_cache_packet.WriteString( global::server->GetMapName( ) );
		info_cache_packet.WriteString( reply_info.game_dir.c_str( ) );
		info_cache_packet.WriteString( reply_info.game_desc.c_str( ) );

		int32_t appid = engine_server->GetAppID( );
		info_cache_packet.WriteShort( appid );

		info_cache_packet.WriteByte( global::server->GetNumClients( ) );
		int32_t maxplayers =
			sv_visiblemaxplayers != nullptr ? sv_visiblemaxplayers->GetInt( ) : -1;
		if( maxplayers <= 0 || maxplayers > reply_info.max_clients )
			maxplayers = reply_info.max_clients;
		info_cache_packet.WriteByte( maxplayers );
		info_cache_packet.WriteByte( global::server->GetNumFakeClients( ) );
		info_cache_packet.WriteByte( 'd' ); // dedicated server identifier
		info_cache_packet.WriteByte( operating_system_char );
		info_cache_packet.WriteByte( global::server->GetPassword( ) != nullptr ? 1 : 0 );
		// if vac protected, it activates itself some time after startup
		ISteamGameServer *steamGS = gameserver_context != nullptr ?
			gameserver_context->m_pSteamGameServer : nullptr;
		info_cache_packet.WriteByte( steamGS != nullptr ? steamGS->BSecure( ) : false );
		info_cache_packet.WriteString( reply_info.game_version.c_str( ) );

		const CSteamID *sid = engine_server->GetGameServerSteamID( );
		uint64_t steamid = 0;
		if( sid != nullptr )
			steamid = sid->ConvertToUint64( );

		bool notags = reply_info.tags.empty( );
		// 0x80 - port number is present
		// 0x10 - server steamid is present
		// 0x20 - tags are present
		// 0x01 - game long appid is present
		info_cache_packet.WriteByte( 0x80 | 0x10 | ( notags ? 0x00 : 0x20 ) | 0x01 );
		info_cache_packet.WriteShort( reply_info.udp_port );
		info_cache_packet.WriteLongLong( steamid );
		if( !notags )
			info_cache_packet.WriteString( reply_info.tags.c_str( ) );
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

		return PacketTypeInvalid; // we've handled it
	}

	inline PacketType HandleInfoQuery( const sockaddr_in &from )
	{
		uint32_t time = static_cast<uint32_t>( globalvars->realtime );
		if( !client_manager.CheckIPRate( from.sin_addr.s_addr, time ) )
			return PacketTypeInvalid;

		if( info_cache_enabled )
			return SendInfoCache( from, time );

		return PacketTypeGood;
	}

	inline const char *IPToString( const in_addr &addr )
	{
		static char buffer[16] = { };
		const char *str =
			inet_ntop( AF_INET, const_cast<in_addr *>( &addr ), buffer, sizeof( buffer ) );
		if( str == nullptr )
			return "unknown";

		return str;
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
			return PacketTypeInvalid;
		}

		if( len < 5 )
			return PacketTypeGood;

		int32_t channel = *reinterpret_cast<const int32_t *>( data );
		if( channel == -2 )
		{
			_DebugWarning(
				"[ServerSecure] Bad OOB! len: %d, channel: 0x%X from %s\n",
				len,
				channel,
				IPToString( from.sin_addr )
			);
			return PacketTypeInvalid;
		}

		if( channel != -1 )
			return PacketTypeGood;

		uint8_t type = *( data + 4 );
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
					return PacketTypeInvalid;
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
					return PacketTypeInvalid;
				}

				return PacketTypeGood;

			case 'T': // server info request
				return len == 25 && strncmp( reinterpret_cast<const char *>( data + 5 ), "Source Engine Query", 19 ) == 0 ?
					PacketTypeInfo : PacketTypeInvalid;

			case 'U': // player info request
			case 'V': // rules request
				return len == 9 ? PacketTypeGood : PacketTypeInvalid;

			case 'q': // connection handshake init
			case 'k': // steam auth packet
				_DebugMsg(
					"[ServerSecure] Good OOB! len: %d, channel: 0x%X, type: %c from %s\n",
					len,
					channel,
					type,
					IPToString( from.sin_addr )
				);
				return PacketTypeGood;
			}

			_DebugWarning(
				"[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
				len,
				channel,
				type,
				IPToString( from.sin_addr )
			);
			return PacketTypeInvalid;
		}

		return type == 'T' ? PacketTypeInfo : PacketTypeGood;
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

	inline packet_t GetQueuedPacket( )
	{
		AUTO_LOCK( threaded_socket_mutex );
		packet_t p = threaded_socket_queue.front( );
		threaded_socket_queue.pop( );
		return p;
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
		sockaddr_in &infrom = *reinterpret_cast<sockaddr_in *>( from );
		ssize_t len = recvfrom_hook.GetTrampoline<recvfrom_t>( )( s, buf, buflen, flags, from, fromlen );
		if( len == -1 )
			return -1;

		const uint8_t *buffer = reinterpret_cast<uint8_t *>( buf );
		if( packet_sampling_enabled )
		{
			packet_t p;
			memcpy( &p.address, from, *fromlen );
			p.address_size = *fromlen;
			p.buffer.assign( buffer, buffer + len );

			AUTO_LOCK( packet_sampling_mutex );

			// there should only be packet_sampling_max_queue packets on the queue
			// at the moment of this check
			if( packet_sampling_queue.size( ) >= packet_sampling_max_queue )
				packet_sampling_queue.pop_front( );

			packet_sampling_queue.push_back( p );
		}

		if( !IsAddressAllowed( infrom ) )
			return -1;

		PacketType type = ClassifyPacket( buffer, len, infrom );
		if( type == PacketTypeInfo )
			type = HandleInfoQuery( infrom );

		if( type == PacketTypeInvalid )
			return -1;

		return len;
	}

	inline bool IsPacketQueueEmpty( )
	{
		AUTO_LOCK( threaded_socket_mutex );
		return threaded_socket_queue.empty( );
	}

	static ssize_t recvfrom_detour(
		SOCKET s,
		void *buf,
		recvlen_t buflen,
		int32_t flags,
		sockaddr *from,
		socklen_t *fromlen
	)
	{
		if( s != game_socket )
			return recvfrom_hook.GetTrampoline<recvfrom_t>( )( s, buf, buflen, flags, from, fromlen );
		
		bool queue_empty = IsPacketQueueEmpty( );
		if( !threaded_socket_enabled && queue_empty )
			return HandleNetError(
				ReceiveAndAnalyzePacket( s, buf, buflen, flags, from, fromlen )
			);

		if( queue_empty )
			return HandleNetError( -1 );

		packet_t p = GetQueuedPacket( );
		int32_t len = static_cast<int32_t>( p.buffer.size( ) );
		if( len > buflen )
			len = buflen;

		size_t addrlen = static_cast<size_t>( *fromlen );
		if( addrlen > sizeof( p.address ) )
			addrlen = sizeof( p.address );

		memcpy( buf, &p.buffer[0], len );
		memcpy( from, &p.address, addrlen );
		*fromlen = p.address_size;

		return len;
	}

	inline bool IsPacketQueueFull( )
	{
		AUTO_LOCK( threaded_socket_mutex );
		return threaded_socket_queue.size( ) >= threaded_socket_max_queue;
	}

	inline void PushPacketToQueue( const packet_t &p )
	{
		AUTO_LOCK( threaded_socket_mutex );
		threaded_socket_queue.push( p );
	}

	static uintp PacketReceiverThread( void * )
	{
		timeval ms100 = { 0, 100000 };
		char tempbuf[65535] = { 0 };
		fd_set readables;

		while( threaded_socket_execute )
		{
			if( !threaded_socket_enabled || IsPacketQueueFull( ) )
				// testing for maximum queue size, this is a very cheap "fix"
				// the socket itself has a queue too but will start dropping packets when full
			{
				ThreadSleep( 100 );
				continue;
			}

			FD_ZERO( &readables );
			FD_SET( game_socket, &readables );
			int res = select( game_socket + 1, &readables, nullptr, nullptr, &ms100 );
			ms100.tv_usec = 100000;
			if( res == -1 || !FD_ISSET( game_socket, &readables ) )
				continue;

			packet_t p;
			ssize_t len = ReceiveAndAnalyzePacket(
				game_socket,
				tempbuf,
				sizeof( tempbuf ),
				0,
				reinterpret_cast<sockaddr *>( &p.address ),
				&p.address_size
			);
			if( len == -1 )
				continue;

			p.buffer.assign( tempbuf, tempbuf + len );

			PushPacketToQueue( p );
		}

		return 0;
	}

	inline void SetReceiveDetourStatus( bool enabled )
	{
		if( enabled )
			recvfrom_hook.Enable( );
		else if( !firewall_whitelist_enabled &&
			!firewall_blacklist_enabled &&
			!packet_validation_enabled &&
			!threaded_socket_enabled )
			recvfrom_hook.Disable( );
	}

	LUA_FUNCTION_STATIC( EnableFirewallWhitelist )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
		firewall_whitelist_enabled = LUA->GetBool( 1 );
		SetReceiveDetourStatus( firewall_whitelist_enabled );
		return 0;
	}

	// Whitelisted IPs bytes need to be in network order (big endian)
	LUA_FUNCTION_STATIC( AddWhitelistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
		firewall_whitelist.insert( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( RemoveWhitelistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
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
		LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
		firewall_blacklist_enabled = LUA->GetBool( 1 );
		SetReceiveDetourStatus( firewall_blacklist_enabled );
		return 0;
	}

	// Blacklisted IPs bytes need to be in network order (big endian)
	LUA_FUNCTION_STATIC( AddBlacklistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
		firewall_blacklist.insert( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( RemoveBlacklistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
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
		LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
		packet_validation_enabled = LUA->GetBool( 1 );
		SetReceiveDetourStatus( packet_validation_enabled );
		return 0;
	}

	LUA_FUNCTION_STATIC( EnableThreadedSocket )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
		threaded_socket_enabled = LUA->GetBool( 1 );
		SetReceiveDetourStatus( threaded_socket_enabled );
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

	LUA_FUNCTION_STATIC( RefreshInfoCache )
	{
		BuildStaticReplyInfo( );
		BuildReplyInfo( );
		return 0;
	}

	LUA_FUNCTION_STATIC( EnableQueryLimiter )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );
		client_manager.SetState( LUA->GetBool( 1 ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( SetMaxQueriesWindow )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
		client_manager.SetMaxQueriesWindow( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( SetMaxQueriesPerSecond )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
		client_manager.SetMaxQueriesPerSecond( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( SetGlobalMaxQueriesPerSecond )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
		client_manager.SetGlobalMaxQueriesPerSecond(
			static_cast<uint32_t>( LUA->GetNumber( 1 ) )
		);
		return 0;
	}

	LUA_FUNCTION_STATIC( EnablePacketSampling )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::BOOL );

		packet_sampling_enabled = LUA->GetBool( 1 );
		if( !packet_sampling_enabled )
		{
			AUTO_LOCK( packet_sampling_mutex );
			packet_sampling_queue.clear( );
		}

		return 0;
	}

	inline packet_t GetSamplePacket( )
	{
		AUTO_LOCK( packet_sampling_mutex );

		if( packet_sampling_queue.empty( ) )
			return packet_t( );

		packet_t p = packet_sampling_queue.front( );
		packet_sampling_queue.pop_front( );
		return p;
	}

	LUA_FUNCTION_STATIC( GetSamplePacket )
	{
		packet_t p = GetSamplePacket( );
		if( p.address.sin_addr.s_addr == 0 )
			return 0;

		LUA->PushNumber( p.address.sin_addr.s_addr );
		LUA->PushNumber( p.address.sin_port );
		LUA->PushString( reinterpret_cast<const char *>( &p.buffer[0] ), p.buffer.size( ) );
		return 3;
	}

	void Initialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		if( !server_loader.IsValid( ) )
			LUA->ThrowError( "unable to get server factory" );

		ICvar *icvar = icvar_loader.GetInterface<ICvar>( CVAR_INTERFACE_VERSION );
		if( icvar != nullptr )
			sv_visiblemaxplayers = icvar->FindVar( "sv_visiblemaxplayers" );

		gamedll = server_loader.GetInterface<IServerGameDLL>( INTERFACEVERSION_SERVERGAMEDLL );
		if( gamedll == nullptr )
			LUA->ThrowError( "failed to load required IServerGameDLL interface" );

		engine_server = global::engine_loader.GetInterface<IVEngineServer>(
			INTERFACEVERSION_VENGINESERVER
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

		{
			SymbolFinder symfinder;

			CreateInterfaceFn factory = nullptr;
			for( const auto &symbol : FileSystemFactory_syms )
			{
				factory = reinterpret_cast<CreateInterfaceFn>( symfinder.Resolve(
					dedicated_loader.GetModule( ),
					symbol.name.c_str( ),
					symbol.length
				) );
				if( factory != nullptr )
					break;
			}

			if( factory == nullptr )
			{
				IFileSystem **filesystem_ptr =
					reinterpret_cast<IFileSystem **>( symfinder.Resolve(
						dedicated_loader.GetModule( ),
						g_pFullFileSystem_sym.name.c_str( ),
						g_pFullFileSystem_sym.length
					) );
				if( filesystem_ptr == nullptr )
					filesystem_ptr =
						reinterpret_cast<IFileSystem **>( symfinder.Resolve(
							server_loader.GetModule( ),
							g_pFullFileSystem_sym.name.c_str( ),
							g_pFullFileSystem_sym.length
						) );

				if( filesystem_ptr != nullptr )
					filesystem = *filesystem_ptr;
			}
			else
			{
				filesystem =
					static_cast<IFileSystem *>( factory( FILESYSTEM_INTERFACE_VERSION, nullptr ) );
			}

			auto GetNetSocket = reinterpret_cast<GetNetSocket_t>(
				global::engine_loader.GetSymbol( GetNetSocket_sym )
			);
			if( GetNetSocket != nullptr )
			{
				netsocket_t *socket = GetNetSocket( 1 );
				if( socket != nullptr )
					game_socket = socket->hUDP;
			}

			if( game_socket == INVALID_SOCKET )
			{
				void *temp_net_sockets = reinterpret_cast<CSteamGameServerAPIContext *>( symfinder.Resolve(
					global::engine_loader.GetModule( ),
					net_sockets_sym.name.c_str( ),
					net_sockets_sym.length
				) );
				if( temp_net_sockets != nullptr )
				{
					netsockets_t *net_sockets =

#if defined SYSTEM_POSIX

						reinterpret_cast<netsockets_t *>

#else

						*reinterpret_cast<netsockets_t **>

#endif

						( temp_net_sockets );
					if( net_sockets != nullptr )
						game_socket = net_sockets->Element( 1 ).hUDP;
				}
			}

			gameserver_context = reinterpret_cast<CSteamGameServerAPIContext *>(
				server_loader.GetSymbol( CSteamGameServerAPIContext_sym )
			);
			if( gameserver_context == nullptr )
			{

#if defined SYSTEM_WINDOWS

				CSteamGameServerAPIContext **gameserver_context_pointer =
					reinterpret_cast<CSteamGameServerAPIContext **>( symfinder.Resolve(
						server_loader.GetModule( ),
						SteamGameServerAPIContext_sym.name.c_str(),
						SteamGameServerAPIContext_sym.length
					) );
				if( gameserver_context_pointer != nullptr )
					gameserver_context = *gameserver_context_pointer;

#else

					gameserver_context =
						reinterpret_cast<CSteamGameServerAPIContext *>( symfinder.Resolve(
							server_loader.GetModule( ),
							SteamGameServerAPIContext_sym.name.c_str(),
							SteamGameServerAPIContext_sym.length
						) );

#endif

			}
		}

		if( gameserver_context == nullptr )
			LUA->ThrowError( "Failed to load required CSteamGameServerAPIContext interface." );

		if( filesystem == nullptr )
			LUA->ThrowError( "failed to initialize IFileSystem" );

		if( game_socket == INVALID_SOCKET )
			LUA->ThrowError( "got an invalid server socket" );

		threaded_socket_execute = true;
		threaded_socket_handle = CreateSimpleThread( PacketReceiverThread, nullptr );
		if( threaded_socket_handle == nullptr )
			LUA->ThrowError( "unable to create thread" );

		BuildStaticReplyInfo( );

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

		LUA->PushCFunction( EnableThreadedSocket );
		LUA->SetField( -2, "EnableThreadedSocket" );

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
