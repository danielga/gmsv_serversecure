#ifndef BASESERVER_H
#define BASESERVER_H

#ifdef _WIN32
#pragma once
#endif

#include <iserver.h>
#include <netadr.h>
#include <bitbuf.h>
#include <utlvector.h>
#include <checksum_md5.h>

class CNetworkStringTableContainer;
class ServerClass;
class INetworkStringTable;
class CClientFrame;
class CFrameSnapshot;
class CBaseClient;

enum server_state_t
{
	ss_dead = 0,	// Dead
	ss_loading,		// Spawning
	ss_active,		// Running
	ss_paused,		// Running, but paused
};

// time a challenge nonce is valid for, in seconds
#define CHALLENGE_NONCE_LIFETIME 6

class CBaseServer : public IServer
{
public:
	virtual ~CBaseServer( ) = 0;

	// IServer implementation

	virtual int GetNumClients( ) const = 0; // returns current number of clients
	virtual int GetNumProxies( ) const = 0; // returns number of attached HLTV proxies
	virtual int GetNumFakeClients( ) const = 0; // returns number of fake clients/bots
	virtual int GetMaxClients( ) const = 0; // returns current client limit
	virtual int GetUDPPort( ) const = 0;
	virtual IClient	*GetClient( int index ) = 0; // returns interface to client 
	virtual int GetClientCount() const = 0; // for iteration;
	virtual float GetTime( ) const = 0;
	virtual int GetTick( ) const = 0;
	virtual float GetTickInterval( ) const = 0;
	virtual const char *GetName( ) const = 0;
	virtual const char *GetMapName( ) const = 0;
	virtual int GetSpawnCount( ) const = 0;
	virtual int GetNumClasses( ) const = 0;
	virtual int GetClassBits( ) const = 0;
	virtual void GetNetStats( float &avgIn, float &avgOut ) = 0;
	virtual int GetNumPlayers( ) = 0;
	virtual	bool GetPlayerInfo( int nClientIndex, player_info_t *pinfo ) = 0;
	virtual float GetCPUUsage( ) = 0;
		
	virtual bool IsActive( ) const = 0;
	virtual bool IsLoading( ) const = 0;
	virtual bool IsDedicated( ) const = 0;
	virtual bool IsPaused( ) const = 0;
	virtual bool IsMultiplayer( ) const = 0;
	virtual bool IsPausable( ) const = 0;
	virtual bool IsHLTV( ) const = 0;
	virtual bool IsReplay( ) const = 0;

	virtual void BroadcastMessage( INetMessage &msg, bool onlyActive = false, bool reliable = false ) = 0;
	virtual void BroadcastMessage( INetMessage &msg, IRecipientFilter &filter ) = 0;
	virtual void BroadcastPrintf( PRINTF_FORMAT_STRING const char *fmt, ... ) FMTFUNCTION( 2, 3 ) = 0;

	virtual const char *GetPassword( ) const = 0;

	virtual void SetMaxClients( int number ) = 0;
	virtual void SetPaused( bool paused ) = 0;
	virtual void SetPassword( const char *password ) = 0;

	virtual void DisconnectClient( IClient *client, const char *reason ) = 0;
	
	virtual void WriteDeltaEntities( CBaseClient *client, CClientFrame *to, CClientFrame *from,	bf_write &pBuf ) = 0;
	virtual void WriteTempEntities( CBaseClient *client, CFrameSnapshot *to, CFrameSnapshot *from, bf_write &pBuf, int nMaxEnts ) = 0;
	
	// IConnectionlessPacketHandler implementation

	virtual bool ProcessConnectionlessPacket( netpacket_t *packet ) = 0;

	virtual void Init( bool isDedicated ) = 0;
	virtual void Clear( ) = 0;
	virtual void Shutdown( ) = 0;
	virtual CBaseClient *CreateFakeClient( const char *name ) = 0;
	virtual void RemoveClientFromGame( CBaseClient *client ) = 0;
	virtual void SendClientMessages ( bool bSendSnapshots ) = 0;
	virtual void FillServerInfo( SVC_ServerInfo &serverinfo ) = 0;
	virtual void UserInfoChanged( int nClientIndex ) = 0;

	virtual void RejectConnection( const netadr_t &adr, int clientChallenge, const char *s ) = 0;

	virtual bool CheckIPRestrictions( const netadr_t &adr, int nAuthProtocol ) = 0;

	virtual IClient *ConnectClient( netadr_t &adr, int protocol, int challenge, int clientChallenge, int authProtocol,
		const char *name, const char *password, const char *hashedCDkey, int cdKeyLen ) = 0;
	
	virtual CBaseClient *GetFreeClient( netadr_t &adr ) = 0;

	virtual CBaseClient *CreateNewClient( int slot ) = 0; // must be derived

	virtual bool FinishCertificateCheck( netadr_t &adr, int nAuthProtocol, const char *szRawCertificate, int clientChallenge ) = 0;
	
	virtual int GetChallengeNr( netadr_t &adr ) = 0;
	virtual int GetChallengeType( netadr_t &adr ) = 0;

	virtual bool CheckProtocol( netadr_t &adr, int nProtocol, int clientChallenge ) = 0;
	virtual bool CheckChallengeNr( netadr_t &adr, int nChallengeValue ) = 0;
	virtual bool CheckChallengeType( CBaseClient *client, int nNewUserID, netadr_t &adr, int nAuthProtocol, const char *pchLogonCookie, int cbCookie, int clientChallenge ) = 0;
	virtual bool CheckPassword( netadr_t &adr, const char *password, const char *name ) = 0;
	virtual bool CheckIPConnectionReuse( netadr_t &adr ) = 0;

	virtual void ReplyChallenge( netadr_t &adr, int clientChallenge ) = 0;
	virtual void ReplyServerChallenge( netadr_t &adr ) = 0;

	virtual void CalculateCPUUsage( ) = 0;

	// Keep the master server data updated.
	virtual bool ShouldUpdateMasterServer( ) = 0;
	
	virtual void UpdateMasterServerPlayers( ) = 0;

	// Data
	server_state_t m_State; // some actions are only valid during load
	int m_Socket; // network socket 
	int m_nTickCount; // current server tick
	bool m_bSimulatingTicks; // whether or not the server is currently simulating ticks
	char m_szMapname[64]; // map name
	char m_szMapFilename[64]; // map filename, may bear no resemblance to map name
	char m_szSkyname[64]; // skybox name
	char m_Password[32]; // server password

	MD5Value_t worldmapMD5; // For detecting that client has a hacked local copy of map, the client will be dropped if this occurs.
	
	CNetworkStringTableContainer *m_StringTables; // newtork string table container

	INetworkStringTable *m_pInstanceBaselineTable; 
	INetworkStringTable *m_pLightStyleTable;
	INetworkStringTable *m_pUserInfoTable;
	INetworkStringTable *m_pServerStartupTable;
	INetworkStringTable *m_pDownloadableFileTable;

	// This will get set to NET_MAX_PAYLOAD if the server is MP.
	bf_write m_Signon;
	CUtlMemory<byte> m_SignonBuffer;

	int serverclasses; // number of unique server classes
	int serverclassbits; // log2 of serverclasses

	int m_nUserid; // increases by one with every new client

	int m_nMaxclients; // Current max #
	int m_nSpawnCount; // Number of servers spawned since start, used to check late spawns (e.g., when d/l'ing lots of data)
	float m_flTickInterval; // time for 1 tick in seconds

	CUtlVector<CBaseClient *> m_Clients; // array of up to [maxclients] client slots.
	
	bool m_bIsDedicated;

	uint32 m_CurrentRandomNonce;
	uint32 m_LastRandomNonce;
	float m_flLastRandomNumberGenerationTime;
	float m_fCPUPercent;
	float m_fStartTime;
	float m_fLastCPUCheckTime;

	// This is only used for Steam's master server updater to refer to this server uniquely.
	bool m_bRestartOnLevelChange;
	
	bool m_bMasterServerRulesDirty;
	double m_flLastMasterServerUpdateTime;

	int m_nNumConnections; //Number of successful client connections.

	bool m_bReportNewFakeClients; // Whether or not newly created fake clients should be included in server browser totals
	float m_flPausedTimeEnd;
};

#endif // BASESERVER_H
