#ifndef NETFILTER_BASESERVER_HPP
#define NETFILTER_BASESERVER_HPP

#ifdef _WIN32
#pragma once
#endif

#include <bitbuf.h>
#include <checksum_md5.h>
#include <iserver.h>
#include <netadr.h>
#include <utlvector.h>

class CNetworkStringTableContainer;
class ServerClass;
class INetworkStringTable;
class CClientFrame;
class CFrameSnapshot;
class CBaseClient;

enum server_state_t {
  ss_dead = 0, // Dead
  ss_loading,  // Spawning
  ss_active,   // Running
  ss_paused,   // Running, but paused
};

// time a challenge nonce is valid for, in seconds
#define CHALLENGE_NONCE_LIFETIME 6

// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)
class CBaseServer : public IServer {
public:
  ~CBaseServer() override = 0;

  // IServer implementation

  [[nodiscard]] int
  GetNumClients() const override = 0; // returns current number of clients
  [[nodiscard]] int
  GetNumProxies() const override = 0; // returns number of attached HLTV proxies
  [[nodiscard]] int
  GetNumFakeClients() const override = 0; // returns number of fake clients/bots
  [[nodiscard]] int
  GetMaxClients() const override = 0; // returns current client limit
  [[nodiscard]] int GetUDPPort() const override = 0;
  IClient *GetClient(int index) override = 0; // returns interface to client
  [[nodiscard]] int GetClientCount() const override = 0; // for iteration;
  [[nodiscard]] float GetTime() const override = 0;
  [[nodiscard]] int GetTick() const override = 0;
  [[nodiscard]] float GetTickInterval() const override = 0;
  [[nodiscard]] const char *GetName() const override = 0;
  [[nodiscard]] const char *GetMapName() const override = 0;
  [[nodiscard]] int GetSpawnCount() const override = 0;
  [[nodiscard]] int GetNumClasses() const override = 0;
  [[nodiscard]] int GetClassBits() const override = 0;
  void GetNetStats(float &avgIn, float &avgOut) override = 0;
  int GetNumPlayers() override = 0;
  bool GetPlayerInfo(int nClientIndex, player_info_t *pinfo) override = 0;
  virtual float GetCPUUsage() = 0;

  [[nodiscard]] bool IsActive() const override = 0;
  [[nodiscard]] bool IsLoading() const override = 0;
  [[nodiscard]] bool IsDedicated() const override = 0;
  [[nodiscard]] bool IsPaused() const override = 0;
  [[nodiscard]] bool IsMultiplayer() const override = 0;
  [[nodiscard]] bool IsPausable() const override = 0;
  [[nodiscard]] bool IsHLTV() const override = 0;
  [[nodiscard]] bool IsReplay() const override = 0;

  void BroadcastMessage(INetMessage &msg, bool onlyActive = false,
                        bool reliable = false) override = 0;
  void BroadcastMessage(INetMessage &msg,
                        IRecipientFilter &filter) override = 0;
  virtual void BroadcastPrintf(PRINTF_FORMAT_STRING const char *fmt, ...)
      FMTFUNCTION(2, 3) = 0;

  [[nodiscard]] const char *GetPassword() const override = 0;

  virtual void SetMaxClients(int number) = 0;
  void SetPaused(bool paused) override = 0;
  void SetPassword(const char *password) override = 0;

  void DisconnectClient(IClient *client, const char *reason) override = 0;

  virtual void WriteDeltaEntities(CBaseClient *client, CClientFrame *to,
                                  CClientFrame *from, bf_write &pBuf) = 0;
  virtual void WriteTempEntities(CBaseClient *client, CFrameSnapshot *to,
                                 CFrameSnapshot *from, bf_write &pBuf,
                                 int nMaxEnts) = 0;

  // IConnectionlessPacketHandler implementation

  bool ProcessConnectionlessPacket(netpacket_t *packet) override = 0;

  virtual void Init(bool isDedicated) = 0;
  virtual void Clear() = 0;
  virtual void Shutdown() = 0;
  virtual CBaseClient *CreateFakeClient(const char *name) = 0;
  virtual void RemoveClientFromGame(CBaseClient *client) = 0;
  virtual void SendClientMessages(bool bSendSnapshots) = 0;
  virtual void FillServerInfo(SVC_ServerInfo &serverinfo) = 0;
  virtual void UserInfoChanged(int nClientIndex) = 0;

  virtual void RejectConnection(const netadr_t &adr, int clientChallenge,
                                const char *s) = 0;

  virtual bool CheckIPRestrictions(const netadr_t &adr, int nAuthProtocol) = 0;

  virtual IClient *ConnectClient(netadr_t &adr, int protocol, int challenge,
                                 int clientChallenge, int authProtocol,
                                 const char *name, const char *password,
                                 const char *hashedCDkey, int cdKeyLen) = 0;

  virtual CBaseClient *GetFreeClient(netadr_t &adr) = 0;

  virtual CBaseClient *CreateNewClient(int slot) = 0; // must be derived

  virtual bool FinishCertificateCheck(netadr_t &adr, int nAuthProtocol,
                                      const char *szRawCertificate,
                                      int clientChallenge) = 0;

  virtual int GetChallengeNr(netadr_t &adr) = 0;
  virtual int GetChallengeType(netadr_t &adr) = 0;

  virtual bool CheckProtocol(netadr_t &adr, int nProtocol,
                             int clientChallenge) = 0;
  virtual bool CheckChallengeNr(netadr_t &adr, int nChallengeValue) = 0;
  virtual bool CheckChallengeType(CBaseClient *client, int nNewUserID,
                                  netadr_t &adr, int nAuthProtocol,
                                  const char *pchLogonCookie, int cbCookie,
                                  int clientChallenge) = 0;
  virtual bool CheckPassword(netadr_t &adr, const char *password,
                             const char *name) = 0;
  virtual bool CheckIPConnectionReuse(netadr_t &adr) = 0;

  virtual void ReplyChallenge(netadr_t &adr, int clientChallenge) = 0;
  virtual void ReplyServerChallenge(netadr_t &adr) = 0;

  virtual void CalculateCPUUsage() = 0;

  // Keep the master server data updated.
  virtual bool ShouldUpdateMasterServer() = 0;

  virtual void UpdateMasterServerPlayers() = 0;

  // Data
  server_state_t m_State;  // some actions are only valid during load
  int m_Socket;            // network socket
  int m_nTickCount;        // current server tick
  bool m_bSimulatingTicks; // whether or not the server is currently simulating
                           // ticks
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
  char m_szMapname[64]; // map name
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
  char m_szMapFilename[64]; // map filename, may bear no resemblance to map name
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
  char m_szSkyname[64]; // skybox name
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
  char m_Password[32]; // server password

  MD5Value_t worldmapMD5; // For detecting that client has a hacked local copy
                          // of map, the client will be dropped if this occurs.

  CNetworkStringTableContainer
      *m_StringTables; // newtork string table container

  INetworkStringTable *m_pInstanceBaselineTable;
  INetworkStringTable *m_pLightStyleTable;
  INetworkStringTable *m_pUserInfoTable;
  INetworkStringTable *m_pServerStartupTable;
  INetworkStringTable *m_pDownloadableFileTable;

  // This will get set to NET_MAX_PAYLOAD if the server is MP.
  bf_write m_Signon;
  CUtlMemory<byte> m_SignonBuffer;

  int serverclasses;   // number of unique server classes
  int serverclassbits; // log2 of serverclasses

  int m_nUserid; // increases by one with every new client

  int m_nMaxclients; // Current max #
  int m_nSpawnCount; // Number of servers spawned since start, used to check
                     // late spawns (e.g., when d/l'ing lots of data)
  float m_flTickInterval; // time for 1 tick in seconds

  CUtlVector<CBaseClient *>
      m_Clients; // array of up to [maxclients] client slots.

  bool m_bIsDedicated;

  uint32 m_CurrentRandomNonce;
  uint32 m_LastRandomNonce;
  float m_flLastRandomNumberGenerationTime;
  float m_fCPUPercent;
  float m_fStartTime;
  float m_fLastCPUCheckTime;

  // This is only used for Steam's master server updater to refer to this server
  // uniquely.
  bool m_bRestartOnLevelChange;

  bool m_bMasterServerRulesDirty;
  double m_flLastMasterServerUpdateTime;

  int m_nNumConnections; // Number of successful client connections.

  bool m_bReportNewFakeClients; // Whether or not newly created fake clients
                                // should be included in server browser totals
  float m_flPausedTimeEnd;
};

#endif // NETFILTER_BASESERVER_HPP
