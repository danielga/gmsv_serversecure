#include "processingtime.hpp"

#include <inetchannel.h>
#include <tier1/iconvar.h>

class CNetChan : public INetChannel {};

namespace netfilter {
static const ConVar
    net_chan_limit_msec("net_chan_limit_msec", "0",
                        FCVAR_ARCHIVE | FCVAR_GAMEDLL,
                        "Netchannel processing is limited to so many "
                        "milliseconds, abort connection if exceeding budget");

static FunctionPointers::CNetChan_ProcessMessages_t ProcessMessages_original =
    nullptr;

static FunctionPointers::NET_ProcessSocket_t NET_ProcessSocket_original =
    nullptr;

static Detouring::Hook NET_ProcessSocket_hook;

static std::unordered_map<CNetChan *, uint32_t> processing_times;

static void NET_ProcessSocket_detour(int sock,
                                     IConnectionlessPacketHandler *handler) {
  processing_times.clear();
  NET_ProcessSocket_hook.GetTrampoline<FunctionPointers::NET_ProcessSocket_t>()(
      sock, handler);
}

CNetChanProxy::CNetChanProxy() {
  ProcessMessages_original = FunctionPointers::CNetChan_ProcessMessages();
  if (ProcessMessages_original == nullptr) {
    throw std::runtime_error("failed to retrieve CNetChan::ProcessMessages");
  }

  NET_ProcessSocket_original = FunctionPointers::NET_ProcessSocket();
  if (NET_ProcessSocket_original == nullptr) {
    throw std::runtime_error("failed to retrieve NET_ProcessSocket");
  }

  if (!Hook(ProcessMessages_original, &CNetChanProxy::ProcessMessages)) {
    throw std::runtime_error("failed to hook CNetChan::ProcessMessages");
  }

  if (!NET_ProcessSocket_hook.Create(NET_ProcessSocket_original,
                                     NET_ProcessSocket_detour)) {
    throw std::runtime_error("failed to create hook for NET_ProcessSocket");
  }

  if (!NET_ProcessSocket_hook.Enable()) {
    throw std::runtime_error("failed to enable hook for NET_ProcessSocket");
  }
}

CNetChanProxy::~CNetChanProxy() { UnHook(ProcessMessages_original); }

bool CNetChanProxy::ProcessMessages(bf_read &buf) {
  const auto limit_msec = net_chan_limit_msec.GetInt();
  if (limit_msec <= 0) {
    return Call(ProcessMessages_original, buf);
  }

  const auto start = Plat_MSTime();
  const bool result = Call(ProcessMessages_original, buf);
  const auto time_spent = Plat_MSTime() - start;

  CNetChan *netchan = This();
  auto it = processing_times.find(netchan);
  if (it == processing_times.end()) {
    const auto [new_it, _] = processing_times.emplace(netchan, 0);
    it = new_it;
  }

  auto &total_spent = it->second;
  total_spent += time_spent;

  if (total_spent >= static_cast<uint32_t>(limit_msec)) {
    netchan->Shutdown("Processing time exceeded");
    return false;
  }

  return result;
}
} // namespace netfilter
