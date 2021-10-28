#include "client.hpp"
#include "clientmanager.hpp"

#include <dbg.h>

namespace netfilter {
Client::Client(ClientManager &_manager, uint32_t _address)
    : manager(_manager), address(_address), last_reset(0), count(0) {}

Client::Client(ClientManager &_manager, uint32_t _address, uint32_t time)
    : manager(_manager), address(_address), last_reset(time), count(1) {}

bool Client::CheckIPRate(uint32_t time) {
  if (time - last_reset >= manager.GetMaxQueriesWindow()) {
    last_reset = time;
    count = 1;
  } else {
    ++count;
    if (count / manager.GetMaxQueriesWindow() >=
        manager.GetMaxQueriesPerSecond()) {
      DevWarning("[ServerSecure] %d.%d.%d.%d reached its query limit!\n",
                 (address >> 24) & 0xFF, (address >> 16) & 0xFF,
                 (address >> 8) & 0xFF, address & 0xFF);
      return false;
    }
  }

  return true;
}

uint32_t Client::GetAddress() const { return address; }

bool Client::TimedOut(uint32_t time) const {
  return time - last_reset >= ClientManager::ClientTimeout;
}
} // namespace netfilter
