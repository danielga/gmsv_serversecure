#include "clientmanager.hpp"

#include <dbg.h>

namespace netfilter {
ClientManager::ClientManager() = default;

void ClientManager::SetState(bool e) { enabled = e; }

bool ClientManager::CheckIPRate(uint32_t from, uint32_t time) {
  if (!enabled) {
    return true;
  }

  if (clients.size() >= MaxClients) {
    for (auto it = clients.begin(); it != clients.end(); ++it) {
      const Client &client = (*it).second;
      if (client.TimedOut(time) && client.GetAddress() != from) {
        clients.erase(it);

        if (clients.size() <= PruneAmount) {
          break;
        }
      }
    }
  }

  auto it = clients.find(from);
  if (it != clients.end()) {
    Client &client = (*it).second;
    if (!client.CheckIPRate(time)) {
      return false;
    }
  } else {
    clients.insert(std::make_pair(from, Client(*this, from, time)));
  }

  if (time - global_last_reset >= max_window) {
    global_last_reset = time;
    global_count = 1;
  } else {
    ++global_count;
    if (global_count / max_window >= global_max_sec) {
      DevWarning("[ServerSecure] %d.%d.%d.%d reached the global query limit!\n",
                 (from >> 24) & 0xFF, (from >> 16) & 0xFF, (from >> 8) & 0xFF,
                 from & 0xFF);
      return false;
    }
  }

  return true;
}

uint32_t ClientManager::GetMaxQueriesWindow() const { return max_window; }

uint32_t ClientManager::GetMaxQueriesPerSecond() const { return max_sec; }

uint32_t ClientManager::GetGlobalMaxQueriesPerSecond() const {
  return global_max_sec;
}

void ClientManager::SetMaxQueriesWindow(uint32_t window) {
  max_window = window;
}

void ClientManager::SetMaxQueriesPerSecond(uint32_t max) { max_sec = max; }

void ClientManager::SetGlobalMaxQueriesPerSecond(uint32_t max) {
  global_max_sec = max;
}
} // namespace netfilter
