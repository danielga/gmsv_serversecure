#ifndef NETFILTER_CLIENTMANAGER_HPP
#define NETFILTER_CLIENTMANAGER_HPP

#pragma once

#include "client.hpp"

#include <map>

namespace netfilter {
class ClientManager {
public:
  ClientManager();

  void SetState(bool enabled);

  bool CheckIPRate(uint32_t from, uint32_t time);

  [[nodiscard]] uint32_t GetMaxQueriesWindow() const;
  [[nodiscard]] uint32_t GetMaxQueriesPerSecond() const;
  [[nodiscard]] uint32_t GetGlobalMaxQueriesPerSecond() const;

  void SetMaxQueriesWindow(uint32_t window);
  void SetMaxQueriesPerSecond(uint32_t max);
  void SetGlobalMaxQueriesPerSecond(uint32_t max);

  static const uint32_t MaxClients = 4096;
  static const uint32_t PruneAmount = MaxClients * 2 / 3;
  static const uint32_t ClientTimeout = 120;

private:
  std::map<uint32_t, Client> clients;
  bool enabled{false};
  uint32_t global_count{0};
  uint32_t global_last_reset{0};
  uint32_t max_window{60};
  uint32_t max_sec{1};
  uint32_t global_max_sec{50};
};
} // namespace netfilter

#endif // NETFILTER_CLIENTMANAGER_HPP
