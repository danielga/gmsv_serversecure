#ifndef NETFILTER_CLIENTMANAGER_HPP
#define NETFILTER_CLIENTMANAGER_HPP

#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

#include "client.hpp"
#include "objectpool.hpp"

namespace netfilter {
class ClientManager {
public:
  enum class RateLimitType { None, Individual, Global };

  void SetState(bool enabled);

  /// Checks individual and global IP rate limits for the given address,
  /// timestamp and number of hits (the last one is mostly for testing). Based
  /// on Counter-Strike: Global Offensive code.
  RateLimitType CheckIPRate(uint32_t address, uint32_t time,
                            uint32_t attempts = 1);

  [[nodiscard]] uint32_t GetMaxQueriesWindow() const;
  [[nodiscard]] uint32_t GetMaxQueriesPerSecond() const;
  [[nodiscard]] uint32_t GetGlobalMaxQueriesPerSecond() const;

  void SetMaxQueriesWindow(uint32_t window);
  void SetMaxQueriesPerSecond(uint32_t max);
  void SetGlobalMaxQueriesPerSecond(uint32_t max);

  static constexpr uint32_t MaxClients = 50000;
  static constexpr uint32_t PruneMaxClients = MaxClients * 4 / 5;
  static constexpr uint32_t CriticalMaxClients = MaxClients * 9 / 10;
  static constexpr uint32_t MaxQueriesWindow = 30;
  static constexpr uint32_t MaxQueriesPerSecond = 10;
  static constexpr uint32_t GlobalMaxQueriesPerSecond = 500;
  static constexpr size_t MinPrune = 10;

private:
  /// Safely remove clients that have timed out.
  void PruneTimedOutClients(uint32_t time);

  void ResetClients();

  bool m_enabled = false;

  ObjectPool<Client, MaxClients> m_clients;
  std::unordered_map<uint32_t, size_t> m_address_to_client_map;

  uint32_t m_global_count = 0;
  uint32_t m_global_last_reset = 0;

  uint32_t m_max_window = MaxQueriesWindow;
  uint32_t m_max_sec = MaxQueriesPerSecond;
  uint32_t m_global_max_sec = GlobalMaxQueriesPerSecond;

  uint32_t m_last_personal_detection = 0;
  uint32_t m_last_distributed_detection = 0;
};
} // namespace netfilter

#endif // NETFILTER_CLIENTMANAGER_HPP
