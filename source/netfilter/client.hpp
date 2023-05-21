#ifndef NETFILTER_CLIENT_HPP
#define NETFILTER_CLIENT_HPP

#pragma once

#include <cstdint>

namespace netfilter {
class Client {
public:
  enum class RateLimitType { None, Sustained, Limited };

  Client() = default;
  explicit Client(uint32_t address);
  Client(uint32_t address, uint32_t time, uint32_t attempts = 1);

  void Reset(uint32_t address, uint32_t time, uint32_t attempts = 1);

  /// Checks individual IP rate limits for the given address, timestamp, max
  /// queries per second, max queries window period and number of hits (the last
  /// one is mostly for testing). Based on Counter-Strike: Global Offensive
  /// code.
  RateLimitType CheckIPRate(uint32_t time, uint32_t max_sec,
                            uint32_t max_window, uint32_t attempts = 1);

  [[nodiscard]] uint32_t GetHitCount() const;

  [[nodiscard]] uint32_t GetAddress() const;
  [[nodiscard]] uint32_t GetLastPing() const;
  [[nodiscard]] bool TimedOut(uint32_t time, uint32_t max_window) const;

  void MarkForRemoval();
  [[nodiscard]] bool MarkedForRemoval() const;

  bool operator<(const Client &rhs) const;

private:
  uint32_t m_address = 0;
  uint32_t m_last_ping = 0;
  uint32_t m_last_reset = 0;
  uint32_t m_count = 0;
  bool m_marked_for_removal = false;
};
} // namespace netfilter

#endif // NETFILTER_CLIENT_HPP
