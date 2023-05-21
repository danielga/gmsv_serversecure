#include "clientmanager.hpp"

#if __has_include(<dbg.h>)
#include <dbg.h>
#else
// NOLINTNEXTLINE(cert-dcl50-cpp)
inline void DevWarning(const char * /*unused*/, ...) {}
#endif

namespace netfilter {
void ClientManager::SetState(const bool enabled) { m_enabled = enabled; }

ClientManager::RateLimitType
ClientManager::CheckIPRate(const uint32_t address, const uint32_t time,
                           const uint32_t attempts) {
  // Check the per IP rate first, so one person DoS'ing doesn't add to the
  // global max rate

  // Prune some elements from the tree
  PruneTimedOutClients(time);

  if (m_clients.Size() > CriticalMaxClients) {
    // This looks like we are under distributed attack where we are seeing a
    // very large number of IP addresses in a short time period
    // Stop tracking individual IP addresses and turn on global rate limit
    DevWarning("IP rate limit detected distributed packet load (%u buckets, "
               "%u global count).\n",
               m_clients.Size(), m_global_count);
    ResetClients();
    m_global_count =
        (std::max)(1U, (m_global_max_sec + 1) * (m_max_window + 1));
    m_global_last_reset = time;
  }

  // now find the entry and check if it's within our rate limits
  const auto address_iterator = m_address_to_client_map.find(address);
  if (address_iterator != m_address_to_client_map.end()) {
    const size_t client_index = address_iterator->second;
    auto *client = &m_clients[client_index];

    const uint32_t hit_count = client->GetHitCount() + attempts;
    const bool different_last_ping = time != client->GetLastPing();
    const Client::RateLimitType client_limit_type =
        client->CheckIPRate(time, m_max_sec, m_max_window, attempts);

    if (different_last_ping) {
      m_clients.UpdateObjectPlacement(client_index);
    }

    if (client_limit_type == Client::RateLimitType::Sustained &&
        time - m_last_personal_detection > m_max_window / 10) {
      DevWarning(
          "[ServerSecure] IP rate limiting client %d.%d.%d.%d sustained %u "
          "hits at %.1f pps (%u buckets, %u global count).\n",
          (address >> 24) & 0xFF, (address >> 16) & 0xFF, (address >> 8) & 0xFF,
          address & 0xFF, hit_count,
          static_cast<double>(hit_count) / static_cast<double>(m_max_window),
          m_clients.Size(), m_global_count);
    } else if (client_limit_type == Client::RateLimitType::Limited) {
      if (time - m_last_personal_detection > m_max_window) {
        m_last_personal_detection = time;
        DevWarning("[ServerSecure] IP rate limiting client %d.%d.%d.%d at "
                   "%u hits (%u buckets, %u global count).\n",
                   (address >> 24) & 0xFF, (address >> 16) & 0xFF,
                   (address >> 8) & 0xFF, address & 0xFF, hit_count,
                   m_clients.Size(), m_global_count);
      }

      return RateLimitType::Individual;
    }
  }

  // Check the global rate
  m_global_count += attempts;

  if (time - m_global_last_reset >= m_max_window) {
    if (m_global_count >= m_global_max_sec * m_max_window &&
        time - m_last_distributed_detection >= m_max_window / 10) {
      DevWarning("[ServerSecure] IP rate limit sustained %u distributed "
                 "packets at %.1f pps (%u buckets).\n",
                 m_global_count,
                 static_cast<double>(m_global_count) /
                     static_cast<double>(m_max_window),
                 m_clients.Size());
    }

    m_global_last_reset = time;
    m_global_count = attempts;
  } else if (m_global_count >= m_global_max_sec * m_max_window) {
    if (time - m_last_distributed_detection >= m_max_window) {
      m_last_distributed_detection = time;
      DevWarning(
          "[ServerSecure] IP rate limit under distributed packet load (%u "
          "buckets, %u global count), rejecting %d.%d.%d.%d.\n",
          m_clients.Size(), m_global_count, (address >> 24) & 0xFF,
          (address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF);
    }

    return RateLimitType::Global;
  }

  // Not found, insert this new address
  if (address_iterator == m_address_to_client_map.end()) {
    auto lock = m_clients.LockObject();
    if (lock.has_value()) {
      auto [client_ref, client_index] = lock.value();
      auto *client = &client_ref.get();
      client->Reset(address, time, attempts);
      m_clients.UpdateObjectPlacement(client_index);
      m_address_to_client_map.emplace(address, client_index);
    }
  }

  return RateLimitType::None;
}

uint32_t ClientManager::GetMaxQueriesWindow() const { return m_max_window; }

uint32_t ClientManager::GetMaxQueriesPerSecond() const { return m_max_sec; }

uint32_t ClientManager::GetGlobalMaxQueriesPerSecond() const {
  return m_global_max_sec;
}

void ClientManager::SetMaxQueriesWindow(const uint32_t window) {
  m_max_window = window;
}

void ClientManager::SetMaxQueriesPerSecond(const uint32_t max) {
  m_max_sec = max;
}

void ClientManager::SetGlobalMaxQueriesPerSecond(const uint32_t max) {
  m_global_max_sec = max;
}

void ClientManager::PruneTimedOutClients(const uint32_t time) {
  size_t num_pruned = 0;
  auto current_client_optional = m_clients.GetFirstObject();
  while (current_client_optional.has_value()) {
    auto [current_client_ref, current_client_index] =
        current_client_optional.value();
    auto &current_client = current_client_ref.get();
    auto next_client_optional = m_clients.GetNextObject(current_client_index);
    if (current_client.TimedOut(time, m_max_window)) {
      m_address_to_client_map.erase(current_client.GetAddress());
      m_clients.UnlockObject(current_client_index);

      ++num_pruned;

      if (num_pruned >= MinPrune &&
          m_address_to_client_map.size() <= PruneMaxClients) {
        break;
      }
    }

    current_client_optional = std::move(next_client_optional);
  }
}

void ClientManager::ResetClients() {
  m_clients.Clear();
  m_address_to_client_map.clear();
}
} // namespace netfilter
