#include "client.hpp"

namespace netfilter {
Client::Client(const uint32_t address) : m_address(address) {}

Client::Client(const uint32_t address, const uint32_t time,
               const uint32_t attempts)
    : m_address(address), m_last_ping(time), m_last_reset(time),
      m_count(attempts) {}

void Client::Reset(const uint32_t address, const uint32_t time,
                   const uint32_t attempts) {
  m_address = address;
  m_last_ping = time;
  m_last_reset = time;
  m_count = attempts;
  m_marked_for_removal = false;
}

Client::RateLimitType Client::CheckIPRate(const uint32_t time,
                                          const uint32_t max_sec,
                                          const uint32_t max_window,
                                          const uint32_t attempts) {
  m_last_ping = time;

  m_count += attempts;

  if (time - m_last_reset >= max_window) {
    const uint32_t previous_count = m_count;
    m_last_reset = time;
    m_count = attempts;

    if (previous_count > max_sec * max_window) {
      return RateLimitType::Sustained;
    }
  } else if (m_count >= max_sec * max_window) {
    return RateLimitType::Limited;
  }

  return RateLimitType::None;
}

uint32_t Client::GetHitCount() const { return m_count; }

uint32_t Client::GetAddress() const { return m_address; }

uint32_t Client::GetLastPing() const { return m_last_ping; }

bool Client::TimedOut(const uint32_t time, const uint32_t max_window) const {
  return time - m_last_reset >= max_window * 2;
}

void Client::MarkForRemoval() { m_marked_for_removal = true; }

bool Client::MarkedForRemoval() const { return m_marked_for_removal; }

bool Client::operator<(const Client &rhs) const {
  return m_last_ping < rhs.m_last_ping;
}
} // namespace netfilter
