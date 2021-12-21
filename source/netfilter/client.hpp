#ifndef NETFILTER_CLIENT_HPP
#define NETFILTER_CLIENT_HPP

#pragma once

#include <cstdint>

namespace netfilter {
class ClientManager;

class Client {
public:
  Client(ClientManager &manager, uint32_t address);
  Client(ClientManager &manager, uint32_t address, uint32_t time);

  bool CheckIPRate(uint32_t time);

  [[nodiscard]] uint32_t GetAddress() const;
  [[nodiscard]] bool TimedOut(uint32_t time) const;

private:
  ClientManager &manager;
  uint32_t address;
  uint32_t last_reset;
  uint32_t count;
};
} // namespace netfilter

#endif // NETFILTER_CLIENT_HPP
