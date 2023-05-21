#include <chrono>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

#include "netfilter/client.hpp"
#include "netfilter/clientmanager.hpp"
#include "netfilter/objectpool.hpp"

static_assert(netfilter::ClientManager::MaxClients > 2,
              "Maximum number of clients should be greater than 2");
static_assert(netfilter::ClientManager::MaxQueriesWindow >= 2,
              "Maximum queries window should be equal or greater than 2");
static_assert(netfilter::ClientManager::MaxQueriesPerSecond >= 1,
              "Maximum queries per second should be equal or greater than 1");

static void TestObjectPool() {
  ObjectPool<netfilter::Client, 50000> clients;

  if (clients.Size() != 0) {
    throw std::runtime_error("Number of locked objects should be 0");
  }

  if (!clients.HasLockableObjects()) {
    throw std::runtime_error("Object pool should have lockable objects");
  }

  for (size_t k = 0; k < clients.Capacity(); ++k) {
    const auto object = clients.LockObject();
    object.value().first.get().CheckIPRate(
        k, netfilter::ClientManager::MaxQueriesPerSecond,
        netfilter::ClientManager::MaxQueriesWindow);
    clients.UpdateObjectPlacement(object.value().second);
  }

  if (clients.HasLockableObjects()) {
    throw std::runtime_error("Object pool shouldn't have lockable objects");
  }

  if (clients.Size() != clients.Capacity()) {
    throw std::runtime_error(
        "Number of locked objects should be equal to object pool capacity");
  }

  clients[0];

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
  const_cast<const decltype(clients) &>(clients)[0];

  const auto first_object = clients.GetFirstObject();
  if (!first_object.has_value()) {
    throw std::runtime_error("GetFirstObject returned an invalid value");
  }

  const auto last_object = clients.GetLastObject();
  if (!last_object.has_value()) {
    throw std::runtime_error("GetLastObject returned an invalid value");
  }

  const auto next_object = clients.GetNextObject(first_object.value().second);
  if (!next_object.has_value()) {
    throw std::runtime_error("GetNextObject returned an invalid value");
  }

  const auto previous_object =
      clients.GetPreviousObject(last_object.value().second);
  if (!previous_object.has_value()) {
    throw std::runtime_error("GetPreviousObject returned an invalid value");
  }

  for (size_t k = 0; k < clients.Capacity(); ++k) {
    clients.UnlockObject(k);
  }

  if (!clients.HasLockableObjects()) {
    throw std::runtime_error("Object pool should have lockable objects");
  }

  if (clients.Size() != 0) {
    throw std::runtime_error("Number of locked objects should be 0");
  }

  const auto client = clients.LockObject();

  if (!client.has_value() || clients.Size() != 1) {
    throw std::runtime_error("Number of locked objects should be 1");
  }

  clients.UnlockObject(client.value().second);

  for (size_t k = 0; k < clients.Capacity(); ++k) {
    const auto object = clients.LockObject();
    object.value().first.get().CheckIPRate(
        // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp,concurrency-mt-unsafe)
        std::rand(), netfilter::ClientManager::MaxQueriesPerSecond,
        netfilter::ClientManager::MaxQueriesWindow);
    clients.UpdateObjectPlacement(object.value().second);
  }

  size_t count = 0;
  uint32_t last_value = 0;
  auto current_object = clients.GetFirstObject();
  while (current_object.has_value()) {
    ++count;
    if (current_object.value().first.get().GetLastPing() < last_value) {
      throw std::runtime_error("FUCK");
    }

    last_value = current_object.value().first.get().GetLastPing();
    current_object = clients.GetNextObject(current_object.value().second);
  }
}

static void TestWithOptions(const uint32_t client_max_queries_per_sec,
                            const uint32_t max_queries_window,
                            const bool set_global_max_queries_per_sec) {
  if (client_max_queries_per_sec < 1) {
    throw std::runtime_error(
        "Maximum queries per second should be equal or greater than 1");
  }

  if (max_queries_window < 2) {
    throw std::runtime_error("Maximum queries window should be higher than 2");
  }

  const uint32_t max_tries_before_ban =
      client_max_queries_per_sec * max_queries_window - 1;
  constexpr uint32_t beginning_of_times = 0;
  const uint32_t within_window_timeout = max_queries_window - 1;
  const uint32_t outside_window_timeout = max_queries_window + 1;

  netfilter::ClientManager client_manager;
  client_manager.SetState(true);
  client_manager.SetMaxQueriesPerSecond(client_max_queries_per_sec);
  client_manager.SetMaxQueriesWindow(max_queries_window);

  if (set_global_max_queries_per_sec) {
    client_manager.SetGlobalMaxQueriesPerSecond(
        client_max_queries_per_sec * netfilter::ClientManager::MaxClients);
  }

  {
    netfilter::Client client(1);

    // Check IP rate "max tries - 1" times and confirm it passes
    for (uint32_t tries = 0; tries < max_tries_before_ban; ++tries) {
      if (client.CheckIPRate(beginning_of_times, client_max_queries_per_sec,
                             max_queries_window) ==
          netfilter::Client::RateLimitType::Limited) {
        throw std::runtime_error(
            "Client didn't pass IP rate check when it should");
      }
    }

    // Check IP rate one more time and confirm it doesn't pass
    if (client.CheckIPRate(beginning_of_times, client_max_queries_per_sec,
                           max_queries_window) !=
        netfilter::Client::RateLimitType::Limited) {
      throw std::runtime_error("Client passed IP rate check when it shouldn't");
    }

    // Check IP rate one more time outside window and confirm it passes
    if (client.CheckIPRate(outside_window_timeout, client_max_queries_per_sec,
                           max_queries_window) ==
        netfilter::Client::RateLimitType::Limited) {
      throw std::runtime_error(
          "Client didn't pass IP rate check when it should");
    }
  }

  // Check IP rate one time for client 1 and confirm it passes both globally and
  // individually
  if (client_manager.CheckIPRate(1, beginning_of_times) !=
      netfilter::ClientManager::RateLimitType::None) {
    throw std::runtime_error(
        "Client 1 didn't pass IP rate check when it should");
  }

  // Check IP rate one time for clients 2 to max and confirm they pass both
  // globally and individually, if we set the global max queries per second If
  // we don't set that value, we might hit the global limit.
  for (uint32_t address = 2;
       address <= netfilter::ClientManager::CriticalMaxClients; ++address) {
    const auto rate_limit =
        client_manager.CheckIPRate(address, within_window_timeout);
    if (rate_limit == netfilter::ClientManager::RateLimitType::Individual ||
        (rate_limit == netfilter::ClientManager::RateLimitType::Global &&
         set_global_max_queries_per_sec)) {
      throw std::runtime_error("Client " + std::to_string(address) +
                               " didn't pass IP rate check when it should");
    }
  }

  // Check IP rate "max tries - 1" times for all clients and confirm they pass
  // both globally and individually, if we set the global max queries per second
  // If we don't set that value, we might hit the global limit.
  for (uint32_t address = 1;
       address <= netfilter::ClientManager::CriticalMaxClients; ++address) {
    const auto rate_limit = client_manager.CheckIPRate(
        address, within_window_timeout, max_tries_before_ban - 1);
    if (rate_limit == netfilter::ClientManager::RateLimitType::Individual ||
        (rate_limit == netfilter::ClientManager::RateLimitType::Global &&
         set_global_max_queries_per_sec)) {
      throw std::runtime_error("Client " + std::to_string(address) +
                               " didn't pass IP rate check when it should");
    }
  }

  // Check IP rate one time for client 1 and confirm it doesn't pass
  if (client_manager.CheckIPRate(1, within_window_timeout) ==
      netfilter::ClientManager::RateLimitType::None) {
    throw std::runtime_error("Client 1 passed IP rate check when it shouldn't");
  }

  // Check IP rate one time for client 1 and confirm it passes both globally and
  // individually, since it should have hit the window timeout
  if (client_manager.CheckIPRate(1, outside_window_timeout) !=
      netfilter::ClientManager::RateLimitType::None) {
    throw std::runtime_error(
        "Client 1 didn't pass IP rate check when it should");
  }

  // Check IP rate one time for client 2 and confirm it doesn't pass
  // individually, since it hasn't hit the window timeout yet (started counting
  // 2 time units ago)
  if (client_manager.CheckIPRate(2, outside_window_timeout) ==
      netfilter::ClientManager::RateLimitType::None) {
    throw std::runtime_error("Client 2 passed IP rate check when it shouldn't");
  }
}

static void TestPerformance(const uint32_t max_clients_multiplier) {
  const uint32_t within_window_timeout =
      netfilter::ClientManager::MaxQueriesWindow - 1;
  const uint32_t outside_window_timeout =
      netfilter::ClientManager::MaxQueriesWindow + 1;

  netfilter::ClientManager client_manager;
  client_manager.SetState(true);
  client_manager.SetGlobalMaxQueriesPerSecond(
      netfilter::ClientManager::MaxClients *
      netfilter::ClientManager::MaxQueriesPerSecond *
      (netfilter::ClientManager::MaxQueriesWindow - 1) *
      max_clients_multiplier);

  for (uint32_t time = 0; time < within_window_timeout; ++time) {
    for (uint32_t address = 1;
         address <=
         netfilter::ClientManager::CriticalMaxClients * max_clients_multiplier;
         ++address) {
      if (client_manager.CheckIPRate(address, time) ==
          netfilter::ClientManager::RateLimitType::Individual) {
        throw std::runtime_error("Client " + std::to_string(address) +
                                 " didn't pass IP rate check at time unit " +
                                 std::to_string(time) + " when it should");
      }
    }
  }

  for (uint32_t address = 1;
       address <=
       netfilter::ClientManager::CriticalMaxClients * max_clients_multiplier;
       ++address) {
    if (client_manager.CheckIPRate(address, outside_window_timeout) ==
        netfilter::ClientManager::RateLimitType::Individual) {
      throw std::runtime_error("Client " + std::to_string(address) +
                               " didn't pass IP rate check at time unit " +
                               std::to_string(outside_window_timeout) +
                               " when it should");
    }
  }
}

inline void Run(const std::string &test_name,
                const std::function<void()> &test_fn) {
  const auto start = std::chrono::high_resolution_clock::now();

  std::optional<std::string> error;
  try {
    test_fn();
  } catch (const std::exception &e) {
    error = e.what();
  }

  const auto end = std::chrono::high_resolution_clock::now();

  if (error.has_value()) {
    std::cout << "Test '" << test_name << "' failed with error '"
              << error.value() << "' and took "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                       start)
                     .count()
              << "ms" << std::endl;
  } else {
    std::cout << "Test '" << test_name << "' succeeded and took "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                       start)
                     .count()
              << "ms" << std::endl;
  }
}

int main(int /*unused*/, const char * /*unused*/[]) {
  Run("TestObjectPool", TestObjectPool);
  Run("TestWithDefaultOptions", [] {
    return TestWithOptions(netfilter::ClientManager::MaxQueriesPerSecond,
                           netfilter::ClientManager::MaxQueriesWindow, true);
  });
  Run("TestWithSourceOptions", [] { return TestWithOptions(3, 30, true); });
  Run("TestWithDefaultOptionsAndNoGlobalMaxQueries", [] {
    return TestWithOptions(netfilter::ClientManager::MaxQueriesPerSecond,
                           netfilter::ClientManager::MaxQueriesWindow, false);
  });
  Run("TestPerformanceWithClientMultiplier1",
      [] { return TestPerformance(1); });
  Run("TestPerformanceWithClientMultiplier2",
      [] { return TestPerformance(2); });
  Run("TestPerformanceWithClientMultiplier4",
      [] { return TestPerformance(4); });
  Run("TestPerformanceWithClientMultiplier8",
      [] { return TestPerformance(8); });
  return 0;
}
