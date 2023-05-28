#ifndef NETFILTER_PROCESSINGTIME_HPP
#define NETFILTER_PROCESSINGTIME_HPP

#pragma once

#include <chrono>
#include <unordered_map>

#include <detouring/classproxy.hpp>

#include <GarrysMod/FunctionPointers.hpp>

#include <tier1/convar.h>

namespace netfilter {
class CNetChanProxy : public Detouring::ClassProxy<CNetChan, CNetChanProxy> {
public:
  CNetChanProxy();
  ~CNetChanProxy();

  bool ProcessMessages(bf_read &buf);
};
} // namespace netfilter
#endif // NETFILTER_PROCESSINGTIME_HPP
