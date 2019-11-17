#pragma once

#include <cstdint>

namespace netfilter
{
	class ClientManager;

	class Client
	{
	public:
		Client( ClientManager &manager, uint32_t address );
		Client( ClientManager &manager, uint32_t address, uint32_t time );

		bool CheckIPRate( uint32_t time );

		uint32_t GetAddress( ) const;
		bool TimedOut( uint32_t time ) const;

	private:
		ClientManager &manager;
		uint32_t address;
		uint32_t last_reset;
		uint32_t count;
	};
}
