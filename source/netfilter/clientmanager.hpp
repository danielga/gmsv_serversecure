#pragma once

#include <map>
#include "client.hpp"

namespace netfilter
{
	class ClientManager
	{
	public:
		ClientManager( );

		void SetState( bool enabled );

		bool CheckIPRate( uint32_t from, uint32_t time );

		uint32_t GetMaxQueriesWindow( ) const;
		uint32_t GetMaxQueriesPerSecond( ) const;
		uint32_t GetGlobalMaxQueriesPerSecond( ) const;

		void SetMaxQueriesWindow( uint32_t window );
		void SetMaxQueriesPerSecond( uint32_t max );
		void SetGlobalMaxQueriesPerSecond( uint32_t max );

		static const uint32_t MaxClients = 4096;
		static const uint32_t PruneAmount = MaxClients * 2 / 3;
		static const uint32_t ClientTimeout = 120;

	private:
		std::map<uint32_t, Client> clients;
		bool enabled;
		uint32_t global_count;
		uint32_t global_last_reset;
		uint32_t max_window;
		uint32_t max_sec;
		uint32_t global_max_sec;
	};
}
