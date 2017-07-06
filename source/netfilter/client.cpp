#include <netfilter/client.hpp>
#include <netfilter/clientmanager.hpp>
#include <main.hpp>

namespace netfilter
{
	Client::Client( ClientManager &manager, uint32_t address ) :
		manager( manager ), address( address ), last_reset( 0 ), count( 0 )
	{ }

	Client::Client( ClientManager &manager, uint32_t address, uint32_t time ) :
		manager( manager ), address( address ), last_reset( time ), count( 1 )
	{ }

	bool Client::CheckIPRate( uint32_t time )
	{
		if( time - last_reset >= manager.GetMaxQueriesWindow( ) )
		{
			last_reset = time;
		}
		else
		{
			++count;
			if( count / manager.GetMaxQueriesWindow( ) >= manager.GetMaxQueriesPerSecond( ) )
			{
				DebugWarning(
					"[ServerSecure] %d.%d.%d.% reached its query limit!\n",
					( address >> 24 ) & 0xFF,
					( address >> 16 ) & 0xFF,
					( address >> 8 ) & 0xFF,
					address & 0xFF
				);
				return false;
			}
		}

		return true;
	}

	uint32_t Client::GetAddress( ) const
	{
		return address;
	}

	bool Client::TimedOut( uint32_t time ) const
	{
		return last_reset - time >= ClientManager::ClientTimeout;
	}
}
