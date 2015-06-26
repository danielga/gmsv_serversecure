#include <filecheck.hpp>
#include <helpers.hpp>
#include <symbolfinder.hpp>
#include <detours.h>
#include <convar.h>
#include <networkstringtabledefs.h>

namespace FileCheck
{

static std::string engine_lib = helpers::GetBinaryFileName( "engine", false, true, "bin/" );

#if defined _WIN32

static const char *IsValidFileForTransfer_sig = "\x55\x8B\xEC\x81\xEC\x2A\x2A\x2A\x2A\x57\x8B\x7D\x08\x85\xFF\x0F\x84";
static size_t IsValidFileForTransfer_siglen = 17;

#elif defined __linux

static const char *IsValidFileForTransfer_sig = "_ZN8CNetChan22IsValidFileForTransferEPKc";
static size_t IsValidFileForTransfer_siglen = 0;

#elif defined __APPLE__

static const char *IsValidFileForTransfer_sig = "__ZN8CNetChan22IsValidFileForTransferEPKc";
static size_t IsValidFileForTransfer_siglen = 0;

#endif

static ConVar ss_show_files( "ss_show_files", "0", 0, "Display file checks" );

typedef bool( *IsValidFileForTransfer_t )( const char *file );

static IsValidFileForTransfer_t IsValidFileForTransfer = nullptr;
static MologieDetours::Detour<IsValidFileForTransfer_t> *IsValidFileForTransfer_detour = nullptr;

static bool IsValidFileForTransfer_d( const char *file )
{
	int32_t len = V_strlen( file );
	if( file == nullptr || len == 0 )
		return false;

	if( ss_show_files.GetBool( ) )
		Msg( "[ServerSecure] Checking file '%s'\n", file );

	if( !IsValidFileForTransfer( file ) )
		return false;

	INetworkStringTable *downloads = Global::networkstringtable->FindTable( "downloadables" );
	if( downloads == nullptr )
	{
		Msg( "[ServerSecure] Missing 'downloadables' string table!\n" );
		return false;
	}

	int32_t index = downloads->FindStringIndex( file );
	if( index == INVALID_STRING_INDEX && ( len > 5 && V_strncmp( file, "maps/", 5 ) == 0 ) )
	{
		char ffile[260] = { 0 };
		V_strncpy( ffile, file, sizeof( ffile ) );
		V_FixSlashes( ffile );
		index = downloads->FindStringIndex( file );
	}

	if( index != INVALID_STRING_INDEX )
		return true;

	if(
		len == 22 &&
		V_strncmp( file, "downloads/", 10 ) == 0 &&
		V_strncmp( file + len - 4, ".dat", 4 ) == 0
	)
		return true;

	Msg( "[ServerSecure] Blocking download: '%s'\n", file );
	return false;
}

void Initialize( lua_State * )
{
	g_pCVar->RegisterConCommand( &ss_show_files );

	SymbolFinder symfinder;
	IsValidFileForTransfer = reinterpret_cast<IsValidFileForTransfer_t>( symfinder.ResolveOnBinary(
		engine_lib.c_str( ),
		IsValidFileForTransfer_sig,
		IsValidFileForTransfer_siglen
	) );
	if( IsValidFileForTransfer == nullptr )
	{
		Msg( "[ServerSecure] Unable to scan CNetChan::IsValidFileForTransfer!\n" );
		return;
	}

	IsValidFileForTransfer_detour = new MologieDetours::Detour<IsValidFileForTransfer_t>(
		IsValidFileForTransfer,
		IsValidFileForTransfer_d
	);
}

void Deinitialize( lua_State * )
{
	if( IsValidFileForTransfer != nullptr )
	{
		delete IsValidFileForTransfer_detour;
		IsValidFileForTransfer_detour = nullptr;
	}

	g_pCVar->UnregisterConCommand( &ss_show_files );
}

}