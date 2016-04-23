#include <cstdint>
#include <refcount.h>
#include <utlsymbol.h>
#include <utlstring.h>
#include <utllinkedlist.h>
#include <utldict.h>
#include <tier1.h>
#include <byteswap.h>
#include <UtlSortVector.h>
#include <filesystem.h>
#include <GarrysMod/Addon.h>
#include <GarrysMod/LegacyAddons.h>
#include <GarrysMod/Gamemode.h>
#include <GarrysMod/GameDepot.h>
#include <GarrysMod/Language.h>

#undef GetCurrentDirectory
#undef AsyncRead

class CPackFile;
class CBaseFileSystem;
class IGet;
struct FIND_DATA;

enum FileMode_t
{
	FM_BINARY,
	FM_TEXT
};

enum FileType_t
{
	FT_NORMAL,
	FT_PACK_BINARY,
	FT_PACK_TEXT
};

union Placeholder4
{
	const uint8_t bytes[4];
	const char *string;
	uint32_t integer;
	void *pointer;
};

template<class T> class CThreadSafeRefCountedObject
{
public:
	CThreadSafeRefCountedObject( T initVal )
	{
		m_RefCount = 0;
		m_pObject = initVal;
		m_RefCount = 0;
	}

	void Init( T pObj )
	{
		Assert( ThreadInMainThread() );
		Assert( !m_pObject );
		m_RefCount = 0;
		m_pObject = pObj;
		m_RefCount = 1;
	}

	T AddRef()
	{
		if ( ++m_RefCount > 1 )
			return m_pObject;

		--m_RefCount;
		return nullptr;
	}
	void ReleaseRef( T pObj )
	{
		if ( --m_RefCount >= 1 )
			Assert( m_pObject == pObj );
	}

	T GetInMainThread()
	{
		Assert( ThreadInMainThread() );
		return m_pObject;
	}

	void ResetWhenNoRemainingReferences( T newValue )
	{
		Assert( ThreadInMainThread() );

		while ( m_RefCount > 0 )
			CThread::Sleep( 20 );

		m_pObject = newValue;
	}

private:
	CInterlockedIntT<long> m_RefCount;
	T m_pObject;
};

class CPackFileHandle
{
public:
	int64_t m_nBase;
	uint32_t m_nFilePointer;
	CPackFile *m_pOwner;
	uint32_t m_nLength;
	uint32_t m_nIndex;
};

class CFileHandle
{
public:
#if !defined( _RETAIL )
	char *m_pszTrueFileName;
#endif

	CPackFileHandle *m_pPackFileHandle;
	int64_t m_nLength;
	FileType_t m_type;
	FILE *m_pFile;
	CBaseFileSystem *m_fs;

	enum
	{
		MAGIC = 'CFHa',
		FREE_MAGIC = 'FreM'
	};

	uint32_t m_nMagic;
};

class CPackFile : public CRefCounted<CRefCountServiceMT>
{
public:
	virtual ~CPackFile( ) = 0;
	virtual CFileHandle *OpenFile( const char *pFileName, const char *pOptions = "rb" ) = 0;
	virtual bool Prepare( int64_t fileLen = -1, int64_t nFileOfs = 0 ) = 0;
	virtual bool FindFile( const char *pFilename, int32_t &nIndex, int64_t &nPosition, int32_t &nLength ) = 0;
	virtual int32_t ReadFromPack( int32_t nIndex, void *buffer, int32_t nDestBytes, int32_t nBytes, int64_t nOffset ) = 0;
	virtual bool IndexToFilename( int32_t nIndex, char *buffer, int32_t nBufferSize ) = 0;
	virtual void SetupPreloadData( ) = 0;
	virtual void DiscardPreloadData( ) = 0;
	virtual int64_t GetPackFileBaseOffset( ) = 0;

	CThreadFastMutex m_mutex; // 8b
	CUtlSymbol m_Path; // 4b
	int64_t m_nBaseOffset; // 8b
	CUtlString m_ZipName; // 4b
	bool m_bIsMapPath; // 4b
	int32_t m_lPackFileTime; // 4b
	int32_t m_refCount; // 4b
	int32_t m_nOpenFiles; // 4b
	FILE *m_hPackFileHandle; // 4b
	int64_t m_FileLength; // 8b
	CBaseFileSystem *m_fs;  // 4b
};

class CZipPackFile : public CPackFile
{
public:
	class CPackFileEntry
	{
	public:
		uint32_t m_nPosition;
		uint32_t m_nLength;
		uint32_t m_HashName;
		uint16_t m_nPreloadIdx;
		uint16_t pad;
#if !defined( _RETAIL )
		FileNameHandle_t m_hDebugFilename;
#endif
	};

	class CPackFileLessFunc
	{
	public:
		bool Less( const CPackFileEntry &src1, const CPackFileEntry &src2, void *pCtx );
	};

	CUtlSortVector<CPackFileEntry, CPackFileLessFunc> m_PackFiles; // 28b
	int64_t m_nPreloadSectionOffset; // 8b
	uint32_t m_nPreloadSectionSize; // 4b
	struct ZIP_PreloadHeader *m_pPreloadHeader; // 4b
	uint16_t *m_pPreloadRemapTable; // 4b
	struct ZIP_PreloadDirectoryEntry *m_pPreloadDirectory; // 4b
	void *m_pPreloadData; // 4b
	CByteswap m_swap; // 4b

	const Placeholder4 placeholders[13];
};

class WilloxHallOfShame
{
public:
	void **vtable;
	uint32_t refcounter;
	uint32_t filepathid;
	const char filepath[1];
};

class CFileInfo;

class CPathIDFileList
{
public:
	CUtlSymbol m_PathID;
	CUtlDict<CFileInfo *, int32_t> m_Files;
	CUtlLinkedList<CFileInfo *, int32_t>	m_UnverifiedCRCFiles;
};

class CFileInfo
{
public:
	uint16_t m_Flags;
	CRC32_t m_CRC;
	CPathIDFileList	*m_pPathIDFileList;
	int32_t m_PathIDFileListDictIndex;
	int32_t m_iNeedsVerificationListIndex;
};

class CFileTracker
{
	CUtlLinkedList<CFileInfo *> m_NeedsVerificationList;
	CUtlDict<CPathIDFileList *, int32_t> m_PathIDs;
	CBaseFileSystem *m_pFileSystem;
	CThreadMutex m_Mutex;
};

class CWhitelistSpecs
{
public:
	IFileList *m_pWantCRCList;
	IFileList *m_pAllowFromDiskList;
};
typedef CThreadSafeRefCountedObject<CWhitelistSpecs *> CWhitelistHolder;

class CBaseFileSystem : public CTier1AppSystem<IFileSystem>
{
public:
	enum KeyValuesPreloadType_t
	{
		TYPE_VMT,
		TYPE_SOUNDEMITTER,
		TYPE_SOUNDSCAPE,
		NUM_PRELOAD_TYPES
	};

	virtual bool Connect( CreateInterfaceFn factory ) = 0;
	virtual void Disconnect( ) = 0;
	virtual void *QueryInterface( const char *pInterfaceName ) = 0;
	virtual InitReturnVal_t Init( ) = 0;
	virtual void Shutdown( ) = 0;
	virtual bool IsSteam( ) const = 0;
	virtual	FilesystemMountRetval_t MountSteamContent( int nExtraAppId = -1 ) = 0;
	virtual void AddSearchPath( const char *pPath, const char *pathID, SearchPathAdd_t addType = PATH_ADD_TO_TAIL ) = 0;
	virtual bool RemoveSearchPath( const char *pPath, const char *pathID = nullptr ) = 0;
	virtual void RemoveAllSearchPaths( void ) = 0;
	virtual void RemoveSearchPaths( const char *szPathID ) = 0;
	virtual void MarkPathIDByRequestOnly( const char *pPathID, bool bRequestOnly ) = 0;
	virtual const char *RelativePathToFullPath( const char *pFileName, const char *pPathID, OUT_Z_CAP( maxLenInChars ) char *pDest, int maxLenInChars, PathTypeFilter_t pathFilter = FILTER_NONE, PathTypeQuery_t *pPathType = nullptr ) = 0;
	virtual int GetSearchPath( const char *pathID, bool bGetPackFiles, OUT_Z_CAP( maxLenInChars ) char *pDest, int maxLenInChars ) = 0;
	virtual bool AddPackFile( const char *fullpath, const char *pathID ) = 0;
	virtual void RemoveFile( char const* pRelativePath, const char *pathID = nullptr) = 0;
	virtual bool RenameFile( char const *pOldPath, char const *pNewPath, const char *pathID = nullptr) = 0;
	virtual void CreateDirHierarchy( const char *path, const char *pathID = nullptr) = 0;
	virtual bool IsDirectory( const char *pFileName, const char *pathID = nullptr) = 0;
	virtual void FileTimeToString( char* pStrip, int maxCharsIncludingTerminator, long fileTime ) = 0;
	virtual void SetBufferSize( FileHandle_t file, unsigned nBytes ) = 0;
	virtual bool IsOk( FileHandle_t file ) = 0;
	virtual bool EndOfFile( FileHandle_t file ) = 0;
	virtual char *ReadLine( char *pOutput, int maxChars, FileHandle_t file ) = 0;
	virtual int FPrintf( FileHandle_t file, PRINTF_FORMAT_STRING const char *pFormat, ... ) = 0;
	virtual CSysModule *LoadModule( const char *pFileName, const char *pPathID = nullptr, bool bValidatedDllOnly = true ) = 0;
	virtual void UnloadModule( CSysModule *pModule ) = 0;
	virtual const char *FindFirst( const char *pWildCard, FileFindHandle_t *pHandle ) = 0;
	virtual const char *FindNext( FileFindHandle_t handle ) = 0;
	virtual bool FindIsDirectory( FileFindHandle_t handle ) = 0;
	virtual void FindClose( FileFindHandle_t handle ) = 0;
	virtual const char *FindFirstEx(const char *pWildCard, const char *pPathID, FileFindHandle_t *pHandle ) = 0;
	virtual const char *GetLocalPath( const char *pFileName, OUT_Z_CAP( maxLenInChars ) char *pDest, int maxLenInChars ) = 0;
	virtual bool FullPathToRelativePath( const char *pFullpath, OUT_Z_CAP( maxLenInChars ) char *pDest, int maxLenInChars ) = 0;
	virtual bool GetCurrentDirectory( char* pDirectory, int maxlen ) = 0;
	virtual FileNameHandle_t FindOrAddFileName( char const *pFileName ) = 0;
	virtual bool String( const FileNameHandle_t& handle, char *buf, int buflen ) = 0;
	virtual FSAsyncStatus_t	AsyncReadMultiple( const FileAsyncRequest_t *pRequests, int nRequests, FSAsyncControl_t *phControls = nullptr) = 0;
	virtual FSAsyncStatus_t	AsyncAppend( const char *pFileName, const void *pSrc, int nSrcBytes, bool bFreeMemory, FSAsyncControl_t *pControl = nullptr) = 0;
	virtual FSAsyncStatus_t	AsyncAppendFile( const char *pAppendToFileName, const char *pAppendFromFileName, FSAsyncControl_t *pControl = nullptr) = 0;
	virtual void AsyncFinishAll( int iToPriority = 0 ) = 0;
	virtual void AsyncFinishAllWrites( ) = 0;
	virtual FSAsyncStatus_t	AsyncFlush( ) = 0;
	virtual bool AsyncSuspend( ) = 0;
	virtual bool AsyncResume( ) = 0;
	virtual void AsyncAddFetcher( IAsyncFileFetch *pFetcher ) = 0;
	virtual void AsyncRemoveFetcher( IAsyncFileFetch *pFetcher ) = 0;
	virtual FSAsyncStatus_t	AsyncBeginRead( const char *pszFile, FSAsyncFile_t *phFile ) = 0;
	virtual FSAsyncStatus_t	AsyncEndRead( FSAsyncFile_t hFile ) = 0;
	virtual FSAsyncStatus_t	AsyncFinish( FSAsyncControl_t hControl, bool wait = true ) = 0;
	virtual FSAsyncStatus_t	AsyncGetResult( FSAsyncControl_t hControl, void **ppData, int *pSize ) = 0;
	virtual FSAsyncStatus_t	AsyncAbort( FSAsyncControl_t hControl ) = 0;
	virtual FSAsyncStatus_t	AsyncStatus( FSAsyncControl_t hControl ) = 0;
	virtual FSAsyncStatus_t	AsyncSetPriority( FSAsyncControl_t hControl, int newPriority ) = 0;
	virtual void AsyncAddRef( FSAsyncControl_t hControl ) = 0;
	virtual void AsyncRelease( FSAsyncControl_t hControl ) = 0;
	virtual WaitForResourcesHandle_t WaitForResources( const char *resourcelist ) = 0;
	virtual bool GetWaitForResourcesProgress( WaitForResourcesHandle_t handle, float *progress, bool *complete ) = 0;
	virtual void CancelWaitForResources( WaitForResourcesHandle_t handle ) = 0;
	virtual int HintResourceNeed( const char *hintlist, int forgetEverything ) = 0;
	virtual bool IsFileImmediatelyAvailable( const char *pFileName ) = 0;
	virtual void GetLocalCopy( const char *pFileName ) = 0;
	virtual void PrintOpenedFiles( void ) = 0;
	virtual void PrintSearchPaths( void ) = 0;
	virtual void SetWarningFunc( void( *pfnWarning )( PRINTF_FORMAT_STRING const char *fmt, ... ) ) = 0;
	virtual void SetWarningLevel( FileWarningLevel_t level ) = 0;
	virtual void AddLoggingFunc( void( *pfnLogFunc )( const char *fileName, const char *accessType ) ) = 0;
	virtual void RemoveLoggingFunc( FileSystemLoggingFunc_t logFunc ) = 0;
	virtual const FileSystemStatistics *GetFilesystemStatistics( ) = 0;
	virtual FileHandle_t OpenEx( const char *pFileName, const char *pOptions, unsigned flags = 0, const char *pathID = nullptr, char **ppszResolvedFilename = nullptr) = 0;
	virtual int ReadEx( void* pOutput, int sizeDest, int size, FileHandle_t file ) = 0;
	virtual int ReadFileEx( const char *pFileName, const char *pPath, void **ppBuf, bool bNullTerminate = false, bool bOptimalAlloc = false, int nMaxBytes = 0, int nStartingByte = 0, FSAllocFunc_t pfnAlloc = nullptr) = 0;
	virtual FileNameHandle_t FindFileName( char const *pFileName ) = 0;
	virtual void SetupPreloadData( ) = 0;
	virtual void DiscardPreloadData( ) = 0;
	virtual void LoadCompiledKeyValues( KeyValuesPreloadType_t type, char const *archiveFile ) = 0;
	virtual KeyValues	*LoadKeyValues( KeyValuesPreloadType_t type, char const *filename, char const *pPathID = nullptr) = 0;
	virtual bool LoadKeyValues( KeyValues& head, KeyValuesPreloadType_t type, char const *filename, char const *pPathID = nullptr) = 0;
	virtual bool ExtractRootKeyName( KeyValuesPreloadType_t type, char *outbuf, size_t bufsize, char const *filename, char const *pPathID = nullptr) = 0;
	virtual FSAsyncStatus_t	AsyncWrite( const char *pFileName, const void *pSrc, int nSrcBytes, bool bFreeMemory, bool bAppend = false, FSAsyncControl_t *pControl = nullptr) = 0;
	virtual FSAsyncStatus_t	AsyncWriteFile( const char *pFileName, const CUtlBuffer *pSrc, int nSrcBytes, bool bFreeMemory, bool bAppend = false, FSAsyncControl_t *pControl = nullptr) = 0;
	virtual FSAsyncStatus_t	AsyncReadMultipleCreditAlloc( const FileAsyncRequest_t *pRequests, int nRequests, const char *pszFile, int line, FSAsyncControl_t *phControls = nullptr) = 0;
	virtual bool GetFileTypeForFullPath( char const *pFullPath, OUT_Z_BYTECAP( bufSizeInBytes ) wchar_t *buf, size_t bufSizeInBytes ) = 0;
	virtual bool ReadToBuffer( FileHandle_t hFile, CUtlBuffer &buf, int nMaxBytes = 0, FSAllocFunc_t pfnAlloc = nullptr) = 0;
	virtual bool GetOptimalIOConstraints( FileHandle_t hFile, unsigned *pOffsetAlign, unsigned *pSizeAlign, unsigned *pBufferAlign ) = 0;
	virtual void *AllocOptimalReadBuffer( FileHandle_t hFile, unsigned nSize = 0, unsigned nOffset = 0 ) = 0;
	virtual void FreeOptimalReadBuffer( void * ) = 0;
	virtual void BeginMapAccess( ) = 0;
	virtual void EndMapAccess( ) = 0;
	virtual bool FullPathToRelativePathEx( const char *pFullpath, const char *pPathId, OUT_Z_CAP( maxLenInChars ) char *pDest, int maxLenInChars ) = 0;
	virtual int GetPathIndex( const FileNameHandle_t &handle ) = 0;
	virtual long GetPathTime( const char *pPath, const char *pPathID ) = 0;
	virtual DVDMode_t GetDVDMode( ) = 0;
	virtual void EnableWhitelistFileTracking( bool bEnable, bool bCacheAllVPKHashes, bool bRecalculateAndCheckHashes ) = 0;
	virtual void RegisterFileWhitelist( IPureServerWhitelist *pWhiteList, IFileList **pFilesToReload ) = 0;
	virtual void MarkAllCRCsUnverified( ) = 0;
	virtual void CacheFileCRCs( const char *pPathname, ECacheCRCType eType, IFileList *pFilter ) = 0;
	virtual EFileCRCStatus CheckCachedFileHash( const char *pPathID, const char *pRelativeFilename, int nFileFraction, FileHash_t *pFileHash ) = 0;
	virtual int GetUnverifiedFileHashes( CUnverifiedFileHash *pFiles, int nMaxFiles ) = 0;
	virtual int GetWhitelistSpewFlags( ) = 0;
	virtual void SetWhitelistSpewFlags( int flags ) = 0;
	virtual void InstallDirtyDiskReportFunc( FSDirtyDiskReportFunc_t func ) = 0;
	virtual FileCacheHandle_t CreateFileCache( ) = 0;
	virtual void AddFilesToFileCache( FileCacheHandle_t cacheId, const char **ppFileNames, int nFileNames, const char *pPathID ) = 0;
	virtual bool IsFileCacheFileLoaded( FileCacheHandle_t cacheId, const char* pFileName ) = 0;
	virtual bool IsFileCacheLoaded( FileCacheHandle_t cacheId ) = 0;
	virtual void DestroyFileCache( FileCacheHandle_t cacheId ) = 0;
	virtual bool RegisterMemoryFile( CMemoryFileBacking *pFile, CMemoryFileBacking **ppExistingFileWithRef ) = 0;
	virtual void UnregisterMemoryFile( CMemoryFileBacking *pFile ) = 0;
	virtual void CacheAllVPKFileHashes( bool bCacheAllVPKHashes, bool bRecalculateAndCheckHashes ) = 0;
	virtual bool CheckVPKFileHash( int PackFileID, int nPackFileNumber, int nFileFraction, MD5Value_t &md5Value ) = 0;
	virtual void NotifyFileUnloaded( const char *pszFilename, const char *pPathId ) = 0;
	virtual void RemoveSearchPathsByGroup( int ) = 0;
	virtual void SetGet( IGet * ) = 0;
	virtual Addon::FileSystem *Addons( ) = 0;
	virtual Gamemode::System *Gamemodes( ) = 0;
	virtual GameDepot::System *Games( ) = 0;
	virtual LegacyAddons::System *LegacyAddons( ) = 0;
	virtual CLanguage *Language( ) = 0;
	virtual void DoFilesystemRefresh( ) = 0;
	virtual int LastFilesystemRefresh( ) = 0;
	virtual void AddVPKFileFromPath( const char *, const char *, unsigned int ) = 0;
	virtual void GMOD_SetupDefaultPaths( const char *, const char * ) = 0;
	virtual FileHandle_t Open( const char *pFileName, const char *pOptions, const char *pathID = nullptr) = 0;
	virtual void Close( FileHandle_t file ) = 0;
	virtual void Seek( FileHandle_t file, int pos, FileSystemSeek_t seekType ) = 0;
	virtual unsigned int Tell( FileHandle_t file ) = 0;
	virtual unsigned int Size( FileHandle_t file ) = 0;
	virtual unsigned int Size( const char *pFileName, const char *pPathID = nullptr) = 0;
	virtual void Flush( FileHandle_t file ) = 0;
	virtual bool Precache( const char *pFileName, const char *pPathID = nullptr ) = 0;
	virtual int Read( void* pOutput, int size, FileHandle_t file ) = 0;
	virtual int Write( void const* pInput, int size, FileHandle_t file ) = 0;
	virtual bool ReadFile( const char *pFileName, const char *pPath, CUtlBuffer &buf, int nMaxBytes = 0, int nStartingByte = 0, FSAllocFunc_t pfnAlloc = nullptr) = 0;
	virtual bool WriteFile( const char *pFileName, const char *pPath, CUtlBuffer &buf ) = 0;
	virtual bool UnzipFile( const char *pFileName, const char *pPath, const char *pDestination ) = 0;
	virtual bool FileExists( const char *pFileName, const char *pPathID = nullptr) = 0;
	virtual long GetFileTime( const char *pFileName, const char *pPathID = nullptr) = 0;
	virtual bool IsFileWritable( char const *pFileName, const char *pPathID = nullptr) = 0;
	virtual bool SetFileWritable( char const *pFileName, bool writable, const char *pPathID = nullptr) = 0;
	virtual void FixUpPath( const char *, char *, int ) = 0;
	virtual FILE *FS_fopen( const char *, const char *, unsigned int, long long * ) = 0;
	virtual void FS_setbufsize( FILE *, unsigned int ) = 0;
	virtual void FS_fclose( FILE * ) = 0;
	virtual void FS_fseek( FILE *, long long, int ) = 0;
	virtual long FS_ftell( FILE * ) = 0;
	virtual int FS_feof( FILE * ) = 0;
	virtual void FS_fread( void *, unsigned long, unsigned long, FILE * ) = 0;
	virtual void FS_fwrite( const void *, unsigned long, FILE * ) = 0;
	virtual bool FS_setmode( FILE *, FileMode_t ) = 0;
	virtual size_t FS_vfprintf( FILE *, const char *, char * ) = 0;
	virtual int FS_ferror( FILE * ) = 0;
	virtual int FS_fflush( FILE * ) = 0;
	virtual char *FS_fgets( char *, int, FILE * ) = 0;
	virtual int FS_stat( const char *, struct stat *, bool * ) = 0;
	virtual int FS_chmod( const char *, int ) = 0;
	virtual HANDLE FS_FindFirstFile( const char *, FIND_DATA * ) = 0;
	virtual bool FS_FindNextFile( HANDLE, FIND_DATA * ) = 0;
	virtual bool FS_FindClose( HANDLE ) = 0;
	virtual int FS_GetSectorSize( FILE * ) = 0;

	FSAsyncStatus_t	AsyncRead( const FileAsyncRequest_t &request, FSAsyncControl_t *phControl = nullptr)
	{
		return AsyncReadMultiple( &request, 1, phControl );
	}

	unsigned GetOptimalReadSize( FileHandle_t hFile, unsigned nLogicalSize )
	{
		unsigned align;
		if( GetOptimalIOConstraints( hFile, &align, nullptr, nullptr) )
			return AlignValue( nLogicalSize, align );

		return nLogicalSize;
	}

	FSAsyncStatus_t AsyncReadCreditAlloc( const FileAsyncRequest_t &request, const char *pszFile, int line, FSAsyncControl_t *phControl = nullptr)
	{
		return AsyncReadMultipleCreditAlloc( &request, 1, pszFile, line, phControl );
	}

	template <size_t maxLenInChars> const char *RelativePathToFullPath_safe( const char *pFileName, const char *pPathID, OUT_Z_ARRAY char( &pDest )[maxLenInChars], PathTypeFilter_t pathFilter = FILTER_NONE, PathTypeQuery_t *pPathType = nullptr)
	{
		return RelativePathToFullPath( pFileName, pPathID, pDest, static_cast<int>( maxLenInChars ), pathFilter, pPathType );
	}

	template <size_t maxLenInChars> int GetSearchPath_safe( const char *pathID, bool bGetPackFiles, OUT_Z_ARRAY char( &pDest )[maxLenInChars] )
	{
		return GetSearchPath( pathID, bGetPackFiles, pDest, static_cast<int>( maxLenInChars ) );
	}

	template <size_t maxLenInChars> const char *GetLocalPath_safe( const char *pFileName, OUT_Z_ARRAY char( &pDest )[maxLenInChars] )
	{
		return GetLocalPath( pFileName, pDest, static_cast<int>( maxLenInChars ) );
	}

	template <size_t maxLenInChars> bool FullPathToRelativePath_safe( const char *pFullpath, OUT_Z_ARRAY char( &pDest )[maxLenInChars] )
	{
		return FullPathToRelativePath( pFullpath, pDest, static_cast<int>( maxLenInChars ) );
	}

	template <size_t maxLenInChars> bool FullPathToRelativePathEx_safe( const char *pFullpath, OUT_Z_ARRAY char( &pDest )[maxLenInChars] )
	{
		return FullPathToRelativePathEx( pFullpath, pDest, static_cast<int>( maxLenInChars ) );
	}

	template <size_t maxLenInChars> bool GetCaseCorrectFullPath( const char *pFullPath, OUT_Z_ARRAY char( &pDest )[maxLenInChars] )
	{
		return GetCaseCorrectFullPath_Ptr( pFullPath, pDest, static_cast<int>( maxLenInChars ) );
	}

	class CPathIDInfo
	{
	public:
		bool m_bByRequestOnly;
		CUtlSymbol m_PathID;
		const char *m_pDebugPathID;
	};

	class CSearchPath
	{
	public:
		int32_t m_storeId;
		CPathIDInfo *m_pPathIDInfo;
		uint32_t enum1;
		uint32_t enum2;
		CUtlSymbol m_Path;
		const char *m_pDebugPath;
		bool m_bIsRemotePath;
		WilloxHallOfShame *m_pPackFile;
	};

	struct FindData_t
	{ };

	struct CompiledKeyValuesPreloaders_t
	{
		FileNameHandle_t m_CacheFile;
		class CCompiledKeyValuesReader *m_pReader;
	};

	class COpenedFile
	{
	public:
		FILE *m_pFile;
		char *m_pName;
	};

	CWhitelistHolder m_FileWhitelist;
	int32_t m_WhitelistSpewFlags;
	CUtlVector<FileSystemLoggingFunc_t> m_LogFuncs;
	CThreadMutex m_SearchPathsMutex;
	CUtlLinkedList<CSearchPath> m_SearchPaths;
	CUtlVector<CPathIDInfo *> m_PathIDInfos;
	CUtlLinkedList<FindData_t> m_FindData; // DO NOT USE AT ALL!
	int32_t m_iMapLoad;
	CUtlVector<CPackFile *> m_ZipFiles;
	FILE *m_pLogFile;
	bool m_bOutputDebugString;
	IThreadPool *m_pThreadPool;
	CThreadFastMutex m_AsyncCallbackMutex;
	FileSystemStatistics m_Stats;
	//CUtlRBTree<COpenedFile, int> m_OpenedFiles;
	CThreadMutex m_OpenedFilesMutex;
	CUtlVector<COpenedFile> m_OpenedFiles;
	FileWarningLevel_t m_fwLevel;
	CUtlFilenameSymbolTable m_FileNames;
	CFileTracker m_FileTracker;
	int32_t m_WhitelistFileTrackingEnabled;
	FSDirtyDiskReportFunc_t m_DirtyDiskReportFunc;
	CompiledKeyValuesPreloaders_t m_PreloadData[IFileSystem::NUM_PRELOAD_TYPES];
};

class CFileSystem_Stdio : public CBaseFileSystem
{
public:
	bool m_bMounted;
	bool m_bCanAsync;
};
