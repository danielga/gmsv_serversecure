#pragma once

#include <cstdint>
#include <filesystem.h>

class CFileSystem_Stdio
{
public:													//  Index Offset
	virtual void Connect(void * (*)(char  const*,int *));								// 0000  0000
	virtual void Disconnect();								// 0001  0004
	virtual void QueryInterface(char  const*);								// 0002  0008
	virtual void Init();								// 0003  000C
	virtual void Shutdown();								// 0004  0010
	virtual void IsSteam()const;								// 0005  0014
	virtual void MountSteamContent(int);								// 0006  0018
	virtual void AddSearchPath(char  const*,char  const*,unsigned int);								// 0007  001C
	virtual void RemoveSearchPath(char  const*,char  const*);								// 0008  0020
	virtual void RemoveAllSearchPaths();								// 0009  0024
	virtual void RemoveSearchPaths(char  const*);								// 0010  0028
	virtual void MarkPathIDByRequestOnly(char  const*,bool);								// 0011  002C
	virtual void RelativePathToFullPath(char  const*,char  const*,char *,int,PathTypeFilter_t,unsigned int *);								// 0012  0030
	virtual void GetSearchPath(char  const*,bool,char *,int);								// 0013  0034
	virtual void AddPackFile(char  const*,char  const*);								// 0014  0038
	virtual void RemoveFile(char  const*,char  const*);								// 0015  003C
	virtual void RenameFile(char  const*,char  const*,char  const*);								// 0016  0040
	virtual void CreateDirHierarchy(char  const*,char  const*);								// 0017  0044
	virtual void IsDirectory(char  const*,char  const*);								// 0018  0048
	virtual void FileTimeToString(char *,int,long);								// 0019  004C
	virtual void SetBufferSize(void *,unsigned int);								// 0020  0050
	virtual void IsOk(void *);								// 0021  0054
	virtual void EndOfFile(void *);								// 0022  0058
	virtual void ReadLine(char *,int,void *);								// 0023  005C
	virtual void FPrintf(void *,char  const*,...);								// 0024  0060
	virtual void LoadModule(char  const*,char  const*,bool);								// 0025  0064
	virtual void UnloadModule(CSysModule *);								// 0026  0068
	virtual void FindFirst(char  const*,int *);								// 0027  006C
	virtual void FindNext(int);								// 0028  0070
	virtual void FindIsDirectory(int);								// 0029  0074
	virtual void FindClose(int);								// 0030  0078
	virtual void FindFirstEx(char  const*,char  const*,int *);								// 0031  007C
	virtual void GetLocalPath(char  const*,char *,int);								// 0032  0080
	virtual void FullPathToRelativePath(char  const*,char *,int);								// 0033  0084
	virtual void GetCurrentDirectory(char *,int);								// 0034  0088
	virtual void FindOrAddFileName(char  const*);								// 0035  008C
	virtual void String(void * const&,char *,int);								// 0036  0090
	virtual void AsyncReadMultiple(FileAsyncRequest_t  const*,int,FSAsyncControl_t__ **);								// 0037  0094
	virtual void AsyncAppend(char  const*,void  const*,int,bool,FSAsyncControl_t__ **);								// 0038  0098
	virtual void AsyncAppendFile(char  const*,char  const*,FSAsyncControl_t__ **);								// 0039  009C
	virtual void AsyncFinishAll(int);								// 0040  00A0
	virtual void AsyncFinishAllWrites();								// 0041  00A4
	virtual void AsyncFlush();								// 0042  00A8
	virtual void AsyncSuspend();								// 0043  00AC
	virtual void AsyncResume();								// 0044  00B0
	virtual void AsyncAddFetcher(IAsyncFileFetch *);								// 0045  00B4
	virtual void AsyncRemoveFetcher(IAsyncFileFetch *);								// 0046  00B8
	virtual void AsyncBeginRead(char  const*,FSAsyncFile_t__ **);								// 0047  00BC
	virtual void AsyncEndRead(FSAsyncFile_t__ *);								// 0048  00C0
	virtual void AsyncFinish(FSAsyncControl_t__ *,bool);								// 0049  00C4
	virtual void AsyncGetResult(FSAsyncControl_t__ *,void **,int *);								// 0050  00C8
	virtual void AsyncAbort(FSAsyncControl_t__ *);								// 0051  00CC
	virtual void AsyncStatus(FSAsyncControl_t__ *);								// 0052  00D0
	virtual void AsyncSetPriority(FSAsyncControl_t__ *,int);								// 0053  00D4
	virtual void AsyncAddRef(FSAsyncControl_t__ *);								// 0054  00D8
	virtual void AsyncRelease(FSAsyncControl_t__ *);								// 0055  00DC
	virtual void WaitForResources(char  const*);								// 0056  00E0
	virtual void GetWaitForResourcesProgress(int,float *,bool *);								// 0057  00E4
	virtual void CancelWaitForResources(int);								// 0058  00E8
	virtual void HintResourceNeed(char  const*,int);								// 0059  00EC
	virtual void IsFileImmediatelyAvailable(char  const*);								// 0060  00F0
	virtual void GetLocalCopy(char  const*);								// 0061  00F4
	virtual void PrintOpenedFiles();								// 0062  00F8
	virtual void PrintSearchPaths();								// 0063  00FC
	virtual void SetWarningFunc(void (*)(char  const*,...));								// 0064  0100
	virtual void SetWarningLevel(FileWarningLevel_t);								// 0065  0104
	virtual void AddLoggingFunc(void (*)(char  const*,char  const*));								// 0066  0108
	virtual void RemoveLoggingFunc(void (*)(char  const*,char  const*));								// 0067  010C
	virtual void GetFilesystemStatistics();								// 0068  0110
	virtual void OpenEx(char  const*,char  const*,unsigned int,char  const*,char **);								// 0069  0114
	virtual void ReadEx(void *,int,int,void *);								// 0070  0118
	virtual void ReadFileEx(char  const*,char  const*,void **,bool,bool,int,int,void * (*)(char  const*,unsigned int));								// 0071  011C
	virtual void FindFileName(char  const*);								// 0072  0120
	virtual void SetupPreloadData();								// 0073  0124
	virtual void DiscardPreloadData();								// 0074  0128
	virtual void LoadCompiledKeyValues(IFileSystem::KeyValuesPreloadType_t,char  const*);								// 0075  012C
	virtual void LoadKeyValues(IFileSystem::KeyValuesPreloadType_t,char  const*,char  const*);								// 0076  0130
	virtual void LoadKeyValues(KeyValues &,IFileSystem::KeyValuesPreloadType_t,char  const*,char  const*);								// 0077  0134
	virtual void ExtractRootKeyName(IFileSystem::KeyValuesPreloadType_t,char *,unsigned long,char  const*,char  const*);								// 0078  0138
	virtual void AsyncWrite(char  const*,void  const*,int,bool,bool,FSAsyncControl_t__ **);								// 0079  013C
	virtual void AsyncWriteFile(char  const*,CUtlBuffer  const*,int,bool,bool,FSAsyncControl_t__ **);								// 0080  0140
	virtual void AsyncReadMultipleCreditAlloc(FileAsyncRequest_t  const*,int,char  const*,int,FSAsyncControl_t__ **);								// 0081  0144
	virtual void GetFileTypeForFullPath(char  const*,wchar_t *,unsigned long);								// 0082  0148
	virtual void ReadToBuffer(void *,CUtlBuffer &,int,void * (*)(char  const*,unsigned int));								// 0083  014C
	virtual void GetOptimalIOConstraints(void *,unsigned int *,unsigned int *,unsigned int *);								// 0084  0150
	virtual void AllocOptimalReadBuffer(void *,unsigned int,unsigned int);								// 0085  0154
	virtual void FreeOptimalReadBuffer(void *);								// 0086  0158
	virtual void BeginMapAccess();								// 0087  015C
	virtual void EndMapAccess();								// 0088  0160
	virtual void FullPathToRelativePathEx(char  const*,char  const*,char *,int);								// 0089  0164
	virtual void GetPathIndex(void * const&);								// 0090  0168
	virtual void GetPathTime(char  const*,char  const*);								// 0091  016C
	virtual void GetDVDMode();								// 0092  0170
	virtual void EnableWhitelistFileTracking(bool,bool,bool);								// 0093  0174
	virtual void RegisterFileWhitelist(IPureServerWhitelist *,IFileList **);								// 0094  0178
	virtual void MarkAllCRCsUnverified();								// 0095  017C
	virtual void CacheFileCRCs(char  const*,ECacheCRCType,IFileList *);								// 0096  0180
	virtual void CheckCachedFileHash(char  const*,char  const*,int,FileHash_t *);								// 0097  0184
	virtual void GetUnverifiedFileHashes(CUnverifiedFileHash *,int);								// 0098  0188
	virtual void GetWhitelistSpewFlags();								// 0099  018C
	virtual void SetWhitelistSpewFlags(int);								// 0100  0190
	virtual void InstallDirtyDiskReportFunc(void (*)());								// 0101  0194
	virtual void CreateFileCache();								// 0102  0198
	virtual void AddFilesToFileCache(void *,char  const**,int,char  const*);								// 0103  019C
	virtual void IsFileCacheFileLoaded(void *,char  const*);								// 0104  01A0
	virtual void IsFileCacheLoaded(void *);								// 0105  01A4
	virtual void DestroyFileCache(void *);								// 0106  01A8
	virtual void RegisterMemoryFile(CMemoryFileBacking *,CMemoryFileBacking **);								// 0107  01AC
	virtual void UnregisterMemoryFile(CMemoryFileBacking *);								// 0108  01B0
	virtual void CacheAllVPKFileHashes(bool,bool);								// 0109  01B4
	virtual void CheckVPKFileHash(int,int,int,MD5Value_t &);								// 0110  01B8
	virtual void NotifyFileUnloaded(char  const*,char  const*);								// 0111  01BC
	virtual void RemoveSearchPathsByGroup(int);								// 0112  01C0
	virtual void SetGet(class IGet *);								// 0113  01C4
	virtual void Addons();								// 0114  01C8
	virtual uintptr_t Gamemodes();								// 0115  01CC
	virtual void Games();								// 0116  01D0
	virtual void LegacyAddons();								// 0117  01D4
	virtual void Language();								// 0118  01D8
	virtual void DoFilesystemRefresh();								// 0119  01DC
	virtual void LastFilesystemRefresh();								// 0120  01E0
	virtual void AddVPKFileFromPath(char  const*,char  const*,unsigned int);								// 0121  01E4
	virtual void GMOD_SetupDefaultPaths(char  const*,char  const*);								// 0122  01E8
	virtual void Open(char  const*,char  const*,char  const*);								// 0123  01EC
	virtual void Close(void *);								// 0124  01F0
	virtual void Seek(void *,int,FileSystemSeek_t);								// 0125  01F4
	virtual void Tell(void *);								// 0126  01F8
	virtual void Size(void *);								// 0127  01FC
	virtual void Size(char  const*,char  const*);								// 0128  0200
	virtual void Flush(void *);								// 0129  0204
	virtual void Precache(char  const*,char  const*);								// 0130  0208
	virtual void Read(void *,int,void *);								// 0131  020C
	virtual void Write(void  const*,int,void *);								// 0132  0210
	virtual void ReadFile(char  const*,char  const*,CUtlBuffer &,int,int,void * (*)(char  const*,unsigned int));								// 0133  0214
	virtual void WriteFile(char  const*,char  const*,CUtlBuffer &);								// 0134  0218
	virtual void UnzipFile(char  const*,char  const*,char  const*);								// 0135  021C
	virtual void FileExists(char  const*,char  const*);								// 0136  0220
	virtual void GetFileTime(char  const*,char  const*);								// 0137  0224
	virtual void IsFileWritable(char  const*,char  const*);								// 0138  0228
	virtual void SetFileWritable(char  const*,bool,char  const*);								// 0139  022C
	virtual void FixUpPath(char  const*,char *,int);								// 0140  0230
/*
	virtual void FS_fopen(char  const*,char  const*,unsigned int,long long *);								// 0141  0234
	virtual void FS_setbufsize(__sFILE *,unsigned int);								// 0142  0238
	virtual void FS_fclose(__sFILE *);								// 0143  023C
	virtual void FS_fseek(__sFILE *,long long,int);								// 0144  0240
	virtual void FS_ftell(__sFILE *);								// 0145  0244
	virtual void FS_feof(__sFILE *);								// 0146  0248
	virtual void FS_fread(void *,unsigned long,unsigned long,__sFILE *);								// 0147  024C
	virtual void FS_fwrite(void  const*,unsigned long,__sFILE *);								// 0148  0250
	virtual void FS_setmode(__sFILE *,FileMode_t);								// 0149  0254
	virtual void FS_vfprintf(__sFILE *,char  const*,char *);								// 0150  0258
	virtual void FS_ferror(__sFILE *);								// 0151  025C
	virtual void FS_fflush(__sFILE *);								// 0152  0260
	virtual void FS_fgets(char *,int,__sFILE *);								// 0153  0264
	virtual void FS_stat(char  const*,stat *,bool *);								// 0154  0268
	virtual void FS_chmod(char  const*,int);								// 0155  026C
	virtual void FS_FindFirstFile(char  const*,FIND_DATA *);								// 0156  0270
	virtual void FS_FindNextFile(void *,FIND_DATA *);								// 0157  0274
	virtual void FS_FindClose(void *);								// 0158  0278
	virtual void FS_GetSectorSize(__sFILE *);								// 0159  027C
*/
};
