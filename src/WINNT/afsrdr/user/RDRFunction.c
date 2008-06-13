
#define _WIN32_WINNT 0x0500
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NON_CONFORMING_SWPRINTFS

#include <windows.h>
#include <sddl.h>
#pragma warning(push)
#pragma warning(disable: 4005)
#include <ntstatus.h>

#include <devioctl.h>

#include "..\\Common\\AFSUserCommon.h"
#include <RDRPrototypes.h>


#pragma warning(pop)

#include <tchar.h>
#include <wchar.h>
#include <winbase.h>
#include <winreg.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>


#include "afsd.h"
#include "cm_btree.h"

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#ifndef BooleanFlagOn
#define BooleanFlagOn(F,SF)   ((BOOLEAN)(((F) & (SF)) != 0))
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

#define QuadAlign(Ptr) (                \
    ((((ULONG)(Ptr)) + 7) & 0xfffffff8) \
    )


DWORD
RDR_SetInitParams( OUT AFSCacheFileInfo **ppCacheFileInfo, OUT DWORD * pCacheFileInfoLen )
{
    extern char cm_CachePath[];
    extern cm_config_data_t cm_data;
    size_t cm_CachePathLen = strlen(cm_CachePath);
    size_t err;

    *pCacheFileInfoLen = sizeof(AFSCacheFileInfo) + (cm_CachePathLen) * sizeof(WCHAR);
    *ppCacheFileInfo = (AFSCacheFileInfo *)malloc(*pCacheFileInfoLen);
    (*ppCacheFileInfo)->CacheBlockSize = cm_data.blockSize;
    (*ppCacheFileInfo)->CacheFileNameLength = cm_CachePathLen * sizeof(WCHAR);
    err = mbstowcs((*ppCacheFileInfo)->CacheFileName, cm_CachePath, (cm_CachePathLen + 1) *sizeof(WCHAR));
    if (err == -1) {
        free(*ppCacheFileInfo);
        return STATUS_OBJECT_NAME_INVALID;
    }

    return 0;
}

cm_user_t *
RDR_UserFromCommRequest( IN AFSCommRequest *RequestBuffer)
{
    cm_user_t *userp = cm_rootUserp;
    HANDLE hProcess = 0, hToken = 0;
    PSID        pSid = 0;
    char      *secSidString = 0;
    char cname[MAX_COMPUTERNAME_LENGTH+1];
    int cnamelen = MAX_COMPUTERNAME_LENGTH+1;

    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, RequestBuffer->ProcessId);
    if (hProcess == NULL)
        goto done;

    if (!OpenProcessToken( hProcess, TOKEN_READ, &hToken))
        goto done;

    if (!smb_GetUserSID( hToken, &pSid))
        goto done;

    if (!ConvertSidToStringSidA(pSid, &secSidString))
        goto done;

    GetComputerNameA(cname, &cnamelen);
    _strupr(cname);

    userp = smb_FindCMUserByName(secSidString, cname, SMB_FLAG_CREATE);
    if (!userp) {
        userp = cm_rootUserp;
        cm_HoldUser(userp);
    }

  done:
    if (secSidString)
        LocalFree(secSidString);
    if (pSid)
        smb_FreeSID(pSid);
    if (hToken)
        CloseHandle(hToken);
    if (hProcess)
        CloseHandle(hProcess);
    return userp;
}

void
RDR_ReleaseUser( IN cm_user_t *userp )
{
    cm_ReleaseUser(userp);
}

void
RDR_PopulateCurrentEntry( IN AFSDirEnumEntry * pCurrentEntry, 
                          IN cm_scache_t     * dscp,
                          IN cm_scache_t     * scp,
                          IN cm_user_t       * userp,
                          IN cm_req_t        * reqp,
                          IN char            * name,
                          IN char            * shortName )
{
    FILETIME ft;
    WCHAR *  wname, *wtarget;
    size_t   len;
    afs_uint32 code;

    if (!name)
        name = "";
    if (!shortName)
        shortName = "";

    lock_ObtainWrite(&scp->rw);
    code = cm_SyncOp( scp, NULL, userp, reqp, 0,
                      CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    pCurrentEntry->FileId.Cell = scp->fid.cell;
    pCurrentEntry->FileId.Volume = scp->fid.volume;
    pCurrentEntry->FileId.Vnode = scp->fid.vnode;
    pCurrentEntry->FileId.Unique = scp->fid.unique;
    pCurrentEntry->FileId.Hash = scp->fid.hash;

    pCurrentEntry->DataVersion.QuadPart = scp->dataVersion;
    pCurrentEntry->FileType = scp->fileType;

    smb_LargeSearchTimeFromUnixTime(&ft, scp->clientModTime);
    pCurrentEntry->CreationTime.LowPart = ft.dwLowDateTime;
    pCurrentEntry->CreationTime.HighPart = ft.dwHighDateTime;
    pCurrentEntry->LastAccessTime = pCurrentEntry->CreationTime;
    pCurrentEntry->LastWriteTime = pCurrentEntry->CreationTime;
    pCurrentEntry->ChangeTime = pCurrentEntry->CreationTime;

    pCurrentEntry->EndOfFile = scp->length;
    pCurrentEntry->AllocationSize = scp->length;
    pCurrentEntry->FileAttributes = smb_ExtAttributes(scp);
    pCurrentEntry->EaSize = 0;
    pCurrentEntry->Links = scp->linkCount;

    len = strlen(shortName);
#ifdef UNICODE
    cch = MultiByteToWideChar( CP_UTF8, 0, shortname, 
                               len * sizeof(char),
                               pCurrentEntry->ShortName, 
                               len * sizeof(WCHAR));
#else
    mbstowcs(pCurrentEntry->ShortName, shortName, len);
#endif
    pCurrentEntry->ShortNameLength = len * sizeof(WCHAR);

    pCurrentEntry->FileNameOffset = sizeof(AFSDirEnumEntry);
    len = strlen(name);
    wname = (WCHAR *)((PBYTE)pCurrentEntry + pCurrentEntry->FileNameOffset);


#ifdef UNICODE
    cch = MultiByteToWideChar( CP_UTF8, 0, name, 
                               len * sizeof(char),
                               wname, 
                               len * sizeof(WCHAR));
#else
    mbstowcs(wname, name, len);
#endif
    pCurrentEntry->FileNameLength = sizeof(WCHAR) * len;

    if (code == 0)
        cm_SyncOpDone( scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);


    switch (scp->fileType) {
    case CM_SCACHETYPE_MOUNTPOINT:
        if (cm_ReadMountPoint(scp, userp, reqp) == 0) {
            afs_uint32 code2;
            cm_scache_t *targetScp = NULL;

            pCurrentEntry->TargetNameOffset = pCurrentEntry->FileNameOffset + pCurrentEntry->FileNameLength;
            len = strlen(scp->mountPointStringp);
            wtarget = (WCHAR *)((PBYTE)pCurrentEntry + pCurrentEntry->TargetNameOffset);

#ifdef UNICODE
            cch = MultiByteToWideChar( CP_UTF8, 0, scp->mountPointStringp, 
                                       len * sizeof(char),
                                       wtarget, 
                                       len * sizeof(WCHAR));
#else
            mbstowcs(wtarget, scp->mountPointStringp, len);
#endif
            pCurrentEntry->TargetNameLength = sizeof(WCHAR) * len;

            code2 = cm_FollowMountPoint(scp, dscp, userp, reqp, &targetScp);

            if (code2 == 0) {
                pCurrentEntry->TargetFileId.Cell = targetScp->fid.cell;
                pCurrentEntry->TargetFileId.Volume = targetScp->fid.volume;
                pCurrentEntry->TargetFileId.Vnode = targetScp->fid.vnode;
                pCurrentEntry->TargetFileId.Unique = targetScp->fid.unique;
                pCurrentEntry->TargetFileId.Hash = targetScp->fid.hash;

                cm_ReleaseSCache(targetScp);
            }
        }
        break;
    case CM_SCACHETYPE_SYMLINK:
    case CM_SCACHETYPE_DFSLINK:
        {
            afs_uint32 code2;
            cm_scache_t *targetScp = NULL;

            lock_ReleaseWrite(&scp->rw);
            code2 = cm_EvaluateSymLink(dscp, scp, &targetScp, userp, reqp);
            lock_ObtainWrite(&scp->rw);
            if (code2 == 0) {
                pCurrentEntry->TargetNameOffset = pCurrentEntry->FileNameOffset + pCurrentEntry->FileNameLength;
                len = strlen(scp->mountPointStringp);
                wtarget = (WCHAR *)((PBYTE)pCurrentEntry + pCurrentEntry->TargetNameOffset);

#ifdef UNICODE
                cch = MultiByteToWideChar( CP_UTF8, 0, scp->mountPointStringp, 
                                           len * sizeof(char),
                                           wtarget, 
                                           len * sizeof(WCHAR));
#else
                mbstowcs(wtarget, scp->mountPointStringp, len);
#endif
                pCurrentEntry->TargetNameLength = sizeof(WCHAR) * len;

                pCurrentEntry->TargetFileId.Cell = targetScp->fid.cell;
                pCurrentEntry->TargetFileId.Volume = targetScp->fid.volume;
                pCurrentEntry->TargetFileId.Vnode = targetScp->fid.vnode;
                pCurrentEntry->TargetFileId.Unique = targetScp->fid.unique;
                pCurrentEntry->TargetFileId.Hash = targetScp->fid.hash;

                cm_ReleaseSCache(targetScp);
            }
        }
        break;
    default:
        pCurrentEntry->TargetNameOffset = 0;
        pCurrentEntry->TargetNameLength = 0;
    }
    lock_ReleaseWrite(&scp->rw);
}

void
RDR_EnumerateDirectory( IN cm_user_t *userp,
                        IN AFSFileID ParentID,
                        IN AFSDirQueryCB *QueryCB,
                        IN DWORD ResultBufferLength,
                        IN OUT AFSCommResult **ResultCB)
{
    DWORD status;
    cm_direnum_t *      enump;
    AFSDirEnumResp  * pDirEnumResp;
    AFSDirEnumEntry * pCurrentEntry;
    size_t size = sizeof(AFSCommResult) + ResultBufferLength - 1;
    afs_uint32  code = 0;
    cm_fid_t      fid;
    cm_scache_t * dscp = NULL;
    cm_req_t      req;

    *ResultCB = (AFSCommResult *)malloc(size);
    if (!(*ResultCB))
	return;

    cm_InitReq(&req);
    memset(*ResultCB, 0, size);

    (*ResultCB)->ResultBufferLength = ResultBufferLength;

    pDirEnumResp = (AFSDirEnumResp *)&(*ResultCB)->ResultData;
    pCurrentEntry = (AFSDirEnumEntry *)QuadAlign(&pDirEnumResp->Entry);

    if (ParentID.Cell != 0) {
        fid.cell   = ParentID.Cell;
        fid.volume = ParentID.Volume;
        fid.vnode  = ParentID.Vnode;
        fid.unique = ParentID.Unique;
        fid.hash   = ParentID.Hash;

        code = cm_GetSCache(&fid, &dscp, userp, &req);
        if (code) {
            smb_MapNTError(code, &status);
            (*ResultCB)->ResultStatus = status;
            return;
        }
    } else {
        fid = cm_data.rootFid;
        dscp = cm_data.rootSCachep;
        cm_HoldSCache(dscp);
    }

    /* get the directory size */
    lock_ObtainWrite(&dscp->rw);
    code = cm_SyncOp(dscp, NULL, userp, &req, 0,
                      CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code) {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        lock_ReleaseWrite(&dscp->rw);
        cm_ReleaseSCache(dscp);
        return;
    }

    cm_SyncOpDone(dscp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    lock_ReleaseWrite(&dscp->rw);

    if (dscp->fileType != CM_SCACHETYPE_DIRECTORY) {
        (*ResultCB)->ResultStatus = STATUS_NOT_A_DIRECTORY;
        cm_ReleaseSCache(dscp);
        return;
    }

    /*
     * If there is no enumeration handle, then this is a new query
     * and we must perform an enumeration for the specified object 
     */
    if (QueryCB->EnumHandle == (ULONG_PTR)NULL) {
        cm_dirOp_t    dirop;
        LARGE_INTEGER thyper;

        thyper.HighPart = thyper.LowPart = 0;

        code = cm_BeginDirOp(dscp, userp, &req, CM_DIRLOCK_READ, &dirop);
        if (code == 0) {
            code = cm_BPlusDirEnumerate(dscp, TRUE, NULL, &enump);

            if (code == 0) {
                lock_ObtainWrite(&dscp->rw);
                code = cm_TryBulkStat(dscp, &thyper, userp, &req);
                lock_ReleaseWrite(&dscp->rw);
            }

            cm_EndDirOp(&dirop);
        }
    } else {
        enump = (cm_direnum_t *)QueryCB->EnumHandle;
    }

    if (enump) {
        cm_direnum_entry_t    * entryp = NULL;

      getnextentry:
        code = cm_BPlusDirNextEnumEntry(enump, &entryp);

        if (code == 0 && entryp) {
            cm_scache_t *scp;

            if ( !strcmp(".", entryp->name) || !strcmp("..", entryp->name) )
                goto getnextentry;

            code = cm_GetSCache(&entryp->fid, &scp, userp, &req);
            if (!code) {
                RDR_PopulateCurrentEntry(pCurrentEntry, dscp, scp, userp, &req, entryp->name, entryp->shortName);
                cm_ReleaseSCache(scp);
            } else {
                goto getnextentry;
            }
        }
    }

    if (code != 0 || enump->next == enump->count) {
        cm_BPlusDirFreeEnumeration(enump);
        enump = NULL;
        if (code != 0)
            (*ResultCB)->ResultStatus = STATUS_NO_MORE_ENTRIES;
        else
            (*ResultCB)->ResultStatus = STATUS_SUCCESS;
    } else 
        (*ResultCB)->ResultStatus = STATUS_MORE_ENTRIES;

    pDirEnumResp->EnumHandle = (ULONG_PTR) enump;

    if (dscp)
        cm_ReleaseSCache(dscp);

    return;
}

void
RDR_EvaluateNodeByName( IN cm_user_t *userp,
                        IN AFSFileID ParentID,
                        IN WCHAR   *Name,
                        IN DWORD    NameLength,
                        IN DWORD    CaseSensitive,
                        IN DWORD    ResultBufferLength,
                        IN OUT AFSCommResult **ResultCB)
{
    AFSDirEnumEntry * pCurrentEntry;
    size_t size = sizeof(AFSCommResult) + ResultBufferLength - 1;
    afs_uint32  code = 0;
    char aname[1025];
    cm_scache_t * scp = NULL;
    cm_scache_t * dscp = NULL;
    cm_req_t      req;
    cm_fid_t      parentFid;
    cm_dirOp_t    dirop;
    DWORD         status;

    cm_InitReq(&req);

    *ResultCB = (AFSCommResult *)malloc(size);
    if (!(*ResultCB))
	return;

    memset(*ResultCB, 0, size);
    (*ResultCB)->ResultBufferLength = ResultBufferLength;

    {
        wchar_t wname[1025];
        size_t err;

        wmemcpy(wname, Name, min(NameLength, 1024));
        wname[min(NameLength, 1024)] = '\0';

        err = wcstombs(aname, wname, sizeof(aname));
        if (err == -1) {
            (*ResultCB)->ResultStatus = STATUS_OBJECT_NAME_INVALID;
            return;
        }
    }

    pCurrentEntry = (AFSDirEnumEntry *)&(*ResultCB)->ResultData;

    if (ParentID.Cell != 0) {
        parentFid.cell   = ParentID.Cell;
        parentFid.volume = ParentID.Volume;
        parentFid.vnode  = ParentID.Vnode;
        parentFid.unique = ParentID.Unique;
        parentFid.hash   = ParentID.Hash;

        code = cm_GetSCache(&parentFid, &dscp, userp, &req);
        if (code) {
            smb_MapNTError(code, &status);
            (*ResultCB)->ResultStatus = status;
            return;
        }
    } else {
        parentFid = cm_data.rootFid;
        dscp = cm_data.rootSCachep;
        cm_HoldSCache(dscp);
    }

    /* get the directory size */
    lock_ObtainWrite(&dscp->rw);
    code = cm_SyncOp(dscp, NULL, userp, &req, 0,
                      CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code) {     
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        lock_ReleaseWrite(&dscp->rw);
        cm_ReleaseSCache(dscp);
        return;
    }

    cm_SyncOpDone(dscp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    lock_ReleaseWrite(&dscp->rw);

    if (dscp->fileType != CM_SCACHETYPE_DIRECTORY) {
        (*ResultCB)->ResultStatus = STATUS_NOT_A_DIRECTORY;
        cm_ReleaseSCache(dscp);
        return;
    }

    code = cm_BeginDirOp(dscp, userp, &req, CM_DIRLOCK_READ, &dirop);
    if (code == 0) {
        cm_fid_t fid;

        code = cm_BPlusDirLookup(&dirop, aname, &fid);
        cm_EndDirOp(&dirop);
        if (code == 0 || (code == CM_ERROR_INEXACT_MATCH && !CaseSensitive)) {
            code = cm_GetSCache(&fid, &scp, userp, &req);
            if (code)
                scp = NULL;
        }
    }

    if (scp) {
        char shortName[13];
        cm_dirFid_t dfid;

        dfid.vnode = htonl(scp->fid.vnode);
        dfid.unique = htonl(scp->fid.unique);

        cm_Gen8Dot3NameInt(aname, &dfid, shortName, NULL);
        RDR_PopulateCurrentEntry(pCurrentEntry, dscp, scp, userp, &req, aname, shortName);

        cm_ReleaseSCache(scp);
        (*ResultCB)->ResultStatus = STATUS_SUCCESS;
#if 0
    } else if (ParentID.Cell == 0) {
        /* We have a share name that does not exist.  Try to evaluate it.
         * It might be a cell name or it might be a volume reference.
         */

#endif    
    } else if (code) {
        DWORD status;
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
    } else {
        (*ResultCB)->ResultStatus = STATUS_NO_SUCH_FILE;
    }
    cm_ReleaseSCache(dscp);

    return;
}

void
RDR_EvaluateNodeByID( IN cm_user_t *userp,
                      IN AFSFileID ParentID, 
                      IN AFSFileID SourceID,
                      IN DWORD    ResultBufferLength,
                      IN OUT AFSCommResult **ResultCB)
{
    AFSDirEnumEntry * pCurrentEntry;
    size_t size = sizeof(AFSCommResult) + ResultBufferLength - 1;
    afs_uint32  code = 0;
    cm_scache_t * scp = NULL;
    cm_scache_t * dscp = NULL;
    cm_req_t      req;
    cm_fid_t      Fid;
    cm_fid_t      parentFid;
    DWORD         status;

    *ResultCB = (AFSCommResult *)malloc(size);
    if (!(*ResultCB))
	return;

    memset(*ResultCB, 0, size);
    (*ResultCB)->ResultBufferLength = ResultBufferLength;

    pCurrentEntry = (AFSDirEnumEntry *)&(*ResultCB)->ResultData;

    cm_InitReq(&req);

    if (ParentID.Cell != 0) {
        parentFid.cell   = ParentID.Cell;
        parentFid.volume = ParentID.Volume;
        parentFid.vnode  = ParentID.Vnode;
        parentFid.unique = ParentID.Unique;
        parentFid.hash   = ParentID.Hash;

        code = cm_GetSCache(&parentFid, &dscp, userp, &req);
        if (code) {
            smb_MapNTError(code, &status);
            (*ResultCB)->ResultStatus = status;
            return;
        }
    } else {
        if (SourceID.Cell == 0) {
            (*ResultCB)->ResultStatus = STATUS_OBJECT_NAME_INVALID;
            return;
        }

        /* If the ParentID.Cell == 0 then we are evaluating the root mount point */
        parentFid = cm_data.rootFid;
        dscp = cm_data.rootSCachep;
        cm_HoldSCache(dscp);
    }

    if (SourceID.Cell != 0) {
        Fid.cell   = SourceID.Cell;
        Fid.volume = SourceID.Volume;
        Fid.vnode  = SourceID.Vnode;
        Fid.unique = SourceID.Unique;
        Fid.hash   = SourceID.Hash;

        code = cm_GetSCache(&Fid, &scp, userp, &req);
        if (code) {
            smb_MapNTError(code, &status);
            (*ResultCB)->ResultStatus = status;
            cm_ReleaseSCache(dscp);
            return;
        }
    } else {
        /* If the SourceID.Cell == 0 then we are evaluating the root mount point */
        Fid = cm_data.rootFid;
        scp = cm_data.rootSCachep;
        cm_HoldSCache(scp);
    }

    /* Make sure the directory is current */
    lock_ObtainWrite(&dscp->rw);
    code = cm_SyncOp(dscp, NULL, userp, &req, 0,
                      CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code) {     
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        lock_ReleaseWrite(&dscp->rw);
        cm_ReleaseSCache(dscp);
        cm_ReleaseSCache(scp);
        return;
    }

    cm_SyncOpDone(dscp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    lock_ReleaseWrite(&dscp->rw);

    if (dscp->fileType != CM_SCACHETYPE_DIRECTORY) {
        (*ResultCB)->ResultStatus = STATUS_NOT_A_DIRECTORY;
        cm_ReleaseSCache(dscp);
        cm_ReleaseSCache(scp);
        return;
    }

    /* Make sure the source vnode is current */
    lock_ObtainWrite(&scp->rw);
    code = cm_SyncOp(scp, NULL, userp, &req, 0,
                      CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code) {     
        DWORD status;
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        lock_ReleaseWrite(&scp->rw);
        cm_ReleaseSCache(dscp);
        cm_ReleaseSCache(scp);
        return;
    }

    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    lock_ReleaseWrite(&scp->rw);

    RDR_PopulateCurrentEntry(pCurrentEntry, dscp, scp, userp, &req, NULL, NULL);

    cm_ReleaseSCache(scp);
    cm_ReleaseSCache(dscp);
    (*ResultCB)->ResultStatus = STATUS_SUCCESS;
    return;
}

void
RDR_CreateFileEntry( IN cm_user_t *userp,
                     IN WCHAR *FileName,
                     IN DWORD FileNameLength,
                     IN AFSFileCreateCB *CreateCB,
                     IN DWORD ResultBufferLength,
                     IN OUT AFSCommResult **ResultCB)
{
    AFSFileCreateResultCB *pResultCB = NULL;
    cm_fid_t            parentFid;
    afs_uint32          code;
    cm_scache_t *       dscp = NULL;
    afs_uint32          flags = 0;
    cm_attr_t           setAttr;
    cm_scache_t *       scp = NULL;
    cm_req_t            req;
    char                utf8_name[1025];
    DWORD               status;

    cm_InitReq(&req);
    memset(&setAttr, 0, sizeof(cm_attr_t));

    *ResultCB = (AFSCommResult *)malloc( sizeof( AFSCommResult) + sizeof( AFSFileCreateResultCB));
    if (!(*ResultCB))
	return;

    memset( *ResultCB,
            '\0',
            sizeof( AFSCommResult) + sizeof( AFSFileCreateResultCB));

    code = !WideCharToMultiByte(CP_UTF8, 0, FileName, FileNameLength, utf8_name, sizeof(utf8_name), NULL, NULL);
    if (code) {
        (*ResultCB)->ResultStatus = STATUS_OBJECT_NAME_INVALID;
        return;
    }

    parentFid.cell   = CreateCB->ParentId.Cell;
    parentFid.volume = CreateCB->ParentId.Volume;
    parentFid.vnode  = CreateCB->ParentId.Vnode;
    parentFid.unique = CreateCB->ParentId.Unique;
    parentFid.hash   = CreateCB->ParentId.Hash;

    code = cm_GetSCache(&parentFid, &dscp, userp, &req);
    if (code) {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        return;
    }

    if (dscp->fileType != CM_SCACHETYPE_DIRECTORY) {
        (*ResultCB)->ResultStatus = STATUS_NOT_A_DIRECTORY;
        cm_ReleaseSCache(dscp);
        return;
    }

    setAttr.mask = CM_ATTRMASK_LENGTH;
    setAttr.length.LowPart = CreateCB->AllocationSize.LowPart;
    setAttr.length.HighPart = CreateCB->AllocationSize.HighPart;
    if (CreateCB->FileAttributes & FILE_ATTRIBUTE_READONLY) {
        setAttr.mask |= CM_ATTRMASK_UNIXMODEBITS;
        setAttr.unixModeBits = 0222;
    }

    code = cm_Create(dscp, utf8_name, flags, &setAttr, &scp, userp, &req);

    if (code == 0) {
        char shortName[13];
        cm_dirFid_t dfid;

        (*ResultCB)->ResultStatus = 0;  // We will be able to fit all the data in here

        (*ResultCB)->ResultBufferLength = sizeof( AFSFileCreateResultCB);

        pResultCB = (AFSFileCreateResultCB *)(*ResultCB)->ResultData;

        pResultCB->FileId.Cell = scp->fid.cell;
        pResultCB->FileId.Volume = scp->fid.volume;
        pResultCB->FileId.Vnode = scp->fid.vnode;
        pResultCB->FileId.Unique = scp->fid.unique;
        pResultCB->FileId.Hash = scp->fid.hash;

        pResultCB->ParentDataVersion.QuadPart = dscp->dataVersion;

        dfid.vnode = htonl(scp->fid.vnode);
        dfid.unique = htonl(scp->fid.unique);

        cm_Gen8Dot3NameInt(utf8_name, &dfid, shortName, NULL);
        RDR_PopulateCurrentEntry(&pResultCB->DirEnum, dscp, scp, userp, &req, utf8_name, shortName);

        cm_ReleaseSCache(scp);
    } else {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        (*ResultCB)->ResultBufferLength = 0;
    }

    cm_ReleaseSCache(dscp);

    return;
}

void
RDR_UpdateFileEntry( IN cm_user_t *userp,
                     IN AFSFileID FileId,
                     IN AFSFileUpdateCB *UpdateCB,
                     IN OUT AFSCommResult **ResultCB)
{
    AFSFileUpdateResultCB *pResultCB = NULL;
    cm_fid_t            Fid;
    cm_fid_t            parentFid;
    afs_uint32          code;
    afs_uint32          flags = 0;
    cm_attr_t           setAttr;
    cm_scache_t *       scp = NULL;
    cm_scache_t *       dscp = NULL;
    cm_req_t            req;
    time_t              clientModTime;
    FILETIME            ft;
    DWORD               status;

    cm_InitReq(&req);
    memset(&setAttr, 0, sizeof(cm_attr_t));

    *ResultCB = (AFSCommResult *)malloc( sizeof( AFSCommResult) + sizeof( AFSFileUpdateResultCB));
    if (!(*ResultCB))
	return;

    memset( *ResultCB,
            '\0',
            sizeof( AFSCommResult) + sizeof( AFSFileUpdateResultCB));

    parentFid.cell   = UpdateCB->ParentId.Cell;
    parentFid.volume = UpdateCB->ParentId.Volume;
    parentFid.vnode  = UpdateCB->ParentId.Vnode;
    parentFid.unique = UpdateCB->ParentId.Unique;
    parentFid.hash   = UpdateCB->ParentId.Hash;

    code = cm_GetSCache(&parentFid, &dscp, userp, &req);
    if (code) {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        return;
    }

    if (dscp->fileType != CM_SCACHETYPE_DIRECTORY) {
        (*ResultCB)->ResultStatus = STATUS_NOT_A_DIRECTORY;
        cm_ReleaseSCache(dscp);
        return;
    }

    Fid.cell   = FileId.Cell;
    Fid.volume = FileId.Volume;
    Fid.vnode  = FileId.Vnode;
    Fid.unique = FileId.Unique;
    Fid.hash   = FileId.Hash;

    code = cm_GetSCache(&Fid, &scp, userp, &req);
    if (code) {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        cm_ReleaseSCache(dscp);
        return;
    }

    lock_ObtainWrite(&scp->rw);
    code = cm_SyncOp(scp, NULL, userp, &req, 0,
                      CM_SCACHESYNC_GETSTATUS | CM_SCACHESYNC_NEEDCALLBACK);
    if (code) {
        DWORD NTStatus;
        lock_ReleaseWrite(&scp->rw);
        smb_MapNTError(code, &NTStatus);
        (*ResultCB)->ResultStatus = NTStatus;
        (*ResultCB)->ResultBufferLength = 0;
        cm_ReleaseSCache(dscp);
        cm_ReleaseSCache(scp);
        return;
    }
    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

    /* Do not set length and other attributes at the same time */
    if (scp->length.QuadPart != UpdateCB->AllocationSize.QuadPart) {
        setAttr.mask |= CM_ATTRMASK_LENGTH;
        setAttr.length.LowPart = UpdateCB->AllocationSize.LowPart;
        setAttr.length.HighPart = UpdateCB->AllocationSize.HighPart;
        lock_ReleaseWrite(&scp->rw);
        code = cm_SetAttr(scp, &setAttr, userp, &req);
        if (code)
            goto on_error;
        setAttr.mask = 0;
        lock_ObtainWrite(&scp->rw);
    }

    if ((scp->unixModeBits & 0222) && !(UpdateCB->FileAttributes & FILE_ATTRIBUTE_READONLY)) {
        setAttr.mask |= CM_ATTRMASK_UNIXMODEBITS;
        setAttr.unixModeBits = scp->unixModeBits & ~0222;
    } else if (!(scp->unixModeBits & 0222) && (UpdateCB->FileAttributes & FILE_ATTRIBUTE_READONLY)) {
        setAttr.mask |= CM_ATTRMASK_UNIXMODEBITS;
        setAttr.unixModeBits = scp->unixModeBits | 0222;
    }

    ft.dwLowDateTime = UpdateCB->LastWriteTime.LowPart;
    ft.dwHighDateTime = UpdateCB->LastWriteTime.HighPart;

    smb_UnixTimeFromLargeSearchTime(&clientModTime, &ft);
    if (scp->clientModTime != clientModTime) {
        setAttr.mask |= CM_ATTRMASK_CLIENTMODTIME;
        setAttr.clientModTime = clientModTime;
    }
    lock_ReleaseWrite(&scp->rw);

    /* call setattr */
    if (setAttr.mask)
        code = cm_SetAttr(scp, &setAttr, userp, &req);
    else
        code = 0;

  on_error:
    if (code == 0) {
        pResultCB = (AFSFileUpdateResultCB *)(*ResultCB)->ResultData;

        RDR_PopulateCurrentEntry(&pResultCB->DirEnum, dscp, scp, userp, &req, NULL, NULL);
    } else {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        (*ResultCB)->ResultBufferLength = 0;
    }
    cm_ReleaseSCache(scp);
    cm_ReleaseSCache(dscp);

    return;
}

void
RDR_DeleteFileEntry( IN cm_user_t *userp,
                     IN AFSFileID ParentId,
                     IN WCHAR *FileName,
                     IN DWORD FileNameLength,
                     IN OUT AFSCommResult **ResultCB)
{

    AFSFileDeleteResultCB *pResultCB = NULL;
    cm_fid_t            parentFid;
    afs_uint32          code;
    cm_scache_t *       dscp = NULL;
    afs_uint32          flags = 0;
    cm_attr_t           setAttr;
    cm_req_t            req;
    char                utf8_norm[1025];
    char                utf8_name[1025];
    DWORD               status;

    cm_InitReq(&req);
    memset(&setAttr, 0, sizeof(cm_attr_t));

    *ResultCB = (AFSCommResult *)malloc( sizeof( AFSCommResult) + sizeof( AFSFileDeleteResultCB));
    if (!(*ResultCB))
	return;

    memset( *ResultCB,
            '\0',
            sizeof( AFSCommResult) + sizeof( AFSFileDeleteResultCB));

    code = !WideCharToMultiByte(CP_UTF8, 0, FileName, FileNameLength, utf8_name, sizeof(utf8_name), NULL, NULL);
    if (code) {
        (*ResultCB)->ResultStatus = STATUS_OBJECT_NAME_INVALID;
        return;
    }

    code = !cm_NormalizeUtf16StringToUtf8(FileName, FileNameLength, utf8_norm, sizeof(utf8_norm));
    if (code) {
        (*ResultCB)->ResultStatus = STATUS_OBJECT_NAME_INVALID;
        return;
    }

    parentFid.cell   = ParentId.Cell;
    parentFid.volume = ParentId.Volume;
    parentFid.vnode  = ParentId.Vnode;
    parentFid.unique = ParentId.Unique;
    parentFid.hash   = ParentId.Hash;

    code = cm_GetSCache(&parentFid, &dscp, userp, &req);
    if (code) {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        return;
    }

    if (dscp->fileType != CM_SCACHETYPE_DIRECTORY) {
        (*ResultCB)->ResultStatus = STATUS_NOT_A_DIRECTORY;
        cm_ReleaseSCache(dscp);
        return;
    }

    code = cm_Unlink(dscp, utf8_name, utf8_norm, userp, &req);

    if (code == 0) {
        (*ResultCB)->ResultStatus = 0;  // We will be able to fit all the data in here

        (*ResultCB)->ResultBufferLength = sizeof( AFSFileDeleteResultCB);

        pResultCB = (AFSFileDeleteResultCB *)(*ResultCB)->ResultData;

        pResultCB->ParentDataVersion.QuadPart = dscp->dataVersion;

    } else {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        (*ResultCB)->ResultBufferLength = 0;
    }

    cm_ReleaseSCache(dscp);

    return;
}

void
RDR_RenameFileEntry( IN cm_user_t *userp,
                     IN WCHAR    *SourceFileName,
                     IN DWORD     SourceFileNameLength,
                     IN AFSFileID SourceFileId,
                     IN AFSFileRenameCB *pRenameCB,
                     IN DWORD ResultBufferLength,
                     IN OUT AFSCommResult **ResultCB)
{

    AFSFileRenameResultCB *pResultCB = NULL;
    AFSFileID              SourceParentId   = pRenameCB->SourceParentId;
    AFSFileID              TargetParentId   = pRenameCB->TargetParentId;
    WCHAR *                TargetFileName       = pRenameCB->TargetName;
    DWORD                  TargetFileNameLength = pRenameCB->TargetNameLength;
    cm_fid_t               SourceParentFid;
    cm_fid_t               TargetParentFid;
    cm_scache_t *          oldDscp;
    cm_scache_t *          newDscp;
    char                   utf8_old_name[1025];
    char                   utf8_old_norm[1025];
    char                   utf8_new_name[1025];
    char                   utf8_new_norm[1025];
    char                   shortName[13];
    cm_dirFid_t            dfid;
    cm_req_t               req;
    afs_uint32             code;
    DWORD                  status;

    cm_InitReq(&req);

    *ResultCB = (AFSCommResult *)malloc( sizeof( AFSCommResult) + sizeof( AFSFileRenameResultCB));
    if (!(*ResultCB))
	return;

    memset( *ResultCB,
            '\0',
            sizeof( AFSCommResult) + sizeof( AFSFileRenameResultCB));

    pResultCB = (AFSFileRenameResultCB *)(*ResultCB)->ResultData;
    
    code = !WideCharToMultiByte( CP_UTF8, 0, SourceFileName, SourceFileNameLength, 
                                 utf8_old_name, sizeof(utf8_old_name), NULL, NULL);
    if (code) {
        (*ResultCB)->ResultStatus = STATUS_OBJECT_NAME_INVALID;
        return;
    }

    code = !cm_NormalizeUtf16StringToUtf8( SourceFileName, SourceFileNameLength, utf8_old_norm, sizeof(utf8_old_norm));
    if (code) {
        (*ResultCB)->ResultStatus = STATUS_OBJECT_NAME_INVALID;
        return;
    }

    SourceParentFid.cell   = SourceParentId.Cell;
    SourceParentFid.volume = SourceParentId.Volume;
    SourceParentFid.vnode  = SourceParentId.Vnode;
    SourceParentFid.unique = SourceParentId.Unique;
    SourceParentFid.hash   = SourceParentId.Hash;

    code = !WideCharToMultiByte( CP_UTF8, 0, TargetFileName, TargetFileNameLength, 
                                 utf8_new_name, sizeof(utf8_new_name), NULL, NULL);
    if (code) {
        (*ResultCB)->ResultStatus = STATUS_OBJECT_NAME_INVALID;
        return;
    }

    code = !cm_NormalizeUtf16StringToUtf8( TargetFileName, TargetFileNameLength, utf8_new_norm, sizeof(utf8_new_norm));
    if (code) {
        (*ResultCB)->ResultStatus = STATUS_OBJECT_NAME_INVALID;
        return;
    }

    TargetParentFid.cell   = TargetParentId.Cell;
    TargetParentFid.volume = TargetParentId.Volume;
    TargetParentFid.vnode  = TargetParentId.Vnode;
    TargetParentFid.unique = TargetParentId.Unique;
    TargetParentFid.hash   = TargetParentId.Hash;

    code = cm_GetSCache(&SourceParentFid, &oldDscp, userp, &req);
    if (code) {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        return;
    }

    if (oldDscp->fileType != CM_SCACHETYPE_DIRECTORY) {
        (*ResultCB)->ResultStatus = STATUS_NOT_A_DIRECTORY;
        cm_ReleaseSCache(oldDscp);
        return;
    }

    code = cm_GetSCache(&TargetParentFid, &newDscp, userp, &req);
    if (code) {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        return;
        cm_ReleaseSCache(oldDscp);
    }

    if (newDscp->fileType != CM_SCACHETYPE_DIRECTORY) {
        (*ResultCB)->ResultStatus = STATUS_NOT_A_DIRECTORY;
        cm_ReleaseSCache(oldDscp);
        cm_ReleaseSCache(newDscp);
        return;
    }

    code = cm_Rename( oldDscp, utf8_old_name, utf8_old_norm, 
                      newDscp, utf8_new_name, userp, &req);
    if (code == 0) {
        cm_dirOp_t dirop;
        cm_fid_t   targetFid;
        cm_scache_t *scp = 0;

        (*ResultCB)->ResultBufferLength = sizeof( AFSFileRenameResultCB);
        (*ResultCB)->ResultStatus = 0;

        pResultCB->SourceParentDataVersion.QuadPart = oldDscp->dataVersion;
        pResultCB->TargetParentDataVersion.QuadPart = newDscp->dataVersion;

        code = cm_BeginDirOp( newDscp, userp, &req, CM_DIRLOCK_READ, &dirop);
        if (code == 0) {
            code = cm_BPlusDirLookup(&dirop, utf8_new_norm, &targetFid);
            if (code == EINVAL)
                code = cm_DirLookup(&dirop, utf8_new_norm, &targetFid);

            cm_EndDirOp(&dirop);
        }

        if (code != 0) {
            (*ResultCB)->ResultStatus = STATUS_OBJECT_PATH_INVALID;
            cm_ReleaseSCache(oldDscp);
            cm_ReleaseSCache(newDscp);
            return;
        } 

        code = cm_GetSCache(&targetFid, &scp, userp, &req);
        if (code) {
            smb_MapNTError(code, &status);
            (*ResultCB)->ResultStatus = status;
            cm_ReleaseSCache(oldDscp);
            cm_ReleaseSCache(newDscp);
            return;
        }

        /* Make sure the source vnode is current */
        lock_ObtainWrite(&scp->rw);
        code = cm_SyncOp(scp, NULL, userp, &req, 0,
                          CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
        if (code) {       
            smb_MapNTError(code, &status);
            (*ResultCB)->ResultStatus = status;
            lock_ReleaseWrite(&scp->rw);
            cm_ReleaseSCache(oldDscp);
            cm_ReleaseSCache(newDscp);
            cm_ReleaseSCache(scp);
            return;
        }

        cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
        lock_ReleaseWrite(&scp->rw);

        dfid.vnode = htonl(scp->fid.vnode);
        dfid.unique = htonl(scp->fid.unique);

        cm_Gen8Dot3NameInt(utf8_new_name, &dfid, shortName, NULL);

        RDR_PopulateCurrentEntry(&pResultCB->DirEnum, newDscp, scp, userp, &req, utf8_new_name, shortName);
            
        cm_ReleaseSCache(scp);
    } else {
        DWORD NTStatus;
        smb_MapNTError(code, &NTStatus);
        (*ResultCB)->ResultStatus = NTStatus;
        (*ResultCB)->ResultBufferLength = 0;
    }

    cm_ReleaseSCache(oldDscp);
    cm_ReleaseSCache(newDscp);
    return;
}

void
RDR_FlushFileEntry( IN cm_user_t *userp,
                    IN AFSFileID FileId,
                    IN DWORD ResultBufferLength,
                    IN OUT AFSCommResult **ResultCB)
{
    cm_scache_t *scp = NULL;
    cm_fid_t    Fid;
    afs_uint32  code;
    cm_req_t    req;
    DWORD       status;

    cm_InitReq(&req);

    *ResultCB = (AFSCommResult *)malloc( sizeof( AFSCommResult));
    if (!(*ResultCB))
	return;

    memset( *ResultCB,
            '\0',
            sizeof( AFSCommResult));

    /* Process the release */
    Fid.cell = FileId.Cell;
    Fid.volume = FileId.Volume;
    Fid.vnode = FileId.Vnode;
    Fid.unique = FileId.Unique;
    Fid.hash = FileId.Hash;

    code = cm_GetSCache(&Fid, &scp, userp, &req);
    if (code) {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        return;
    }

    code = cm_FSync(scp, userp, &req);
    cm_ReleaseSCache(scp);

    if (code) {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
    } else
        (*ResultCB)->ResultStatus = 0;

    (*ResultCB)->ResultBufferLength = 0;
    
    return;
}

afs_uint32
RDR_CheckAccess( IN cm_scache_t *scp, cm_user_t *userp, cm_req_t *reqp,
                 ULONG access,
                 ULONG *granted)
{
    ULONG afs_acc, afs_gr;
    BOOLEAN file, dir;
    afs_uint32 code;

    file = (scp->fileType == CM_SCACHETYPE_FILE);
    dir = !file;

    /* access definitions from prs_fs.h */
    afs_acc = 0;
    if (access & FILE_READ_DATA)
	afs_acc |= PRSFS_READ;
    if (file && ((access & FILE_WRITE_DATA) || (access & FILE_APPEND_DATA)))
	afs_acc |= PRSFS_WRITE;
    if (access & FILE_WRITE_EA || access & FILE_WRITE_ATTRIBUTES)
	afs_acc |= PRSFS_WRITE;
    if (dir && ((access & FILE_ADD_FILE) || (access & FILE_ADD_SUBDIRECTORY)))
	afs_acc |= PRSFS_INSERT;
    if (dir && (access & FILE_LIST_DIRECTORY))
	afs_acc |= PRSFS_LOOKUP;
    if (access & FILE_READ_EA || access & FILE_READ_ATTRIBUTES)
	afs_acc |= PRSFS_LOOKUP;
    if (file && (access & FILE_EXECUTE))
	afs_acc |= PRSFS_WRITE;
    if (dir && (access & FILE_TRAVERSE))
	afs_acc |= PRSFS_READ;
    if (dir && (access & FILE_DELETE_CHILD))
	afs_acc |= PRSFS_DELETE;
    if ((access & DELETE))
	afs_acc |= PRSFS_DELETE;

    /* check ACL with server */
    lock_ObtainWrite(&scp->rw);
    while (1)
    {
	if (cm_HaveAccessRights(scp, userp, afs_acc, &afs_gr))
        {
            break;
        }
	else
        {
            /* we don't know the required access rights */
            code = cm_GetAccessRights(scp, userp, reqp);
            if (code)
                break;
            continue;
        }
    }
    lock_ReleaseWrite(&(scp->rw));

    if (code == 0) {
        *granted = 0;
        if (afs_gr & PRSFS_READ)
            *granted |= FILE_READ_DATA | FILE_EXECUTE;
        if (afs_gr & PRSFS_WRITE)
            *granted |= FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_EXECUTE;
        if (afs_gr & PRSFS_INSERT)
            *granted |= (dir ? FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY : 0) | (file ? FILE_ADD_SUBDIRECTORY : 0);
        if (afs_gr & PRSFS_LOOKUP)
            *granted |= (dir ? FILE_LIST_DIRECTORY : 0) | FILE_READ_EA | FILE_READ_ATTRIBUTES;
        if (afs_gr & PRSFS_DELETE)
            *granted |= FILE_DELETE_CHILD | DELETE;
        if (afs_gr & PRSFS_LOCK)
            *granted |= 0;
        if (afs_gr & PRSFS_ADMINISTER)
            *granted |= 0;

        *granted |= SYNCHRONIZE | READ_CONTROL;
    }
    return 0;
}

void
RDR_OpenFileEntry( IN cm_user_t *userp,
                   IN AFSFileID FileId,
                   IN AFSFileOpenCB *OpenCB,
                   IN DWORD ResultBufferLength,
                   IN OUT AFSCommResult **ResultCB)
{
    AFSFileOpenResultCB *pResultCB = NULL;
    cm_scache_t *scp = NULL;
    cm_fid_t    Fid;
    cm_lock_data_t      *ldp = NULL;
    afs_uint32  code;
    cm_req_t    req;
    DWORD       status;

    cm_InitReq(&req);

    *ResultCB = (AFSCommResult *)malloc( sizeof( AFSCommResult) + sizeof( AFSFileOpenResultCB));
    if (!(*ResultCB))
	return;

    memset( *ResultCB,
            '\0',
            sizeof( AFSCommResult) + sizeof( AFSFileOpenResultCB));

    pResultCB = (AFSFileOpenResultCB *)(*ResultCB)->ResultData;

    /* Process the release */
    Fid.cell = FileId.Cell;
    Fid.volume = FileId.Volume;
    Fid.vnode = FileId.Vnode;
    Fid.unique = FileId.Unique;
    Fid.hash = FileId.Hash;

    code = cm_GetSCache(&Fid, &scp, userp, &req);
    if (code) {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
        return;
    }

    code = cm_CheckNTOpen(scp, OpenCB->DesiredAccess, OPEN_ALWAYS, userp, &req, &ldp);
    if (code == 0) {
        cm_CheckNTOpenDone(scp, userp, &req, &ldp);

        code = RDR_CheckAccess(scp, userp, &req, OpenCB->DesiredAccess, &pResultCB->GrantedAccess);
    }
    cm_ReleaseSCache(scp);

    if (code) {
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
    } else {
        (*ResultCB)->ResultStatus = 0;
        (*ResultCB)->ResultBufferLength = sizeof( AFSFileOpenResultCB);
    }
    return;
}

void
RDR_RequestFileExtentsSync( IN cm_user_t *userp,
                            IN AFSFileID FileId,
                            IN AFSRequestExtentsCB *RequestExtentsCB,
                            IN DWORD ResultBufferLength,
                            IN OUT AFSCommResult **ResultCB)
{
    AFSRequestExtentsResultCB *pResultCB = NULL;
    DWORD Length;
    DWORD count;
    cm_scache_t *scp = NULL;
    cm_fid_t    Fid;
    cm_buf_t    *bufp;
    afs_uint32  code;
    osi_hyper_t thyper;
    LARGE_INTEGER ByteOffset, EndOffset;
    cm_req_t    req;
    DWORD               NTStatus;

    cm_InitReq(&req);

    Length = sizeof( AFSCommResult) + sizeof( AFSRequestExtentsResultCB) * (RequestExtentsCB->Length / cm_data.blockSize + 1);
    if (Length > ResultBufferLength) {
        *ResultCB = (AFSCommResult *)malloc(sizeof(AFSCommResult));
        if (!(*ResultCB))
            return;
        memset( *ResultCB, 0, sizeof(AFSCommResult));
        (*ResultCB)->ResultStatus = STATUS_BUFFER_OVERFLOW;
        return;
    }

    *ResultCB = (AFSCommResult *)malloc( Length );
    if (!(*ResultCB))
	return;
    memset( *ResultCB, '\0', Length );
    (*ResultCB)->ResultBufferLength = Length;

    pResultCB = (AFSRequestExtentsResultCB *)(*ResultCB)->ResultData;

    /* Allocate the extents from the buffer package */
    Fid.cell = FileId.Cell;
    Fid.volume = FileId.Volume;
    Fid.vnode = FileId.Vnode;
    Fid.unique = FileId.Unique;
    Fid.hash = FileId.Hash;

    code = cm_GetSCache(&Fid, &scp, userp, &req);
    if (code) {
        smb_MapNTError(code, &NTStatus);
        (*ResultCB)->ResultStatus = NTStatus;
        (*ResultCB)->ResultBufferLength = 0;
        return;
    }

    lock_ObtainWrite(&scp->rw);

    /* start by looking up the file's end */
    code = cm_SyncOp(scp, NULL, userp, &req, 0,
                      CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code) {
        lock_ReleaseWrite(&scp->rw);
        smb_MapNTError(code, &NTStatus);
        (*ResultCB)->ResultStatus = NTStatus;
        (*ResultCB)->ResultBufferLength = 0;
        return;
    }
    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

    /* the scp is now locked and current */

    /* Allocate the extents from the buffer package */
    for ( count = 0, ByteOffset = RequestExtentsCB->ByteOffset, EndOffset.QuadPart = ByteOffset.QuadPart + Length; 
          ByteOffset.QuadPart < EndOffset.QuadPart; 
          ByteOffset.QuadPart += cm_data.blockSize)
    {
        thyper.QuadPart = ByteOffset.QuadPart;

        lock_ReleaseWrite(&scp->rw);
        code = buf_Get(scp, &thyper, &bufp);
        lock_ObtainWrite(&scp->rw);
        
        if (code == 0) {
            lock_ObtainMutex(&bufp->mx);
            bufp->flags |= CM_BUF_REDIR;
            lock_ReleaseMutex(&bufp->mx);

            /* now get the data in the cache */
            if (ByteOffset.QuadPart < scp->length.QuadPart) {
                while (1) {
                    code = cm_SyncOp(scp, bufp, userp, &req, 0,
                                     CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_READ);
                    if (code) 
                        break;

                    cm_SyncOpDone(scp, bufp, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_READ);

                    if (cm_HaveBuffer(scp, bufp, 0)) 
                        break;

                    /* otherwise, load the buffer and try again */
                    code = cm_GetBuffer(scp, bufp, NULL, userp, &req);
                    if (code) 
                        break;
                }
            } else {
                memset(bufp->datap, 0, cm_data.blockSize);
            }

            pResultCB->FileExtents[count].Flags = 0;
            pResultCB->FileExtents[count].FileOffset = ByteOffset;
            pResultCB->FileExtents[count].CacheOffset.QuadPart = bufp->datap - cm_data.baseAddress;
            pResultCB->FileExtents[count].Length = cm_data.blockSize;
            count++;
            buf_Release(bufp);
        }
    }
    pResultCB->ExtentCount = count;
    lock_ReleaseWrite(&scp->rw);
    cm_ReleaseSCache(scp);

    (*ResultCB)->ResultStatus = 0;
    (*ResultCB)->ResultBufferLength = sizeof( AFSRequestExtentsResultCB);
    return;
}

void
RDR_RequestFileExtentsAsync( IN cm_user_t *userp,
                             IN AFSFileID FileId,
                             IN AFSRequestExtentsCB *RequestExtentsCB,
                             IN OUT DWORD * ResultBufferLength,
                             IN OUT AFSSetFileExtentsCB **ResultCB)
{
    AFSSetFileExtentsCB *pResultCB = NULL;
    DWORD Length;
    DWORD count;
    cm_scache_t *scp = NULL;
    cm_fid_t    Fid;
    cm_buf_t    *bufp;
    afs_uint32  code;
    osi_hyper_t thyper;
    LARGE_INTEGER ByteOffset, EndOffset;
    cm_req_t    req;

    cm_InitReq(&req);

    Length = sizeof( AFSSetFileExtentsCB) + sizeof( AFSRequestExtentsResultCB) * (RequestExtentsCB->Length / cm_data.blockSize + 1);

    *ResultCB = (AFSSetFileExtentsCB *)malloc( Length );
    if (*ResultCB == NULL) {
        *ResultBufferLength = 0;
        return;
    }
    *ResultBufferLength = Length;

    memset( *ResultCB, '\0', Length );

    Fid.cell = FileId.Cell;
    Fid.volume = FileId.Volume;
    Fid.vnode = FileId.Vnode;
    Fid.unique = FileId.Unique;
    Fid.hash = FileId.Hash;

    code = cm_GetSCache(&Fid, &scp, userp, &req);
    if (code) {
        free(*ResultCB);
        *ResultCB = NULL;
        *ResultBufferLength = 0;
        return;
    }

    lock_ObtainWrite(&scp->rw);

    /* start by looking up the file's end */
    code = cm_SyncOp(scp, NULL, userp, &req, 0,
                      CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code) {
        free(*ResultCB);
        *ResultCB = NULL;
        *ResultBufferLength = 0;
        lock_ReleaseWrite(&scp->rw);
        cm_ReleaseSCache(scp);
        return;
    }
    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

    /* the scp is now locked and current */

    (*ResultCB)->FileID = FileId;

    /* Allocate the extents from the buffer package */
    for ( count = 0, ByteOffset = RequestExtentsCB->ByteOffset, EndOffset.QuadPart = ByteOffset.QuadPart + Length; 
          ByteOffset.QuadPart < EndOffset.QuadPart; 
          ByteOffset.QuadPart += cm_data.blockSize)
    {
        thyper.QuadPart = ByteOffset.QuadPart;

        lock_ReleaseWrite(&scp->rw);
        code = buf_Get(scp, &thyper, &bufp);
        lock_ObtainWrite(&scp->rw);
        
        if (code == 0) {
            lock_ObtainMutex(&bufp->mx);
            bufp->flags |= CM_BUF_REDIR;
            lock_ReleaseMutex(&bufp->mx);

            /* now get the data in the cache */
            if (ByteOffset.QuadPart < scp->length.QuadPart) {
                while (1) {
                    code = cm_SyncOp(scp, bufp, userp, &req, 0,
                                     CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_READ);
                    if (code) 
                        break;

                    cm_SyncOpDone(scp, bufp, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_READ);

                    if (cm_HaveBuffer(scp, bufp, 0)) 
                        break;

                    /* otherwise, load the buffer and try again */
                    code = cm_GetBuffer(scp, bufp, NULL, userp, &req);
                    if (code) 
                        break;
                }
            } else {
                memset(bufp->datap, 0, cm_data.blockSize);
            }

            (*ResultCB)->FileExtents[count].Flags = 0;
            (*ResultCB)->FileExtents[count].FileOffset = ByteOffset;
            (*ResultCB)->FileExtents[count].CacheOffset.QuadPart = bufp->datap - cm_data.baseAddress;
            (*ResultCB)->FileExtents[count].Length = cm_data.blockSize;
            count++;
            buf_Release(bufp);
        }
    }
    (*ResultCB)->ExtentCount = count;
    lock_ReleaseWrite(&scp->rw);
    cm_ReleaseSCache(scp);

    return;
}



void
RDR_ReleaseFileExtents( IN cm_user_t *userp,
                        IN AFSFileID FileId,
                        IN AFSReleaseExtentsCB *ReleaseExtentsCB,
                        IN DWORD ResultBufferLength,
                        IN OUT AFSCommResult **ResultCB)
{
    DWORD count;
    cm_scache_t *scp = NULL;
    cm_fid_t    Fid;
    cm_buf_t    *bufp;
    afs_uint32  code;
    osi_hyper_t thyper;
    cm_req_t    req;
    int         dirty = 0;

    cm_InitReq(&req);

    *ResultCB = (AFSCommResult *)malloc( sizeof( AFSCommResult));
    memset( *ResultCB,
            '\0',
            sizeof( AFSCommResult));

    /* Process the release */
    Fid.cell = FileId.Cell;
    Fid.volume = FileId.Volume;
    Fid.vnode = FileId.Vnode;
    Fid.unique = FileId.Unique;
    Fid.hash = FileId.Hash;

    code = cm_GetSCache(&Fid, &scp, userp, &req);
    if (code) {
        free(*ResultCB);
        *ResultCB = NULL;
        return;
    }

    for ( count = 0; count < ReleaseExtentsCB->ExtentCount; count++) {
        thyper.QuadPart = ReleaseExtentsCB->FileExtents[count].FileOffset.QuadPart;

        code = buf_Get(scp, &thyper, &bufp);
        if (code == 0) {
            if (ReleaseExtentsCB->FileExtents[count].Flags) {
                lock_ObtainMutex(&bufp->mx);
                if ( ReleaseExtentsCB->FileExtents[count].Flags & AFS_EXTENT_FLAG_RELEASE )
                    bufp->flags &= ~CM_BUF_REDIR;
                if ( ReleaseExtentsCB->FileExtents[count].Flags & AFS_EXTENT_FLAG_DIRTY ) {
                    buf_SetDirty(bufp, 0, cm_data.blockSize);
                    dirty = 1;
                }
                lock_ReleaseMutex(&bufp->mx);
            }
            buf_Release(bufp);
        }
    }

    if (dirty)
        code = cm_FSync(scp, userp, &req);

    cm_ReleaseSCache(scp);

    if (code) {
        DWORD status;
        smb_MapNTError(code, &status);
        (*ResultCB)->ResultStatus = status;
    } else
        (*ResultCB)->ResultStatus = 0;

    (*ResultCB)->ResultBufferLength = 0;

    return;
}
