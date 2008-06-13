//
// File: AFSWrite.cpp
//

#include "AFSCommon.h"

static
NTSTATUS
CachedWrite( IN PDEVICE_OBJECT DeviceObject,
             IN PIRP Irp,
             IN LARGE_INTEGER StartingByte,
             IN ULONG ByteCount);
static
NTSTATUS
NonCachedWrite( IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp,
                IN LARGE_INTEGER StartingByte,
                IN ULONG ByteCount);

static
NTSTATUS 
ExtendingWrite( IN AFSFcb *Fcb,
                IN PFILE_OBJECT FileObject,
                IN LONGLONG NewLength);

//
// Function: AFSWrite
//
// Description:
//
//      This is the dispatch handler for the IRP_MJ_WRITE request
//
// Return:
//
//      A status is returned for the function
//

NTSTATUS
AFSWrite( IN PDEVICE_OBJECT DeviceObject,
          IN PIRP Irp)
{

    NTSTATUS           ntStatus = STATUS_SUCCESS;
    AFSDeviceExt      *pDeviceExt = (AFSDeviceExt *)DeviceObject->DeviceExtension;
    IO_STACK_LOCATION *pIrpSp;
    AFSFcb            *pFcb = NULL;
    AFSNonPagedFcb    *pNPFcb = NULL;
    BOOLEAN            bPagingIo = FALSE;
    BOOLEAN            bNonCachedIo = FALSE;
    ULONG              ulByteCount = 0;
    LARGE_INTEGER      liStartingByte;
    PFILE_OBJECT       pFileObject;
    BOOLEAN            bReleaseMain = FALSE;    
    BOOLEAN            bReleasePaging = FALSE;    
    BOOLEAN            bExtendingWrite = FALSE;
    BOOLEAN            bSynchronousIo = FALSE, bCanQueueRequest = FALSE;
    ULONG              ulExtensionLength = 0;

    pIrpSp = IoGetCurrentIrpStackLocation( Irp);

    pFileObject = pIrpSp->FileObject;

    //
    // Extract the fileobject references
    //

    pFcb = (AFSFcb *)pFileObject->FsContext;
    pNPFcb = pFcb->NPFcb;

    __Enter
    {
        ObReferenceObject( pFileObject);

        //
        // If this is a read against an IOCtl node then handle it 
        // in a different pathway
        //

        if( pFcb->Header.NodeTypeCode == AFS_IOCTL_FCB)
        {

            ntStatus = AFSIOCtlWrite( DeviceObject,
                                      Irp);

            try_return( ntStatus);
        }

        //
        // TODO we need some interlock to stop the cache being town
        // down after this check 
        //
        if( NULL == pDeviceExt->Specific.RDR.CacheFileObject) 
        {
            try_return( ntStatus = STATUS_TOO_LATE );
        }

        //
        // If this is a read against an IOCtl node then handle it 
        // in a different pathway
        //

        if( pFcb->Header.NodeTypeCode == AFS_IOCTL_FCB)
        {

            ntStatus = AFSIOCtlWrite( DeviceObject,
                                      Irp);

            try_return( ntStatus);
        }

        liStartingByte = pIrpSp->Parameters.Write.ByteOffset;

        bSynchronousIo = BooleanFlagOn( pFileObject->Flags, FO_SYNCHRONOUS_IO);
        bPagingIo      = BooleanFlagOn( Irp->Flags, IRP_PAGING_IO);
        bNonCachedIo   = BooleanFlagOn( Irp->Flags, IRP_NOCACHE);
        ulByteCount    = pIrpSp->Parameters.Write.Length;

        if( !bPagingIo)
        {
            bExtendingWrite = (((liStartingByte.QuadPart + ulByteCount) >= 
                                pFcb->Header.FileSize.QuadPart) ||
                               (liStartingByte.LowPart == FILE_WRITE_TO_END_OF_FILE &&
                                liStartingByte.HighPart == -1)) ;
        }

        bCanQueueRequest = !(IoIsOperationSynchronous( Irp));

        //
        // Check for zero length write
        //

        if( ulByteCount == 0)
        {

            AFSPrint("AFSCommonWrite Processed zero length write\n");

            try_return( ntStatus);
        }

        //
        // Is this Fcb valid???
        //

        if( BooleanFlagOn( pFcb->Flags, AFS_FCB_INVALID))
        {

            AFSPrint("AFSCommonWrite Dropping request for invalid Fcb\n");

            //
            // OK, this Fcb was probably deleted then renamed into but we re-used the source fcb
            // hence this flush is bogus. Drop it
            //

            Irp->IoStatus.Information = ulByteCount;

            try_return( ntStatus = STATUS_SUCCESS);
        }

        if( FlagOn(pIrpSp->MinorFunction, IRP_MN_COMPLETE) ) {
        
            AFSPrint("MN_COMPLETE \n");

            CcMdlWriteComplete(pFileObject, &pIrpSp->Parameters.Write.ByteOffset, Irp->MdlAddress);

            //
            // Mdl is now Deallocated
            //

            Irp->MdlAddress = NULL;
        
            try_return( ntStatus = STATUS_SUCCESS );
        }


        //
        // TODO
        // If we get a non cached IO for a cached file we should do a purge.  
        // For now we will just promote to cached
        //
        if( CcIsFileCached(pFileObject) && !bPagingIo) {
            bNonCachedIo = TRUE;
        }

        //
        // Take locks 
        //
        //   - if Paging then we need to nothing (the precalls will
        //     have acquired the paging resource), for clarity we will collect 
        //     the paging resource 
        //   - If extending Write then take the fileresource EX (EOF will change, Allocation will only move out)
        //   - Otherwise we collect the file shared
        //
        if( bPagingIo) 
        {
            ASSERT( ExIsResourceAcquiredLite( &pNPFcb->PagingResource ));
    
            AFSAcquireShared( &pNPFcb->PagingResource,
                              TRUE);

            bReleasePaging = TRUE;
        } 
        else if( bExtendingWrite) 
        {
            //
            // Check for lock inversion
            //
            ASSERT( !ExIsResourceAcquiredLite( &pNPFcb->PagingResource ));
    
            AFSPrint("Extending Write\n");

            AFSAcquireExcl( &pNPFcb->Resource,
                              TRUE);

            if (liStartingByte.LowPart == FILE_WRITE_TO_END_OF_FILE &&
                liStartingByte.HighPart == -1)
            {
                if (pFcb->Header.ValidDataLength.QuadPart > pFcb->Header.FileSize.QuadPart)
                {
                    liStartingByte = pFcb->Header.ValidDataLength;
                } 
                else
                {
                    liStartingByte = pFcb->Header.FileSize;
                }
            }
            bReleaseMain = TRUE;

        }
        else
        {
            ASSERT( !ExIsResourceAcquiredLite( &pNPFcb->PagingResource ));
    
            AFSAcquireShared( &pNPFcb->Resource,
                              TRUE);

            bReleaseMain = TRUE;
        }

        if( BooleanFlagOn( pFcb->Flags, AFS_FCB_DELETED))
        {

            try_return( ntStatus = STATUS_FILE_DELETED);
        }

        //
        // Check the BR locks on the file. TODO: Add OPLock checks and
        // queuing mechanism
        //

        if( !bPagingIo && 
            !FsRtlCheckLockForWriteAccess( &pFcb->Specific.File.FileLock,
                                           Irp)) 
        {
            
            AFSPrint("AFSCommonWrite Failed BR lock check for cached I/O\n");

            try_return( ntStatus = STATUS_FILE_LOCK_CONFLICT);
        }

        if( !bNonCachedIo && pFileObject->PrivateCacheMap == NULL)
        {

            CcInitializeCacheMap( pFileObject,
                                  (PCC_FILE_SIZES)&pFcb->Header.AllocationSize,
                                  FALSE,
                                  &AFSCacheManagerCallbacks,
                                  pFcb);

            CcSetReadAheadGranularity( pFileObject, 
                                       READ_AHEAD_GRANULARITY);
        }

        if ( bExtendingWrite)
        {

            ntStatus = ExtendingWrite( pFcb, pFileObject, (liStartingByte.QuadPart + ulByteCount));

            if ( !NT_SUCCESS(ntStatus)) 
            {
                
                try_return( ntStatus );
            }
        }

        if( !bPagingIo &&
            !bNonCachedIo)
        {
            ntStatus = CachedWrite( DeviceObject, Irp, liStartingByte, ulByteCount);

            try_return( ntStatus );
        }
        else
        {
            ntStatus = NonCachedWrite( DeviceObject, Irp,  liStartingByte, ulByteCount);
        }

try_exit:

        ObDereferenceObject(pFileObject);

        if( !NT_SUCCESS( ntStatus))
        {

            AFSPrint("AFSCommonWrite Failed to process write request Status %08lX\n", ntStatus);
        }

        if( bReleaseMain)
        {

            AFSReleaseResource( &pNPFcb->Resource);
        }
        if( bReleasePaging)
        {

            AFSReleaseResource( &pNPFcb->PagingResource);
        }
    }

    return ntStatus;
}

NTSTATUS
AFSIOCtlWrite( IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    AFSPIOCtlIORequestCB stIORequestCB;
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    AFSFcb *pFcb = NULL;
    UNICODE_STRING uniFullName;
    AFSPIOCtlIOResultCB stIOResultCB;
    ULONG ulBytesReturned = 0;

    __Enter
    {

        uniFullName.Length = 0;
        uniFullName.Buffer = NULL;

        stIORequestCB.MappedBuffer = NULL;
        stIORequestCB.BufferLength = 0;

        if( pIrpSp->Parameters.Write.Length == 0)
        {

            //
            // Nothing to do in this case
            //

            try_return( ntStatus);
        }

        pFcb = (AFSFcb *)pIrpSp->FileObject->FsContext;

        AFSAcquireShared( &pFcb->NPFcb->Resource,
                          TRUE);

        ntStatus = AFSGetFullName( pFcb,
                                   &uniFullName);

        if( !NT_SUCCESS( ntStatus))
        {

            try_return( ntStatus);
        }

        //
        // Locak down the buffer
        //

        stIORequestCB.MappedBuffer = AFSMapToService( Irp,
                                                      pIrpSp->Parameters.Write.Length);

        if( stIORequestCB.MappedBuffer == NULL)
        {

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }

        stIORequestCB.BufferLength = pIrpSp->Parameters.Write.Length;

        stIOResultCB.BytesProcessed = 0;

        ulBytesReturned = sizeof( AFSPIOCtlIOResultCB);

        //
        // Issue the request to the service
        //

        ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_PIOCTL_WRITE,
                                      AFS_REQUEST_FLAG_SYNCHRONOUS,
                                      &uniFullName,
                                      NULL,
                                      (void *)&stIORequestCB,
                                      sizeof( AFSPIOCtlIORequestCB),
                                      &stIOResultCB,
                                      &ulBytesReturned);

        if( !NT_SUCCESS( ntStatus))
        {

            try_return( ntStatus);
        }

        //
        // Update the length written
        //

        Irp->IoStatus.Information = stIOResultCB.BytesProcessed;

try_exit:

        if( stIORequestCB.MappedBuffer != NULL)
        {

            AFSUnmapServiceMappedBuffer( stIORequestCB.MappedBuffer,
                                         Irp->MdlAddress);
        }

        if( uniFullName.Buffer != NULL)
        {

            ExFreePool( uniFullName.Buffer);
        }

        if( pFcb != NULL)
        {

            AFSReleaseResource( &pFcb->NPFcb->Resource);
        }

        //
        // Complete the request
        //

        AFSCompleteRequest( Irp,
                            ntStatus);
    }

    return ntStatus;
}


static
NTSTATUS
NonCachedWrite( IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp,
                IN LARGE_INTEGER StartingByte,
                IN ULONG ByteCount)
{
    NTSTATUS           ntStatus = STATUS_UNSUCCESSFUL;
    VOID              *pSystemBuffer = NULL;
    BOOLEAN            bPagingIo = BooleanFlagOn( Irp->Flags, IRP_PAGING_IO);
    BOOLEAN            bLocked = FALSE; 
    BOOLEAN            bCompleteIrp = TRUE;
    BOOLEAN            bExtentsMapped = FALSE;
    AFSGatherIo       *pGatherIo = NULL;
    AFSIoRun          *pIoRuns = NULL;
    AFSIoRun           stIoRuns[AFS_MAX_STACK_IO_RUNS];
    ULONG              extentsCount = 0;
    AFSExtent         *pStartExtent;
    AFSExtent         *pEndExtent;
    IO_STACK_LOCATION *pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    PFILE_OBJECT       pFileObject = pIrpSp->FileObject;
    AFSFcb            *pFcb = (AFSFcb *)pFileObject->FsContext;
    BOOLEAN            bSynchronousIo = BooleanFlagOn( pFileObject->Flags, FO_SYNCHRONOUS_IO);
    AFSDeviceExt      *pDevExt = (AFSDeviceExt *)DeviceObject->DeviceExtension;

    __Enter
    {
        Irp->IoStatus.Information = 0;

        //
        // Get the mapping for the buffer
        //
        pSystemBuffer = AFSLockSystemBuffer( Irp,
                                             ByteCount);

        if( pSystemBuffer == NULL)
        {
                
            AFSPrint("AFSCommonWrite Failed to retrieve system buffer\n");

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }


        //
        // Provoke a get of the extents - if we need to.
        // TODO - right now we wait for the extents to be there.  We should 
        // Post if we can or return STATUS_FILE_LOCKED otherwise
        //
        while (TRUE) 
        {
            ntStatus = AFSRequestExtents( pFcb, &StartingByte, ByteCount, &bExtentsMapped );

            if (!NT_SUCCESS(ntStatus)) 
            {
                try_return( ntStatus );
            }

            if (bExtentsMapped)
            {
                break;
            }

            ntStatus =  AFSWaitForExtentMapping ( pFcb );

            if (!NT_SUCCESS(ntStatus)) 
            {
                try_return( ntStatus );
            }
        }
        
        //
        // As per the read path - collect the extents lock - just for sanity
        //

        AFSAcquireShared( &pFcb->NPFcb->Specific.File.ExtentsResource, TRUE );
        bLocked = TRUE;

        ntStatus = AFSGetExtents( pFcb, 
                                  &StartingByte, 
                                  ByteCount, 
                                  &pStartExtent, 
                                  &pEndExtent, 
                                  &extentsCount);
        
        if (!NT_SUCCESS(ntStatus)) 
        {
            try_return( ntStatus );
        }
        
        if (extentsCount > AFS_MAX_STACK_IO_RUNS) {

            pIoRuns = (AFSIoRun*) ExAllocatePoolWithTag( PagedPool,
                                                         extentsCount * sizeof( AFSIoRun ),
                                                         AFS_IO_RUN_TAG );
            if (NULL == pIoRuns) 
            {
                try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES );
            }
        } else {
            
            pIoRuns = stIoRuns;

        }

        RtlZeroMemory( pIoRuns, extentsCount * sizeof( AFSIoRun ));

        ntStatus = AFSSetupIoRun( pDevExt->Specific.RDR.CacheFileObject->Vpb->DeviceObject, 
                                  Irp, 
                                  pSystemBuffer, 
                                  pIoRuns, 
                                  &StartingByte, 
                                  ByteCount, 
                                  pStartExtent, 
                                  extentsCount );

        if (!NT_SUCCESS(ntStatus)) 
        {
            try_return( ntStatus );
        }

        AFSReleaseResource( &pFcb->NPFcb->Specific.File.ExtentsResource );
        bLocked = FALSE;

        pGatherIo = (AFSGatherIo*) ExAllocatePoolWithTag( NonPagedPool,
                                                      sizeof( AFSGatherIo ),
                                                      AFS_GATHER_TAG );

        if (NULL == pGatherIo) 
        {
            try_return (ntStatus = STATUS_INSUFFICIENT_RESOURCES );
        }

        RtlZeroMemory( pGatherIo, sizeof( AFSGatherIo ));

        //
        // Initialize count to 1, that was we won't get an early
        // completion if the first irp completes before the second is
        // queued.
        //
        pGatherIo->Count = 1;
        pGatherIo->Status = STATUS_SUCCESS;
        pGatherIo->MasterIrp = Irp;
        pGatherIo->Synchronous = TRUE;
        bCompleteIrp = FALSE;

        if (pGatherIo->Synchronous) {
            KeInitializeEvent( &pGatherIo->Event, NotificationEvent, FALSE );
        }

        //
        // Pre-emptively set up the count
        //
        Irp->IoStatus.Information = ByteCount;

        ntStatus = AFSStartIos( pDevExt->Specific.RDR.CacheFileObject,
                                IRP_MJ_WRITE,
                                IRP_WRITE_OPERATION | IRP_SYNCHRONOUS_API,
                                pIoRuns, 
                                extentsCount, 
                                pGatherIo );

        //
        // Regardless of the status we we do the complete - there may
        // be IOs in flight
        //
        // Decrement the count - setting the event if we are done
        //
        AFSCompleteIo( pGatherIo, STATUS_SUCCESS );

        //
        // Wait for completion of All IOs we started.
        //
        (VOID) KeWaitForSingleObject( &pGatherIo->Event,
                                      Executive,
                                      KernelMode,
                                      FALSE,
                                      NULL);
        
        if (NT_SUCCESS(ntStatus)) 
        {
            ntStatus = pGatherIo->Status;
        } 
        else 
        {
            try_return( ntStatus);
        }

        //
        // Since this is dirty we can mark the extents dirty now
        // (asynch we would fire off a thread to wait for the event)
        //

        AFSMarkDirty( pFcb, &StartingByte, ByteCount);

        //
        // Equally we can flush them
        //
        ntStatus = AFSFlushExtents( pFcb);

        //
        // All done
        //
try_exit:
        if (NT_SUCCESS(ntStatus) &&
            !bPagingIo &&
            bSynchronousIo) 
        {
            //
            // Update the CBO if this is a sync, nopaging read
            //
            pFileObject->CurrentByteOffset.QuadPart = StartingByte.QuadPart + ByteCount;
        }

        SetFlag( pFcb->Flags, AFS_UPDATE_WRITE_TIME);

        if (bLocked) 
        {
            AFSReleaseResource( &pFcb->NPFcb->Specific.File.ExtentsResource );
        }

        if (pGatherIo) {
            ExFreePoolWithTag(pGatherIo, AFS_GATHER_TAG);
        }

        if (NULL != pIoRuns && stIoRuns != pIoRuns) {
            ExFreePoolWithTag(pIoRuns, AFS_IO_RUN_TAG);
        }

        if (bCompleteIrp) {
            Irp->IoStatus.Information = 0;

            AFSCompleteRequest( Irp, ntStatus );
        }
    }

    return ntStatus;
}

static
NTSTATUS
CachedWrite( IN PDEVICE_OBJECT DeviceObject,
             IN PIRP Irp,
             IN LARGE_INTEGER StartingByte,
             IN ULONG ByteCount)
{
    PVOID              pSystemBuffer = NULL;
    NTSTATUS           ntStatus = STATUS_SUCCESS;
    IO_STACK_LOCATION *pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    PFILE_OBJECT       pFileObject = pIrpSp->FileObject;
    AFSFcb            *pFcb = (AFSFcb *)pFileObject->FsContext;
    BOOLEAN            bSynchronousIo = BooleanFlagOn( pFileObject->Flags, FO_SYNCHRONOUS_IO);
    BOOLEAN            bMapped = FALSE; 

    Irp->IoStatus.Information = 0;
    __Enter
    {
        //
        // Provoke a get of the extents - if we need to.
        //
        ntStatus = AFSRequestExtents( pFcb, &StartingByte, ByteCount, &bMapped );

        if (!NT_SUCCESS(ntStatus)) {
            try_return( ntStatus );
        }

        //
        // TODO - CcCanIwrite
        //
        

        //
        // Get the mapping for the buffer
        //

        pSystemBuffer = AFSLockSystemBuffer( Irp,
                                             ByteCount);

        if( pSystemBuffer == NULL)
        {
                
            AFSPrint("AFSCommonWrite Failed to retrieve system buffer\n");

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }

        __try 
        {
            if( !CcCopyWrite( pFileObject,
                              &StartingByte,
                              ByteCount,
                              TRUE,
                              pSystemBuffer)) 

            {
                //
                // Failed to process request.
                //

                AFSPrint("AFSWrite failed to issue cached read Write %08lX\n", Irp->IoStatus.Status);

                try_return( ntStatus = STATUS_UNSUCCESSFUL);
            }
            Irp->IoStatus.Information = ByteCount;
            ntStatus = STATUS_SUCCESS;
        }
        __except( AFSExceptionFilter( GetExceptionCode(), GetExceptionInformation()))
        {
            try_return( ntStatus = GetExceptionCode());
        }

        if( bSynchronousIo)
        {

            pFileObject->CurrentByteOffset.QuadPart = StartingByte.QuadPart + ByteCount;
        }

        //
        // If this extended the Vdl, then update it accordinly
        //

        if( StartingByte.QuadPart + ByteCount > pFcb->Header.ValidDataLength.QuadPart)
        {

            pFcb->Header.ValidDataLength.QuadPart = StartingByte.QuadPart + ByteCount;
        }

        SetFlag( pFcb->Flags, AFS_UPDATE_WRITE_TIME);



    try_exit:
        ;
    }

    //
    // Complete the request.
    //
    AFSCompleteRequest( Irp,
                        ntStatus);

    return ntStatus;
}

static
NTSTATUS 
ExtendingWrite( IN AFSFcb *Fcb,
                IN PFILE_OBJECT FileObject,
                IN LONGLONG NewLength)
{
    LARGE_INTEGER liSaveFileSize = Fcb->Header.FileSize;
    LARGE_INTEGER liSaveAllocation = Fcb->Header.AllocationSize;
    NTSTATUS      ntStatus = STATUS_SUCCESS;

    if( NewLength > Fcb->Header.AllocationSize.QuadPart)
    {

        //
        // Adjust the allocation size. For now we utilize a 512 byte sector for allocation, this will change.
        //

        if( (NewLength % 512) > 0)
        {

            Fcb->Header.AllocationSize.QuadPart = ((NewLength / 512) + 1) * 512;
        }
        else
        {

            Fcb->Header.AllocationSize.QuadPart = NewLength;
        }
        
        Fcb->DirEntry->DirectoryEntry.AllocationSize = Fcb->Header.AllocationSize;

    }

    if( NewLength > Fcb->Header.FileSize.QuadPart)
    {
        
        //
        // Adjust the file size
        //

        Fcb->Header.FileSize.QuadPart = NewLength;

        Fcb->DirEntry->DirectoryEntry.EndOfFile = Fcb->Header.FileSize;

    }

    //
    // Tell the server
    //
    ntStatus = AFSUpdateFileInformation( AFSRDRDeviceObject, Fcb);

    if (NT_SUCCESS(ntStatus))
    {
        
        SetFlag( Fcb->Flags, AFS_FILE_MODIFIED);
        //
        // If the file is currently cached, then let the MM know about the extension
        //
    
        if( CcIsFileCached( FileObject)) 
        {
            CcSetFileSizes( FileObject, 
                            (PCC_FILE_SIZES)&Fcb->Header.AllocationSize);
        }
    }
    else
    {
        Fcb->Header.FileSize = liSaveFileSize;
        Fcb->Header.AllocationSize = liSaveAllocation;
    }

    //
    // DownConvert file resource to shared
    //
    ExConvertExclusiveToSharedLite( &Fcb->NPFcb->Resource);

    return ntStatus;
}