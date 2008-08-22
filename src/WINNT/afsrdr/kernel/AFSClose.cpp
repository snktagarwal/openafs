//
// File: AFSClose.cpp
//

#include "AFSCommon.h"

//
// Function: AFSClose
//
// Description: 
//
//      This function is the IRP_MJ_CLOSE dispatch handler
//
// Return:
//
//       A status is returned for the handling of this request
//

NTSTATUS
AFSClose( IN PDEVICE_OBJECT DeviceObject,
          IN PIRP Irp)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG ulRequestType = 0;
    IO_STACK_LOCATION *pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    AFSFcb *pFcb = NULL;
    AFSDeviceExt *pDeviceExt = NULL;
    AFSCcb *pCcb = NULL;

    __try
    {

        if( DeviceObject == AFSDeviceObject)
        {

            try_return( ntStatus);
        }

        pDeviceExt = (AFSDeviceExt *)DeviceObject->DeviceExtension;

        pIrpSp = IoGetCurrentIrpStackLocation( Irp);

        pFcb = (AFSFcb *)pIrpSp->FileObject->FsContext;

        if( pFcb == NULL)
        {

            try_return( ntStatus);
        }

        //
        // Perform the cleanup functionality depending on the type of node it is
        //

        switch( pFcb->Header.NodeTypeCode)
        {

            case AFS_IOCTL_FCB:
            {

                AFSPIOCtlOpenCloseRequestCB stPIOCtlClose;
                AFSFileID stParentFileId;

                AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                  TRUE);

                pCcb = (AFSCcb *)pIrpSp->FileObject->FsContext2;

                //
                // Send the close to the CM
                //

                RtlZeroMemory( &stPIOCtlClose,
                               sizeof( AFSPIOCtlOpenCloseRequestCB));

                stPIOCtlClose.RequestId = pCcb->PIOCtlRequestID;

                if( pFcb->RootFcb != NULL)
                {
                    stPIOCtlClose.RootId = pFcb->RootFcb->DirEntry->DirectoryEntry.FileId;
                }

                RtlZeroMemory( &stParentFileId,
                               sizeof( AFSFileID));

                if( pFcb->ParentFcb != NULL)
                {
                    stParentFileId = pFcb->ParentFcb->DirEntry->DirectoryEntry.FileId;
                }

                //
                // Issue the open request to the service
                //

                AFSProcessRequest( AFS_REQUEST_TYPE_PIOCTL_CLOSE,
                                   AFS_REQUEST_FLAG_SYNCHRONOUS,
                                   0,
                                   NULL,
                                   &stParentFileId,
                                   (void *)&stPIOCtlClose,
                                   sizeof( AFSPIOCtlOpenCloseRequestCB),
                                   NULL,
                                   NULL);

                //
                // If we ahve a Ccb then remove it from the Fcb chain
                //

                if( pCcb != NULL)
                {

                    //
                    // Remove the Ccb and de-allocate it
                    //

                    ntStatus = AFSRemoveCcb( pFcb,
                                             pCcb);

                    if( !NT_SUCCESS( ntStatus))
                    {

                        AFSPrint("AFSClose Failed to remove Ccb from Fcb Status %08lX\n", ntStatus);

                        //
                        // We can't actually fail a close operation so reset the status
                        //

                        ntStatus = STATUS_SUCCESS;
                    }
                }

                //
                // For these Fcbs we tear them down in line since they have not been
                // added to any of the Fcb lists for post processing
                //

                InterlockedDecrement( &pFcb->OpenReferenceCount);

                //
                // If this is not the root then decrement the open child reference count
                //

                if( pFcb->ParentFcb != NULL)
                {
                   
                    InterlockedDecrement( &pFcb->ParentFcb->Specific.Directory.ChildOpenReferenceCount);
                }

                if( pFcb->OpenReferenceCount == 0)
                {

                    AFSReleaseResource( &pFcb->NPFcb->Resource);

                    AFSRemoveFcb( pFcb);
                }
                else
                {

                    AFSReleaseResource( &pFcb->NPFcb->Resource);
                }

                break;
            }

            //
            // This Fcb represents a file
            //

            case AFS_FILE_FCB:

            //
            // Root or directory node
            //

            case AFS_ROOT_FCB:
            case AFS_DIRECTORY_FCB:
            case AFS_ROOT_ALL:
            {
            
                BOOLEAN bReleaseParent = FALSE;

                pCcb = (AFSCcb *)pIrpSp->FileObject->FsContext2;

                //
                // We may be performing some cleanup on the Fcb so grab it exclusive to ensure no collisions
                //

                AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                TRUE);

                KeQueryTickCount( &pFcb->LastAccessCount);

                //
                // If this node is deleted then we will need to drop
                // the lock, grab the parent then grab the lock again
                //

                if( BooleanFlagOn( pFcb->Flags, AFS_FCB_DELETED))
                {

                    AFSReleaseResource( &pFcb->NPFcb->Resource);

                    ASSERT( pFcb->ParentFcb != NULL);

                    AFSAcquireExcl( &pFcb->ParentFcb->NPFcb->Resource,
                                      TRUE);

                    bReleaseParent = TRUE;

                    AFSAcquireExcl( &pFcb->NPFcb->Resource,
                                      TRUE);
                }

                //
                // If we ahve a Ccb then remove it from the Fcb chain
                //

                if( pCcb != NULL)
                {

                    //
                    // Remove the Ccb and de-allocate it
                    //

                    ntStatus = AFSRemoveCcb( pFcb,
                                               pCcb);

                    if( !NT_SUCCESS( ntStatus))
                    {

                        AFSPrint("AFSClose Failed to remove Ccb from Fcb Status %08lX\n", ntStatus);

                        //
                        // We can't actually fail a close operation so reset the status
                        //

                        ntStatus = STATUS_SUCCESS;
                    }
                }

                //
                // Decrement the reference count on the Fcb
                //

                InterlockedDecrement( &pFcb->OpenReferenceCount);

                if( pFcb->OpenReferenceCount == 0 &&
                    BooleanFlagOn( pFcb->Flags, AFS_FCB_DELETED))
                {

                    //
                    // Add the space back in if it is a file
                    //

                    if( pFcb->DirEntry->DirectoryEntry.AllocationSize.QuadPart > 0)
                    {

                    }

                    //
                    // Now remove the directory entry
                    //

                    AFSDeleteDirEntry( pFcb->ParentFcb,
                                       pFcb->DirEntry);

                    //
                    // Remove the DirEntry reference from the Fcb
                    //

                    pFcb->DirEntry = NULL;
                }

                //
                // If this is not the root then decrement the open child reference count
                //

                if( pFcb->ParentFcb != NULL)
                {
                   
                    InterlockedDecrement( &pFcb->ParentFcb->Specific.Directory.ChildOpenReferenceCount);
                }

                AFSReleaseResource( &pFcb->NPFcb->Resource);

                if( bReleaseParent)
                {

                    AFSReleaseResource( &pFcb->ParentFcb->NPFcb->Resource);
                }

                break;
            }
           
            default:

                AFSPrint("AFSCleanup Processing unknown node type %d\n", pFcb->Header.NodeTypeCode);

                break;
        }


try_exit:

        //
        // Complete the request
        //

        AFSCompleteRequest( Irp,
                              ntStatus);
    }
    __except( AFSExceptionFilter( GetExceptionCode(), GetExceptionInformation()) )
    {

        AFSPrint("EXCEPTION - AFSClose\n");
    }

    return ntStatus;
}