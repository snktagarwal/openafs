/*
 * Copyright (c) 2008, 2009 Kernel Drivers, LLC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice,
 *   this list of conditions and the following disclaimer in the
 *   documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Kernel Drivers, LLC nor the names of its
 *   contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission from Kernel Drivers, LLC.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

//
// File: AFSNetworkProviderSupport.cpp
//

#include "AFSCommon.h"

NTSTATUS
AFSAddConnection( IN AFSNetworkProviderConnectionCB *ConnectCB,
                  IN OUT PULONG ResultStatus,
                  IN OUT ULONG_PTR *ReturnOutputBufferLength)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    AFSProviderConnectionCB *pConnection = NULL, *pLastConnection = NULL;
    UNICODE_STRING uniRemoteName;
    USHORT usIndex = 0;

    __Enter
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSAddConnection Acquiring AFSProviderListLock lock %08lX EXCL %08lX\n",
                      &AFSProviderListLock,
                      PsGetCurrentThread());

        AFSAcquireExcl( &AFSProviderListLock,
                        TRUE);

        //
        // Look for the connection
        //

        uniRemoteName.Length = (USHORT)ConnectCB->RemoteNameLength;
        uniRemoteName.MaximumLength = uniRemoteName.Length;

        uniRemoteName.Buffer = ConnectCB->RemoteName;

        pConnection = AFSProviderConnectionList;

        while( pConnection != NULL)
        {

            if( pConnection->LocalName == ConnectCB->LocalName &&
                RtlCompareUnicodeString( &uniRemoteName,
                                         &pConnection->RemoteName,
                                         TRUE) == 0)
            {

                break;
            }

            pConnection = pConnection->fLink;
        }

        if( pConnection != NULL)
        {

            *ResultStatus = WN_ALREADY_CONNECTED;

            *ReturnOutputBufferLength = sizeof( ULONG);

            try_return( ntStatus);
        }

        //
        // Validate the remote name
        //

        if( uniRemoteName.Length > 2 * sizeof( WCHAR) &&
            uniRemoteName.Buffer[ 0] == L'\\' &&
            uniRemoteName.Buffer[ 1] == L'\\')
        {

            uniRemoteName.Buffer = &uniRemoteName.Buffer[ 2];

            uniRemoteName.Length -= (2 * sizeof( WCHAR));
        }

        if( uniRemoteName.Length >= AFSServerName.Length)
        {

            USHORT usLength = uniRemoteName.Length;

            if (uniRemoteName.Buffer[AFSServerName.Length/sizeof( WCHAR)] != L'\\') 
            {

                *ResultStatus = WN_BAD_NETNAME;

                *ReturnOutputBufferLength = sizeof( ULONG);

                try_return( ntStatus = STATUS_SUCCESS);
            }

            uniRemoteName.Length = AFSServerName.Length;

            if( RtlCompareUnicodeString( &AFSServerName,
                                         &uniRemoteName,
                                         TRUE) != 0)
            {

                *ResultStatus = WN_BAD_NETNAME;

                *ReturnOutputBufferLength = sizeof( ULONG);

                try_return( ntStatus = STATUS_SUCCESS);
            }

            uniRemoteName.Length = usLength;
        }
        else
        {

            *ResultStatus = WN_BAD_NETNAME;

            *ReturnOutputBufferLength = sizeof( ULONG);

            try_return( ntStatus = STATUS_SUCCESS);
        }

        uniRemoteName.Length = (USHORT)ConnectCB->RemoteNameLength;
        uniRemoteName.MaximumLength = uniRemoteName.Length;

        uniRemoteName.Buffer = ConnectCB->RemoteName;

        //
        // Strip off any trailing slashes
        //

        if( uniRemoteName.Buffer[ (uniRemoteName.Length/sizeof( WCHAR)) - 1] == L'\\')
        {

            uniRemoteName.Buffer[ (uniRemoteName.Length/sizeof( WCHAR)) - 1] = L'\0';

            uniRemoteName.Length -= sizeof( WCHAR);
        }

        //
        // Allocate a new node and add it to our list
        //

        pConnection = (AFSProviderConnectionCB *)ExAllocatePoolWithTag( PagedPool,
                                                                        sizeof( AFSProviderConnectionCB) +
                                                                                      uniRemoteName.Length,
                                                                        AFS_PROVIDER_CB);

        if( pConnection == NULL)
        {

            *ResultStatus = WN_OUT_OF_MEMORY;

            *ReturnOutputBufferLength = sizeof( ULONG);

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }

        RtlZeroMemory( pConnection,
                       sizeof( AFSProviderConnectionCB) + uniRemoteName.Length);

        pConnection->LocalName = ConnectCB->LocalName;

        pConnection->RemoteName.Length = uniRemoteName.Length;
        pConnection->RemoteName.MaximumLength = pConnection->RemoteName.Length;

        pConnection->RemoteName.Buffer = (WCHAR *)((char *)pConnection + sizeof( AFSProviderConnectionCB));

        RtlCopyMemory( pConnection->RemoteName.Buffer,
                       uniRemoteName.Buffer,
                       pConnection->RemoteName.Length);

        pConnection->Type = ConnectCB->Type;

        //
        // Point to the component portion of the name
        //

        pConnection->ComponentName.Length = 0;
        pConnection->ComponentName.MaximumLength = 0;

        pConnection->ComponentName.Buffer = &pConnection->RemoteName.Buffer[ (pConnection->RemoteName.Length/sizeof( WCHAR)) - 1];

        while( pConnection->ComponentName.Length <= pConnection->RemoteName.Length)
        {

            if( pConnection->ComponentName.Buffer[ 0] == L'\\')
            {

                pConnection->ComponentName.Buffer++;

                break;
            }

            pConnection->ComponentName.Length += sizeof( WCHAR);
            pConnection->ComponentName.MaximumLength += sizeof( WCHAR);

            pConnection->ComponentName.Buffer--;
        }

        //
        // Go initialize the information about the connection
        //

        AFSInitializeConnectionInfo( pConnection,
                                     (ULONG)-1);

        //
        // Insert the entry into our list
        //

        if( AFSProviderConnectionList == NULL)
        {

            AFSProviderConnectionList = pConnection;
        }
        else
        {

            //
            // Get the end of the list
            //

            pLastConnection = AFSProviderConnectionList;

            while( pLastConnection->fLink != NULL)
            {

                pLastConnection = pLastConnection->fLink;
            }

            pLastConnection->fLink = pConnection;
        }

        *ResultStatus = WN_SUCCESS;

        *ReturnOutputBufferLength = sizeof( ULONG);

try_exit:

        AFSReleaseResource( &AFSProviderListLock);

    }

    return ntStatus;
}

NTSTATUS
AFSAddConnectionEx( IN UNICODE_STRING *RemoteName,
                    IN ULONG DisplayType,
                    IN ULONG Flags)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    AFSProviderConnectionCB *pConnection = NULL, *pLastConnection = NULL, *pServerConnection = NULL;
    UNICODE_STRING uniRemoteName;

    __Enter
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSAddConnectionEx Acquiring AFSProviderListLock lock %08lX EXCL %08lX\n",
                      &AFSProviderListLock,
                      PsGetCurrentThread());

        AFSAcquireExcl( &AFSProviderListLock,
                        TRUE);

        //
        // If this is a server, start in the enum list, otherwise
        // locate the server node
        //

        if( DisplayType == RESOURCEDISPLAYTYPE_SERVER)
        {

            pConnection = AFSProviderEnumerationList;
        }
        else
        {

            pServerConnection = AFSProviderEnumerationList; // For now we have only one server ...

            if( pServerConnection == NULL)
            {

                try_return( ntStatus);
            }

            pConnection = pServerConnection->EnumerationList;
        }

        //
        // Look for the connection
        //

        uniRemoteName.Length = RemoteName->Length;
        uniRemoteName.MaximumLength = RemoteName->Length;

        uniRemoteName.Buffer = RemoteName->Buffer;

        while( pConnection != NULL)
        {

            if( RtlCompareUnicodeString( &uniRemoteName,
                                         &pConnection->RemoteName,
                                         TRUE) == 0)
            {

                break;
            }

            pConnection = pConnection->fLink;
        }

        if( pConnection != NULL)
        {

            try_return( ntStatus);
        }

        //
        // Strip off any trailing slashes
        //

        if( uniRemoteName.Buffer[ (uniRemoteName.Length/sizeof( WCHAR)) - 1] == L'\\')
        {

            uniRemoteName.Buffer[ (uniRemoteName.Length/sizeof( WCHAR)) - 1] = L'\0';

            uniRemoteName.Length -= sizeof( WCHAR);
        }

        //
        // Allocate a new node and add it to our list
        //

        pConnection = (AFSProviderConnectionCB *)ExAllocatePoolWithTag( PagedPool,
                                                                        sizeof( AFSProviderConnectionCB) +
                                                                                      uniRemoteName.Length,
                                                                        AFS_PROVIDER_CB);

        if( pConnection == NULL)
        {

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }

        RtlZeroMemory( pConnection,
                       sizeof( AFSProviderConnectionCB) + uniRemoteName.Length);

        pConnection->LocalName = L'\0';

        pConnection->RemoteName.Length = uniRemoteName.Length;
        pConnection->RemoteName.MaximumLength = pConnection->RemoteName.Length;

        pConnection->RemoteName.Buffer = (WCHAR *)((char *)pConnection + sizeof( AFSProviderConnectionCB));

        RtlCopyMemory( pConnection->RemoteName.Buffer,
                       uniRemoteName.Buffer,
                       pConnection->RemoteName.Length);

        //
        // Point to the component portion of the name
        //

        pConnection->ComponentName.Length = 0;
        pConnection->ComponentName.MaximumLength = 0;

        pConnection->ComponentName.Buffer = &pConnection->RemoteName.Buffer[ (pConnection->RemoteName.Length/sizeof( WCHAR)) - 1];

        while( pConnection->ComponentName.Length <= pConnection->RemoteName.Length)
        {

            if( pConnection->ComponentName.Buffer[ 0] == L'\\')
            {

                pConnection->ComponentName.Buffer++;

                break;
            }

            pConnection->ComponentName.Length += sizeof( WCHAR);
            pConnection->ComponentName.MaximumLength += sizeof( WCHAR);

            pConnection->ComponentName.Buffer--;
        }

        //
        // Go initialize the information about the connection
        //

        AFSInitializeConnectionInfo( pConnection,
                                     DisplayType);

        //
        // Store away the flags for the connection
        //

        pConnection->Flags = Flags;

        //
        // Insert the entry into our list. If this is a server
        // connection then add it to the enumeration list, otherwise
        // find the server name for this connection
        //

        if( DisplayType == RESOURCEDISPLAYTYPE_SERVER)
        {

            if( AFSProviderEnumerationList == NULL)
            {

                AFSProviderEnumerationList = pConnection;
            }
            else
            {

                //
                // Get the end of the list
                //

                pLastConnection = AFSProviderEnumerationList;

                while( pLastConnection->fLink != NULL)
                {

                    pLastConnection = pLastConnection->fLink;
                }

                pLastConnection->fLink = pConnection;
            }
        }
        else
        {

            ASSERT( pServerConnection != NULL);

            if( pServerConnection->EnumerationList == NULL)
            {

                pServerConnection->EnumerationList = pConnection;
            }
            else
            {

                //
                // Get the end of the list
                //

                pLastConnection = pServerConnection->EnumerationList;

                while( pLastConnection->fLink != NULL)
                {

                    pLastConnection = pLastConnection->fLink;
                }

                pLastConnection->fLink = pConnection;
            }
        }

try_exit:

        AFSReleaseResource( &AFSProviderListLock);
    }

    return ntStatus;
}

NTSTATUS
AFSCancelConnection( IN AFSNetworkProviderConnectionCB *ConnectCB,
                     IN OUT PULONG ResultStatus,
                     IN OUT ULONG_PTR *ReturnOutputBufferLength)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    AFSProviderConnectionCB *pConnection = NULL, *pLastConnection = NULL;
    UNICODE_STRING uniRemoteName;

    __Enter
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSCancelConnection Acquiring AFSProviderListLock lock %08lX EXCL %08lX\n",
                      &AFSProviderListLock,
                      PsGetCurrentThread());

        AFSAcquireExcl( &AFSProviderListLock,
                        TRUE);

        //
        // Look for the connection
        //

        uniRemoteName.Length = (USHORT)ConnectCB->RemoteNameLength;
        uniRemoteName.MaximumLength = uniRemoteName.Length;

        uniRemoteName.Buffer = NULL;

        if( uniRemoteName.Length > 0)
        {

            uniRemoteName.Buffer = ConnectCB->RemoteName;
        }

        pConnection = AFSProviderConnectionList;

        while( pConnection != NULL)
        {

            if( ( ConnectCB->LocalName != L'\0' &&
                  pConnection->LocalName == ConnectCB->LocalName) 
                            ||
                ( RtlCompareUnicodeString( &uniRemoteName,
                                           &pConnection->RemoteName,
                                           TRUE) == 0))
            {

                break;
            }

            pLastConnection = pConnection;

            pConnection = pConnection->fLink;
        }

        if( pConnection == NULL)
        {

            *ResultStatus = WN_NOT_CONNECTED;

            *ReturnOutputBufferLength = sizeof( ULONG);

            try_return( ntStatus);
        }

        if( pLastConnection == NULL)
        {

            AFSProviderConnectionList = pConnection->fLink;
        }
        else
        {

            pLastConnection->fLink = pConnection->fLink;
        }

        if( pConnection->Comment.Buffer != NULL)
        {

            ExFreePool( pConnection->Comment.Buffer);
        }

        ExFreePool( pConnection);

        *ResultStatus = WN_SUCCESS;

        *ReturnOutputBufferLength = sizeof( ULONG);

try_exit:

        AFSReleaseResource( &AFSProviderListLock);
    }

    return ntStatus;
}

NTSTATUS
AFSGetConnection( IN AFSNetworkProviderConnectionCB *ConnectCB,
                  IN OUT WCHAR *RemoteName,
                  IN ULONG RemoteNameBufferLength,
                  IN OUT ULONG_PTR *ReturnOutputBufferLength)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    AFSProviderConnectionCB *pConnection = NULL;

    __Enter
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSGetConnection Acquiring AFSProviderListLock lock %08lX SHARED %08lX\n",
                      &AFSProviderListLock,
                      PsGetCurrentThread());

        AFSAcquireShared( &AFSProviderListLock,
                          TRUE);

        //
        // Look for the connection
        //

        pConnection = AFSProviderConnectionList;

        while( pConnection != NULL)
        {

            if( pConnection->LocalName == ConnectCB->LocalName)
            {

                break;
            }

            pConnection = pConnection->fLink;
        }

        if( pConnection == NULL)
        {

            try_return( ntStatus = STATUS_INVALID_PARAMETER);
        }

        if( RemoteNameBufferLength < pConnection->RemoteName.Length)
        {

            try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
        }

        RtlCopyMemory( RemoteName,
                       pConnection->RemoteName.Buffer,
                       pConnection->RemoteName.Length);

        *ReturnOutputBufferLength = pConnection->RemoteName.Length;

try_exit:

        AFSReleaseResource( &AFSProviderListLock);
    }

    return ntStatus;
}

NTSTATUS
AFSListConnections( IN OUT AFSNetworkProviderConnectionCB *ConnectCB,
                    IN ULONG ConnectionBufferLength,
                    IN OUT ULONG_PTR *ReturnOutputBufferLength)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    AFSProviderConnectionCB *pConnection = NULL, *pRootConnection = NULL;
    ULONG ulCopiedLength = 0, ulRemainingLength = ConnectionBufferLength;
    ULONG ulScope, ulType;
    UNICODE_STRING uniRemoteName, uniServerName, uniShareName, uniRemainingPath;
    BOOLEAN bGlobalEnumeration = FALSE;
    ULONG       ulIndex = 0;

    __Enter
    {

        //
        // Save off some data before moving on
        //

        ulScope = ConnectCB->Scope;

        ulType = ConnectCB->Type;

        uniRemoteName.Length = 0;
        uniRemoteName.MaximumLength = 0;
        uniRemoteName.Buffer = NULL;

        uniServerName.Length = 0;
        uniServerName.MaximumLength = 0;
        uniServerName.Buffer = NULL;

        uniShareName.Length = 0;
        uniShareName.MaximumLength = 0;
        uniShareName.Buffer = NULL;

        if( ConnectCB->RemoteNameLength > 0)
        {

            uniRemoteName.Length = (USHORT)ConnectCB->RemoteNameLength;
            uniRemoteName.MaximumLength = uniRemoteName.Length + sizeof( WCHAR);

            uniRemoteName.Buffer = (WCHAR *)ExAllocatePoolWithTag( PagedPool,
                                                                   uniRemoteName.MaximumLength,
                                                                   AFS_GENERIC_MEMORY_TAG);

            if( uniRemoteName.Buffer == NULL)
            {

                try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
            }

            RtlCopyMemory( uniRemoteName.Buffer,
                           ConnectCB->RemoteName,
                           uniRemoteName.Length);

            if( uniRemoteName.Buffer[ 0] == L'\\' &&
                uniRemoteName.Buffer[ 1] == L'\\')
            {

                uniRemoteName.Buffer = &uniRemoteName.Buffer[ 1];

                uniRemoteName.Length -= sizeof( WCHAR);
            }

            if( uniRemoteName.Buffer[ (uniRemoteName.Length/sizeof( WCHAR)) - 1] == L'\\')
            {

                uniRemoteName.Length -= sizeof( WCHAR);
            }

            FsRtlDissectName( uniRemoteName,
                              &uniServerName,
                              &uniRemainingPath);

            uniRemoteName = uniRemainingPath;

            if( uniRemoteName.Length > 0)
            {

                FsRtlDissectName( uniRemoteName,
                                  &uniShareName,
                                  &uniRemainingPath);
            }

            //
            // If this is an enumeration of the global share name then
            // adjust it to be the server name itself
            //

            if( uniShareName.Length == 0 ||
                RtlCompareUnicodeString( &uniShareName,
                                         &AFSGlobalRootName,
                                         TRUE) == 0)
            {

                bGlobalEnumeration = TRUE;
            }
        }

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSListConnections Acquiring AFSProviderListLock lock %08lX SHARED %08lX\n",
                      &AFSProviderListLock,
                      PsGetCurrentThread());

        AFSAcquireShared( &AFSProviderListLock,
                          TRUE);

        //
        // If this is a globalnet enumeration with no name then enumerate the server list
        //

        if( ulScope == RESOURCE_GLOBALNET)
        {

            if( uniServerName.Buffer == NULL)
            {

                pConnection = AFSProviderEnumerationList;
            }
            else
            {

                //
                // Go locate the root entry for the name passed in
                //

                if( bGlobalEnumeration)
                {

                    if( AFSProviderEnumerationList == NULL)
                    {

                        AFSReleaseResource( &AFSProviderListLock);

                        try_return( ntStatus);
                    }

                    pConnection = AFSProviderEnumerationList->EnumerationList;
                }
                else
                {

                    ASSERT( FALSE);

                    pRootConnection = AFSLocateEnumRootEntry( &uniShareName);

                    if( pRootConnection == NULL)
                    {

                        AFSReleaseResource( &AFSProviderListLock);

                        try_return( ntStatus);
                    }

                    //
                    // Need to handle these enumeraitons from the directory listing
                    //

                    ntStatus = AFSEnumerateConnection( ConnectCB,
                                                       pRootConnection,
                                                       ConnectionBufferLength,
                                                       &ulCopiedLength);
                }
            }
        }
        else
        {

            pConnection = AFSProviderConnectionList;
        }

        ulIndex = ConnectCB->CurrentIndex;

        while( pConnection != NULL)
        {

            if( bGlobalEnumeration &&
                BooleanFlagOn( pConnection->Flags, AFS_CONNECTION_FLAG_GLOBAL_SHARE))
            {

                pConnection = pConnection->fLink;

                continue;
            }

            if( ulScope != RESOURCE_GLOBALNET &&
                !BooleanFlagOn( pConnection->Usage, RESOURCEUSAGE_ATTACHED))
            {

                pConnection = pConnection->fLink;

                continue;
            }

            if( ulIndex > 0)
            {

                ulIndex--;

                pConnection = pConnection->fLink;

                continue;
            }

            if( ulRemainingLength < (ULONG)FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                         pConnection->RemoteName.Length +
                                                         pConnection->Comment.Length)
            {

                break;
            }

            ConnectCB->RemoteNameLength = pConnection->RemoteName.Length;

            RtlCopyMemory( ConnectCB->RemoteName,
                           pConnection->RemoteName.Buffer,
                           pConnection->RemoteName.Length);

            ConnectCB->LocalName = pConnection->LocalName;

            ConnectCB->Type = pConnection->Type;

            ConnectCB->Scope = pConnection->Scope;

            ConnectCB->DisplayType = pConnection->DisplayType;

            ConnectCB->Usage = pConnection->Usage;
            
            ConnectCB->CommentLength = pConnection->Comment.Length;

            if( pConnection->Comment.Length > 0)
            {

                ConnectCB->CommentOffset = (ULONG)(FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                                        ConnectCB->RemoteNameLength);

                RtlCopyMemory( (void *)((char *)ConnectCB + ConnectCB->CommentOffset),
                               pConnection->Comment.Buffer,
                               ConnectCB->CommentLength);
            }

            ulCopiedLength += FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                    ConnectCB->RemoteNameLength +
                                                    ConnectCB->CommentLength;

            ulRemainingLength -= FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                    ConnectCB->RemoteNameLength +
                                                    ConnectCB->CommentLength;

            ConnectCB = (AFSNetworkProviderConnectionCB *)((char *)ConnectCB + 
                                                            FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                            ConnectCB->RemoteNameLength +
                                                            ConnectCB->CommentLength);

            pConnection = pConnection->fLink;
        }

        if( NT_SUCCESS( ntStatus))
        {

            *ReturnOutputBufferLength = ulCopiedLength;
        }

        AFSReleaseResource( &AFSProviderListLock);

try_exit:

        if( uniRemoteName.Buffer != NULL)
        {

            ExFreePool( uniRemoteName.Buffer);
        }
    }

    return ntStatus;
}

void
AFSInitializeConnectionInfo( IN AFSProviderConnectionCB *Connection,
                             IN ULONG DisplayType)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    UNICODE_STRING uniName, uniComponentName, uniRemainingName;

    __Enter
    {

        uniName = Connection->RemoteName;

        //
        // Strip of the double leading slash if there is one
        //

        if( uniName.Buffer[ 0] == L'\\' &&
            uniName.Buffer[ 1] == L'\\')
        {

            uniName.Buffer = &uniName.Buffer[ 1];

            uniName.Length -= sizeof( WCHAR);
        }


        FsRtlDissectName( uniName,
                          &uniComponentName,
                          &uniRemainingName);

        //
        // Initialize the information for the connection
        // First, if this is the server only then mark it accordingly
        //

        if( uniRemainingName.Length == 0 ||
            DisplayType == RESOURCEDISPLAYTYPE_SERVER)
        {

            Connection->Type = RESOURCETYPE_DISK;

            Connection->Scope = RESOURCE_GLOBALNET;

            Connection->DisplayType = RESOURCEDISPLAYTYPE_SERVER;

            Connection->Usage = RESOURCEUSAGE_CONTAINER;

            Connection->Comment.Length = 20;
            Connection->Comment.MaximumLength = 22;

            Connection->Comment.Buffer = (WCHAR *)ExAllocatePoolWithTag( PagedPool,
                                                                         Connection->Comment.MaximumLength,
                                                                         AFS_GENERIC_MEMORY_TAG);

            if( Connection->Comment.Buffer != NULL)
            {

                RtlZeroMemory( Connection->Comment.Buffer,
                               Connection->Comment.MaximumLength);

                RtlCopyMemory( Connection->Comment.Buffer,
                               L"AFS Root",
                               16);
            }
            else
            {

                Connection->Comment.Length = 0;
                Connection->Comment.MaximumLength = 0;
            }

            try_return( ntStatus);
        }

        uniName = uniRemainingName;

        FsRtlDissectName( uniName,
                          &uniComponentName,
                          &uniRemainingName);

        if( uniRemainingName.Length == 0 ||
            uniRemainingName.Buffer == NULL ||
            DisplayType == RESOURCEDISPLAYTYPE_SHARE)
        {

            Connection->Type = RESOURCETYPE_DISK;

            Connection->Scope = RESOURCE_GLOBALNET;

            Connection->DisplayType = RESOURCEDISPLAYTYPE_SHARE;

            Connection->Usage = RESOURCEUSAGE_CONNECTABLE;

            if( Connection->LocalName != L'\0')
            {

                Connection->Usage |= RESOURCEUSAGE_ATTACHED;
            }

            Connection->Comment.Length = 18;
            Connection->Comment.MaximumLength = 20;

            Connection->Comment.Buffer = (WCHAR *)ExAllocatePoolWithTag( PagedPool,
                                                                         Connection->Comment.MaximumLength,
                                                                         AFS_GENERIC_MEMORY_TAG);

            if( Connection->Comment.Buffer != NULL)
            {

                RtlZeroMemory( Connection->Comment.Buffer,
                               Connection->Comment.MaximumLength);

                RtlCopyMemory( Connection->Comment.Buffer,
                               L"AFS Share",
                               18);
            }
            else
            {

                Connection->Comment.Length = 0;
                Connection->Comment.MaximumLength = 0;
            }

            try_return( ntStatus);
        }

        //
        // This is a sub directory within a share
        //

        Connection->Type = RESOURCETYPE_DISK;

        Connection->Scope = RESOURCE_CONTEXT;

        Connection->DisplayType = RESOURCEDISPLAYTYPE_DIRECTORY;

        Connection->Usage = RESOURCEUSAGE_CONNECTABLE;

        if( Connection->LocalName != L'\0')
        {

            Connection->Usage |= RESOURCEUSAGE_ATTACHED;
        }

        Connection->Comment.Length = 26;
        Connection->Comment.MaximumLength = 28;

        Connection->Comment.Buffer = (WCHAR *)ExAllocatePoolWithTag( PagedPool,
                                                                     Connection->Comment.MaximumLength,
                                                                     AFS_GENERIC_MEMORY_TAG);

        if( Connection->Comment.Buffer != NULL)
        {

            RtlZeroMemory( Connection->Comment.Buffer,
                           Connection->Comment.MaximumLength);

            RtlCopyMemory( Connection->Comment.Buffer,
                           L"AFS Directory",
                           26);
        }
        else
        {

            Connection->Comment.Length = 0;
            Connection->Comment.MaximumLength = 0;
        }

try_exit:

        NOTHING;
    }

    return;
}

AFSProviderConnectionCB *
AFSLocateEnumRootEntry( IN UNICODE_STRING *RemoteName)
{

    AFSProviderConnectionCB *pConnection = NULL;
    UNICODE_STRING uniServerName, uniRemoteName = *RemoteName;

    __Enter
    {

        if( AFSProviderEnumerationList == NULL)
        {

            try_return( pConnection);
        }

        pConnection = AFSProviderEnumerationList->EnumerationList;

        while( pConnection != NULL)
        {

            if( RtlCompareUnicodeString( &uniRemoteName,
                                         &pConnection->ComponentName,
                                         TRUE) == 0)
            {

                break;
            }

            pConnection = pConnection->fLink;
        }

try_exit:

        NOTHING;
    }

    return pConnection;
}

NTSTATUS
AFSEnumerateConnection( IN OUT AFSNetworkProviderConnectionCB *ConnectCB,
                        IN AFSProviderConnectionCB *RootConnection,
                        IN ULONG BufferLength,
                        OUT PULONG CopiedLength)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    AFSDeviceExt *pDeviceExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;
    ULONG ulCRC = 0, ulCopiedLength = 0;
    AFSDirEntryCB *pShareDirEntry = NULL;
    AFSFcb *pRootFcb = NULL, *pCurrentFcb = NULL;
    AFSDirEntryCB *pDirEntry = NULL;
    ULONG ulIndex = 0;
    BOOLEAN bContinueProcessing = TRUE;
    AFSFileInfoCB stFileInformation;

    __Enter
    {

        ulCRC = AFSGenerateCRC( &RootConnection->ComponentName,
                                FALSE);

        //
        // Grab our tree lock shared
        //

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSEnumerateConnection Acquiring GlobalRoot DirectoryNodeHdr.TreeLock lock %08lX EXCL %08lX\n",
                      AFSGlobalRoot->Specific.Directory.DirectoryNodeHdr.TreeLock,
                      PsGetCurrentThread());

        AFSAcquireExcl( AFSGlobalRoot->Specific.Directory.DirectoryNodeHdr.TreeLock,
                        TRUE);

        //
        // Locate the dir entry for this node
        //

        ntStatus = AFSLocateCaseSensitiveDirEntry( AFSGlobalRoot->Specific.Directory.DirectoryNodeHdr.CaseSensitiveTreeHead,
                                                   ulCRC,
                                                   &pShareDirEntry);

        if( pShareDirEntry == NULL ||
            !NT_SUCCESS( ntStatus))
        {

            //
            // Perform a case insensitive search
            //

            ulCRC = AFSGenerateCRC( &RootConnection->ComponentName,
                                    TRUE);

            ntStatus = AFSLocateCaseInsensitiveDirEntry( AFSGlobalRoot->Specific.Directory.DirectoryNodeHdr.CaseInsensitiveTreeHead,
                                                         ulCRC,
                                                         &pShareDirEntry);

            if( pShareDirEntry == NULL ||
                !NT_SUCCESS( ntStatus))
            {

                AFSReleaseResource( AFSGlobalRoot->Specific.Directory.DirectoryNodeHdr.TreeLock);

                try_return( ntStatus);
            }
        }

        //
        // Grab the dir node exclusive while we determine the state
        //

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSEnumerateConnection Acquiring ShareEntry DirNode lock %08lX EXCL %08lX\n",
                      &pShareDirEntry->NPDirNode->Lock,
                      PsGetCurrentThread());

        AFSAcquireExcl( &pShareDirEntry->NPDirNode->Lock,
                        TRUE);

        AFSReleaseResource( AFSGlobalRoot->Specific.Directory.DirectoryNodeHdr.TreeLock);

        //
        // If the root node for this entry is NULL, then we need to initialize 
        // the volume node information
        //

        if( pShareDirEntry->Fcb == NULL)
        {

            ntStatus = AFSInitFcb( AFSGlobalRoot,
                                   pShareDirEntry,
                                   NULL);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSReleaseResource( &pShareDirEntry->NPDirNode->Lock);

                try_return( ntStatus);
            }
        }
        else
        {

            //
            // Grab the root node exclusive before returning
            //

            AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSEnumerateConnection Acquiring ShareEntry Fcb lock %08lX EXCL %08lX\n",
                          &pShareDirEntry->Fcb->NPFcb->Resource,
                          PsGetCurrentThread());

            AFSAcquireExcl( &pShareDirEntry->Fcb->NPFcb->Resource,
                            TRUE);
        }

        //
        // Drop the volume lock
        //

        AFSReleaseResource( &pShareDirEntry->NPDirNode->Lock);

        //
        // Go until we get to the directory or root
        //

        pCurrentFcb = pShareDirEntry->Fcb;

        while( bContinueProcessing)
        {
           
            //
            // Ensure the root node has been evaluated, if not then go do it now
            //

            if( BooleanFlagOn( pCurrentFcb->DirEntry->Flags, AFS_DIR_ENTRY_NOT_EVALUATED))
            {

                ntStatus = AFSEvaluateNode( (ULONGLONG)PsGetCurrentProcessId(),
                                            pCurrentFcb);

                if( !NT_SUCCESS( ntStatus))
                {

                    AFSReleaseResource( &pCurrentFcb->NPFcb->Resource);

                    try_return( ntStatus);
                }

                ClearFlag( pCurrentFcb->DirEntry->Flags, AFS_DIR_ENTRY_NOT_EVALUATED);
            }

            switch( pCurrentFcb->DirEntry->DirectoryEntry.FileType)
            {

                case AFS_FILE_TYPE_SYMLINK:
                {

                    //
                    // Build the symlink target
                    //

                    ntStatus = AFSBuildSymLinkTarget( (ULONGLONG)PsGetCurrentProcessId(),
                                                      pCurrentFcb,
                                                      NULL,
                                                      NULL,
                                                      0,
                                                      NULL,
                                                      &pRootFcb);

                    if( !NT_SUCCESS( ntStatus) ||
                        ntStatus == STATUS_REPARSE)
                    {

                        try_return( ntStatus = STATUS_INVALID_PARAMETER);
                    }

                    pCurrentFcb = pRootFcb;

                    pRootFcb = NULL;

                    continue;
                }

                case AFS_FILE_TYPE_MOUNTPOINT:
                {

                    //
                    // Check if we have a target Fcb for this node
                    //

                    if( pCurrentFcb->Specific.MountPoint.VolumeTargetFcb == NULL)
                    {

                        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                                      AFS_TRACE_LEVEL_VERBOSE,
                                      "AFSEnumerateConnection Acquiring RDR VolumeTree.TreeLock lock %08lX SHARED %08lX\n",
                                      pDeviceExt->Specific.RDR.VolumeTree.TreeLock,
                                      PsGetCurrentThread());

                        AFSAcquireShared( pDeviceExt->Specific.RDR.VolumeTree.TreeLock,
                                          TRUE);

                        AFSLocateHashEntry( pDeviceExt->Specific.RDR.VolumeTree.TreeHead,
                                            AFSCreateHighIndex( &pCurrentFcb->DirEntry->DirectoryEntry.TargetFileId),
                                            &pCurrentFcb->Specific.MountPoint.VolumeTargetFcb);

                        AFSReleaseResource( pDeviceExt->Specific.RDR.VolumeTree.TreeLock);
                    }

                    if( pCurrentFcb->Specific.MountPoint.VolumeTargetFcb == NULL)
                    {

                        AFSReleaseResource( &pCurrentFcb->NPFcb->Resource);

                        try_return( ntStatus = STATUS_ACCESS_DENIED);
                    }

                    //
                    // Swap out where we are in the chain
                    //

                    AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSEnumerateConnection Acquiring ShareEntry LinkTarget Fcb lock %08lX EXCL %08lX\n",
                                  &pCurrentFcb->Specific.MountPoint.VolumeTargetFcb->NPFcb->Resource,
                                  PsGetCurrentThread());

                    AFSAcquireExcl( &pCurrentFcb->Specific.MountPoint.VolumeTargetFcb->NPFcb->Resource,
                                    TRUE);

                    AFSReleaseResource( &pCurrentFcb->NPFcb->Resource);

                    pCurrentFcb = pShareDirEntry->Fcb->Specific.MountPoint.VolumeTargetFcb;

                    continue;
                }

                default:
                {

                    pRootFcb = pCurrentFcb;

                    //
                    // We're done ...
                    //

                    bContinueProcessing = FALSE;

                    break;
                }
            }
        } // End of while()

        //
        // If the entry is not initialized then do it now
        //

        if( ( pRootFcb->Header.NodeTypeCode == AFS_DIRECTORY_FCB ||
              pRootFcb->Header.NodeTypeCode == AFS_ROOT_FCB) &&
            !BooleanFlagOn( pRootFcb->Flags, AFS_FCB_DIRECTORY_ENUMERATED))
        {

            ntStatus = AFSEnumerateDirectory( (ULONGLONG)PsGetCurrentProcessId(),
                                              pRootFcb,
                                              &pRootFcb->Specific.Directory.DirectoryNodeHdr,
                                              &pRootFcb->Specific.Directory.DirectoryNodeListHead,
                                              &pRootFcb->Specific.Directory.DirectoryNodeListTail,
                                              &pRootFcb->Specific.Directory.ShortNameTree,
                                              TRUE);

            if( !NT_SUCCESS( ntStatus))
            {

                AFSReleaseResource( &pRootFcb->NPFcb->Resource);

                try_return( ntStatus);
            }

            SetFlag( pRootFcb->Flags, AFS_FCB_DIRECTORY_ENUMERATED);
        }

        //
        // Enumerate the content
        //

        pDirEntry = pRootFcb->Specific.Directory.DirectoryNodeListHead;

        ulIndex = ConnectCB->CurrentIndex;

        while( pDirEntry != NULL)
        {

            if( ulIndex > 0)
            {

                ulIndex--;

                pDirEntry = (AFSDirEntryCB *)pDirEntry->ListEntry.fLink;

                continue;
            }

            if( BufferLength < (ULONG)FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                               pDirEntry->DirectoryEntry.FileName.Length)
            {

                break;
            }

            ConnectCB->LocalName = L'\0';

            ConnectCB->RemoteNameLength = pDirEntry->DirectoryEntry.FileName.Length;

            RtlCopyMemory( ConnectCB->RemoteName,
                           pDirEntry->DirectoryEntry.FileName.Buffer,
                           pDirEntry->DirectoryEntry.FileName.Length);

            ConnectCB->Type = 0;

            ConnectCB->Scope = 0;

            RtlZeroMemory( &stFileInformation,
                           sizeof( AFSFileInfoCB));

            AFSGetFileInformation( pRootFcb,
                                   NULL,
                                   pDirEntry, 
                                   &stFileInformation);

            if( BooleanFlagOn( stFileInformation.FileAttributes, FILE_ATTRIBUTE_DIRECTORY))
            {

                ConnectCB->DisplayType = RESOURCEDISPLAYTYPE_DIRECTORY;
            }
            else
            {

                ConnectCB->DisplayType = RESOURCEDISPLAYTYPE_FILE;
            }

            ConnectCB->Usage = 0;
            
            ConnectCB->CommentLength = 0;

            ulCopiedLength += FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                    pDirEntry->DirectoryEntry.FileName.Length;

            BufferLength -= FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                    pDirEntry->DirectoryEntry.FileName.Length;

            ConnectCB = (AFSNetworkProviderConnectionCB *)((char *)ConnectCB + 
                                                            FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                            ConnectCB->RemoteNameLength);

            pDirEntry = (AFSDirEntryCB *)pDirEntry->ListEntry.fLink;
        }

        *CopiedLength = ulCopiedLength;

        AFSReleaseResource( &pRootFcb->NPFcb->Resource);

try_exit:

        NOTHING;
    }

    return ntStatus;
}

NTSTATUS
AFSGetConnectionInfo( IN AFSNetworkProviderConnectionCB *ConnectCB,
                      IN ULONG BufferLength,
                      IN OUT ULONG_PTR *ReturnOutputBufferLength)
{

    NTSTATUS ntStatus = STATUS_SUCCESS;
    AFSProviderConnectionCB *pConnection = NULL, *pBestMatch = NULL;
    UNICODE_STRING uniRemoteName, uniServerName, uniShareName, uniRemainingPath;

    __Enter
    {

        uniServerName.Length = 0;
        uniServerName.MaximumLength = 0;
        uniServerName.Buffer = NULL;

        uniShareName.Length = 0;
        uniShareName.MaximumLength = 0;
        uniShareName.Buffer = NULL;

        uniRemoteName.Length = (USHORT)ConnectCB->RemoteNameLength;
        uniRemoteName.MaximumLength = uniRemoteName.Length + sizeof( WCHAR);
        uniRemoteName.Buffer = (WCHAR *)ConnectCB->RemoteName;

        if( uniRemoteName.Buffer[ 0] == L'\\' &&
            uniRemoteName.Buffer[ 1] == L'\\')
        {

            uniRemoteName.Buffer = &uniRemoteName.Buffer[ 1];

            uniRemoteName.Length -= sizeof( WCHAR);
        }

        if( uniRemoteName.Buffer[ (uniRemoteName.Length/sizeof( WCHAR)) - 1] == L'\\')
        {

            uniRemoteName.Length -= sizeof( WCHAR);
        }

        FsRtlDissectName( uniRemoteName,
                          &uniServerName,
                          &uniRemainingPath);

        uniRemoteName = uniRemainingPath;

        if( uniRemoteName.Length > 0)
        {

            FsRtlDissectName( uniRemoteName,
                              &uniShareName,
                              &uniRemainingPath);
        }

        if( RtlCompareUnicodeString( &uniServerName,
                                     &AFSServerName,
                                     TRUE) != 0)
        {

            try_return( ntStatus = STATUS_INVALID_PARAMETER);
        }

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSGetConnectionInfo Acquiring AFSProviderListLock lock %08lX SHARED %08lX\n",
                      &AFSProviderListLock,
                      PsGetCurrentThread());

        AFSAcquireShared( &AFSProviderListLock,
                          TRUE);

        //
        // If this is the server then return information about the 
        // server entry
        //

        if( uniShareName.Length == 0 &&
            RtlCompareUnicodeString( &uniServerName,
                                     &AFSServerName,
                                     TRUE) == 0)
        {

            pConnection = AFSProviderEnumerationList;
        }
        else
        {

            //
            // Locate the entry for the share
            //

            pConnection = AFSLocateEnumRootEntry( &uniShareName);
        }


        if( pConnection == NULL)
        {
            UNICODE_STRING uniFullName;
            AFSFileID stFileID;
            AFSDirEnumEntry *pDirEnumEntry = NULL;

            //
            // Drop the lock, we will pick it up again later
            //
            
            AFSReleaseResource( &AFSProviderListLock);

            //
            // Perform a case insensitive search
            //

            RtlZeroMemory( &stFileID,
                           sizeof( AFSFileID));

            //
            // OK, ask the CM about this component name
            //

            ntStatus = AFSEvaluateTargetByName( (ULONGLONG)PsGetCurrentProcessId(),
                                                &stFileID,
                                                &uniShareName,
                                                &pDirEnumEntry);

            if( !NT_SUCCESS( ntStatus))
            {

                try_return( ntStatus = STATUS_INVALID_PARAMETER);

            }

            // 
            // Don't need this
            //

            ExFreePool( pDirEnumEntry);

            //
            // The share name is valid
            // Allocate a new node and add it to our list
            //
            uniFullName.MaximumLength = PAGE_SIZE;
            uniFullName.Length = 0;

            uniFullName.Buffer = (WCHAR *)ExAllocatePoolWithTag( PagedPool,
                                                                 uniFullName.MaximumLength,
                                                                 AFS_GENERIC_MEMORY_TAG);

            if( uniFullName.Buffer == NULL)
            {

                try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES);
            }

            uniFullName.Buffer[ 0] = L'\\';
            uniFullName.Buffer[ 1] = L'\\';

            uniFullName.Length = 2 * sizeof( WCHAR);

            RtlCopyMemory( &uniFullName.Buffer[ 2],
                           AFSServerName.Buffer,
                           AFSServerName.Length);
                                               
            uniFullName.Length += AFSServerName.Length;

            uniFullName.Buffer[ uniFullName.Length/sizeof( WCHAR)] = L'\\';

            uniFullName.Length += sizeof( WCHAR);

            RtlCopyMemory( &uniFullName.Buffer[ uniFullName.Length/sizeof( WCHAR)],
                           uniShareName.Buffer,
                           uniShareName.Length);

            uniFullName.Length += uniShareName.Length;

            AFSAcquireExcl( AFSGlobalRoot->Specific.Directory.DirectoryNodeHdr.TreeLock,
                            TRUE);

            ntStatus = AFSAddConnectionEx( &uniFullName,
                                           RESOURCEDISPLAYTYPE_SHARE,
                                           0);

            AFSReleaseResource( AFSGlobalRoot->Specific.Directory.DirectoryNodeHdr.TreeLock);

            ExFreePool( uniFullName.Buffer);

            AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSGetConnectionInfo Acquiring AFSProviderListLock lock %08lX SHARED %08lX\n",
                          &AFSProviderListLock,
                          PsGetCurrentThread());

            AFSAcquireShared( &AFSProviderListLock,
                              TRUE);

            if ( NT_SUCCESS( ntStatus) ) 
            {
                //
                // Once again, locate the entry for the share we just created
                //

                pConnection = AFSLocateEnumRootEntry( &uniShareName);
            }

        }

        if( pConnection == NULL)
        {

            AFSReleaseResource( &AFSProviderListLock);

            try_return( ntStatus = STATUS_INVALID_PARAMETER);
        }

        //
        // Fill in the returned connection info block
        //

        if( BufferLength < (ULONG)FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                               pConnection->RemoteName.Length +
                                                               pConnection->Comment.Length)
        {

            AFSReleaseResource( &AFSProviderListLock);

            try_return( ntStatus = STATUS_BUFFER_OVERFLOW);
        }

        ConnectCB->RemoteNameLength = pConnection->RemoteName.Length;

        RtlCopyMemory( ConnectCB->RemoteName,
                       pConnection->RemoteName.Buffer,
                       pConnection->RemoteName.Length);

        ConnectCB->LocalName = pConnection->LocalName;

        ConnectCB->Type = pConnection->Type;

        ConnectCB->Scope = pConnection->Scope;

        ConnectCB->DisplayType = pConnection->DisplayType;

        ConnectCB->Usage = pConnection->Usage;
            
        ConnectCB->CommentLength = pConnection->Comment.Length;

        if( pConnection->Comment.Length > 0)
        {

            ConnectCB->CommentOffset = (ULONG)(FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                                        ConnectCB->RemoteNameLength);

            RtlCopyMemory( (void *)((char *)ConnectCB + ConnectCB->CommentOffset),
                           pConnection->Comment.Buffer,
                           ConnectCB->CommentLength);
        }

        *ReturnOutputBufferLength = FIELD_OFFSET( AFSNetworkProviderConnectionCB, RemoteName) +
                                                    ConnectCB->RemoteNameLength +
                                                    ConnectCB->CommentLength;

        AFSReleaseResource( &AFSProviderListLock);

try_exit:

        NOTHING;
    }

    return ntStatus;
}