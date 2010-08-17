#include <afsconfig.h>
#include "afs/param.h"


#include "afs/sysincludes.h"	/* Standard vendor system headers */
#include "afsincludes.h"	/* Afs-based standard headers */
#include "afs/afs_stats.h"	/* statistics */
#include "afs/afs_cbqueue.h"
#include "afs/nfsclient.h"
#include "afs/afs_osidnlc.h"
#include "afs/afs_osi.h"

#include <asm/div64.h>



/* Used for division, modulus in kernel mode, a%b when b!=2^k */
unsigned long int do_mod64(long long int x, long long int y){
	/* Does not modify either x or y unlike the asm counter part */
	
	long long int x1=x, y1=y;
	
	return do_div(x1, y1);
}

/* Prints the uio structure info */
void afs_print_uioinfo(struct uio *uiop){
	int i;
	printk("offset: %d iovcnt: %d, uio_resid: %d\n", uiop->uio_offset, uiop->uio_iovcnt, uiop->uio_resid);
	for(i=0;i<uiop->uio_iovcnt;i++)
		printk("iov_len: %d, ",uiop->uio_iov[i].iov_len);
}


/* Implementation of the ROT-13 cipher */ 
void
afs_decrypt_extent(char *extent_vec, int extent_len){
	
	/* Decrypt an extent *in place* */
	
	afs_int32 i;
	
	for(i=0;i<extent_len;i++)
	{
		if(extent_vec[i]>='A' && extent_vec[i]<='Z')
			/* Caps is here */
			extent_vec[i]=((extent_vec[i]-'A')+13)%26 + 'A';
		else if(extent_vec[i]>='a' && extent_vec[i]<='z')
			/* smalls is here */
			extent_vec[i]=((extent_vec[i]-'a')+13)%26+'a';
		else
			{/* leave the PT=CT */}
 	}
 	
}



void
afs_write_extent(struct uio *uiop, char *iov_base, int base, char *extent_vec, int extent_len)
{
	/* Writes the data back to the uiop, which is now decrypted */
	
	afs_int32 i;
	
	for(i=0;i<extent_len;i++)
		iov_base[base+i] = extent_vec[i];
}


/* Assuming that the chunk is always a multiple of AFS_ENC_EXTENT, decrypts the chunk.
 * see afs.h for afs_enc_chunk definition
 */
void afs_decrypt(struct afs_enc_chunk *chunk){

	/* We know that the chunk contanins N times AFS_ENC_EXTENT
	 * and we decrypt it inplace */
	 
	afs_int32 left=chunk->len;
	char *extent=chunk->base;
	
	while(1){
		/* if else not required if we consider chunk->len = k*AFS+_ENC_EXTENT.
		 * but let's be safe.
		 */
		if(left>AFS_ENC_EXTENT){
			afs_decrypt_extent(extent, AFS_ENC_EXTENT);
			extent+=AFS_ENC_EXTENT;
			left-=AFS_ENC_EXTENT;
		}
		
		else{
			afs_decrypt_extent(extent, left);
			break;
		}
	}
}

/* Encrypts the chunk */
void afs_encrypt(struct afs_enc_chunk *chunk){
	
	/* For now simply call the decrypt functionality, as ROT13(ROT13(X)) = X */
	
	afs_decrypt(chunk);

}

/* Suppose that AFS_ENC_EXTENT is 1000 and a read/write request for 10 - 90 is recieved,
 * we will need to extend the extent from 0-1000, so start extent will mean 0 - 9.
 * end extent will be 91 - 1000, and the main extent is 10 - 90
 */

/* Obtains the starting compeletion extent */

struct uio *
afs_get_start_extent(struct uio *basis, int rdwr){
	/* We extend the basis struct to the left.
	 * invarient, we would never need to extend beyond 0 */
	 
	 struct uio *start_uio = (struct uio *)osi_Alloc(sizeof(struct uio));
	 struct iovec *start_iovec = (struct iovec *)osi_Alloc(sizeof(struct iovec));
	 unsigned long int mod;
	 
	 afsio_copy(basis, start_uio, start_iovec);
	
 	 mod = do_mod64(start_uio->uio_offset, AFS_ENC_EXTENT);
	 start_uio->uio_offset -= mod; 
	 if(rdwr==AFS_ENC_READ)
		 start_uio->uio_iov[0].iov_len = mod;
	 else if(rdwr==AFS_ENC_WRITE)
	 	 start_uio->uio_iov[0].iov_len = AFS_ENC_EXTENT;
	 start_uio->uio_iov[0].iov_base = (void *)osi_Alloc(start_uio->uio_iov[0].iov_len);
	 return start_uio;
}

/* Obtains the ending completion extent */

struct uio *
afs_get_end_extent(struct uio *basis, afs_int32 len, int rdrw){
	/* We extend the basis struct to the right.
	 * invarient, we would never need to extend beyond avc->f.m.Length */
	 unsigned long int mod;
	 struct uio *end_uio = (struct uio *)osi_Alloc(sizeof(struct uio));
	 struct iovec *end_iovec = (struct iovec *)osi_Alloc(sizeof(struct iovec));
	 
	 afsio_copy(basis, end_uio, end_iovec);
	 
 	 mod = do_mod64(end_uio->uio_offset+len, AFS_ENC_EXTENT);
 	 
 	 if(rdrw==AFS_ENC_READ){
	 	 end_uio->uio_offset = end_uio->uio_offset + len;
		 end_uio->uio_iov[0].iov_len = AFS_ENC_EXTENT - mod;
	 }
	 else if(rdrw==AFS_ENC_WRITE){
	 	end_uio->uio_offset = end_uio->uio_offset + len - mod;
	 	end_uio->uio_iov[0].iov_len = AFS_ENC_EXTENT;
	 }
	 end_uio->uio_iov[0].iov_base = (void *)osi_Alloc(end_uio->uio_iov[0].iov_len);
	 return end_uio;
}

/* Utility function to see what contents a chunk hold,
 * useful when debugging
 */

void afs_print_chunk(struct afs_enc_chunk *chunk){
	
	afs_int32 i;
	printk("Size: %d\nStart: %d\nEnd: %d\n", chunk->len, chunk->uio_start, chunk->uio_len);
	for(i=0;i<chunk->len;i++)
		printk("%c", chunk->base[i]);
}

/* Flow of encryption(write):
 * Read the request
 * Find completion extents
 * Construct a chunk
 * Encrypt
 * Write back to the initial request structure. <-- enc_chunk_wb writes back encrypted/decrypted
 * data to the initial request structure.
 * Parameters:
 * chunk: decrypted/encrypted(read/write) chunk
 * data: the request structure to be written to
 * basis: the basis to obtain base pointers to iovec structures
 */


void afs_enc_chunk_wb(struct afs_enc_chunk *chunk, struct uio *data, struct uio *basis){
	afs_int32 i, iov_no=0, space, chunk_len = chunk->uio_len, ind=0;
	char *d;
	/* Considering WRITE requests */
	if(basis==NULL) basis = data;
	while(chunk_len){
		/* Transfer the chunk back to the tuiop structure */
		
		space = basis->uio_iov[iov_no].iov_len;
		d = (char *)basis->uio_iov[iov_no].iov_base;
		i=0;
		while(i<space && chunk_len){
			d[i] = chunk->base[chunk->uio_start+ind];
			i++;
			ind++;
			chunk_len--;
		}
		d[i] = -1;
		iov_no++;
	}
}
		
/* Appends data stored in uio to a chunk */

void afs_chunk_append(struct afs_enc_chunk *ch, struct uio *data, struct uio *basis){
	
	/* Appends the data to the chunk */
	char *temp;
	int i, len;
	len = basis?basis->uio_iov[0].iov_len:data->uio_iov[0].iov_len;
	if(basis!=NULL)	temp = (char *)basis->uio_iov[0].iov_base;
	else temp = (char *)data->uio_iov[0].iov_base;
	
	for(i=0;i<len;i++)
		ch->base[i+ch->trans] = temp[i];
	ch->trans += basis->uio_iov[0].iov_len;
			
		
}

/* Appends data stored in a chunk to another chunk */

void afs_chunk_append1(struct afs_enc_chunk *ch, struct afs_enc_chunk *data){
	
	/* Appends data chunk to original chunk */
	
	int i;
	ch->len += data->uio_len;
	ch->uio_len += data->uio_len;
	for(i=0;i<data->uio_len;i++)
		ch->base[ch->trans+i] = data->base[data->uio_start+i];
}

/* Constructs a chunk( allocates space for data, fixes length etc ) on the basis of start, main and end
 * entents during read/write
 * Parameters:
 * s1: Start extent
 * t1: Mid extent
 * e1: End extent
 */

struct afs_enc_chunk *afs_prepare_chunk(struct uio *s, struct uio *t, struct uio *e){
	
	/* Sets the various checkpoints for the chunk which is to be read */
	
	int len = (s?s->uio_iov[0].iov_len:0) + (t?t->uio_iov[0].iov_len:0) + (e?e->uio_iov[0].iov_len:0);
	
	struct afs_enc_chunk *chunk = (struct afs_enc_chunk *)osi_Alloc(sizeof(struct afs_enc_chunk));
	
	chunk->uio_start = s?s->uio_iov[0].iov_len:0;
	chunk->uio_len = t?t->uio_iov[0].iov_len:0;
	chunk->len = len;
	chunk->base = (char *)osi_Alloc(len * sizeof(char));
	
	return chunk;
}


/* Trims a chunk to specified start and end point */

void afs_trim_chunk(struct afs_enc_chunk *chunk, int start, int end){
	
	/* Trims the chunk to start and end */
	
	if(start!=-1){
		/* Perhaps trimming the last segment */
		
		chunk->uio_start = start;
		chunk->uio_len -= start;
	}
	
	if(end!=-1){
		/* Perhaps trimming the starting segment */
		chunk->uio_len = end;
	}
	
}	


/* Prepares an equivalent chunk from a uio strucure */
struct afs_enc_chunk *afs_enc_tochunk(struct uio *uiop){
	
	/* Returns a chunk equivalent to the uiop structure */
	struct afs_enc_chunk *ch = (struct afs_enc_chunk *)osi_Alloc(sizeof(struct afs_enc_chunk));
	int len = uiop->uio_iov[0].iov_len, i;
	char *temp;

	ch->base = (char *)osi_Alloc(len * sizeof(char));
	ch->len = len;
	ch->uio_start = 0;
	ch->uio_len = len;
	temp = (char *)uiop->uio_iov[0].iov_base;
	for(i=0;i<len;i++){	
		ch->base[i] = temp[i];
	}

	return ch;
}

/* Merges 3 chunks together, general use case, merge Start, mid and end completion parts */

struct afs_enc_chunk *afs_merge_chunk3(struct afs_enc_chunk *c1, struct afs_enc_chunk *c2, struct afs_enc_chunk *c3){
	
	/* Merges the three chunks based on the uio_start and uio_len, and *assume* that c2 is the actual request */
	
		struct afs_enc_chunk *ch;
	int totalLength = (c1?c1->uio_len:0) + (c2?c2->uio_len:0) + (c3?c3->uio_len:0), i, trans=0;
	int diff=do_mod64(totalLength, AFS_ENC_EXTENT);
	
	totalLength += (AFS_ENC_EXTENT - diff);	/* Patch the length */
	ch = (struct afs_enc_chunk *)osi_Alloc(sizeof(struct afs_enc_chunk));
	ch->base = (char *)osi_Alloc(totalLength * sizeof(char));
	
	ch->uio_start = 0;
	ch->len = totalLength;
	if(c1)
		for(i=0;i<c1->uio_len;i++)
			ch->base[trans++] = c1->base[c1->uio_start + i];

	for(i=0;i<c2->uio_len;i++)
		ch->base[trans++] = c2->base[c2->uio_start + i];
	if(c3)
		for(i=0;i<c3->uio_len;i++)
			ch->base[trans++] = c3->base[c3->uio_start + i];
	/* We now need to transfer some junk to make the last extent look smooth */
	for(i=0;i<(AFS_ENC_EXTENT-diff);i++)
		ch->base[trans++] = '\0';
	ch->uio_start = c1?c1->uio_len:0;
	if(diff) ch->uio_len = totalLength;
	else ch->uio_len = c2->uio_len;
	return ch;
}


struct uio * afs_prepare_wb(struct uio *u, int len){

	struct uio *tuio2 = (struct uio *)osi_Alloc(sizeof(struct uio));
	struct iovec *tiovec2 = (struct iovec *)osi_Alloc(sizeof(struct iovec));
	afsio_copy(u, tuio2, tiovec2);
    tiovec2->iov_len = len;
    tiovec2->iov_base = (void *)osi_Alloc(len * sizeof(char));
    return tuio2;
}


/* Returns a file name with metadata tag attached */

char *afs_get_md_filename(char *aname){
	
	char *mdaname = (char *)osi_Alloc((strlen(aname)+10)*sizeof(char));
	strcat(mdaname, "_m_");
	strcat(mdaname, aname);
	
	return mdaname;
}

afs_int32 afs_is_md(char *aname){
	
	if(strstr(aname, "_m_") == 0) return 1;
	else return 0;
}

/* A mindless function currently, constructs a metadata file
 * using just the file size.
 * TODO: Construct a more full fledged API for metadata storage
 */

struct uio *afs_get_mduio(int size){

	char dummy[10];
	sprintf(dummy,"%d",size);
	struct uio *mdauio = (struct uio *)osi_Alloc(sizeof(struct uio));
	struct iovec *mdiovec = (struct iovec *)osi_Alloc(sizeof(struct iovec));;
	
	mdauio->uio_offset = 0;
	mdauio->uio_resid = strlen(dummy);
	mdiovec->iov_len = strlen(dummy)+1;
	mdiovec->iov_base = (void *)osi_Alloc(mdiovec->iov_len * sizeof(char));
	strcpy((char *)(mdiovec->iov_base), dummy);
	mdauio->uio_iovcnt = 1;
	mdauio->uio_iov = mdiovec;
	
	return mdauio;
}

struct uio*
afs_get_mduio1(struct vcache *md){
	struct uio *mdauio = (struct uio *)osi_Alloc(sizeof(struct uio));
	struct iovec *mdiovec = (struct iovec *)osi_Alloc(sizeof(struct iovec));
	mdauio->uio_offset = 0;
	mdauio->uio_resid = md->f.m.Length;
	mdiovec->iov_len = md->f.m.Length;
	mdiovec->iov_base = (void *)osi_Alloc(mdiovec->iov_len * sizeof(char));
	mdauio->uio_iovcnt = 1;
	mdauio->uio_iov = mdiovec;
	return mdauio;
}
	
int myatoi(char *str){
    
    int ind=0, val=0;
    while(str!=NULL && str[ind]-'0' >=0 && str[ind]-'0'<=9){
        val = val*10 + str[ind]-'0';
        ind++;
    }
    return val;
}

/* Takes vcache as input and tries to fill in information about the encrypted files */
void
afs_fill_mdinfo(struct vcache *avc, struct vcache *mdavcp, afs_ucred_t *acred){
	
	char buf[10];
	int i, size=-1, code;
	struct vrequest treq;
	struct uio *temp = (struct uio *)osi_Alloc(sizeof(struct uio)), *mduio;
	struct iovec *mdiovec = (struct iovec *)osi_Alloc(sizeof(struct iovec));
	afs_InitReq(&treq, acred);
	mduio = afs_get_mduio1(mdavcp);
	afsio_copy(mduio, temp, mdiovec);
	
	afs_open(&mdavcp, 0, acred);
	afs_UFSRead(mdavcp, mduio, acred, 0, NULL, 0, 0);
	afs_close(mdavcp, 0, acred);
	
	for(i=0;i<temp->uio_iov[0].iov_len;i++)
		buf[i]=((char *)(temp->uio_iov[0].iov_base))[i];
	buf[i]='\0';
	size = myatoi(buf);
	avc->f.m.Length = size;		
}
