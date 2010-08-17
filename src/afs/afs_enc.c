#include <afsconfig.h>
#include "afs/param.h"


#include "afs/sysincludes.h"	/* Standard vendor system headers */
#include "afsincludes.h"	/* Afs-based standard headers */
#include "afs/afs_stats.h"	/* statistics */
#include "afs/afs_cbqueue.h"
#include "afs/nfsclient.h"
#include "afs/afs_osidnlc.h"
#include "afs/afs_osi.h"

#include<asm/div64.h>

#define AFS_ENC_EXTENT 1000


/* Utility function to print the struct uio stats, to be removed later */

unsigned long int do_mod64(long long int x, long long int y){
	/* Does not modify either x or y unlike the asm counter part */
	
	long long int x1=x, y1=y;
	
	return do_div(x1, y1);
}

void afs_print_uioinfo(struct uio *uiop){
	
	printk("offset: %d iovcnt: %d, uio_resid: %d\n", uiop->uio_offset, uiop->uio_iovcnt, uiop->uio_resid);
	int i;
	for(i=0;i<uiop->uio_iovcnt;i++)
		printk("iov_len: %d, ",uiop->uio_iov[i].iov_len);
}


/* data structure contains the uio structure after transfer, basis contains it before transfer
 * we find the diff of the two and manipulate the data.
 */


/* Proof of concept implementation.
 * Presently the model is as simple as ROT-13. This is a byte wise substitution cipher
 * which takes a byte at a time( ascii character ) and rotates it by 13 places.
 * For ascii characters decryption is simply (char)val + 13. 
 */

/* Presently implements the rot13 algorithm, block size is one byte */
 
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

void afs_decrypt(struct afs_enc_chunk *chunk){

	/* We know that the chunk contanins N times AFS_ENC_EXTENT
	 * and we decrypt it inplace */
	 
	afs_int32 left=chunk->len;
	char *extent=chunk->base;
	
	while(1){
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
	
	

void
afs_decrypt1(struct uio *data, struct uio *basis)
{
	afs_int32 i, j, vec_trans, extent_ind=0, extent_basis;
	char *datap;
	char *extent_vec = (char *)osi_Alloc(AFS_ENC_EXTENT*sizeof(char));
	
	for(i=0;i<=(basis->uio_iovcnt - data->uio_iovcnt);i++){
		/* find the data transferred in this segment */
		j=0;
		vec_trans = basis->uio_iov[i].iov_len - data->uio_iov[i].iov_len;
		printk("Len of transfer: %d\n", vec_trans);
		datap = (char *)basis->uio_iov[i].iov_base;
		extent_basis = 0;
		while(j < vec_trans)
		{
			extent_vec[extent_ind++] = datap[j++];
			
			if(j==vec_trans){
				/* We might be facing a situation where the last extent is incomplete */
				afs_decrypt_extent(extent_vec, extent_ind);
				
				afs_write_extent(data, datap, extent_basis, extent_vec, extent_ind);
				
				break;
			}
			
			else if(extent_ind == AFS_ENC_EXTENT)
			{
				//printk("Decrypting extent with basis: %d", extent_basis);
				/* Decrypt the extent */
				afs_decrypt_extent(extent_vec, AFS_ENC_EXTENT);
			
				/* Write back to the data uio */
				afs_write_extent(data, datap, extent_basis, extent_vec, AFS_ENC_EXTENT);
			
				/* Reset extent_ind, extent_basis and continue */
				extent_basis += AFS_ENC_EXTENT;
				extent_ind = 0;
			}
		} 
	}
	
	
}

void
afs_print_uiodata(struct uio *data, struct uio *basis)
{

	printk("Out Vnop");
	printk("info data");
	afs_print_uioinfo(data);
			
	printk("info basis");
	afs_print_uioinfo(basis);
	
	int iovcnt = basis->uio_iovcnt - data->uio_iovcnt;
	
	printk("len: %d", basis->uio_iov[0].iov_len);
	
	return;
			
	afs_int32 i, j;
	char *datap;
	
	for(i=0;i<=(basis->uio_iovcnt - data->uio_iovcnt);i++){
		/* find the data transferred in this segment */
		afs_int32 vec_trans = basis->uio_iov[i].iov_len - data->uio_iov[i].iov_len;
		printk("Data in segment: %d\n", vec_trans);
		datap = (char *)basis->uio_iov[i].iov_base;
		for(j=0;j<vec_trans;j++)
			printk("%d:%c", j, datap[j]);
			
	}
	
	
}


struct uio *
afs_encrypt(struct uio *ainuio)
{
	struct uio *aoutuio = (struct uio *)osi_Alloc(sizeof(struct uio));
    register int i, j;
    register struct iovec *tvec, *aoutvec;

    if (ainuio->afsio_iovcnt > AFS_MAXIOVCNT)
	return EINVAL;
    memcpy((char *)aoutuio, (char *)ainuio, sizeof(struct uio));
    aoutvec = (struct iovec *)osi_Alloc(aoutuio->uio_iovcnt*sizeof(struct iovec));
   
    tvec = ainuio->afsio_iov;
    /* Overwrite afsio_iov */
    aoutuio->afsio_iov = aoutvec;
    for (i = 0; i < ainuio->afsio_iovcnt; i++) {
		memcpy((char *)aoutvec, (char *)tvec, sizeof(struct iovec));
		
		/* Allocate space/overwrite base pointer for the new vector */
		aoutvec->iov_base = (void *)afs_osi_Alloc(aoutvec->iov_len);
		//memcpy((char *)(aoutvec->iov_base), (char *)(tvec->iov_base), tvec->iov_len);
		char *in = (char *)(tvec->iov_base);
		char *out = (char *)(aoutvec->iov_base);
		for(j=0;j<aoutvec->iov_len;j++)
			if(in[j]>='A' && in[j]<='Z')
				/* Caps is here */
				out[j]=((in[j]-'A')+13)%26 + 'A';
			else if(in[j]>='a' && in[j]<='z')
				/* smalls is here */
				out[j]=((in[j]-'a')+13)%26+'a';
			else
				out[j] = in[j];
		tvec++;			/* too many compiler bugs to do this as one expr */
		aoutvec++;
    }
    return aoutuio;
}

struct uio *
afs_get_start_extent(struct uio *basis){
	/* We extend the basis struct to the left.
	 * invarient, we would never need to extend beyond 0 */
	 
	 struct uio *start_uio = (struct uio *)osi_Alloc(sizeof(struct uio));
	 struct iovec *start_iovec = (struct iovec *)osi_Alloc(sizeof(struct iovec));
	 
	 afsio_copy(basis, start_uio, start_iovec);
 	 unsigned long int mod = do_mod64(start_uio->uio_offset, AFS_ENC_EXTENT);
 	 printk("The mod for the start extent is: %ld", mod);
	 start_uio->uio_offset -= mod; 
	 //afsio_trim(start_uio, mod);
	 start_uio->uio_iov[0].iov_len = mod;
	 return start_uio;
}

struct uio *
afs_get_end_extent(struct uio *basis, afs_int32 len){
	/* We extend the basis struct to the right.
	 * invarient, we would never need to extend beyond avc->f.m.Length */
	 
	 struct uio *end_uio = (struct uio *)osi_Alloc(sizeof(struct uio));
	 struct iovec *end_iovec = (struct iovec *)osi_Alloc(sizeof(struct iovec));
	 
	 afsio_copy(basis, end_uio, end_iovec);
	 
 	 unsigned long int mod = do_mod64(end_uio->uio_offset+len, AFS_ENC_EXTENT);
 	 printk("The mod for the last extent is: %ld", mod);
 	 end_uio->uio_offset = end_uio->uio_offset + len;
	 end_uio->uio_iov[0].iov_len = AFS_ENC_EXTENT - mod;
	 
	 return end_uio;
}

void afs_print_chunk(struct afs_enc_chunk *chunk){
	
	printk("Size: %d\nStart: %d\nEnd: %d\n", chunk->len, chunk->uio_start, chunk->uio_len);
	afs_int32 i;
	for(i=0;i<chunk->uio_len;i++);
		//printk("%c", chunk->base[chunk->uio_start+i]);
}

void afs_enc_chunk_wb(struct afs_enc_chunk *chunk, struct uio *data, struct uio *basis){
	
	
	afs_int32 i, j, iovcnt_diff, iov_no=0, space, chunk_len = chunk->uio_len, ind=0;
	
	while(chunk_len){
		/* Transfer the chunk back to the tuiop structure */
		
		space = basis->uio_iov[iov_no].iov_len - data->uio_iov[iov_no].iov_len;
		char *d = (char *)basis->uio_iov[iov_no].iov_base;
		i=0;
		while(i<space && chunk_len){
			d[i] = chunk->base[ind++];
			i++;
			chunk_len--;
		}
		
		iov_no++;
	}
}
		
		

struct afs_enc_chunk *afs_get_extent(struct uio *s, struct uio *s1, struct uio *t, struct uio *t1, struct uio *e, struct uio *e1)
{
	/* Considers the start extent, the current extent and the end extent to find the actual extent */
	
	int trans_len= (s1?s1->uio_iov[0].iov_len:0) + (t1?t1->uio_iov[0].iov_len:0) + (e1?e1->uio_iov[0].iov_len:0);
	
	printk("trans len: %d\n", trans_len);
	
	struct afs_enc_chunk *ext = (struct afs_enc_chunk *)osi_Alloc(sizeof(struct afs_enc_chunk));
	
	ext->uio_start = s1?s1->uio_iov[0].iov_len:0;
	ext->uio_len = t1?t1->uio_iov[0].iov_len:0;
	ext->len = trans_len;
	ext->base = (char *)osi_Alloc(trans_len * sizeof(char));
	
	char *temp, *extent = ext->base;
	
	int transfer=0, i;
	
	if(s!=NULL){
		
		temp = (char *)s1->uio_iov[0].iov_base;
		i=0;
		printk("\nStart extent\n");
		for(i=0;i<s1->uio_iov[0].iov_len;i++){
			printk("%c", temp[i]);
			extent[transfer++] = temp[i];
		}
	}
	
	if(t!=NULL){
		
		temp = (char *)t1->uio_iov[0].iov_base;
		printk("\nMid extent\n");		
		for(i=0;i<t1->uio_iov[0].iov_len;i++){
			printk("%c", temp[i]);
			extent[transfer++] = temp[i];
		}
	
	}
	
	if(e!=NULL){
		
		temp = (char *)e1->uio_iov[0].iov_base;
		printk("\nEnd extent\n");
		for(i=0;i<e1->uio_iov[0].iov_len;i++){
			printk("%c", temp[i]);
			extent[transfer++] = temp[i];
		}
	
	}
	
	return ext;

}

	
	
	
	
	
	
	

