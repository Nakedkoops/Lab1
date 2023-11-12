#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen) {
	/* TODO: write this.  If entropy is given, apply a KDF to it to get ////////////////////////////////////
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	if (entropy == NULL) {
        // generate random aesKey and hmacKey
        // half of buff array corresponds to HMAC key
        // the other half corresponds to AES key
        unsigned char* buff = malloc(64); 
        randBytes(buff, 64);               
        memcpy((*K).aesKey, buff, 32); 
        memcpy((*K).hmacKey, buff + 32, 32); 
        free(buff);
    }
    else {
        // get 512-bit authentication code of entropy with KDF_KEY
		unsigned char* keys = malloc(64);
        HMAC(EVP_sha512(), &KDF_KEY, 32, entropy, entLen, keys, NULL); 
        // half of keys array corresponds to HMAC key
        // the other half corresponds to AES key
        memcpy((*K).aesKey, keys, 32); 
        memcpy((*K).hmacKey, keys + 32, 32);
        free(keys);
        }

	return 0;
}

size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}

size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c  //////////////////////////////////
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */
	if(IV == NULL) {
        IV = malloc(IV_LEN);
        randBytes(IV, IV_LEN);
    }
	
	// setup context ctx for encryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (0 == EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, (*K).aesKey, IV)) {
	        ERR_print_errors_fp(stderr);
	}

	// do the actual encryption
	int nWritten;
    unsigned char* ct = malloc(len);
	if(0 == EVP_EncryptUpdate(ctx, ct, &nWritten, inBuf, len))
		ERR_print_errors_fp(stderr);	

	// free up cipher context
        EVP_CIPHER_CTX_free(ctx); 

	// compute hmac of IV + ct
	unsigned char* iv_ct = malloc(IV_LEN + nWritten);
	memcpy(iv_ct, IV, IV_LEN);
	memcpy(iv_ct + IV_LEN, ct, nWritten); 
    unsigned char* md = malloc(32);
    HMAC(EVP_sha256(), (*K).hmacKey, 32, iv_ct, IV_LEN + nWritten, md, NULL); 

    //assemble message for specified format
	unsigned char* iv_ct_hmac = malloc(IV_LEN + nWritten + HM_LEN); 
	memcpy(iv_ct_hmac, iv_ct, IV_LEN + nWritten);
	memcpy(iv_ct_hmac + IV_LEN + nWritten, md, 32);
        
	// copy to outBuf
	memcpy(outBuf, iv_ct_hmac, IV_LEN + nWritten + HM_LEN);

	// free up heap memory
	free(ct);
	free(iv_ct);
 	free(md);
    free(iv_ct_hmac);
	return (IV_LEN + nWritten + HM_LEN); /* TODO: should return number of bytes written, which hopefully matches ske_getOutputLen(...). */
	}

size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out) {
	/* TODO: write this.  Hint: mmap. */
	// setup a random initialization vector (IV) if none is given
    // open input and output files. If output file does not exist, create it
    int fd_fnin, fd_fnout;
	fd_fnin = open(fnin, O_RDONLY);

	if (-1 == fd_fnin) {
		perror("open(fnin, O_RDONLY)");
		exit(EXIT_FAILURE);
	}

    fd_fnout = open(fnout, O_RDWR | O_CREAT, (mode_t)0644);
	if (-1 == fd_fnout){
		close(fd_fnin);
		perror("open(fnout, O_RDWR | O_CREAT, (mode_t)0644)");
		exit(EXIT_FAILURE);
	}

	// get status information of input file
    struct stat stat_fnin;
    if (0 != fstat(fd_fnin, &stat_fnin)) {
		close(fd_fnin);
		close(fd_fnout);
		perror("fstat(fd_fnin, &stat_fnin)");
		exit(EXIT_FAILURE);
	}	

	// map input file to memory 
	void* mmp_fnin = mmap(0, stat_fnin.st_size, PROT_READ, MAP_SHARED, fd_fnin, 0);
	if (mmp_fnin == MAP_FAILED) {
		close(fd_fnin);
		close(fd_fnout);
		perror("mmap(0, stat_fnin.st_size, PROT_READ, MAP_SHARED, fd_fnin, 0)");
		exit(EXIT_FAILURE);
	}

    // increase size of output file
   	int outLen = ske_getOutputLen(stat_fnin.st_size); 
    if (0 != ftruncate(fd_fnout, (off_t)(offset_out + outLen))) {
                close(fd_fnin);
                close(fd_fnout);
                munmap(mmp_fnin, stat_fnin.st_size); 
                perror("ftruncate(fd_fnout, (off_t) offset_out + outLen)");
                exit(EXIT_FAILURE);
        }	
		
    // map output file to memory
    void* mmp_fnout = mmap(0, outLen, PROT_WRITE, MAP_SHARED, fd_fnout, (off_t)offset_out);
	if (mmp_fnout == MAP_FAILED) {
		close(fd_fnin);
		close(fd_fnout);
                munmap(mmp_fnin, stat_fnin.st_size);
		perror("mmap(0, outLen, PROT_WRITE, MAP_SHARED, fd_fnout, (off_t)offset_out)");
		exit(EXIT_FAILURE);
	}

    // do the encryption
	ske_encrypt((unsigned char*)mmp_fnout, (unsigned char*)mmp_fnin, stat_fnin.st_size, K, IV); 
        // write changes to disk
        	if (0 != msync(mmp_fnout, outLen, MS_SYNC)) {
			close(fd_fnin);
			close(fd_fnout);
            munmap(mmp_fnin, stat_fnin.st_size);
            perror("msync(mmp_fnout, outLen, MS_SYNC)");
            exit(EXIT_FAILURE);
        } 
	// unmap and close files
        munmap(mmp_fnin, stat_fnin.st_size);
        munmap(mmp_fnout, outLen);
        close(fd_fnin);
		close(fd_fnout);
			
	return 0;
	}

size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K) {
	/* TODO: write this.  Make sure you check the mac before decypting!  /////////////////////////////////////
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	// compute hmac of IV + ct
	unsigned char* mac = malloc(HM_LEN);	
	HMAC(EVP_sha256(), (*K).hmacKey, 32, inBuf, len - HM_LEN, mac, NULL); 
	if (0 != memcmp(mac, inBuf + len - HM_LEN, HM_LEN)) {
		return -1;
	}

	// extract IV 
	unsigned char* IV = malloc(IV_LEN);
	memcpy(IV, inBuf, IV_LEN);

	// setup ctx for decryption
	int nWritten;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();	
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, (*K).aesKey, IV)) {
		ERR_print_errors_fp(stderr);
	}

	// do the actual decryption
	if (1 != EVP_DecryptUpdate(ctx, outBuf, &nWritten, inBuf + IV_LEN, len - IV_LEN - HM_LEN)) {
		ERR_print_errors_fp(stderr);
	}

    // free up the memory
    free(mac);
	free(IV);
	EVP_CIPHER_CTX_free(ctx); 

	return 0;
}

size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in) {
	/* TODO: write this. */   /////////////////////////////////////////////////////////////////////////////
	int fd_fnin, fd_fnout;
	fd_fnin = open(fnin, O_RDONLY);
	if (-1 == fd_fnin){
		perror("open(fnin, O_RDONLY)");
		exit(EXIT_FAILURE);
	}

    fd_fnout = open(fnout, O_RDWR | O_CREAT, (mode_t)0644);
	if (-1 == fd_fnout){
		close(fd_fnin);
		perror("open(fnout, O_RDWR | O_CREAT, (mode_t)0644)");
		exit(EXIT_FAILURE);
	}

	// get status information of input file
    struct stat stat_fnin;
	if (0 != fstat(fd_fnin, &stat_fnin)) {
        close(fd_fnin);
		close(fd_fnout);
		perror("fstat(fd_fnin, &stat_fnin)");
		exit(EXIT_FAILURE);
	}

    // map input file to memory 
	void* mmp_fnin = mmap(0, (stat_fnin.st_size - offset_in), PROT_READ, MAP_SHARED, fd_fnin, (off_t)offset_in);
	if (mmp_fnin == MAP_FAILED) {
		close(fd_fnin);
		close(fd_fnout);
		perror("mmap(0, (stat_fnin.st_size - offset_in), PROT_READ, MAP_SHARED, fd_fnin, (off_t)offset_in)");
		exit(EXIT_FAILURE);
	}
        
	// truncate output file
	int outLen = stat_fnin.st_size - offset_in - IV_LEN - HM_LEN;
    if (0 != ftruncate(fd_fnout, outLen)) {
            close(fd_fnin);
            close(fd_fnout);
            munmap(mmp_fnin, (stat_fnin.st_size - offset_in));
            perror("ftruncate(fd_fnout, outLen)");
            exit(EXIT_FAILURE);
    }

    // map output file to memory
    void* mmp_fnout = mmap(0, outLen, PROT_WRITE, MAP_SHARED, fd_fnout, (off_t) 0);
    if (mmp_fnout == MAP_FAILED) {
		close(fd_fnin);
		close(fd_fnout);
        munmap(mmp_fnin, (stat_fnin.st_size - offset_in));
		perror("mmap(0, outLen, PROT_WRITE, MAP_SHARED, fd_fnout, (off_t)0)");
		exit(EXIT_FAILURE);
	}

	// do the decryption 
	ske_decrypt((unsigned char*)mmp_fnout, (unsigned char*)mmp_fnin, (stat_fnin.st_size - offset_in), K); 
    
	// write to file
    if (0 != msync(mmp_fnout, outLen, MS_SYNC)) {
            close(fd_fnin);
            close(fd_fnout);
            munmap(mmp_fnin, (stat_fnin.st_size - offset_in));
            munmap(mmp_fnout, outLen);
            perror("msync(mmp_fnout, outLen, MS_SYNC)");
            exit(EXIT_FAILURE);
    }

	// unmap and close files
    munmap(mmp_fnin, (stat_fnin.st_size - offset_in));
    munmap(mmp_fnout, outLen);
    close(fd_fnin);
	close(fd_fnout);
	return 0;
	return 0;
}
