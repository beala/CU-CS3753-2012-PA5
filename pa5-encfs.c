/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>
  Modified by: Alex Beal (2012) <http://usrsb.in>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include "aes-crypt.h"
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#define USAGE "Usage:\n\t./pa5-encfs KEY ENC_DIR MOUNT_POINT\n"
#define LOGFILE "encfs_log"
#define TMPSUFFIX ".really_awesome_enc"

#define ENCATTR "user.pa5-encfs.encrypted"
#define MAXATTR 6

/* Macro for accessing the private data struct */
#define ENC_DATA (((EncState*)fuse_get_context()->private_data))

typedef struct {
    char *rootdir;
    char *enc_key;
} EncState;

EncState* init_enc_state(){
    EncState* enc_structp = NULL;
    enc_structp = malloc(sizeof(EncState));
    if(enc_structp == NULL){
        fprintf(stderr, "There was an error allocating memory for the state struct. Exiting.\n");
        exit(EXIT_FAILURE);
    }
    return enc_structp;
}

void destroy_enc_state(EncState* enc_structp){
    free(enc_structp->rootdir);
    free(enc_structp->enc_key);
    free(enc_structp);
}

void *enc_init(struct fuse_conn_info *conn){
    (void)conn;
    return ENC_DATA;
}

void enc_destroy(void *userdata){
    (void)userdata;
    destroy_enc_state(ENC_DATA);
}

/* Get the enc attr.
 * Return:
 *  1: set to "true"
 *  0: set to "false"
 *  -1: attr doesn't exist
 */
int getencattr(const char* path){
    ssize_t attrsize = -1;
    char attrstr[MAXATTR] = "";
    attrsize = getxattr(path, ENCATTR, attrstr, MAXATTR);
    if(attrsize == -1){
        return -1;
    } else if(strcmp(attrstr, "true") == 0) {
        return 1;
    } else {
        return 0;
    }
}

int setencattr(const char* path, int val){
    char strval[MAXATTR];
    if(val){
        strcpy(strval, "true");
    } else {
        strcpy(strval, "false");
    }
    if(setxattr(path, ENCATTR, strval, MAXATTR, 0))
        return -errno;
    return 0;
}

char* trans_flags(int flags){
    if(flags && O_RDWR == O_RDWR){
        return strdup("r+");
    }else if(flags && O_RDONLY == O_RDONLY){
        return strdup("r");
    }else{
        return strdup("w");
    }
}

char* tmp_path(const char* old_path){
    char* new_path;
    int len=0;
    len=strlen(old_path) + strlen(TMPSUFFIX) + 1;
    new_path = malloc(sizeof(char)*len);
    if(new_path == NULL){
        return NULL;
    }
    new_path[0] = '\0';
    strcat(new_path, old_path);
    strcat(new_path, TMPSUFFIX);
    return new_path;
}
char* rewrite_path(const char* old_path){
    char* new_path;
    int len=0;
    /* Calculate length. Allocate string, and initialize str */
    len = strlen(old_path) + strlen(ENC_DATA->rootdir) + 1;
    new_path = malloc(sizeof(char)*len);
    new_path[0] = '\0';
    if(new_path == NULL){
        fprintf(stderr, "ERROR: Could not allocate memory in rewrite_path().\n");
        return NULL;
    }
    strcat(new_path, ENC_DATA->rootdir);
    strcat(new_path, old_path);
    return new_path;
}

/* Decrypt a file at `path`, and store the decrypted version back to
 * `path`.
 * Only decrypt if its ENCATTR is set to true.
 * Return 0 if it was decrypted.
 * Return 1 if it wasn't.
 */
int dec_file(const char* path){
    const char* tmp_name;
    const char* new_path = rewrite_path(path);
    FILE *enc_fp, *dec_fp;

    if(getencattr(new_path) != 1)
        return 1;

    /* Open encrypted copy */
    enc_fp = fopen(new_path, "r");
    /* Make decrypted copy at tmp_name */
    tmp_name = tmp_path(new_path);
    dec_fp = fopen(tmp_name, "w");
    do_crypt(enc_fp, dec_fp, 0, ENC_DATA->enc_key);
    /* Close both copies */
    fclose(dec_fp);
    fclose(enc_fp);
    /* Remove the encrypted copy */
    remove(new_path);
    /* Rename decrypted copy to original name */
    rename(tmp_name, new_path);
    fprintf(stderr, "Dec! New: %s Tmp: %s\n", new_path, tmp_name);
    /* Set the encryption attr */
    setencattr(new_path, 0);
    free((void*)new_path);
    free((void*)tmp_name);
    return 0;
}

int enc_file(const char* path){
    const char* tmp_name;
    const char* new_path = rewrite_path(path);
    FILE *enc_fp, *dec_fp;

    if(getencattr(new_path) != 0)
        return 1;

    /* Open decrypted copy */
    dec_fp = fopen(new_path, "r");
    /* Make encrypted copy at tmp_name */
    tmp_name = tmp_path(new_path);
    enc_fp = fopen(tmp_name, "w");
    do_crypt(dec_fp, enc_fp, 1, ENC_DATA->enc_key);
    /* Close both copies */
    fclose(dec_fp);
    fclose(enc_fp);
    /* Remove the decrypted copy */
    remove(new_path);
    /* Rename encrypted copy to original name */
    rename(tmp_name, new_path);
    fprintf(stderr, "Enc! New: %s Tmp: %s\n", new_path, tmp_name);
    /* Set the encryption attr */
    setencattr(new_path, 1);
    free((void*)new_path);
    free((void*)tmp_name);
    return 0;
}

int enc_file_copy(const char* path, const char* dest_path){
    const char* new_path = rewrite_path(path);
    FILE *enc_fp, *dec_fp;

    /* Open decrypted copy */
    dec_fp = fopen(new_path, "r");
    /* Make encrypted copy at tmp_name */
    enc_fp = fopen(dest_path, "w");
    if(getencattr(new_path) == 0)
        do_crypt(dec_fp, enc_fp, 1, ENC_DATA->enc_key);
    else
        do_crypt(dec_fp, enc_fp, -1, ENC_DATA->enc_key);
    /* Close both copies */
    fclose(dec_fp);
    fclose(enc_fp);
    fprintf(stderr, "Enc Copy! Src: %s Dest: %s\n", new_path, dest_path);
    free((void*)new_path);
    return 0;
}

int dec_file_copy(const char* path, const char* dest_path){
    const char* new_path = rewrite_path(path);
    FILE *enc_fp, *dec_fp;

    /* Open encrypted copy */
    enc_fp = fopen(new_path, "r");
    /* Make decrypted copy at tmp_name */
    dec_fp = fopen(dest_path, "w");
    if(getencattr(new_path) == 1)
        do_crypt(enc_fp, dec_fp, 0, ENC_DATA->enc_key);
    else
        do_crypt(enc_fp, dec_fp, -1, ENC_DATA->enc_key);
    /* Close both copies */
    fclose(dec_fp);
    fclose(enc_fp);
    fprintf(stderr, "Dec Copy! Src: %s Dest: %s\n", new_path, dest_path);
    free((void*)new_path);
    return 0;
}

/* Truncate the log file. */
int truncate_log(){
    FILE *logfp = NULL;
    logfp = fopen(LOGFILE, "w");
    fclose(logfp);
    return 0;
}

/* Append a message to the log file. */
int log_msg(char *fmt, ...){
    va_list argptr;
    va_start(argptr, fmt);
    FILE *logfp = NULL;
    logfp = fopen(LOGFILE, "a");
    if(logfp == NULL)
        exit(EXIT_FAILURE);
    vfprintf(logfp, fmt, argptr);
    fclose(logfp);
    va_end(argptr);
    return 0;
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;
    time_t atime, mtime, ctime;
    mode_t mode;
    const char* new_path = rewrite_path(path);
    const char* tmp_name;
    /* Test if the file exists */
    res = lstat(new_path, stbuf);
    if (res == -1){
        return -errno;
    }
    /* Is the file a regular file? */
    if(S_ISREG(stbuf->st_mode)){
        atime = stbuf->st_atime;
        mtime = stbuf->st_mtime;
        ctime = stbuf->st_ctime;
        mode = stbuf->st_mode;
        /* Decrypt and get its attrs */
        tmp_name = tmp_path(new_path);
        dec_file_copy(path, tmp_name);
        res = lstat(tmp_name, stbuf);
        if (res == -1){
            return -errno;
        }
        stbuf->st_atime = atime;
        stbuf->st_mtime = mtime;
        stbuf->st_ctime = ctime;
        stbuf->st_mode= mode;
        /* Remove the copy */
        remove(tmp_name);
        free((void*)new_path);
        free((void*)tmp_name);
    }
    return 0;
}

static int xmp_access(const char *path, int mask)
{
    int res;
    const char* new_path = rewrite_path(path);
    //res = access(path, mask);
    res = access(new_path, mask);
    free((void*)new_path);
    if (res == -1)
        return -errno;

    return res;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
    int res;
    const char* new_path = rewrite_path(path);
    //res = readlink(path, buf, size - 1);
    res = readlink(new_path, buf, size - 1);
    free((void*)new_path);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info *fi)
{

    DIR *dp;
    struct dirent *de;

    (void) offset;
    (void) fi;
    const char* new_path = rewrite_path(path);

    //dp = opendir(path);
    dp = opendir(new_path);
    free((void*)new_path);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;
    const char* new_path = rewrite_path(path);

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(new_path, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(new_path, mode);
    else
        res = mknod(new_path, mode, rdev);
    if (res == -1)
        return -errno;

    free((void*)new_path);
    enc_file(path);
    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
    int res;
    const char* new_path = rewrite_path(path);

    res = mkdir(new_path, mode);
    free((void*)new_path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_unlink(const char *path)
{
    int res;
    const char* new_path = rewrite_path(path);

    res = unlink(new_path);
    free((void*)new_path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rmdir(const char *path)
{
    int res;
    const char* new_path = rewrite_path(path);

    res = rmdir(new_path);
    free((void*)new_path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
    int res;
    const char* new_from = rewrite_path(from);
    const char* new_to = rewrite_path(to);

    res = symlink(new_from, new_to);
    free((void*)new_from);
    free((void*)new_to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(const char *from, const char *to)
{
    int res;
    const char* new_from = rewrite_path(from);
    const char* new_to = rewrite_path(to);

    res = rename(new_from, new_to);
    free((void*)new_from);
    free((void*)new_to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_link(const char *from, const char *to)
{
    int res;
    const char* new_from = rewrite_path(from);
    const char* new_to = rewrite_path(to);

    res = link(new_from, new_to);
    free((void*)new_from);
    free((void*)new_to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
    int res;
    const char* new_path = rewrite_path(path);

    res = chmod(new_path, mode);
    free((void*)new_path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;
    const char* new_path = rewrite_path(path);

    res = lchown(new_path, uid, gid);
    free((void*)new_path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
    int res;
    const char* new_path = rewrite_path(path);

    res = truncate(new_path, size);
    free((void*)new_path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
    int res;
    struct timeval tv[2];
    const char* new_path = rewrite_path(path);

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(new_path, tv);
    free((void*)new_path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
    (void)fi;
    (void)path;
    return 0;
}


static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi)
{
    (void)fi;
    int fd;
    int res;
    const char* new_path = rewrite_path(path);
    const char* tmp_name = tmp_path(new_path);

    dec_file_copy(path, tmp_name);
    fd = open(tmp_name, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    remove(tmp_name);
    free((void*)new_path);
    free((void*)tmp_name);
    return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
             off_t offset, struct fuse_file_info *fi)
{
    (void)fi;
    int fd;
    int res;
    const char* new_path = rewrite_path(path);

    dec_file(path);
    fd = open(new_path, O_WRONLY);
    if (fd == -1)
        return -errno;

    res = pwrite(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    enc_file(path);
    free((void*)new_path);
    return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    int res;
    const char* new_path = rewrite_path(path);

    res = statvfs(new_path, stbuf);
    free((void*)new_path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void)fi;
    int res;
    const char* new_path = rewrite_path(path);

    res = creat(new_path, mode);
    fprintf(stderr, "Created file descriptor: %d\n", res);
    if(res == -1){
        free((void*)new_path);
        return -errno;
    }
    close(res);

    setencattr(new_path, 0);
    enc_file(path);
    free((void*)new_path);
    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    (void)fi;
    (void)path;
    return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
             struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) isdatasync;
    (void) fi;
    return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
            size_t size, int flags)
{
    const char* new_path = rewrite_path(path);
    int res = lsetxattr(new_path, name, value, size, flags);
    free((void*)new_path);
    if (res == -1)
        return -errno;
    return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
            size_t size)
{
    const char* new_path = rewrite_path(path);
    int res = lgetxattr(new_path, name, value, size);
    free((void*)new_path);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
    const char* new_path = rewrite_path(path);
    int res = llistxattr(new_path, list, size);
    free((void*)new_path);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
    const char* new_path = rewrite_path(path);
    int res = lremovexattr(new_path, name);
    free((void*)new_path);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
    .getattr    = xmp_getattr,
    .access     = xmp_access,
    .readlink   = xmp_readlink,
    .readdir    = xmp_readdir,
    .mknod      = xmp_mknod,
    .mkdir      = xmp_mkdir,
    .symlink    = xmp_symlink,
    .unlink     = xmp_unlink,
    .rmdir      = xmp_rmdir,
    .rename     = xmp_rename,
    .link       = xmp_link,
    .chmod      = xmp_chmod,
    .chown      = xmp_chown,
    .truncate   = xmp_truncate,
    .utimens    = xmp_utimens,
    .open       = xmp_open,
    .read       = xmp_read,
    .write      = xmp_write,
    .statfs     = xmp_statfs,
    .create         = xmp_create,
    .release    = xmp_release,
    .fsync      = xmp_fsync,
    .init       = enc_init,
    .destroy    = enc_destroy,
#ifdef HAVE_SETXATTR
    .setxattr   = xmp_setxattr,
    .getxattr   = xmp_getxattr,
    .listxattr  = xmp_listxattr,
    .removexattr    = xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
    EncState* es = init_enc_state();
    umask(0);
    /* Check the arguments */
    if(argc < 4){
        fprintf(stderr, "ERROR: Not enough arguments.\n");
        fprintf(stderr, USAGE);
        exit(EXIT_FAILURE);
    }
    /* Copy the password and rootdir to our private data struct */
    es->enc_key = strdup(argv[1]);
    es->rootdir = strdup(argv[2]);
    /* Set the first arg to the name of the program */
    argv[2] = argv[0];
    return fuse_main(argc-2, argv+2, &xmp_oper, es);
}
