#include "common.h"
#ifdef HAVE_EVHTP

#define DEBUG_FLAG SEAFILE_DEBUG_HTTP
#include "log.h"

#include "seafile-object.h"
#include "seafile-crypt.h"
#include "seafile-error.h"

#include "utils.h"

#include "seafile-session.h"
#include "pack-dir.h"
#include "seaf-utils.h"

#include <archive.h>
#include <archive_entry.h>
#include <iconv.h>

#ifdef WIN32
#define S_IFLNK    0120000 /* Symbolic link */
#define S_ISLNK(x) (((x) & S_IFMT) == S_IFLNK)
#endif


typedef struct {
    struct archive *a;
    SeafileCrypt *crypt;
    const char *top_dir_name;
    gboolean is_windows;
    time_t mtime;
    char store_id[37];
    int repo_version;
    int tmp_fd;
    char *tmp_zip_file;
} PackDirData;

static char *
do_iconv (char *fromcode, char *tocode, char *in)
{
    iconv_t conv;
    size_t inlen, outlen, len;
    char out[1024];
    char *pin = in;
    char *pout = out;
    
    conv = iconv_open (tocode, fromcode);
    if (conv == (iconv_t)-1) {
        return NULL;
    }

    inlen = strlen (in);
    outlen = sizeof(out);

    len = iconv (conv, &pin, &inlen, &pout, &outlen);
    iconv_close (conv);

    if (len == -1) {
        return NULL;
    }

    outlen = sizeof(out) - outlen;

    return g_strndup(out, outlen);
}

static int
add_file_to_archive (PackDirData *data,
                     const char *parent_dir,
                     const char *base_name,
                     SeafDirent *dent)
{
    struct archive *a = data->a;
    struct SeafileCrypt *crypt = data->crypt;
    gboolean is_windows = data->is_windows;
    const char *top_dir_name = data->top_dir_name;
    
    struct archive_entry *entry = NULL;
    Seafile *file = NULL;
    char *pathname = NULL;
    char buf[64 * 1024];
    int len = 0;
    int n = 0;
    int idx = 0;
    BlockHandle *handle = NULL;
    BlockMetadata *bmd = NULL;
    char *blk_id = NULL;
    uint32_t remain = 0;
    EVP_CIPHER_CTX *ctx;
    gboolean enc_init = FALSE;
    char *dec_out = NULL;
    int dec_out_len = -1;
    int ret = 0;

    pathname = g_build_filename (top_dir_name, parent_dir, base_name, NULL);

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                        data->store_id, data->repo_version,
                                        dent->id);
    if (!file) {
        ret = -1;
        goto out;
    }

    entry = archive_entry_new ();

    /* File name fixup for WinRAR */
    if (is_windows && seaf->http_server->windows_encoding) {
        char *win_file_name = do_iconv ("UTF-8",
                                        seaf->http_server->windows_encoding,
                                        pathname);
        if (!win_file_name) {
            seaf_warning ("Failed to convert file name to %s\n",
                          seaf->http_server->windows_encoding);
            ret = -1;
            goto out;
        }
        archive_entry_copy_pathname (entry, win_file_name);
        g_free (win_file_name);

    } else {
        archive_entry_set_pathname (entry, pathname);
    }

    /* FIXME: 0644 should be set when upload files in repo-mgr.c */
    archive_entry_set_mode (entry, dent->mode | 0644);
    archive_entry_set_size (entry, file->file_size);
    archive_entry_set_mtime (entry, data->mtime, 0);

    n = archive_write_header (a, entry);
    if (n != ARCHIVE_OK) {
        seaf_warning ("archive_write_header  error: %s\n", archive_error_string(a));
        ret = -1;
        goto out;
    }

    /* Read data of this entry block by block */
    while (idx < file->n_blocks) {
        blk_id = file->blk_sha1s[idx];
        handle = seaf_block_manager_open_block (seaf->block_mgr,
                                                data->store_id,
                                                data->repo_version,
                                                blk_id, BLOCK_READ);
        if (!handle) {
            seaf_warning ("Failed to open block %s:%s\n", data->store_id, blk_id);
            ret = -1;
            goto out;
        }

        bmd = seaf_block_manager_stat_block_by_handle (seaf->block_mgr,
                                                       handle);
        if (!bmd) {
            seaf_warning ("Failed to stat block %s:%s\n", data->store_id, blk_id);
            ret = -1;
            goto out;
        }
        remain = bmd->size;
        g_free (bmd);

        if (crypt) {
            if (seafile_decrypt_init (&ctx, crypt->version,
                                      crypt->key, crypt->iv) < 0) {
                seaf_warning ("Failed to init decrypt.\n");
                ret = -1;
                goto out;
            }
            enc_init = TRUE;
        }

        while (remain != 0) {
            n = seaf_block_manager_read_block (seaf->block_mgr, handle,
                                               buf, sizeof(buf));
            if (n <= 0) {
                seaf_warning ("failed to read block %s\n", blk_id);
                ret = -1;
                goto out;
            }
            remain -= n;

            /* OK, We're read some data of this block  */
            if (crypt == NULL) {
                /* not encrypted */
                len = archive_write_data (a, buf, n);
                if (len <= 0) {
                    seaf_warning ("archive_write_data error: %s\n", archive_error_string(a));
                    ret = -1;
                    goto out;
                }

            } else {
                /* an encrypted block */
                dec_out = g_new (char, n + 16);
                if (!dec_out) {
                    seaf_warning ("Failed to alloc memory.\n");
                    ret = -1;
                    goto out;
                }

                int r = EVP_DecryptUpdate (ctx,
                                           (unsigned char *)dec_out,
                                           &dec_out_len,
                                           (unsigned char *)buf,
                                           n);

                /* EVP_DecryptUpdate returns 1 on success, 0 on failure */
                if (r != 1) {
                    seaf_warning ("Decrypt block %s failed.\n", blk_id);
                    ret = -1;
                    goto out;
                }

                if (dec_out_len > 0) {
                    len = archive_write_data (a, dec_out, dec_out_len);
                    if (len <= 0) {
                        seaf_warning ("archive_write_data error: %s\n", archive_error_string(a));
                        ret = -1;
                        goto out;
                    }
                }

                /* If it's the last piece of a block, call decrypt_final()
                 * to decrypt the possible partial block. */
                if (remain == 0) {
                    r = EVP_DecryptFinal_ex (ctx,
                                             (unsigned char *)dec_out,
                                             &dec_out_len);
                    if (r != 1) {
                        seaf_warning ("Decrypt block %s failed.\n", blk_id);
                        ret = -1;
                        goto out;
                    }

                    if (dec_out_len != 0) {
                        len = archive_write_data (a, dec_out, dec_out_len);
                        if (len <= 0) {
                            seaf_warning ("archive_write_data error: %s\n", archive_error_string(a));
                            ret = -1;
                            goto out;
                        }
                    }
                }

                g_free (dec_out);
                dec_out = NULL;
            }
        }

        seaf_block_manager_close_block (seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
        handle = NULL;

        /* turn to next block */
        idx++;
    }

out:
    g_free (pathname);
    if (entry)
        archive_entry_free (entry);
    if (file)
        seafile_unref (file);
    if (handle) {
        seaf_block_manager_close_block (seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free(seaf->block_mgr, handle);
    }
    if (crypt != NULL && enc_init)
        EVP_CIPHER_CTX_free (ctx);
    g_free (dec_out);

    return ret;
}

static int
archive_dir (PackDirData *data,
             const char *root_id,
             const char *dirpath,
             Progress *progress)
{
    SeafDir *dir = NULL;
    SeafDirent *dent;
    GList *ptr;
    char *subpath = NULL;
    int ret = 0;

    dir = seaf_fs_manager_get_seafdir (seaf->fs_mgr,
                                       data->store_id, data->repo_version,
                                       root_id);
    if (!dir) {
        seaf_warning ("failed to get dir %s:%s\n", data->store_id, root_id);
        goto out;
    }
    if (!dir->entries) {
        char *pathname = g_build_filename (data->top_dir_name, dirpath, NULL);
        struct archive_entry *entry = archive_entry_new ();
        gboolean is_windows = data->is_windows;

        if (is_windows && seaf->http_server->windows_encoding) {
            char *win_file_name = do_iconv ("UTF-8",
                    seaf->http_server->windows_encoding,
                    pathname);
            if (!win_file_name) {
                seaf_warning ("Failed to convert file name to %s\n",
                              seaf->http_server->windows_encoding);
                ret = -1;
                goto out;
            }
            archive_entry_copy_pathname (entry, win_file_name);
            g_free (win_file_name);

        } else {
            archive_entry_set_pathname (entry, pathname);
        }

        archive_entry_set_filetype (entry, AE_IFDIR);
        archive_entry_set_mtime (entry, data->mtime, 0);
        archive_entry_set_perm (entry, 0755);
        int n = archive_write_header (data->a, entry);
        if (n != ARCHIVE_OK) {
            seaf_warning ("archive_write_header  error: %s\n", archive_error_string(data->a));
            ret = -1;
        }

        archive_entry_free (entry);
        g_free (pathname);
        goto out;
    }

    for (ptr = dir->entries; ptr; ptr = ptr->next) {
        if (progress->canceled) {
            ret = -1;
            goto out;
        }

        dent = ptr->data;
        if (S_ISREG(dent->mode)) {
            ret = add_file_to_archive (data, dirpath, dent->name, dent);
            if (ret == 0) {
                g_atomic_int_inc (&progress->zipped);
            }
        } else if (S_ISLNK(dent->mode)) {
            if (archive_version_number() >= 3000001) {
                /* Symlink in zip arhive is not supported in earlier version
                 * of libarchive */
                ret = add_file_to_archive (data, dirpath, dent->name, dent);
            }

        } else if (S_ISDIR(dent->mode)) {
            subpath = g_build_filename (dirpath, dent->name, NULL);
            ret = archive_dir (data, dent->id, subpath, progress);
            g_free (subpath);
        }

        if (ret < 0) {
            goto out;
        }
    }

out:
    if (dir)
        seaf_dir_free (dir);

    return ret;
}

static PackDirData *
pack_dir_data_new (const char *store_id,
                   int repo_version,
                   const char *dirname,
                   SeafileCrypt *crypt,
                   gboolean is_windows)
{
    struct archive *a = NULL;
    char *tmpfile_name = NULL ;
    int fd = -1;
    PackDirData *data = NULL;

    tmpfile_name = g_strdup_printf ("%s/seafile-XXXXXX.zip",
                                    seaf->http_server->http_temp_dir);
    fd = g_mkstemp (tmpfile_name);
    if (fd < 0) {
        seaf_warning ("Failed to open temp file: %s.\n", strerror (errno));
        g_free (tmpfile_name);
        return NULL;
    }

    a = archive_write_new ();
    archive_write_add_filter_none (a);
    archive_write_set_format_zip (a);
    archive_write_open_fd (a, fd);

    data = g_new0 (PackDirData, 1);
    data->crypt = crypt;
    data->is_windows = is_windows;
    data->a = a;
    data->top_dir_name = dirname;
    data->mtime = time(NULL);
    memcpy (data->store_id, store_id, 36);
    data->repo_version = repo_version;
    data->tmp_fd = fd;
    data->tmp_zip_file = tmpfile_name;

    return data;
}

static gboolean
name_exists (GList *file_list, const char *filename)
{
    GList *ptr;
    char *name;

    for (ptr = file_list; ptr != NULL; ptr = ptr->next) {
        name = ptr->data;
        if (strcmp (name, filename) == 0)
            return TRUE;
    }

    return FALSE;
}

static char *
generate_unique_filename (const char *file, GList *file_list)
{
    int i = 1;
    char *name, *ext, *unique_name;

    unique_name = g_strdup(file);
    split_filename (unique_name, &name, &ext);
    while (name_exists (file_list, unique_name)) {
        g_free (unique_name);
        if (ext)
            unique_name = g_strdup_printf ("%s (%d).%s", name, i, ext);
        else
            unique_name = g_strdup_printf ("%s (%d)", name, i);
        i++;
    }

    g_free (name);
    g_free (ext);

    return unique_name;
}

static int
archive_multi (PackDirData *data, GList *dirent_list,
               Progress *progress)
{
    GList *iter;
    SeafDirent *dirent;
    GList *file_list = NULL;

    for (iter = dirent_list; iter; iter = iter->next) {
        char *unique_name = NULL;
        if (progress->canceled) {
            string_list_free (file_list);
            return -1;
        }
        dirent = iter->data;
        if (S_ISREG(dirent->mode)) {
            unique_name = generate_unique_filename (dirent->name, file_list);
            file_list = g_list_prepend (file_list, unique_name);
            if (add_file_to_archive (data, "", unique_name, dirent) < 0) {
                string_list_free (file_list);
                seaf_warning ("Failed to archive file: %s.\n", dirent->name);
                return -1;
            }
            g_atomic_int_inc (&progress->zipped);
        } else if (S_ISDIR(dirent->mode)) {
            unique_name = generate_unique_filename (dirent->name, file_list);
            file_list = g_list_prepend (file_list, unique_name);
            if (archive_dir (data, dirent->id, unique_name, progress) < 0) {
                string_list_free (file_list);
                seaf_warning ("Failed to archive dir: %s.\n", dirent->name);
                return -1;
            }
        }
    }

    string_list_free (file_list);
    return 0;
}

int
pack_files (const char *store_id,
            int repo_version,
            const char *dirname,
            void *internal,
            SeafileCrypt *crypt,
            gboolean is_windows,
            Progress *progress)
{
    int ret = 0;
    PackDirData *data = NULL;

    data = pack_dir_data_new (store_id, repo_version, dirname,
                              crypt, is_windows);
    if (!data) {
        seaf_warning ("Failed to create pack dir data for %s.\n",
                      strcmp (dirname, "")==0 ? "multi files" : dirname);
        return -1;
    }

    progress->zip_file_path = data->tmp_zip_file;

    if (strcmp (dirname, "") != 0) {
        // Pack dir
        if (archive_dir (data, (char *)internal, "", progress) < 0) {
            if (progress->canceled)
                seaf_warning ("Zip task for dir %s in repo %.8s canceled.\n", dirname, store_id);
            else
                seaf_warning ("Failed to archive dir %s in repo %.8s.\n", dirname, store_id);
            ret = -1;
        }
    } else {
        // Pack multi
        if (archive_multi (data, (GList *)internal, progress) < 0) {
            if (progress->canceled)
                seaf_warning ("Archiving multi files in repo %.8s canceled.\n", store_id);
            else
                seaf_warning ("Failed to archive multi files in repo %.8s.\n", store_id);
            ret = -1;
        }
    }

    if (archive_write_free (data->a) < 0) {
        seaf_warning ("Failed to archive write finish for %s in repo %.8s.\n",
                      strcmp (dirname, "")==0 ? "multi files" : dirname, store_id);
        ret = -1;
    }

    close (data->tmp_fd);
    free (data);

    return ret;
}
#endif
