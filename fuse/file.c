#include "common.h"

#define FUSE_USE_VERSION  26
#include <fuse.h>

#include <glib.h>
#include <glib-object.h>

#include <seaf-db.h>

#include "log.h"
#include "utils.h"

#include "seaf-fuse.h"

/* An open file: its file object and where each of its blocks starts. */
struct FuseFile {
    char store_id[37];
    int version;
    Seafile *file;
    /* offsets[i] is the start of block i, offsets[n_blocks] the end of the last. */
    guint64 *offsets;

    /* The block read last and the file position of its next byte, so that a
     * sequential read continues where the previous one stopped. */
    GMutex lock;
    BlockHandle *handle;
    int block;
    guint64 pos;
};

#define SKIP_BUF_SIZE (64 * 1024)

FuseFile *
fuse_file_open (SeafileSession *seaf, const char *store_id, int version,
                const char *file_id)
{
    Seafile *file;
    FuseFile *ff;
    BlockMetadata *bmd;
    int i;

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr, store_id, version, file_id);
    if (!file)
        return NULL;

    ff = g_new0 (FuseFile, 1);
    memcpy (ff->store_id, store_id, 36);
    ff->version = version;
    ff->file = file;
    ff->offsets = g_new0 (guint64, file->n_blocks + 1);
    g_mutex_init (&ff->lock);

    for (i = 0; i < file->n_blocks; i++) {
        bmd = seaf_block_manager_stat_block (seaf->block_mgr, store_id, version,
                                             file->blk_sha1s[i]);
        if (!bmd) {
            seaf_warning ("Failed to stat block %s:%s.\n", store_id, file->blk_sha1s[i]);
            fuse_file_free (seaf, ff);
            return NULL;
        }
        ff->offsets[i + 1] = ff->offsets[i] + bmd->size;
        g_free (bmd);
    }

    return ff;
}

static void
close_block (SeafileSession *seaf, FuseFile *ff)
{
    if (!ff->handle)
        return;
    seaf_block_manager_close_block (seaf->block_mgr, ff->handle);
    seaf_block_manager_block_handle_free (seaf->block_mgr, ff->handle);
    ff->handle = NULL;
}

void
fuse_file_free (SeafileSession *seaf, FuseFile *ff)
{
    if (!ff)
        return;
    close_block (seaf, ff);
    g_mutex_clear (&ff->lock);
    seafile_unref (ff->file);
    g_free (ff->offsets);
    g_free (ff);
}

/* Makes block i the open block with its next read at file position pos.
 * Blocks are read forward only: a position before the current one reopens
 * the block, and the bytes up to pos are read and discarded. */
static int
seek_block (SeafileSession *seaf, FuseFile *ff, int i, guint64 pos)
{
    char *skip = NULL;
    int n;

    if (!ff->handle || ff->block != i || ff->pos > pos) {
        close_block (seaf, ff);
        ff->handle = seaf_block_manager_open_block (seaf->block_mgr, ff->store_id,
                                                    ff->version,
                                                    ff->file->blk_sha1s[i],
                                                    BLOCK_READ);
        if (!ff->handle) {
            seaf_warning ("Failed to open block %s:%s.\n", ff->store_id,
                          ff->file->blk_sha1s[i]);
            return -1;
        }
        ff->block = i;
        ff->pos = ff->offsets[i];
    }

    while (ff->pos < pos) {
        if (!skip)
            skip = g_malloc (SKIP_BUF_SIZE);
        n = seaf_block_manager_read_block (seaf->block_mgr, ff->handle, skip,
                                           MIN (SKIP_BUF_SIZE, pos - ff->pos));
        if (n <= 0) {
            seaf_warning ("Failed to read block %s:%s.\n", ff->store_id,
                          ff->file->blk_sha1s[i]);
            close_block (seaf, ff);
            g_free (skip);
            return -1;
        }
        ff->pos += n;
    }

    g_free (skip);
    return 0;
}

int read_file(SeafileSession *seaf, FuseFile *ff, char *buf, size_t size,
              off_t offset)
{
    Seafile *file = ff->file;
    guint64 pos = offset;
    guint64 end = MIN (pos + size, ff->offsets[file->n_blocks]);
    int lo, hi, mid, i, len, n;
    int ret = 0;

    if (pos >= end)
        return 0;

    /* the last block that starts at or before pos */
    lo = 0;
    hi = file->n_blocks - 1;
    while (lo < hi) {
        mid = (lo + hi + 1) / 2;
        if (ff->offsets[mid] <= pos)
            lo = mid;
        else
            hi = mid - 1;
    }

    g_mutex_lock (&ff->lock);
    for (i = lo; pos < end; i++) {
        len = MIN (end, ff->offsets[i + 1]) - pos;
        if (len == 0)
            continue;

        if (seek_block (seaf, ff, i, pos) < 0) {
            ret = -EIO;
            break;
        }

        n = seaf_block_manager_read_block (seaf->block_mgr, ff->handle,
                                           buf + (pos - offset), len);
        if (n != len) {
            seaf_warning ("Failed to read block %s:%s.\n", ff->store_id,
                          file->blk_sha1s[i]);
            close_block (seaf, ff);
            ret = -EIO;
            break;
        }
        ff->pos += n;
        pos += n;
    }
    g_mutex_unlock (&ff->lock);

    return ret < 0 ? ret : (int)(pos - offset);
}
