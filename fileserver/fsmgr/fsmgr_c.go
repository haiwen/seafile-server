package fsmgr

/*#cgo pkg-config: zlib jansson glib-2.0
#include <stdio.h>
#include <glib.h>
#include <zlib.h>
#include <jansson.h>

#define ZLIB_BUF_SIZE 16384

int
seaf_decompress (unsigned char *input, int inlen, unsigned char **output, int *outlen)
{
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char out[ZLIB_BUF_SIZE];
    GByteArray *barray;

    if (inlen == 0) {
        g_warning ("Empty input for zlib, invalid.\n");
        return -1;
    }

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        g_warning ("inflateInit failed.\n");
        return -1;
    }

    strm.avail_in = inlen;
    strm.next_in = input;
    barray = g_byte_array_new ();

    do {
        strm.avail_out = ZLIB_BUF_SIZE;
        strm.next_out = out;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret < 0) {
            g_warning ("Failed to inflate.\n");
            goto out;
        }
        have = ZLIB_BUF_SIZE - strm.avail_out;
        g_byte_array_append (barray, out, have);
    } while (ret != Z_STREAM_END);

out:
    (void)inflateEnd(&strm);

    if (ret == Z_STREAM_END) {
        *outlen = barray->len;
        *output = g_byte_array_free (barray, 0);
        return 0;
    } else {
        g_byte_array_free (barray, 1);
        return -1;
    }
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func (seafile *Seafile) unmarshal(b []byte) error {
	if b == nil || len(b) == 0 {
		err := fmt.Errorf("failed to load seafile json object")
		return err
	}
	object := C.json_loadb((*C.char)(unsafe.Pointer(&b[0])), C.ulong(len(b)), 0, nil)
	if unsafe.Pointer(object) == C.NULL {
		err := fmt.Errorf("failed to load seafile json object2")
		return err
	}

	err := seafile.fillSeafileFromJsonObject(object)

	C.json_decref(object)

	return err
}

func (seafile *Seafile) fillSeafileFromJsonObject(object *C.json_t) error {
	seafile.Version = int(jsonGetIntMember(object, "version"))
	seafile.FileType = int(jsonGetIntMember(object, "type"))
	seafile.FileSize = uint64(jsonGetIntMember(object, "size"))
	seafile.FileID = jsonGetStringMember(object, "file_id")

	cKey := C.CString("block_ids")
	block_id_array := C.json_object_get(object, cKey)
	C.free(unsafe.Pointer(cKey))
	if unsafe.Pointer(block_id_array) == C.NULL {
		err := fmt.Errorf("no block id array in seafile object")
		return err
	}
	n_blocks := C.json_array_size(block_id_array)

	for i := 0; i < int(n_blocks); i++ {
		block_id_obj := C.json_array_get(block_id_array, C.ulong(i))
		block_id := C.json_string_value(block_id_obj)
		if unsafe.Pointer(block_id) == C.NULL {
			err := fmt.Errorf("no block id in block id array")
			return err
		}
		seafile.BlkIDs = append(seafile.BlkIDs, C.GoString(block_id))
	}

	return nil
}

func (seafdir *SeafDir) unmarshal(b []byte) error {
	if b == nil || len(b) == 0 {
		err := fmt.Errorf("failed to load seafile json object")
		return err
	}
	object := C.json_loadb((*C.char)(unsafe.Pointer(&b[0])), C.ulong(len(b)), 0, nil)
	if unsafe.Pointer(object) == C.NULL {
		err := fmt.Errorf("failed to load seafile json object2")
		return err
	}

	err := seafdir.fillSeaDirFromJsonObject(object)

	C.json_decref(object)

	return err
}

func (seafdir *SeafDir) fillSeaDirFromJsonObject(object *C.json_t) error {
	seafdir.Version = int(jsonGetIntMember(object, "version"))
	seafdir.DirType = int(jsonGetIntMember(object, "type"))
	seafdir.DirID = jsonGetStringMember(object, "dir_id")

	cKey := C.CString("dirents")
	dirent_array := C.json_object_get(object, cKey)
	C.free(unsafe.Pointer(cKey))
	if unsafe.Pointer(dirent_array) == C.NULL {
		err := fmt.Errorf("no dirents in dir object")
		return err
	}
	n_dirents := C.json_array_size(dirent_array)

	for i := 0; i < int(n_dirents); i++ {
		dirent_obj := C.json_array_get(dirent_array, C.ulong(i))
		if unsafe.Pointer(dirent_obj) == C.NULL {
			err := fmt.Errorf("no dirent in dirent array")
			return err
		}
		seafdir.fillSeafDirentFromJsonObject(dirent_obj)
	}

	return nil
}

func (seafdir *SeafDir) fillSeafDirentFromJsonObject(object *C.json_t) {
	dirent := new(SeafDirent)
	dirent.Mode = uint32(jsonGetIntMember(object, "mode"))
	dirent.ID = jsonGetStringMember(object, "id")
	dirent.Name = jsonGetStringMember(object, "name")
	dirent.Mtime = jsonGetIntMember(object, "mtime")
	dirent.Modifier = jsonGetStringMember(object, "modifier")
	dirent.Size = jsonGetIntMember(object, "size")

	seafdir.Entries = append(seafdir.Entries, dirent)
}

func jsonGetIntMember(object *C.json_t, key string) int64 {
	cKey := C.CString(key)
	integer := C.json_object_get(object, cKey)
	C.free(unsafe.Pointer(cKey))
	return int64(C.json_integer_value(integer))
}

func jsonGetStringMember(object *C.json_t, key string) string {
	cKey := C.CString(key)
	str := C.json_object_get(object, cKey)
	C.free(unsafe.Pointer(cKey))
	if unsafe.Pointer(str) == C.NULL {
		return C.GoString((*C.char)(C.NULL))
	}
	return C.GoString(C.json_string_value(str))
}

func uncompress(p []byte) ([]byte, error) {
	var c_out *C.uchar
	var outlen C.int

	if p == nil || len(p) == 0 {
		err := fmt.Errorf("empty input for zlib")
		return nil, err
	}
	ret := C.seaf_decompress((*C.uchar)(unsafe.Pointer(&p[0])), C.int(len(p)), &c_out, &outlen)
	if ret < 0 {
		err := fmt.Errorf("failed to uncompress data")
		return nil, err
	}

	out := []byte(C.GoStringN((*C.char)(unsafe.Pointer(c_out)), outlen))

	C.free(unsafe.Pointer(c_out))

	return out, nil
}
