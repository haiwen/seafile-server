#ifndef ACCESS_FILE_H
#define ACCESS_FILE_H

int
access_file_init (evhtp_t *htp);

gboolean
parse_range_val (const char *byte_ranges, guint64 *pstart, guint64 *pend,
                 guint64 fsize);

#endif
