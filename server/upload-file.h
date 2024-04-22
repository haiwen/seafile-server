#ifndef UPLOAD_FILE_H
#define UPLOAD_FILE_H

#ifdef HAVE_EVHTP
int
upload_file_init (evhtp_t *evhtp, const char *http_temp_dir);
#endif

#endif
