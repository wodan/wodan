#ifndef _UTIL_H_
#define _UTIL_H_

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"

/**
 * determines if a file or directory is writable
 * @param p memory pool
 * @param path the path to check
 * @retval 1 if writable
 * @retval 0 if not writable
 */
int util_file_is_writable(apr_pool_t *p, const char *path);
#endif //_UTIL_H_
