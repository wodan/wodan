/**
 * @file util.c
 *
 * Implements different utility functions that are used by Wodan2
 */
#include "util.h"

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"

#include "apr_file_info.h"

int util_file_is_writable(apr_pool_t *p, const char *path)
{
	apr_finfo_t file_info;
	apr_uid_t user_id;
	apr_gid_t group_id;
	
	apr_stat(&file_info, path, APR_FINFO_USER | APR_FINFO_GROUP |
		APR_FINFO_PROT, p);
	apr_uid_current(&user_id, &group_id, p);
	
	if (file_info.protection & APR_UWRITE)
	 	return 1;
	 return 0;
}