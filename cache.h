/** $Id: cache.h 162 2005-02-16 15:36:06Z ilja $
 *(c) 2000-2005 IC&S, The Netherlands
 */

#ifndef CACHE_H
#define CACHE_H

#include <time.h>

#include "datatypes.h"

#include "apr_time.h"

/**
 * This is used when allocating buffers to work with
 */
#define MAX_CACHEFILE_PATH_LENGTH 256

/**
 * used for signaling if a URI is present in the cache
 */
typedef enum {
	WODAN_CACHE_PRESENT,        /** present and fresh */
	WODAN_CACHE_PRESENT_EXPIRED,/** present but expired */
	WODAN_CACHE_NOT_PRESENT,     /** not present */
	WODAN_CACHE_NOT_CACHEABLE,   /** cannot be cached */
	WODAN_CACHE_404              /** cached 404 */
} WodanCacheStatus_t;

/**
 * Look wether or not the request can be handled from the cache
 * @param r the request record
 * @param config the wodan configuration
 * @param[out] cache_file_time the time the cache file was created.
 * @return
 *      - WODAN_CACHE_PRESENT if present and fresh
 *      - WODAN_CACHE_PRESENT_EXPIRED if present but expired
 *      - WODAN_CACHE_NOT_PRESENT not present in cache 
 *      - WODAN_CACHE_NOT_CACHEABLE for requests that cannot be cached
 *      - WODAN_CACHE_404 for requests that are cached as a 404 (not found)
 */
WodanCacheStatus_t cache_get_status(wodan2_config_t *config, request_rec *r, 
	apr_time_t *cache_file_time);

/**
 * Look whether the request can be handled from the cache.
 * @param r The request record
 * @param config the wodan configuration 
 * @param httpresponse The httpresponse record the data should be set in
 * @return 1 of request can be handled from cache 0 otherwise
 */
int cache_read_from_cache (wodan2_config_t *config, request_rec *r, 
	struct httpresponse* httpresponse);

/**
 * get cache file
 * @param r request_rec
 * @param config the wodan configuration
 * @param httpresponse the httpresponse from the backend
 * @retval NULL if not being cached
 * @retval apr_file_t pointer otherwise.
 */
apr_file_t *cache_get_cachefile(wodan2_config_t *config, request_rec *r,
	struct httpresponse *httpresponse);

/**
 * close the cache file.
 * @param r request_rec
 * @param config the wodan configuration
 * @param cachefile the cache file, may be NULL
 */
void cache_close_cachefile(wodan2_config_t *config, request_rec *r, 
	apr_file_t *cachefile);

/**
 * update the timestamp in the cache file 
 * @param r request_rec
 * @param config the wodan configuration
 */
int cache_update_expiry_time(wodan2_config_t *config, request_rec *r);
#endif
