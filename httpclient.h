/** $Id: httpclient.h 162 2005-02-16 15:36:06Z ilja $
 *(c) 2000-2005 IC&S, The Netherlands
 */

#ifndef HTTPCLIENT_H
#define HTTPCLIENT_H

#include "datatypes.h"
#include "util.h"
#include "networkconnector.h"

#include "httpd.h"
#include "apr_tables.h"
#include "apr_time.h"

#include <time.h>
#include <sys/time.h>

/**
 * Method that connects to the backend and gets data from it
 * @param host The ReverseProxyPass url
 * @param httpresponse The httpresponse structure to put the data in
 * @param r The request record
 * @param backend_timeout timeout for the backend
 * @param cache_file_time creation time of cache file (or (time_t) 0 if there's
 * 		no cache file.
 * @return The result code returned by the backend
 * 
 */
int http_proxy (wodan2_config_t *config, const char* host, char* uri, 
	struct httpresponse* httpresponse, request_rec *r, 
	struct timeval backend_timeout, apr_time_t cache_file_time);


#endif
