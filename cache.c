/** $Id: cache.c 162 2005-02-16 15:36:06Z ilja $
 *(c) 2000-2005 IC&S, The Netherlands
 */

#include <sys/stat.h>
#include <string.h>

#include "cache.h"
#include "datatypes.h"
#include "match.h"
#include "util.h"

#include "httpd.h"
#include "http_log.h"
#include "apr_md5.h"
#include "apr_strings.h"
#include "apr_file_io.h"

#include <string.h>

/**
 * \brief check if the CacheDir directive is set
 * \param config the server configuration
 * \return 
 *     - 0 if not set
 *     - 1 if set
 */
static int is_cachedir_set(wodan2_config_t *config);

/**
 * Return whether the http result code is cacheable
 * @param httpcode The http code to check
 * @param cache404s Specifies if 404s are treated as cacheable
 * @retval 1 if return code is cachable
 * @retval 0 if return code is not cachable
 */
static int is_response_cacheable (int httpcode, int cache404s);

/**
 * return the name of the (nested) subdirectory used for
 * the cache file. The name of the directory is determined
 * by the name of the cache file and the number of levels
 * the directory has to be nested. A nesting depth of 
 * 2 and a cachefile of the name "abcdef" will result in
 * a name like: "a/b/" for the directory. The nr parameter
 * determines which part of the nested subdirectory will
 * be returned, counting from 0. In the above example, if
 * nr is 0, 'a' will be returned.
 * @param r request record
 * @param config the wodan configuration
 * @param cachefilename name of cachefile
 * @param nr which part of the complete directory to return.
 */
static char *get_cache_file_subdir(wodan2_config_t *config, request_rec *r,
	char *cachefilename, int nr);
	
/**
 * return the name of the cachefile
 * @param r request record
 * @param config the wodan configuration
 * @param unparsed_uri the unparsed URI
 * @param[out] filename will hold the filename
 * @retval 0 on error
 * @retval 1 on success 
 */
static int get_cache_filename(wodan2_config_t *config, request_rec *r,
	char *unparsed_uri, char **filename);
	
WodanCacheStatus_t cache_get_status(wodan2_config_t *config, request_rec *r, 
	time_t *cache_file_time)
{
	char* cachefilename;
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	int status;
	int interval_time;

	*cache_file_time = (time_t) 0;
	
	if(r->method_number != M_GET && !r->header_only)
		return WODAN_CACHE_NOT_CACHEABLE;

	// if the CacheDir directive is not set, we cannot read from cache
	if (!is_cachedir_set(config))
		return WODAN_CACHE_NOT_PRESENT;

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		     "Searching Cache file");	
	get_cache_filename(config, r, r->unparsed_uri, &cachefilename);
	if (apr_file_open(&cachefile, cachefilename, APR_READ, APR_OS_DEFAULT, r->pool)
		!= APR_SUCCESS) {
		return WODAN_CACHE_NOT_PRESENT;
	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
		     "Cache file exists");

    /* Read url field, but we don't do anything with it */
	ap_hard_timeout("read url field", r);
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS)
		ap_kill_timeout(r);
	/* read expire interval field, but don't do anything with it */
	interval_time = 0;
	ap_hard_timeout("read expire interval field", r);
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		interval_time = atoi(buffer);
		ap_kill_timeout(r);
	}
	ap_hard_timeout("read expire field", r);
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		time_t time;
	
	    ap_kill_timeout(r);
		
		/* An empty line will return 0 */
		time = ap_parseHTTPdate(buffer);
		
		/* time - interval_time = time that file was created */
		*cache_file_time = time - (time_t) interval_time;
		
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Cachefile expires %s (%ld), now %s (%ld)",
			     ap_ht_time(r->pool,time, "%a %d %b %Y %T %Z",1),
			     (long int) time, 
			     ap_ht_time(r->pool, (r->request_time), 
					"%a %d %b %Y %T %Z",1), 
			     (long int) r->request_time);

		if((r->request_time > time) && (!config->run_on_cache))
		{
			apr_file_close(cachefile);
	         return WODAN_CACHE_PRESENT_EXPIRED;
		}

		ap_hard_timeout("check status line for 404", r);
		/* Read empty line before status line */
		apr_file_gets(buffer, BUFFERSIZE, cachefile);
		if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
			ap_kill_timeout(r);
			status = atoi(buffer);
			if (status == HTTP_NOT_FOUND) {
				ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,
				             r->server, "File in cache has status 404");
				ap_pfclose(r->pool, cachefile);
				return WODAN_CACHE_404;
			}
		}
		
		apr_file_close(cachefile);
		return WODAN_CACHE_PRESENT;
   	}
	apr_file_close(cachefile);
	return WODAN_CACHE_NOT_PRESENT;
}

int cache_read_from_cache (wodan2_config_t *config, request_rec *r,
	struct httpresponse* httpresponse)
{
	char* cachefilename;
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	int write_error;
	int content_length = 0;
	int body_bytes_written = 0;
	
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		     "Searching Cache file");	

	get_cache_filename(config, r, r->unparsed_uri, &cachefilename);
	apr_file_open(&cachefile, cachefilename, APR_READ, APR_OS_DEFAULT, r->pool);
    /* Read url field, but we don't do anything with it */
	ap_hard_timeout("read url field", r);
    if(apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS)
		ap_kill_timeout(r);
	/* same for expire interval field */
	ap_hard_timeout("read expire interval field", r);
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS)
		ap_kill_timeout(r);
	/* same for expire field */
	ap_hard_timeout("read expire field", r);
	if(apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS)
		ap_kill_timeout(r);
	ap_hard_timeout("read response code", r);	
	if(apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		ap_kill_timeout(r);
		httpresponse->response = atoi(buffer);
	}
	else {
		//Remove file and return 0
		ap_kill_timeout(r);
		ap_pfclose(r->pool, cachefile);
		ap_hard_timeout("removing cache file", r);
		unlink(cachefilename);
		ap_kill_timeout(r);
		return 0;
	}

	ap_hard_timeout("proxy receive response headers", r);
    while(apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS)
	{
		int counter = 0;
		char* key;
		char* bufferpointer;
                if(strcasecmp(buffer, CRLF) == 0)
	                break;
                bufferpointer = &buffer[0];
                key = ap_getword(r->pool, (const char**) &bufferpointer, ':');
                bufferpointer = util_skipspaces(bufferpointer);
                while(bufferpointer[counter])
                {
	            		if(bufferpointer[counter] == CR || 
	                		bufferpointer[counter] == LF || 
	                		bufferpointer[counter] == '\n')
                        {
	                        bufferpointer[counter] = '\0';
	                        break;
                        }
                        counter++;
                }
                ap_table_add(httpresponse->headers, key, bufferpointer);
		if (strcasecmp(key, "Content-Length") == 0) {
			content_length = atoi(bufferpointer);
		}
         ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
         	"Added header: \"%s\", value: \"%s\"", key, bufferpointer);
	}
	adjust_headers_for_sending(r, httpresponse);
	ap_send_http_header(r);
	
    ap_kill_timeout(r);

	if(r->header_only) {
		return 1;
	}
	
	ap_hard_timeout("proxy receive body", r);
	write_error = 0;
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
		     "going to write %d bytes to client", content_length);
	/* TODO add checking of errors in reading from file */
	while(!apr_file_eof(cachefile) && !write_error) {
		apr_size_t bytes_read;
		int bytes_written;

		apr_file_read_full(cachefile, buffer, BUFFERSIZE, &bytes_read);
		ap_reset_timeout(r);
		
		bytes_written = ap_rwrite(buffer, bytes_read, r);
		body_bytes_written += bytes_written;
		if (bytes_read != bytes_written || bytes_written == -1) {
			write_error = 1;
		}

		if(bytes_read < BUFFERSIZE)
	                break;
	}
	
	/* TODO add error checking for file reading */
	if (write_error) {
		const char *user_agent;

		user_agent = apr_table_get(r->headers_in, "User-Agent");
		if (user_agent == NULL) 
			user_agent = "unknown";
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
			     "error writing to socket. "
			     "Bytes written/Body length = %d/%d, "
			     "User-Agent: %s",
			     body_bytes_written, content_length, user_agent);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ap_kill_timeout(r);	

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		"Returned answer from cache");
		
	return 1;
}

static int find_cache_time(wodan2_config_t *config,
			 request_rec *r,
			 struct httpresponse *httpresponse)
{
	int cachetime;
	wodan2_default_cachetime_header_t *default_cachetime_header_config;
	wodan2_default_cachetime_regex_t *default_cachetime_regex_config;
	wodan2_default_cachetime_t *default_cachetime_config;
	
	if (httpresponse != NULL) {
		default_cachetime_header_config = 
			default_cachetime_header_match(config, httpresponse->headers);
		if (default_cachetime_header_config != NULL) {
			cachetime = default_cachetime_header_config->cachetime;
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
			       r->server,
			       "Got cachetime from header match! "
			       "cachetime = %d",
			       cachetime);
		  return cachetime;
		}
	}

	default_cachetime_regex_config =
		default_cachetime_regex_match(config, r->uri);
	if (default_cachetime_regex_config != NULL) {
		cachetime = 
			default_cachetime_regex_config->cachetime;
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Got cachetime from regex match! cachetime = %d",
			     cachetime);
		return cachetime;
	}
	
	default_cachetime_config = 
		default_cachetime_longest_match(config, r->uri);
	if (default_cachetime_config != NULL) {
		cachetime = default_cachetime_config->cachetime;
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
			     r->server,"Got cachetime from normal match "
			     "cachetime = %d", cachetime);
		return cachetime;
	}
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		     "Using normal cachetime %d", DEFAULT_CACHETIME);
	return DEFAULT_CACHETIME;
}

static time_t parse_xwodan_expire(request_rec *r,
				  char *xwodan, int cachetime, 
				  int *cachetime_interval) 
{
	time_t expire_time;
	char *c;

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "entering %s", __func__);
	*cachetime_interval = 0;
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "Parsing expire header: "
		     "\"%s\"", skipspaces(&xwodan[6]));
	c = util_skipspaces(&xwodan[6]);
	if ( *c >= '0' && *c <= '9' ) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Expire header is numeric. Assuming addition of "
			     "interval to current time." );
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Specified interval: %s", c );
		*cachetime_interval = string_to_seconds(c);
		expire_time = r->request_time + *cachetime_interval;
	} else {
		/* IB 2004-12-07: there's no information on this next 
		 * piece of code
		 * in  the README.. Is it safe to delete this or 
		 * is there code that relies on it? */
		expire_time = ap_parseHTTPdate(skipspaces(&xwodan[6]));
		if (expire_time == 0) { 
			expire_time = r->request_time + cachetime;
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
				     r->server, "Received 0 expire time, "
				     "using default cache time" );
		}	
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Time: %ld", (long int) expire_time);
		if(r->request_time > expire_time) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
				     r->server, "Expire date is before "
				     "request time, won't cache response");
			return 0;
		} else 
			*cachetime_interval = expire_time - r->request_time;

	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "leaving %s", __func__);

	return expire_time;
}

char *get_expire_time(wodan2_config_t *config,
		      request_rec *r, struct httpresponse *httpresponse,
		      int *cachetime_interval)
{
	int cachetime;
	char *expire = NULL;
	char *xwodan;
	time_t expire_time = 0;

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "entering %s", __func__);
	
	*cachetime_interval = 0;
	cachetime = find_cache_time(config, r, httpresponse);
	/* check X-Wodan header */
	if (httpresponse && 
	    (xwodan = (char *) ap_table_get(httpresponse->headers, "X-Wodan"))
	    != NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Found an X-Wodan header \"%s\"", xwodan);
		if (strcasecmp(xwodan, "no-cache") == 0) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
				     r->server, "Header is 'no-cache'. "
				     "Not caching..." );
			return NULL;
		} else if (strncasecmp(xwodan, "expire", 6) == 0) {
			expire_time = parse_xwodan_expire(r, xwodan, 
							  cachetime,
							  cachetime_interval);
			if (expire_time == 0)
				return NULL;
			expire = ap_ht_time(r->pool, expire_time, 
					    "%a %d %b %Y %T %Z", 1);
		} else {
			if (cachetime == -1) {
				ap_log_error(APLOG_MARK, 
					     APLOG_NOERRNO|APLOG_DEBUG, 0,
					     r->server, 
					     "DefaultCacheTime in httpd.conf "
					     "is 'no-cache'. Not caching..." );
				return NULL;
			}
		}
	}

	if (expire == NULL) {
		expire_time = r->request_time + cachetime;
		*cachetime_interval = cachetime;
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "No expire-header found. Using default cache "
			     " time" );
		expire = ap_ht_time(r->pool, expire_time, "%a %d %b %Y %T %Z",
				    1);
	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "leaving %s", __func__);

	return expire;
}

apr_file_t *open_cachefile(wodan2_config_t *config, request_rec *r)
{
	apr_file_t *cachefile = NULL;
	char *cachefilename;
	int i;
	char *subdir;
	int result;
	struct stat dir_status;

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "entering %s", __func__);

	get_cache_filename(config, r, r->unparsed_uri, &cachefilename);
	
	ap_hard_timeout( "Creating subdirectories as needed", r );
	for ( i = 0; i < config->cachedir_levels; i++ ) {
		subdir = get_cache_file_subdir(config, r, cachefilename, i);
		
		result = stat( subdir, &dir_status );
		if ( ( result != 0 ) || ( ! S_ISDIR( dir_status.st_mode ) ) )
			mkdir( subdir, 0770 );
	}
	ap_kill_timeout( r );

	ap_hard_timeout("opening cachefile", r);
	apr_file_open(&cachefile, cachefilename, 
		APR_WRITE | APR_CREATE | APR_TRUNCATE, APR_OS_DEFAULT,
		r->pool);
	ap_kill_timeout(r);
	if(cachefile == NULL)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "Error opening cache file, filename = %s, config->cachedir = %s", 
			     cachefilename, config->cachedir);
		return NULL;
	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, 
		     r->server, "leaving %s", __func__);

	return cachefile;
}

/**
 * @param cachefile the cache file
 * @param r request record
 * @param httpresponse httpresponse record
 * @param expire_time_string time at which cache expires.
 * @param expire_interval time interval between request and expire
 */
static int write_preamble(apr_file_t *cachefile, request_rec *r,
			  httpresponse_t *httpresponse, 
			  char *expire_time_string,
			  int expire_interval)
{
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "entering %s", __func__);

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
		     "Writing file");

	ap_hard_timeout("writing preamble", r);
	apr_file_printf(cachefile, "%s%s", r->unparsed_uri, CRLF);
	apr_file_printf(cachefile, "%d%s", expire_interval, CRLF);
	apr_file_printf(cachefile, "%s%s", expire_time_string, CRLF);
	apr_file_printf(cachefile, "%d%s", httpresponse->response, CRLF);
	/* TODO add error checking */
	//Write headers
	{
		int i;
		const apr_array_header_t *headers_array = apr_table_elts(httpresponse->headers);
		apr_table_entry_t *headers_elts = (apr_table_entry_t *) headers_array->elts;
		
		for(i = 0; i < headers_array->nelts; i++)
	        {
			apr_file_printf(cachefile, "%s: %s%s", headers_elts[i].key, 
				headers_elts[i].val, CRLF);
			/* TODO add error checking */
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
				     r->server, "writing header: "
				     "%s: %s", headers_elts[i].key,
				     headers_elts[i].val);
		}
	}
	//Write end of headers line
	apr_file_printf(cachefile, "%s", CRLF);
	ap_kill_timeout(r);
	/* TODO add  eror checking */
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "leaving %s", __func__);
	return 0;

}

apr_file_t *cache_get_cachefile(wodan2_config_t *config, request_rec *r, 
	struct httpresponse *httpresponse)
{
	apr_file_t *cache_file = NULL;
	char *expire = NULL;
	int expire_interval = 0;
	char *tempfile_template;

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "entering %s", __func__);
	
	if(!is_cachedir_set(config)) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "%s: cachedir not set.", __func__);

		return NULL;
	}

	if (r->method_number != M_GET ||
	    r->header_only ||
	    !is_response_cacheable(httpresponse->response, 
				   config->cache_404s)) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,
			     r->server, "Response isn't cacheable");
		return NULL;
	}
	
	if ((char *) ap_strcasestr(r->unparsed_uri, "cache=no") != NULL)
		return NULL;
	
	if ((expire = get_expire_time(config, r, httpresponse,
				      &expire_interval)) == NULL)
		return NULL;
	
	tempfile_template = apr_pstrdup(r->pool, "wodan_temp_XXXXXX");
	if (apr_file_mktemp(&cache_file, tempfile_template, 0, r->pool) != APR_SUCCESS)
		return NULL;
	
	/* write url, expire, cache constraint and headers */
	if (write_preamble(cache_file, r, httpresponse, expire,
			   expire_interval) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "error writing preamble to tempcachefile");
		apr_file_close(cache_file);
		return NULL;
	}
		
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "leaving %s", __func__);

	return cache_file;
}

void cache_close_cachefile(wodan2_config_t *config, request_rec *r,
	apr_file_t *temp_cachefile)
{
	apr_file_t *real_cachefile;
	char buffer[BUFFERSIZE];
	apr_size_t bytes_read, bytes_written;

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "entering %s", __func__);

	/* open the real cache file (until now, only a temporary file
	   was openened */
	if (temp_cachefile) {
		if ((real_cachefile = open_cachefile(config, r)) == NULL) {
			apr_file_close(temp_cachefile);
			return;
		}
		
		/* go to start of temporary cache file */
		apr_file_flush(temp_cachefile);
		apr_file_seek(temp_cachefile, APR_SET, (apr_off_t) 0);

		/* TODO add error checking */
		while(!apr_file_eof(temp_cachefile)) {
			apr_file_read_full(temp_cachefile, buffer, BUFFERSIZE, &bytes_read);
			apr_file_write_full(real_cachefile, buffer, BUFFERSIZE, &bytes_written);
			if (bytes_read != bytes_written) {
				// What now?
			}

			if(bytes_read < BUFFERSIZE)
				break;
		}
		/* TODO add error checking for file reads and writes */		
		apr_file_close(temp_cachefile);
		apr_file_flush(real_cachefile);
		apr_file_close(real_cachefile);
	}
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "leaving %s", __func__);
}		

int cache_update_expiry_time(wodan2_config_t *config, request_rec *r) 
{
	char *cachefilename;
	int expire_interval;
	char *expire_time_string;
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	apr_size_t bytes_written;

	get_cache_filename(config, r, r->unparsed_uri, &cachefilename);
	(void) get_expire_time(config, r, NULL, &expire_interval);
       
    if (apr_file_open(&cachefile, cachefilename, APR_WRITE, APR_OS_DEFAULT,
    		r->pool) != APR_SUCCESS) 
    		return -1;   
	
	/* skip URL field */
	ap_hard_timeout("read url field", r);
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS)
		ap_kill_timeout(r);
	ap_hard_timeout("read expire interval", r);
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS)
		ap_kill_timeout(r);
	/* calculate new expire_time */
	expire_interval = (int) strtol(buffer, NULL, 10);
	expire_time_string = ap_ht_time(r->pool, 
					(r->request_time + expire_interval), 
					"%a %d %b %Y %T %Z",1);
	ap_log_error(APLOG_MARK, 
		APLOG_NOERRNO|APLOG_DEBUG, 0,
		r->server, 
		"%s: new expire time = %s", __func__, expire_time_string);
	/* write new expire time field in cachefile */
	apr_file_write_full(cachefile, expire_time_string, strlen(expire_time_string),
		&bytes_written);
	if (bytes_written != strlen(expire_time_string)) {
		ap_log_error(APLOG_MARK, 
			APLOG_NOERRNO|APLOG_DEBUG, 0,
			r->server, 
			"%s: error writing to cachefile", __func__);
	
		apr_file_close_p(cachefile);
		return -1;
	}
	ap_log_error(APLOG_MARK, 
			APLOG_NOERRNO|APLOG_DEBUG, 0,
			r->server, 
			"%s: success writing to cachefile", __func__);
	 
	apr_file_flush(cachefile);
	apr_file_close(cachefile);
	return 0;
}

/** static functions down here */

static int get_cache_filename(wodan2_config_t *config, request_rec *r,
	char *unparsed_uri, char **filename )
{
	char md5[APR_MD5_DIGESTSIZE];
	char dir[MAX_CACHEFILE_PATH_LENGTH + 1];
	char *ptr;
	int i;

	apr_md5(md5, unparsed_uri, strlen(unparsed_uri));

	/* If cachedir + subdirs + md5sum don't fit in buffer, 
	 * we have a problem */
	if (strlen(config->cachedir) > 
	     (MAX_CACHEFILE_PATH_LENGTH - 32 - (2 * MAX_CACHEDIR_LEVELS))) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
			     "Cachefile pathname doesn't fit into buffer.");
		*filename = NULL;
		return 0;
	}

	apr_cpystrn(dir, config->cachedir, MAX_CACHEFILE_PATH_LENGTH + 1);
	ptr = &dir[0] + (int) strlen(dir);
	
	if (*ptr == '/')
		ptr--;

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		      "Cachedir levels: %d", config->cachedir_levels);	
	for (i = 0; i < config->cachedir_levels; i++) {
		ptr[0] = '/';
		ptr[1] = md5[i];
		ptr += 2;
	}
	*ptr = '\0';

	*filename = ap_make_full_path(r->pool, dir, md5);

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
		     "Cachefile pathname: %s", *filename);	

	return 1;
}
static char *get_cache_file_subdir(wodan2_config_t *config, request_rec *r, 
				   char *cachefilename, int nr)
{
	int count;
	char *ptr;
	char *buffer;

	buffer = apr_pstrdup(r->pool, cachefilename);

	/* We count back (from the end of the path) just enough parts 
	   to get the desired subdir */
	count = config->cachedir_levels - nr;
	ptr = buffer + (int) strlen( buffer );

	while ( ( count > 0 ) && ( ptr > buffer ) ) {
		if ( *ptr == '/' ) {
			*ptr = '\0';
			count--;
		}
		ptr--;
	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		     "Requested subdir %d: %s", nr, buffer);
	return buffer;
}

static int is_response_cacheable (int httpcode, int cache404s)
{
	if (cache404s)
		if (httpcode == 404)
			return 1;

	if(httpcode >= 200 && httpcode < 400)
		return 1;
	else return 0;
}

static int is_cachedir_set(wodan2_config_t* config)
{
     if (config->is_cachedir_set)
		return 1;
	else 
		return 0;
}
