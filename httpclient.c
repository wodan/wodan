/** $Id: httpclient.c 162 2005-02-16 15:36:06Z ilja $
 *(c) 2000-2005 IC&S, The Netherlands
 */


#include "cache.h"
#include "httpclient.h"

#include "httpd.h"
#include "http_log.h"

#include "apr_date.h"
#include "apr_file_io.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_time.h"
#include "apr_uri.h"

#include <errno.h>
#include <string.h>

/**
 * get all parts of the backend url
 * @param[in] pool pointer to memory pool
 * @param[in] proxyurl the complete destination url
 * @param[in] uri the requested uri
 * @param[out] desthost destination host
 * @param[out] destport destination port
 * @param[out] destpath destination path
 * @param[out] dest_host_and_port host:port (e.g. www.ic-s.nl:80)
 * @param[out] do_ssl will be set to one if we need to do ssl to
 *             the backend.
 */
static apr_status_t get_destination_parts(apr_pool_t *p,
				 const char *proxy_url, const char *uri,
				 char **dest_host,
				 int *dest_port, char **dest_path,
				 char **dest_host_and_port,
				 int *do_ssl);

/**
 * send request line and Host header
 * @param connection connection struct
 * @param r request record
 * @param dest_path destination path
 * @param modified_time set 'If-Modified-Since'-header 
 * @retval -1 on error.
 */
static int send_request(network_connection_t *connection, 
			request_rec *r, const char *dest_host,
			const char *dest_path, apr_time_t modified_time);

/**
 * send request body
 * @param connection connection struct
 * @param r request record
 */
static int send_request_body(network_connection_t *connection,
			request_rec *r);

/**
 * add X-headers to table.
 * @param r request_rec
 * @param out_headers_to_backend table of headers to send to the backend.
 */
static void add_x_headers(const request_rec *r,
			  apr_table_t *out_headers_to_backend);

/**
 * send headers to client. Also sends the empty newline after headers.
 * @param connection connection struct
 * @param r request record
 * @param headers the headers
 * @retval OK on succes
 * @retval -1 on failure.
 */
static int send_headers(network_connection_t *connection, 
			 const request_rec *r, const apr_table_t *headers);

/**
 * does a request for a url to the backend.
 * @param connection connection struct
 * @param r request_rec
 * @param dest_host destination host
 * @param dest_path destination path
 * @param out_headers headers sent to backend
 * @param modified_time last modified time in cache
 */
static int send_complete_request(network_connection_t *connection,
			  request_rec *r,
			  const char *dest_host,
			  const char *dest_path,
			  apr_table_t *out_headers,
			  apr_time_t modified_time);

/** receive the whole response from the backend 
 * @param connection connection to backend
 * @param r request_rec
 * @param httpresponse will hold response
 * @return OK if finished
 */
static int receive_complete_response(wodan2_config_t *config,
	network_connection_t *connection, request_rec *r,  
	httpresponse_t *httpresponse);

/** receive status line from backend
 * @param connection connection to backend
 * @param r request_rec
 * @param httpresponse will hold response.
 * @return status, or -1 if no response
 */
static int receive_status_line(network_connection_t *connection, request_rec *r,
			struct httpresponse *httpresponse);

/**
 * receive headers from backend
 */
static int receive_headers(network_connection_t *connection, request_rec *r,
		     struct httpresponse *httpresponse);

/** receive the body of the response from the backend */
static int receive_body(wodan2_config_t *config, network_connection_t *connection, 
	request_rec *r, httpresponse_t *httpresponse, apr_file_t *cache_file);
/** adjust dates to one form */
static void adjust_dates(request_rec *r, struct httpresponse *httpresponse);

/** do the real work 
 * @param config the wodan configuration
 * @param proxyurl URL to proxy
 * @param uri URI to retrieve
 * @param[in,out] httpresponse httpresponse
 * @param r request_rec
 * @param cache_file_time creation time of cache file (or (time_t) 0 if there's
 * 		no cache file.
 * @retval OK if all ok
 * @retval HTTP_BAD_GATEWAY if problem connecting or retreiving
 */
static int do_http_proxy (wodan2_config_t *config, const char* proxyurl, char* uri, 
		   struct httpresponse* httpresponse, 
		   request_rec *r, 
		   apr_time_t cache_file_time);
		   
/**
 * Remove all connection based header from the table
 * Copied from mod_proxy
 */
static void ap_reverseproxy_clear_connection(apr_pool_t *p, apr_table_t *headers);



/**
 * entry point in this source file. Performs the whole process
 * of getting the requested content from the backend and writing
 * it to the client and the cache (if appropriate)
 * @param[in] proxyurl url of proxy
 * @param[in] uri of requested object.
 * @param[out] httpresponse response from backend
 * @param[in,out] r request record
 * @param cache_file_time creation time of cache file (or (time_t) 0 if there's
 * 		no cache file.
 * @retval HTTP_BAD_GATEWAY if error in connection .
 * @retval HTTP_GATEWAY_TIME_OUT if connection to backend timeout out.
 * @retval OK if connection OK.
 */
int http_proxy(wodan2_config_t *config, const char* proxyurl, char *uri,
	       struct httpresponse *httpresponse,
	       request_rec *r,
	       apr_time_t cache_file_time)
{
	int result = HTTP_BAD_GATEWAY;

	result = do_http_proxy(config, proxyurl, uri,
			       httpresponse, r, cache_file_time);
	
	return result;
}

static void ap_reverseproxy_clear_connection(apr_pool_t *p, apr_table_t *headers)
{
    const char *name;
    char *next = apr_pstrdup(p, apr_table_get(headers, "Connection"));

    /* Some proxies (Squid, ICS) use the non-standard "Proxy-Connection" 
       header. */
    apr_table_unset(headers, "Proxy-Connection");

    if (next != NULL) {
       while (*next) {
	       name = next;
	       while (*next && !apr_isspace(*next) && (*next != ','))
                    ++next;
               while (*next && (apr_isspace(*next) || (*next == ','))) {
                    *next = '\0';
                    ++next;
               }
               apr_table_unset(headers, name);
        }
        apr_table_unset(headers, "Connection");
    }

    apr_table_unset(headers,"Keep-Alive");
    apr_table_unset(headers,"Proxy-Authenticate");
    apr_table_unset(headers,"TE");
    apr_table_unset(headers,"Trailer");
    apr_table_unset(headers,"Transfer-Encoding");
    apr_table_unset(headers,"Upgrade");
}    

static apr_status_t get_destination_parts(apr_pool_t *p,
			  const char *proxy_url, const char *uri,
			  char **dest_host,
			  int *dest_port, char **dest_path,
			  char **dest_host_and_port,
			  int *do_ssl) 
{
	apr_uri_t uptr;
	char *tmp_path;
	int uri_parse_retval;
	
	if ((uri_parse_retval = apr_uri_parse(p, proxy_url, &uptr)) != APR_SUCCESS) {
		return uri_parse_retval;
	}
	
	*do_ssl = (strncmp(uptr.scheme, "https", 5) == 0) ? 1 : 0;

	*dest_host = apr_pstrdup(p, uptr.hostname);

	if (uptr.port_str == NULL)
		*dest_port = DEFAULT_HTTP_PORT;
	else
		*dest_port = uptr.port;

	/* for some reason, uptr.path isn't always at least '/' (the
	 * O'Reilly book says it should), so we have to check for that */
	if (uptr.path == NULL) 
	  tmp_path = apr_pstrdup(p, "");
	else {
	  tmp_path = apr_pstrdup(p, uptr.path);
	  /* tmp_path is "/" or longer, always ending in '/'. We need to
	   * strip this / */
	  if (tmp_path[(int) strlen(tmp_path) - 1] == '/') 
		  tmp_path[(int) strlen(tmp_path) - 1] = '\0';
	}

	*dest_path = apr_pstrcat(p, tmp_path, uri, NULL);

	*dest_host_and_port = apr_psprintf(p, "%s:%d", *dest_host, *dest_port);
	return APR_SUCCESS;
}

static int send_complete_request(network_connection_t *connection, request_rec *r, 
		const char *dest_host_and_port, const char *dest_path, apr_table_t *out_headers,
		apr_time_t modified_time) {
	int result;

	if(send_request(connection, r, dest_host_and_port, dest_path, modified_time) < 0)
		return -1;
	add_x_headers(r, out_headers);
	apr_table_set(out_headers, "Connection", "close");
	apr_table_unset(out_headers, "Via");
	if (send_headers(connection, r, out_headers) == -1)
		return -1;
	if (connection_flush_write_stream(connection, r) == -1)
		return -1;

	if((result = send_request_body(connection, r)))
		return result;
	
	return OK;
}

static int send_request(network_connection_t *connection, request_rec *r,
		const char *dest_host_and_port, const char *dest_path, apr_time_t modified_time) {
	const char *request_string;
	const char *host_header_string;
	
	request_string = apr_psprintf(r->pool, "%s %s HTTP/1.0%s",
				     r->method, dest_path, CRLF);
	if (connection_write_string(connection, r, request_string) == -1)
		return -1;
	host_header_string = apr_psprintf(r->pool, "Host: %s%s",
					 dest_host_and_port, CRLF);
	if (connection_write_string(connection, r, 
				    host_header_string) == -1)
		return -1;
	if (modified_time != APR_DATE_BAD) {
		char if_modified_header_value[APR_RFC822_DATE_LEN];
		const char *if_modified_header;
		if (apr_rfc822_date(&(if_modified_header_value[0]), modified_time) !=
			APR_SUCCESS) 
			return -1;
			
		if_modified_header = apr_psprintf(r->pool, "If-Modified-Since: %s%s",
				if_modified_header_value, CRLF);
		
		if (connection_write_string(connection, r, if_modified_header) == -1)
			return -1;
	} 
	return OK;
}

static void add_x_headers(const request_rec *r,
		   apr_table_t *out_headers_to_backend)
{
	const char *temp;

	/* Add X-Forwarded-For so the backend can find out where the 
	 * request came from. If there's already a X-Forwarded-For
	 * header, the remote_ip is added to that header */
	apr_table_mergen(out_headers_to_backend, "X-Forwarded-For",
			r->connection->remote_ip);
	/* With X-Forwarded-Host, the backend can determine the original
	 * Host: header send to Wodan */
	if ((temp = apr_table_get(r->headers_in, "Host"))) 
		apr_table_mergen(out_headers_to_backend, "X-Forwarded-Host",
				temp);
	/* Add this server (the server Wodan runs on) as the X-Forwarded-Server,
	   The backend can determine the frontend servername by this. */
	apr_table_mergen(out_headers_to_backend, "X-Forwarded-Server",
			r->server->server_hostname);
	/* Pass the protocol used for client<->wodan communication through
	 * to the backend. */
	apr_table_set(out_headers_to_backend, "X-Wodan-Protocol", r->protocol);
}

static int send_headers(network_connection_t *connection, 
		  const request_rec *r, const apr_table_t *headers) 
{
	int i;
	const char* header_end_string;
	
	const apr_array_header_t *headers_array = apr_table_elts(headers);
	apr_table_entry_t *headers_elts = (apr_table_entry_t *) headers_array->elts;
	for (i = 0; i < headers_array->nelts; i++) {
		const char *header_string;
		/* the following headers should not be sent to the
		   backend. */
		if(headers_elts[i].key == NULL || 
		   headers_elts[i].val == NULL || 
		   !strcasecmp(headers_elts[i].key, "Host") || 
		   !strcasecmp(headers_elts[i].key, "Keep-Alive") || 
		   !strcasecmp(headers_elts[i].key, "TE") || 
		   !strcasecmp(headers_elts[i].key, "Trailer") || 
		   !strcasecmp(headers_elts[i].key, 
			       "Transfer-Encoding") || 
		   !strcasecmp(headers_elts[i].key, 
			       "Proxy-Authorization") ||
		   !strcasecmp(headers_elts[i].key,
			       "If-Modified-Since") ||
		   !strcasecmp(headers_elts[i].key, "Cache-Control") ||
		   !strcasecmp(headers_elts[i].key, "If-None-Match"))
		{
			continue;
		}
		header_string = apr_psprintf(r->pool, "%s: %s%s",
					    headers_elts[i].key,
					    headers_elts[i].val, 
					    CRLF);
		if (connection_write_string(connection, r, 
					    header_string) == -1)
			return -1;
	}
	/* add empty line, signals end of headers */
	header_end_string = apr_psprintf(r->pool, "%s", CRLF);
	if (connection_write_string(connection, r,
				    header_end_string) == -1)
		return -1;

	return OK;
}

static int send_request_body(network_connection_t *connection, request_rec *r)
{
	int result;

	if ((result = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)))
		return result;
	
	if (ap_should_client_block(r)) {
		int nr_bytes_read;
		char buffer[BUFFERSIZE];

		while ((nr_bytes_read = 
			ap_get_client_block(r, buffer, BUFFERSIZE)) > 0) { 
			if (connection_write_bytes(connection, r,
						   buffer,
						   nr_bytes_read) == -1) 
				return -1;
		}
		if (connection_flush_write_stream(connection, r) == -1)
			return -1;
	}
	return OK;
}
       
static int receive_complete_response(wodan2_config_t *config, 
	network_connection_t *connection, request_rec *r, 
	httpresponse_t *httpresponse) 
{
	int status;
	int receive_headers_result;
	int receive_body_result;
	apr_file_t *cache_file = NULL;

	if ((status = receive_status_line(connection, r, httpresponse)) == -1) 
		return HTTP_BAD_GATEWAY;
	
	if (status == HTTP_NOT_FOUND) {
		if (config->cache_404s) {
			/* We have to duplicate the cache_get_cachefile call
			 * because it writes headers, and we don't want any
			 * headers in a 404 file. It only wastes space. */
			cache_file = cache_get_cachefile(config, r, httpresponse);
			cache_close_cachefile(config, r, cache_file);
			// flush content to client
			apr_file_flush(cache_file);
		}
			return HTTP_NOT_FOUND;
	}
	if (status == HTTP_NOT_MODIFIED) { /* = 304 */
		return status;
	}
	
	if ((receive_headers_result = receive_headers(connection, r, httpresponse)) !=
		OK) 
		return receive_headers_result;
		
	cache_file = cache_get_cachefile(config, r, httpresponse);
	adjust_headers_for_sending(config, r, httpresponse);
	
	if ((receive_body_result = receive_body(config, connection, r, httpresponse, 
				   cache_file)) != OK)
		return receive_body_result;

	return status;
}

static int receive_status_line(network_connection_t *connection, request_rec *r,
	httpresponse_t *httpresponse)
{
	const char *read_string;
	const char *http_string, *status_string;
	int status;

	read_string = connection_read_string(connection, r);
	if (read_string == NULL)
		return -1;

	http_string = ap_getword_white(r->pool, &read_string);
	status_string = ap_getword_white(r->pool, &read_string);
	
	ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,
		     r->server, "statusstr = %s", status_string);

	status = atoi(status_string);
	
	httpresponse->response = status;

	return status;
}

static int receive_headers(network_connection_t *connection, request_rec *r,
		    struct httpresponse *httpresponse)
{
	const char *read_header;
	char *header; // only used as a workaround for when read_header is
	// not big enough to store the incoming header, for
	// example with large Set-Cookie headers
	char *key, *val;
	int val_pos, len;
	
	header = 0;
	while((read_header = connection_read_string(connection, r))) {
		/* if read_header is NULL, this signals an error. Escape from here right
		 * away in that case */
		if (read_header == NULL)
			return HTTP_BAD_GATEWAY;
			
		if (strcasecmp(read_header, CRLF) == 0)
			break;
		
		len = 0;
		if(strlen(read_header) == BUFFERSIZE - 1)
		{
			if(header) len = strlen(header);
			header = (char *) realloc(header, (len + BUFFERSIZE));
			header = strncat(header, read_header, BUFFERSIZE);
			continue;
		}

		if(header) { // we append the final bytes of header here
            len = strlen(header);
            header = (char *) realloc(header, (len + BUFFERSIZE));
            header = strcat(header, read_header);
        }

		key = ap_getword(r->pool, header ? &header: &read_header, ':');
		val = apr_pstrdup(r->pool, header ? header : read_header);
		val = util_skipspaces(val);
		
		// strip whitespace from start and end.
		val_pos = 0;
		while(val[val_pos]) {
			if (val[val_pos] == CR || val[val_pos] == LF) {
				val[val_pos] = '\0';
				break;
			}
			val_pos++;
		}
		apr_table_add(httpresponse->headers, key, val);
		free(header);
		header = 0;
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Added header: \"%s\", value: \"%s\"", 
			     key, val);
	}
	/* adjust headers */
	ap_reverseproxy_clear_connection(r->pool, httpresponse->headers);
	adjust_dates(r, httpresponse);
	httpresponse->headers = apr_table_overlay(r->pool, r->err_headers_out, 
		httpresponse->headers);
	
	return OK;
}

static int receive_body(wodan2_config_t *config, network_connection_t *connection, 
	request_rec *r, httpresponse_t *httpresponse, apr_file_t *cache_file)
{
	char *buffer;
	int nr_bytes_read;
	int writtenbytes;
	int body_bytes_written;
	int backend_read_error, client_write_error, cache_write_error;

	buffer = apr_pcalloc(r->pool, BUFFERSIZE);

	body_bytes_written = 0;
	backend_read_error = 0;
	client_write_error = 0;
	cache_write_error = 0;

	while(1)
	{
		nr_bytes_read = connection_read_bytes(connection, r, buffer, BUFFERSIZE);
		//nr_bytes_read = fread(buffer, sizeof(char), BUFFERSIZE, 
		//		      connection->readstream);
		ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
			     r->server, "read %d bytes from backend",
			     nr_bytes_read);
		
		if (nr_bytes_read == -1) backend_read_error = 1;

		/* write to cache and check for errors */
		if (cache_file) {
			apr_size_t cache_bytes_written;
			apr_file_write_full(cache_file, buffer, nr_bytes_read, 
				&cache_bytes_written);
			/* TODO check for ferror */
			if ((int) cache_bytes_written < nr_bytes_read) {
				cache_write_error = 1;
				break;
			}
		}
					
		if (!r->header_only) {
			writtenbytes = ap_rwrite(buffer, nr_bytes_read, r);
			body_bytes_written += writtenbytes;
			/* escape from loop if there's an error */
			if (writtenbytes < 0 || 
			    writtenbytes != nr_bytes_read) {
			    client_write_error = 1;
				break;
			}
		}
			
		/* last escape hatch */
		if (nr_bytes_read == 0)
		if (nr_bytes_read == 0)
		if (nr_bytes_read == 0)
			break;
	}
	
	/* handle the possible errors */
	if (client_write_error) {
		/* add a more explicit error message to the error_log
		 * including User-Agent and Content-Length */
		const char *user_agent;
		const char *content_length_str;
		int content_length;
		
		user_agent = apr_table_get(r->headers_in, "User-Agent");
		if (user_agent == NULL)
			user_agent = "unknown";
		content_length_str = apr_table_get(httpresponse->headers,
						  "Content-Length");
		content_length = (content_length_str) ? 
			atoi(content_length_str): 0;
					
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
			     "Error writing to client. "
			     "Bytes written/total bytes = %d/%d, "
			     "User-Agent: %s",
			     body_bytes_written, content_length, user_agent);
		return HTTP_BAD_GATEWAY;
	}

	if (cache_write_error) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "Error writing to cache file");
		ap_rflush(r);
		return HTTP_BAD_GATEWAY;
	}

	if (backend_read_error) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "Error reading from backend");
		return HTTP_BAD_GATEWAY;
	}
	
	/* everything went well. Close cache file and make sure
	 * all content goes to the client */
	cache_close_cachefile(config, r, cache_file);
	ap_rflush(r);

	return OK;
}

static void adjust_dates(request_rec *r, struct httpresponse *httpresponse) 
{
	const char* datestr = NULL;
	if ((datestr = apr_table_get(httpresponse->headers, "Date")) != NULL)
		apr_table_set(httpresponse->headers, "Date", 
			wodan_date_canon(r->pool, datestr));
	if ((datestr = apr_table_get(httpresponse->headers, "Last-Modified")) 
	    != NULL)
		apr_table_set(httpresponse->headers, "Last-Modified", 
			wodan_date_canon(r->pool, datestr));
	if ((datestr = apr_table_get(httpresponse->headers, "Expires")) != NULL)
		apr_table_set(httpresponse->headers, "Expires",
			wodan_date_canon(r->pool, datestr));
}


static int do_http_proxy (wodan2_config_t *config, const char* proxyurl, char* uri, 
		   struct httpresponse* httpresponse, 
		   request_rec *r, apr_time_t cache_file_time)
{
	network_connection_t* connection;
	int result = OK;
	char *desthost, *destpath;
	char *dest_host_and_port;
	int destport;
	int do_ssl;
	apr_pool_t* p = r->pool;
	apr_table_t *out_headers;
	int gdp_retval = 0;

	if ((gdp_retval = get_destination_parts(p, proxyurl, uri,
				  &desthost, &destport,
				  &destpath, &dest_host_and_port,
				  &do_ssl)) != 0) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,
			     r->server, "failed to parse proxy_url %s and "
			     "uri %s, retval = %d", proxyurl, uri, gdp_retval);
		return 0;
	}
		
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		     "Destination: %s %d %s", desthost, destport, destpath);
	
	//Connect to proxyhost
	connection = networkconnect(config, desthost, destport, r, do_ssl);
	if(connection == NULL)
	{
		httpresponse->response = HTTP_BAD_GATEWAY;
		return HTTP_BAD_GATEWAY;//TODO BAD_GATEWAY??
	}

	//Copy headers and make adjustments
	out_headers = apr_table_copy(r->pool, r->headers_in);
	ap_reverseproxy_clear_connection(p, out_headers);
	
	/* send request */
	if (send_complete_request(connection, r, dest_host_and_port, destpath,
				  out_headers, cache_file_time) == -1) {
		connection_close_connection(connection, r);
		return HTTP_BAD_GATEWAY;
	}	
	
	result = receive_complete_response(config, connection, r, httpresponse);
	connection_close_connection(connection, r);
	return result;
}
