/** $Id: networkconnector.c 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2006 IC&S, The Netherlands
 */
#include "datatypes.h"
#include "networkconnector.h"

#include "apr.h"
#include "httpd.h"
#include "http_log.h"

#include <unistd.h>
#include <errno.h>

network_connection_t* networkconnect (wodan2_config_t *config, char* host, int port, 
		request_rec *r, int do_ssl WODAN_UNUSED_PARAMETER)
{
	network_connection_t* network_connection;
	apr_socket_t *socket;
	apr_sockaddr_t *server_address;
	
	// TODO check if we need to allocate room for the socket
	//	socket = apr_pcalloc(r->pool, sizeof(apr_socket_t));
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,r->server,
		"Looking up host %s", host);
	if (apr_sockaddr_info_get(&server_address, host, APR_UNSPEC, port, 0, r->pool) !=
		APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
			"Hostname lookup failure for: %s", host);
		return NULL;
	}
	
	if (apr_socket_create(&socket, APR_INET, SOCK_STREAM, APR_PROTO_TCP,  r->pool) !=
		APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
			"Error creating socket");
		return NULL;
	}

	if (config->backend_timeout > 0) {
		apr_socket_timeout_set(socket, config->backend_timeout);
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			"socket timeout set to %llu", config->backend_timeout);
	}
	if (apr_socket_connect(socket, server_address) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
		"Socket error while connecting to server at %s:%d", host, port);
		return NULL;
	}
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		"Succesfully connected to %s:%d", host, port);

	network_connection = 
		(network_connection_t *) apr_pcalloc(r->pool, sizeof(network_connection_t));

	network_connection->socket = socket;
	return network_connection;	
}

int connection_close_connection(network_connection_t *connection,
	const request_rec *r WODAN_UNUSED_PARAMETER)
{
	/* no need to do anything. This is done by apache internal 
	   functions */
	apr_socket_close(connection->socket);
	return 0;
}

int connection_write_bytes(network_connection_t *connection,
	const request_rec *r,
	const char *buffer, int buffersize) 
{
	apr_size_t nr_bytes = (apr_size_t) buffersize;
	apr_status_t socket_status;

	socket_status = apr_socket_send(connection->socket, buffer, &nr_bytes);
	if (socket_status == APR_TIMEUP) {
		ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_DEBUG, 0, r->server,
			"write to backend timed out");
		return -1;
	}
    if (nr_bytes < ((apr_size_t) buffersize)) { 
     	ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
     		"%s:%s: error writing bytes to backend.",
     		__FILE__, __func__); 
	  	return -1;
     }

     return (int) nr_bytes;
}

int connection_read_bytes(network_connection_t *connection,
	const request_rec *r, char *buffer, int buffersize) 
{
    apr_size_t nr_bytes = (apr_size_t) buffersize;
    apr_status_t socket_status;
     
    socket_status = apr_socket_recv(connection->socket, buffer, &nr_bytes);
	
	if (socket_status != APR_SUCCESS) {
		if (socket_status == APR_TIMEUP) {
			ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_DEBUG, 0, r->server,
				"read from backend timed out");
			return -1;
		}
		if ((nr_bytes != (apr_size_t) buffersize) && socket_status != APR_EOF) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
	 			"error reading bytes from backend, read %lu bytes, "
	 			"buffersize = %d, err = %d", nr_bytes, buffersize, socket_status);
	  		return -1;
		}
	 }
     return (int) nr_bytes;
}
	  
int connection_write_string(network_connection_t *connection,
	const request_rec *r, const char *the_string)
{
	int len = (int) strlen(the_string);
	
	return connection_write_bytes(connection, r, the_string, len);
}

char *connection_read_string(network_connection_t *connection,
	const request_rec *r)
{
	char *buffer = (char *) apr_pcalloc(r->pool, BUFFERSIZE);
	apr_size_t index = 0;
	apr_size_t byte_read = 1;
	int end_of_line = 0;
	
	while(index < BUFFERSIZE && !end_of_line) {
		apr_status_t socket_status;
		socket_status = apr_socket_recv(connection->socket, &(buffer[index]), 
			&byte_read);
		if (socket_status == APR_TIMEUP) {
			apr_interval_time_t timeout;
			apr_socket_timeout_get(connection->socket, &timeout);
			ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_DEBUG, 0, r->server,
				"read from backend connection timed out, timeout = %lld", timeout);
				
			return NULL;
		}
		if (socket_status == APR_EOF || buffer[index] == '\n')
			end_of_line = 1;
		index += 1;
		
	 	if (byte_read != 1) {
	     	ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
    		 		"%s,%s: Error reading string from backend", 
     			__FILE__, __func__);
     		return NULL;
	 	}
     }
     
     return buffer;
}

int connection_flush_write_stream(
	network_connection_t *connection WODAN_UNUSED_PARAMETER,
	const request_rec *r WODAN_UNUSED_PARAMETER)
{			  
     /* noop */
     return 1;
}

