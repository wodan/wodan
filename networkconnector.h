/** $Id: networkconnector.h 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2006 IC&S, The Netherlands
 */

#ifndef NETWORKCONNECTOR_H
#define NETWORKCONNECTOR_H

#include "datatypes.h"

#include "httpd.h"

#include <sys/time.h>

/**
 * connect to the backend 
 * @param config the wodan configuration
 * @param host host to connect to
 * @param port port to connect to
 * @param r request record
 * @param do_ssl 1 if doing SSL connection, 0 otherwise. only used
 * when WODAN_HAVE_SSL is defined.
 */
network_connection_t* networkconnect (wodan2_config_t *config, char* host, int port, 
					  request_rec *r,
					  int do_ssl);

/**
 * close the network connection to the backend 
 * @param connection connection to close
 * @param r request record
 */
int connection_close_connection(network_connection_t *connection,
	const request_rec *r);

/**
 * write a number of bytes to the host on the other side of
 * the connection.
 * @param connection connection to use
 * @param r request record
 * @param buffer buffer with bytes to send.
 * @param buffersize size of buffer
 * @retval number of bytes written
 * @retval -1 on error.
 */
int connection_write_bytes(network_connection_t *connection,
	const request_rec *r, const char *buffer, int buffersize);

/**
 * read a number of bytes from the host on the other side
 * of the connection.
 * @param connection connection to use
 * @param r request record
 * @param buffer buffer to fill 
 * @param buffersize size of buffer
 * @retval number of bytes read
 * @retval -1 on error
 * @retval 0 on immediate EOF (number of bytes read is 0 of course).
 */
int connection_read_bytes(network_connection_t *connection,
	const request_rec *r, char *buffer, int buffersize);

/**
 * write a string to the other end of the connection
 * @param connection the connection to write to
 * @param r request record
 * @param the_string string to write
 * @retval 0 on success
 * @retval -1 on error
 */
int connection_write_string(network_connection_t *connection,
	const request_rec *r, const char *the_string);

/**
 * read a string from the backend 
 * @param connection connection to read from
 * @param r request record (used for its memory pool)
 * @return the string (will be NULL on error)
 * @note buffer[buffersize - 1] is always set to '\0' by function.
 */
char *connection_read_string(network_connection_t *connection, 
	const request_rec *r);


/**
 * flush the writestream of the connection.
 * @param connection the connection to flush
 * @retval -1 on error
 * @retval  0 on success
 */
int connection_flush_write_stream(network_connection_t *connection,
	const request_rec *r);
#endif
