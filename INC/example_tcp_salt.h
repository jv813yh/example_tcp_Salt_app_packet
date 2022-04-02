/*
* example_tcp_salt.h   v.0.3
* 
* KEMT FEI TUKE, Diploma thesis
*
* Functions required to deploy the Salt channelv2 protocol on
* the TCP communication channel + auxiliary functions for work
*    
* Windows/Linux
*
* Author-Jozef Vendel  Create date- 22.03.2022 
*/

#ifndef EXAMPLE_TCP_SALT_H
#define EXAMPLE_TCP_SALT_H

/** 
* Delay attack protection, 
* threshold for differense in milliseconds. 
*/
#define TRESHOLD            	5000
/**
 * The protocol offers work with two types of packets:
 * 
 * App Packet: The data is not divided into multiple blocks
 * Multi App Packet: The data is divided into multiple blocks
 *
 * If a single application message (App Packet) is sent, 
 * the size might be longer than UINT16_MAX, however, 
 * if a multi application message the size must not be
 * longer than UINT16_MAX
 * 
 * The program divides the data into blocks 
 * of maximum size BLOCK_SIZE, because it uses 
 * Multi app packet, but if the data is smaller 
 * than UINT16_MAX, the protocol will use App packet. 
 *
 * 
 * if (size > UINT16_MAX) {
 *      if (p_msg->write.message_count > 0) {
 *          p_msg->write.state = SALT_WRITE_STATE_ERROR;
 *          return SALT_ERROR;
 *       }
 *       p_msg->write.state = SALT_WRITE_STATE_SINGLE_MSG;
 *   }
 *
 * You can used only App Packet for large data, if you want,
 * but in this source code I try to point out working with both.
 *
 */
#define BLOCK_SIZE          	UINT16_MAX

/* Encryption buffer overhead size for read */
#define SALT_READ_OVRHD_SIZE    38   

/* Encryption buffer overhead size for write */  
#define SALT_WRITE_OVRHD_SIZE   42      

#define AUXILIARY_FIELD_SIZE 	4096

/* 
 * Supported protocol of salt-channel. 
 * The user support what protocols is used by the
 * salt-channel.
 */
#define PROTOCOL_BUFFER     	128


/* ======================== FUNCTIONS ============================ */


/* 
 * Create a socket with which the client will connect to the       * server.
 * Function parameters are arguments from the command line.
 *
 * @par ip_server: ip adrress server 
 * @par port: number of port
 *
 * return client socket with connection to the server in case   * success
 * return wrong report in case failure
 */
SOCKET create_socket_and_connect(const char* ip_server, const char *port);


/* 
 * Creates a socket (return this socket) and expects 
 * a connection from the client.
 * Function parameters are arguments from the command line.
 *
 * @par ip_server: ip adrress server 
 * @par port: number of port
 *
 * return server socket and expects a connection from the client.
 * return wrong report in case failure
 */
SOCKET create_socket_and_listen(const char* host, const char *port);


/* 
 * Function for Salt channel protocol deployment for the client 
 * and connection establishment (Salt handshake)
 *
 * @par p_client_channel:       pointer to salt_channel_t structure
 * @par write_impl:             write implementation 
 * @par read_impl:              read implementation 
 * @par p_socket:               SOCKET (TCP/IP)
 * @par p_time_impl             time implementation
 * @par treshold                value for threshold
 *
 * @return SALT_SUCCESS          in case success
 * @return SALT_ERROR
 * @return SALT_PENDING
 */

salt_ret_t salt_impl_and_hndshk(salt_channel_t *p_client_channel, 
                                    salt_io_impl write_impl,
                                    salt_io_impl read_impl,
                                    SOCKET *p_socket,
                                    salt_time_t *p_time_impl,
                                    uint32_t treshold);


/* 
 * Function for Salt channel protocol deployment for the server 
 * and connection establishment (Salt handshake)
 *
 * @par p_server_channel:       pointer to salt_channel_t structure
 * @par p_protocols:            version of protocol
 * @par write_impl:             write implementation 
 * @par read_impl:              read implementation 
 * @par p_socket:               SOCKET (TCP/IP)
 * @par p_time_impl             time implementation
 * @par p_signature             array with signature
 * @par treshold                value for threshold
 *
 * @return SALT_SUCCESS          in case success
 * @return SALT_ERROR
 * @return SALT_PENDING
 */

salt_ret_t salt_impl_and_hndshk_server(salt_channel_t *p_server_channel,
                                    salt_protocols_t *p_protocols, 
                                    salt_io_impl write_impl,
                                    salt_io_impl read_impl,
                                    SOCKET *p_socket,
                                    salt_time_t *p_time_impl,
                                    const uint8_t *p_signature,
                                    uint32_t treshold); 


/* 
 * Function for buffer preparation, data too, 
 * encryption and data sending (in Salt channel) for client and server.
 *
 * @par p_channel:       pointer to salt_channel_t structure
 * @par p_buffer:        buffer for encryption
 * @par size_buffer:     size of buffer
 * @par file_size:       size of data what we want encrypt and send
 * @par block_size:      size of block 
 * @par p_input:         input data 
 * @par p_msg:           pointer to salt_msg_t structure
 *
 * @return SALT_SUCCESS          in case success
 * @return SALT_ERROR
 * @return SALT_PENDING
 */

salt_ret_t salt_encrypt_and_send(salt_channel_t *p_channel,
                               uint8_t *p_buffer,
                               uint32_t size_buffer,
                               uint32_t file_size,
                               uint32_t block_size,
                               uint8_t *p_input,
                               salt_msg_t *p_msg);


/* 
 * Function for data receiving, decryption, verify and
 * read them (in Salt channel) for client and server.
 *
 * @par p_channel:       pointer to salt_channel_t structure
 * @par p_buffer:        buffer for encryption
 * @par size_buffer:     size of buffer
 * @par p_msg:           pointer to salt_msg_t structure
 * @par print_out:       if you want to list of receive data -> 1
 *                       or no -> 0
 *
 * @return SALT_SUCCESS          in case success
 * @return SALT_ERROR
 * @return SALT_PENDING
 */
salt_ret_t salt_read_and_decrypt(salt_channel_t *p_channel,
                                uint8_t *p_buffer,
                                uint32_t size_buffer,
                                salt_msg_t *p_msg,
                                uint8_t *p_coppy_buffer,
                                uint32_t *p_decrypt_size,
                                int32_t print_out);


/* Function for calculated count of blocks */
int calculated_count_of_blocks(uint32_t file_size, 
                               uint32_t block_size, 
                               uint32_t overhead_size);


/* Function for creating / loading file 
 * 
 * @par *file:      name of file
 * @par *file_size: size of file
 * @par my_file:    if you want test file -> 0
 *                  if our file -> 1
 *
 * @return stream to the file
 */
uint8_t *loading_file(char *file, 
                      uint32_t *file_size, 
                      uint32_t my_file);  

#endif
