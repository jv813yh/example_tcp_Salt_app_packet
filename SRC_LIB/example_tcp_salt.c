/**
 * ===============================================
 * example_tcp_salt.c   v.0.5
 * 
 * KEMT FEI TUKE, Diploma thesis
 *
 * Created support functions for deploying 
 * Salt channel protocol on TCP/IP
 *
 * Windows/Linux
 *
 * Author-Jozef Vendel  Create date- 21.03.2022 
 * ===============================================
 */

/* ======== Includes ===================================== */

/* Basic libraries for working in C. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
* Macro allows diagnostic information to be written 
* to the standard error file.
*/
#include <assert.h>

/* ===== Salt-channel libraries ===== */

/**
* Salt-channel version 2 implementation. 
* Main source code of protocol.
*/
#include "salt.h"

/**
 * Function for dependency injection to make the salt-channel
 * available for reliable I/O channel. 
 * 
 * The I/O channel may be blockable or non-blockable.
 * 
 * If any error occurs the function must return SALT_ERROR and the error code
 * must be reported in p_channel->err_code. The function must only 
 * return SALT_SUCCESS when p_channel->size_expected == p_channel.size.
 * 
 * The read operation is always done in two steps:
 *  1. Read 4 size bytes, derive length n.
 *  2. Read the package of length n.
 *
 * The write opration is done in one step:
 *  1. Write { size[4] , package[n] }.
 */
#include "salt_io.h"

/**
 * Internal routines used by salt-channel as:
 *
 * read / write  process state machine,
 * encrypts and wraps clear text data,
 * unwraps and decrypts a salt channel package,
 * auxiliary functions for reading 
 * and writing data (clear / encrypt / decrypt)
 * and others ....
 */
#include "salti_util.h"

/* ======= Auxiliary header files   ======== */

/* Macros for networking work Windows/Linux */
#include "win_linux_sockets.h"

/* 
 * Created functions for implementing 
 * Salt channel protocol on TCP/IP  
 */
#include "example_tcp_salt.h"

/* for Linux for fseeko() and ftello() */
#if !defined(_WIN32)
#define _FILE_OFFSET_BITS 64
#endif

/*======= Global function implementation ===========*/

/* 
 * Create a socket with which the client will connect to the server.
 * Function parameters are arguments from the command line.
 *
 * @par ip_server: ip adrress server 
 * @par port: number of port
 *
 * return client socket with connection to the server in case success
 * return wrong report in case failure
 */
SOCKET create_socket_and_connect(const char* ip_server, const char *port) 
{
    printf("\nConfiguring remote address...\n");

    /*
     * We use getaddrinfo() to fill in a 
     * struct addrinfo structure with the needed information
     */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *peer_address;
    
    if (getaddrinfo(ip_server, port, &hints, &peer_address))
    {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    /*
     * We use getnameinfo() to convert the address back into a string 
     * because we want print it out
     */
    printf("Remote address is: ");
    char address_buffer[AUXILIARY_FIELD_SIZE];
    char service_buffer[AUXILIARY_FIELD_SIZE];

    int return_getnameinfo;
    return_getnameinfo = getnameinfo(peer_address->ai_addr, 
            peer_address->ai_addrlen,
            address_buffer, sizeof(address_buffer),
            service_buffer, sizeof(service_buffer),
            NI_NUMERICHOST);

    if (return_getnameinfo)
    {
        fprintf(stderr, "getnameinfo() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }
    printf("%s %s\n", address_buffer, service_buffer);

    /* Creating client socket - client_socket */
    printf("\nCreating client socket...\n");
    SOCKET client_socket;
    client_socket = socket(peer_address->ai_family,
            peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(client_socket)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    /* 
     * After the socket has been created, we call connect() 
     * to establish a connection to the remote server
     */
    printf("Connecting...\n");
    if (connect(client_socket,
                peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    /*
     * After we've called connect() with peer_address, 
     * we use the freeaddrinfo() function to free the memory for peer_address
     */
    freeaddrinfo(peer_address);

    return client_socket;
}

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
SOCKET create_socket_and_listen(const char* host, const char *port) 
{
    printf("\nConfiguring local address...\n");

    /* 
     * Configuring remote address with getaddrinfo - 
     * the parameters were entered from the command line 
     * like ip address and port number 
     */
    /* Struct addrinfo hints */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    /* Looking address IPv4 */
    hints.ai_family = AF_INET;
    /* TCP connection */
    hints.ai_socktype = SOCK_STREAM;
    /* 
     * We ask getaddrinfo () to set the address, 
     * for the availability of any network device
     */
    hints.ai_flags = AI_PASSIVE;

    /* 
     * Setting a pointer to a structure that contains return 
     * information from the getaddrinfo () function
     */
    struct addrinfo *bind_address;
    /*
     * for example port 8080, generate an address suitable for the bind () function
     * IPVv4 and port from CLI
     */
    if (getaddrinfo(host, port, &hints, &bind_address))
    {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    /* Creating server socket - socket_listen */
    printf("Creating socket...\n");
    SOCKET socket_listen;
    socket_listen = socket(bind_address->ai_family,
            bind_address->ai_socktype, bind_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_listen)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }
    /* Binding socket to local address */
    printf("Binding socket to local address...\n");
    if (bind(socket_listen,
                bind_address->ai_addr, bind_address->ai_addrlen)) {
        fprintf(stderr, "bind() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }

    /*
     * After we've called bind(), we use the freeaddrinfo() 
     * function to free the memory for bind_address
     */
    puts("Bind done\n");
    freeaddrinfo(bind_address);

    /* The server is waiting for a client connection attempt */
    printf("Listening...\n\n");
    if (listen(socket_listen, 1) < 0) {
        fprintf(stderr, "listen() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }

    return socket_listen;
}

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
                                    uint32_t treshold) 
{   
    /* 
     * Verification of return values during protocol implementation 
     *
     * typedef enum
     * which can obtain values:
     * SALT_SUCCESS, SALT_PENDING, SALT_ERROR            
     */
    salt_ret_t ret;

    /* Buffer for performing a Salt handshake of size SALT_HNDSHK_BUFFER_SIZE */
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];

  /* ========  Salt-channel version 2 implementation  ======== */

    /**
     * Create a new Salt channel client 
     * 
     * @param client_channel       Pointer to channel handle.
     * @param SALT_CLIENT          Salt channel mode { SALT_SERVER, SALT_CLIENT }
     * @param my_write             User injected read implementation.
     * @param my_read              Used injected write implementation.
     * @param my_time              User injected get time implementation, may be NULL.
     *
     * @return SALT_SUCCESS The salt channel was successfully initiated.
     * @return SALT_ERROR   Any input pointer was a NULL pointer or invalid salt mode.
     * 
     */
    ret = salt_create(p_client_channel, SALT_CLIENT, write_impl, read_impl, p_time_impl);
    assert(ret == SALT_SUCCESS);

    /**
     * Creates and sets the signature used for the salt channel.
     *
     * @param client_channel Pointer to channel handle.
     *
     * @return SALT_SUCCESS The signature was successfully set.
     * @return SALT_ERROR   Any input pointer was a NULL pointer.
     */
    ret = salt_create_signature(p_client_channel); 
    assert(ret == SALT_SUCCESS);

    /**
     * Initiates a new salt session.
     *
     * A new ephemeral key pair is generated and the read and write nonce
     * is reseted.
     *
     * @param client_channel  Pointer to channel handle.
     * @param hndsk_buffer    Pointer to buffer used for handsize. Must be at least
     *                        SALT_HNDSHK_BUFFER_SIZE bytes large.
     * @param sizeof()        Size of the handshake buffer.
     *
     * @return SALT_SUCCESS The session was successfully initiated.
     * @return SALT_ERROR   The channel handle or buffer was a NULL pointer.
     *
     */
    ret = salt_init_session(p_client_channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

   /**
    * Sets the context passed to the user injected read/write implementation.
    *
    * @param client_channel     Pointer to channel handle.
    * @param socket_peer        Pointer to write context.
    * @param socket_peer        Pointer to read context.
    *
    * @return SALT_SUCCESS The context was successfully set.
    * @return SALT_ERROR   p_channel was a NULL pointer.
    */
    ret = salt_set_context(p_client_channel, p_socket, p_socket);
    assert(ret == SALT_SUCCESS);

    /* Set threshold for delay protection */
    ret = salt_set_delay_threshold(p_client_channel, treshold);
    assert(ret == SALT_SUCCESS);

    /* ========  Salt-handshake process  ================= */
    do {

        printf("Performing Salt Handshake\n");
        ret = salt_handshake(p_client_channel, NULL);

        /**
         * @return SALT_SUCCESS When the handshake process is completed.
         * 
         * @return SALT_PENDING When the handshake process is still pending.
         * 
         * @return SALT_ERROR   If any error occured during the handshake process. 
         *                      At this time the session should be ended.
         */

        if (ret == SALT_ERROR) 
        {
            printf("Salt error: 0x%02x\r\n", p_client_channel->err_code);
            printf("Salt error read: 0x%02x\r\n", p_client_channel->read_channel.err_code);
            printf("Salt error write: 0x%02x\r\n", p_client_channel->write_channel.err_code);

            /* Closing application */
            assert(ret != SALT_ERROR);
        } else if (ret == SALT_SUCCESS) 
        {   
            /**
             * If the salt handshake passed successfully, 
             * we can access the data exchange. 
             */    
            printf("\nSalt handshake successful for CLIENT :)\r\n\n");
        }
    } while (ret == SALT_PENDING);

    return ret;
}

/* 
 * Function for Salt channel protocol deployment for the server 
 * and connection establishment (Salt handshake)
 *
 * @par p_server_channel:       pointer to salt_channel_t structure
 * @par p_protocols:            type of protocol
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
                                    uint32_t treshold) 
{ 

    /* 
     * Verification of return values during working with protocol  
     *
     * typedef enum
     * which can obtain values:
     * SALT_SUCCESS, SALT_PENDING, SALT_ERROR            
     */
    salt_ret_t ret;

    /* Buffer for performing a Salt handshake of size SALT_HNDSHK_BUFFER_SIZE */
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE],

    /* 
     * protocol buffer: Supported protocol of salt-channel. 
     * The user support what protocols is used by the
     * salt-channel.
     */
    protocol_buffer[PROTOCOL_BUFFER];

/* ========  Salt-channel version 2 implementation  ======== */

    /**
     * Create a new Salt channel client 
     * 
     * @param server               Pointer to channel handle.
     * @param SALT_SERVER          Salt channel mode { SALT_SERVER, SALT_CLIENT }
     * @param my_write             User injected read implementation.
     * @param my_read              Used injected write implementation.
     * @param my_time              User injected get time implementation, may be NULL.
     *
     * @return SALT_SUCCESS The salt channel was successfully initiated.
     * @return SALT_ERROR   Any input pointer was a NULL pointer or invalid salt mode.
     * 
     */
    ret = salt_create(p_server_channel, SALT_SERVER, write_impl, read_impl, p_time_impl);
    assert(ret == SALT_SUCCESS);

    /* Initiates to add information about supported protocols to host */
    ret = salt_protocols_init(p_server_channel, p_protocols, protocol_buffer, sizeof(protocol_buffer));
    assert(ret == SALT_SUCCESS);

    /**
     * Add a protocol to supported protocols.
     *
     * See \ref salt_protocols_init
     *
     * When the client sends an A1 request the following will be the response:
     *  Response = {
     *      "SC2-------",
     *      "ECHO------",
     *      "SC2-------",
     *      "TEMP------",
     *  }
     *
     * @param protocols   Pointer to protocol structure.
     * @param ECHO        type of supported protocols
     * @param size        Size of protocol, <= 10.
     *
     * @return SALT_ERROR   Protocol buffer is too small or size > 10.
     * @return SALT_SUCCESS Protocol was added.
     */
    ret = salt_protocols_append(p_protocols, "ECHO", 4);
    assert(ret == SALT_SUCCESS);

    /**
     * Sets the signature used for the salt channel.
     *
     * This function will copy the signature in p_signature 
     * to the salt-channel structure.
     *
     *
     * @param server        Pointer to channel handle.
     * @param host_sk_sec   Pointer to signature. 
     *                      Must be crypto_sign_SECRETKEYBYTES bytes long.
     *
     * @return SALT_SUCCESS The signature was successfully set.
     * @return SALT_ERROR   Any input pointer was a NULL pointer.
     */
    ret = salt_set_signature(p_server_channel, p_signature);
    assert(ret == SALT_SUCCESS);

    /**
     * Initiates a new salt session.
     *
     * A new ephemeral key pair is generated and the read and write nonce
     * is reseted.
     *
     * @param server  Pointer to channel handle.
     * @param hndsk_buffer    Pointer to buffer used for handsize. Must be at least
     *                        SALT_HNDSHK_BUFFER_SIZE bytes large.
     * @param sizeof()        Size of the handshake buffer.
     *
     * @return SALT_SUCCESS The session was successfully initiated.
     * @return SALT_ERROR   The channel handle or buffer was a NULL pointer.
     *
     */
    ret = salt_init_session(p_server_channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

    /**
    * Sets the context passed to the user injected read/write implementation.
    *
    * @param client_channel     Pointer to channel handle.
    * @param socket_peer        Pointer to write context.
    * @param socket_peer        Pointer to read context.
    *
    * @return SALT_SUCCESS The context was successfully set.
    * @return SALT_ERROR   p_channel was a NULL pointer.
    */
    ret = salt_set_context(p_server_channel, p_socket, p_socket);
    assert(ret == SALT_SUCCESS);

    /* Set threshold for delay protection */
    ret = salt_set_delay_threshold(p_server_channel, treshold);
    assert(ret == SALT_SUCCESS);

    printf("Performing Salt Handshake\n");
    ret = salt_handshake(p_server_channel, NULL);

    /**
     * @return SALT_SUCCESS When the handshake process is completed.
     * 
     * @return SALT_PENDING When the handshake process is still pending.
     * 
     * @return SALT_ERROR   If any error occured during the handshake process. 
     *                      At this time the session should be ended.
     */

    if (ret == SALT_ERROR) 
    {
        printf("Error during handshake:\r\n");
        printf("Salt error: 0x%02x\r\n", p_server_channel->err_code);
        printf("Salt error read: 0x%02x\r\n", p_server_channel->read_channel.err_code);
        printf("Salt error write: 0x%02x\r\n", p_server_channel->write_channel.err_code);

        printf("Connection closed.\r\n");
        CLOSESOCKET(*p_socket);
    }

    if (ret == SALT_SUCCESS) 
    {
        printf("\nSalt handshake successful for SERVER :)\r\n");
  
        /**
         * If the salt handshake passed successfully, 
         * we can access the data exchange. 
         */
        printf("\n");
    }

    return ret;
}

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
                               salt_msg_t *p_msg)
{ 
    /*
     * typedef enum
     * which can obtain values:
     * SALT_SUCCESS, SALT_PENDING, SALT_ERROR            
     */
    salt_ret_t ret_msg;

    /* Variables for working with data   */          
    uint32_t begin = 0, sent_size = block_size; 

    printf("\n******| Encrypting data and sending it with Salt channel |********\n");
          
    /**
    * Write encrypted messages
    *
    * One or more messages can be sent using one encrypted message. 
    * Due to encryption overhead the size of data must be more 
    * than clear text message size.
    *
    * The content of tx_buffer will be modified during the authenticated encryption.
    *
    * @param tx_buffer:
    * Pointer where to store clear text data.
    * Cryptographic operations with data are performed in the tx_buffer, 
    * the buffer must be larger than the size of the data itself !!!
    * @param file_size + count_of_write_blocks:
    * Size of tx_buffer.
    * @param msg_out:
    * Pointer to message state structure.
    *
    * @return SALT_SUCCESS Message state structure was initialized.
    * @return SALT_ERROR   Bad buffer size or bad state of channel session.
    *
    */
    ret_msg = salt_write_begin(p_buffer, size_buffer, p_msg);
    assert(ret_msg == SALT_SUCCESS);

    /**
    * Copy a clear text message to be encrypted to next encrypted package.
    *
    * If this function is called more than once after salt_write_begin(),
    * all following clear text packages will be sent as one encrypted package. 
    * The content of p_buffer will be copied to the buffer of the p_msg structure,
    * because on the application layer it is possible to work with 
    * two types of packages Apppacket and Multipacket.
    *
    * The available buffer is in p_msg->buffer_available.
    * 
    * The function calls other support functions that verify whether the input data 
    * can be processed efficiently according to the rules of the salt channel protocol 
    * if no -> return SALT_ERROR.
    *
    * @param msg_out        Pointer to message state structure.
    * @param input + begin  Pointer to clear text message.
    * @param sent_size      Size of clear text message.
    *
    * @return SALT_SUCCESS A message was successfully appended to the state structure.
    * @return SALT_ERROR   The message was to large to fit in the state structure,
    *                      or does not meet the requirements
    * 
    * sent_size = BLOCK_SIZE
    *
    * The while() ensures that all data is moved to tx_buffer and prepared
    * for authenticated encryption and subsequent sending. 
    *
    * The function also verifies all the necessary conditions that must be met 
    * in order for the data to be properly secured.
    *
    */

    while(begin < file_size)
    {
        /* 
        * If file_size < sent_size (BLOCK_SIZE)
        * then we use APP packet
        */
        if (file_size % sent_size == file_size) sent_size = file_size;

        /*
        * If left bytes less than sent_size(BLOCK_SIZE)
        * send residue bytes
        */
        if (begin + sent_size > file_size) sent_size = file_size - begin;

        ret_msg = salt_write_next(p_msg, p_input + begin, sent_size);
        assert(ret_msg == SALT_SUCCESS);

        begin += sent_size;
    }

 /**      
    * Encrypts and send the messages prepared in salt_write_begin and 
    * salt_write_next !
    *
    * The prepared message state structure will be encrypted and 
    * send to the other peer.
    * This routine will modify the data in the buffer of p_msg->p_buffer.
    *
    * The function calls other support functions that verify the 
    * correctness of the data readiness for encryption and also uses the 
    * salti_wrap() function for encryption, which, after verifying the 
    * success of the encryption, then sends the salti_io_write() 
    * function to the channel.
    *
    * @param client_channel     Pointer to salt channel handle.
    * @param msg_out            Pointer to message structure.
    *
    * @return SALT_SUCCESS A message was successfully sent.
    * @return SALT_ERROR   If any error occured during the sending process. 
    *                      If this occured, the session is considered
    *                      closed and a new handshake must be performed.
    *                      I.e., the session must be initated
    *                      and then a handshake.
    */

    do 
    {
        ret_msg = salt_write_execute(p_channel, p_msg, false);
    } while(ret_msg == SALT_PENDING);

    /* Verification of the encryption and data transmission process */
    if (ret_msg == SALT_ERROR) printf("\nError during writting:\r\n");

    return ret_msg;
}

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
                                int32_t print_out)
{

    /*
     * typedef enum
     * which can obtain values:
     * SALT_SUCCESS, SALT_PENDING, SALT_ERROR            
     */
    salt_ret_t ret_msg;

    printf("\n******| Data reception and decryption with Salt channel |********\n");

    /**
    * Reads one or multiple encrypted message.
    *
    * The actual I/O operation of the read process.
    *
    * @param client_channel:
    * Pointer to salt channel handle.
    * @param rx_buffer:      
    * Pointer where to store received (clear text) data.
    * @param file_size + count_of_read_blocks:   
    * Size of p_buffer, must be greater or equal to SALT_READ_OVERHEAD_SIZE.
    * @param msg_in:         
    * Pointer to message structure to use when reading the message.
    *
    *
    * @return SALT_SUCCESS A message was successfully received.
    * @return SALT_PENDING The receive process is still pending.
    * @return SALT_ERROR   If any error occured during the read. If this occured, the session is considered
    *                      closed and a new handshake must be performed. I.e., the session must be initated
    *                      and then a handshake.
    */

    do 
    {
        ret_msg = salt_read_begin(p_channel, p_buffer, size_buffer, p_msg);
    } while (ret_msg == SALT_PENDING);

    /**
    * Used to read messages recevied.
    *
    * Used to read single or multiple application packages. Due to encryption overhead
    * the longest clear text message that can be received is SALT_READ_OVERHEAD_SIZE smaller
    * than the provided receive buffer.
    *
    * @param msg_in     Pointer to message structure.
    *
    * @return SALT_SUCCESS The next message could be parsed and ready to be read.
    * @return SALT_ERROR   No more messages available.
    *
    * Read message structure:
    * typedef union salt_msg_u {
    *   struct {
    *      uint8_t     *p_buffer;          < Message buffer. 
    *      uint8_t     *p_payload;         < Pointer to current message. 
    *      uint32_t    buffer_size;        < Message buffer size. 
    *      uint32_t    buffer_used;        < Index of how many bytes have been processed. 
    *      uint16_t    messages_left;      < Number of messages left to read. 
    *      uint32_t    message_size;       < Current message size. 
    *   } read;
    * } salt_msg_t;
    * 
    */

    if (ret_msg == SALT_SUCCESS)     
    {   
        printf("\nRecevied %d BLOCK/BLOCKS:\n\n", ++p_msg->read.messages_left);

        do 
        {
            if (SALT_CLIENT == p_channel->mode) 
            {
                /* Listing of received data */
                if(print_out)
                    printf("%*.*s\r\n", 0, p_msg->read.message_size, (char*) p_msg->read.p_payload);
            } else if (SALT_SERVER == p_channel->mode) 
            {
                memcpy(&p_coppy_buffer[*p_decrypt_size], p_msg->read.p_payload, p_msg->read.message_size);
                *p_decrypt_size += p_msg->read.message_size;
            }
        } while (salt_read_next(p_msg) == SALT_SUCCESS);
    }

    /* Verification of the decryption and data transmission process */
    if (ret_msg == SALT_ERROR) printf("\nError during reading :(\r\n");

    return ret_msg;
}

/* Function for calculated count of blocks */
uint32_t calculated_count_of_blocks(uint32_t file_size, 
                               uint32_t block_size, 
                               uint32_t overhead_size)
{
    uint32_t begin = 0, count_blocks = 0;
    
    while(begin < file_size)
    {
        count_blocks++;
        
        begin += block_size;

        if (begin > file_size) break;
        
        if (begin + block_size > file_size)
        {
           count_blocks++;
           
           break;
        }
    }

    return count_blocks;  
}

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
                      uint32_t my_file)
{   

    FILE *stream;

    int32_t result1, result2;

    uint8_t *input;
    uint32_t expected_size_file,
             range;

    /**
     * if my_file == 0 -> test file 
     * if my_file == 1 -> your file 
     * 
     * Creating our random test file:
     * 
     */

    if(!my_file) 
    {
        if ((stream = fopen(file, "wb")) == NULL) 
        {
            printf("Failed to open create file %s\n", file);
            exit(0);
        }
        
        printf("Creating own file\n");
      
        uint32_t i = 0;

        printf("Enter the approximate file size in bytes: \n");
        if (EOF == scanf("%u",&expected_size_file))
        {   
            printf("Failed to load size\n");
            return 0;
        }
        expected_size_file = expected_size_file / 
                            (sizeof(expected_size_file) * sizeof(expected_size_file));
        printf("Enter max integer (range): \n");
        if (EOF == scanf("%u",&range))
        {   
            printf("Failed to load range\n");
            return 0;
        }

        while(i++ < expected_size_file)
        {
            fprintf(stream, "Number %d. %u, ", i,  rand() % range);
        }

        fprintf(stream, "\nThis is the end of the file being tested :)");

        if(fclose(stream) == EOF) 
            printf("Failed to closed file\n");

    }

    if ((stream = fopen(file, "rb")) == NULL) 
    {
        printf("Failed to open file %s\n", file);
        exit(0);
    }

    /**
     * _fseeki64 functions moves the file pointer (if any) 
     * associated with stream to a new location that is offset 
     * bytes from origin 
     *
     * SEEK_END : End of file
     * SEEK_SET : Beginning of file.
     *
     * for linux fseekko() and ftello()
     */

#if defined(_WIN32)
    /* If successful, return 0 */
    if ((result1 = _fseeki64(stream, 0L, SEEK_END)) != 0)
        printf("_fseeki64 error1\n");

    /* _ftelli64 return the current file position */
    *file_size = _ftelli64(stream);

    /* If successful, return 0 */
    if ((result2 = _fseeki64(stream, 0L, SEEK_SET)) != 0)
        printf("_fseeki64 error2\n");
#else 
    /* If successful, return 0 */
    if ((result1 = fseeko(stream, 0L, SEEK_END)) != 0)
        printf("fseeko error1\n");

    /* _ftelli64 return the current file position */
    *file_size = ftello(stream);

    /* If successful, return 0 */
    if ((result2 = fseeko(stream, 0L, SEEK_SET)) != 0)
        printf("fseeko error2\n");
#endif
    /* Allocates the requested memory and returns a pointer to it */
    input = (uint8_t *) malloc(*file_size);
    if (input == NULL) 
    {
        printf("Memory not allocated.\n");
        exit(0);
    }

    /*
     * reads data from the given stream into the 
     * array pointed to, by input
     * 
     * file_size is the number of elements, 
     * each one with a size of size bytes.
     */
    int test = fread(input, 1, *file_size, stream);

    if (!test) printf("We can provide no input at all !!! \n");

    if(fclose(stream) == EOF) 
        printf("Failed to closed file\n");

    return input;
}
