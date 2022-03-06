/**
 * ===============================================
 * server00.c   v.2.0
 * 
 * KEMT FEI TUKE, Diploma thesis
 * 
 * The program is used for a simple demonstration 
 * of the implementation of the Salt channel protocol 
 * on TCP and working with the protocol.
 *
 * SERVER: The server establishes a TCP connection, 
 * the client connects, and a Salt handshake occurs 
 * between the partners. The server provides the service
 * using the toupper(), where it converts all data received
 * from the client by the toupper() function and sends the 
 * changed data back to the client. Cryptographic security 
 * is provided by the salt channel protocol.
 *
 * Encryption:
 *      - Key exchange: X25519
 *      - Encryption: XSalsa20 stream cipher
 *      - Authentication: Poly1305 MAC
 *
 *  Signatures:
 *      - Ed25519
 *
 *  Hashing:
 *      - SHA512
 *
 * Deployment of Salt-Channelv2 cryptographic 
 * protocol on TCP communication channel.
 *
 * Compileable on Windows with WinLibs standalone build 
 * of GCC and MinGW-w64 but also functional on Linux.
 *
 * For more details on salt channel see:
 * https://github.com/assaabloy-ppi/salt-channel-c
 *
 * Author-Jozef Vendel  Create date- 20.12.2021 
 * ===============================================
 */

/* ======== Includes ===================================== */

/* Basic libraries for working in C. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/**
* Macro allows diagnostic information to be written 
* to the standard error file.
*/
#include <assert.h>

/* Salt-channel handshake proccess is measured between devices */
#include <time.h>


/* Libraries needed for networking work on Windows/Linux */
#include "win_linux_sockets.h"

/* ===== Salt-channel local macro definition & libraries ===== */

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

/* Ready sk_sec key for server */
#include "server_sk_key.h"

/* ======= Local Macro Definitions ======================= */

/* Maximum size of data transmitted */
#define MAX_SIZE            UINT32_MAX  

/* 
 * Supported protocol of salt-channel. 
 * The user support what protocols is used by the
 * salt-channel.
 */
#define PROTOCOL_BUFFER     128

/** 
* Delay attack protection, 
* threshold for differense in milliseconds. 
*/
#define TRESHOLD            5000

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
#define BLOCK_SIZE          UINT16_MAX


int main() {

    /* Basic description of the program */
    printf("\nDeployment of Salt-Channelv2 cryptographic\n" 
        "protocol on TCP communication channel.\n");
    printf("\nSERVER: The server establishes a TCP connection\n" 
        "the client connects, and a Salt handshake occurs\n" 
        "between the partners. The server provides the service\n"
        "using the toupper(), where it converts all data received\n"
        "from the client by the toupper() function and sends the\n" 
        "changed data back to the client. Cryptographic security\n" 
        "is provided by the salt channel protocol.\n\n\n");

     /* ========  Variables & arrays ======== */

    /** 
     * Buffer for storing data during 
     * the handshake process. 
     */
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE], 

    /* 
     * tx_buffer: receive decrypted modified data, 
     * which is encrypted and sent back to the client
     * rrx_buffer: receive encrypted data from the client
     * copy_buffer: receive decrypted data from the client
     */
    *tx_buffer, *rrx_buffer, *copy_buffer,

    /* 
     * protocol buffer: Supported protocol of salt-channel. 
     * The user support what protocols is used by the
     * salt-channel.
     *
     * verify: if the salt handshake passes successfully, 
     * the verify is incremented and the data
     * is exchanged -> while (verify){ ... } 
     *
     */
    protocol_buffer[PROTOCOL_BUFFER], verify = 0;

    /* Time measurement variables */
    clock_t start_t, end_t;

    /* 
     * client socket: is used to communicate with the client 
     * after a successful tcp handshake   
     */
    SOCKET socket_client;

    /* ==  Variables for working with salt-channel protocol == */

    /* Salt channel structure */
    salt_channel_t server;

    /* Initiates to add information about supported protocols to host */
    salt_protocols_t protocols;

    /**
     * Structure used for easier 
     * creating/reading/working with messages 
     */
    salt_msg_t msg_out, msg_in;

    /*
     * typedef enum
     * which can obtain values:
     * SALT_SUCCESS, SALT_PENDING, SALT_ERROR            
     */
    salt_ret_t ret;

    /* ==== Creating client socket and TCP connection ==== */

    /* Initializing Winscok - Win32 apps */
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        fprintf(stderr, "Failed to initialize.\n");
        return 1;
    }

    /* 
     * Configuring remote address with getaddrinfo - 
     * the parameters were entered from the command line 
     * like ip address and port number 
     */
    printf("Configuring local address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *bind_address;
    getaddrinfo(0, "8080", &hints, &bind_address);

    /* Creating server socket - socket_listen */
    printf("Creating socket...\n");
    SOCKET socket_listen;
    socket_listen = socket(bind_address->ai_family,
            bind_address->ai_socktype, bind_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_listen)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    printf("Binding socket to local address...\n");
    if (bind(socket_listen,
                bind_address->ai_addr, bind_address->ai_addrlen)) {
        fprintf(stderr, "bind() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }
    freeaddrinfo(bind_address);

    /* Waiting for connections */
    printf("Listening...\n");
    if (listen(socket_listen, 1) < 0) {
        fprintf(stderr, "listen() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    printf("Waiting for connections...\n");

    /* Creating TCP connection with client */
    struct sockaddr_storage client_address;
    socklen_t client_len = sizeof(client_address);
    socket_client = accept(socket_listen,
                            (struct sockaddr*) &client_address,
                            &client_len);

    if (!ISVALIDSOCKET(socket_client)) 
    {
        fprintf(stderr, "accept() failed. (%d)\n",
                GETSOCKETERRNO());
        return 1;
    }

    char address_buffer[100];
    getnameinfo((struct sockaddr*)&client_address,
                client_len, address_buffer, sizeof(address_buffer), 0, 0,
                NI_NUMERICHOST);

    printf("New connection from %s\n", address_buffer);

    /*
     * TCP connection was successfully established in the 
     * client-server architecture.
     * 
     * Now, We are implementing salt channel v2 
     * and We will try a salt handshake with the server
     */

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
    ret = salt_create(&server, SALT_SERVER, my_write, my_read, &my_time);
    assert(ret == SALT_SUCCESS);

    /* Initiates to add information about supported protocols to host */
    ret = salt_protocols_init(&server, &protocols, protocol_buffer, sizeof(protocol_buffer));
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
    ret = salt_protocols_append(&protocols, "ECHO", 4);
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
    ret = salt_set_signature(&server, host_sk_sec);
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
    ret = salt_init_session(&server, hndsk_buffer, sizeof(hndsk_buffer));
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
    ret = salt_set_context(&server, &socket_client, &socket_client);
    assert(ret == SALT_SUCCESS);

    /* Set threshold for delay protection */
    ret = salt_set_delay_threshold(&server, TRESHOLD);
    assert(ret == SALT_SUCCESS);

    /* ========  Salt-handshake process  ================= */
    start_t = clock();
    ret = salt_handshake(&server, NULL);
    end_t = clock();

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
        printf("Salt error: 0x%02x\r\n", server.err_code);
        printf("Salt error read: 0x%02x\r\n", server.read_channel.err_code);
        printf("Salt error write: 0x%02x\r\n", server.write_channel.err_code);

        printf("Connection closed.\r\n");
        CLOSESOCKET(socket_client);
    }

    if (ret == SALT_SUCCESS) 
    {
        printf("\nSalt handshake successful\r\n");
        printf("\n");
        printf("\t\n***** Server: Salt channelv2 handshake lasted: %6.6f sec. *****\n", ((double) (end_t -
            start_t) / (CLOCKS_PER_SEC))); 

        /**
         * If the salt handshake passed successfully, 
         * we can access the data exchange. 
         */
        verify = 1;
        printf("\n");
    }

    /* Allocates the requested memory and returns a pointer to it */

    /* Buffer for data before send and encrypted to clien*/
    tx_buffer = (uint8_t *) malloc(MAX_SIZE);
    /* Buffer for receiving encrypted message from client */
    rrx_buffer = (uint8_t *) malloc(MAX_SIZE);
    /* Buffer for decrypted and modifying data from client */
    copy_buffer = (uint8_t *) malloc(MAX_SIZE);

    if((tx_buffer == NULL) || (rrx_buffer == NULL) || (copy_buffer == NULL))
    {
        printf("Memory not allocated.\n");
        exit(0);   
    }


    /* ======= Sending/receiving data ==================== */

    while(verify) 
    {
        /* Variables for working with data   */   
        ret = SALT_ERROR;

        /* Filling a block of memory with a particular value */
        memset(rrx_buffer, 0, MAX_SIZE);
        memset(tx_buffer, 0, MAX_SIZE);

        /* The size of the decrypted data */
        uint32_t decrypt_size = 0;
        
        printf("Data reception and decryption\n");

        /**
         * Reads one or multiple encrypted message.
         *
         * The actual I/O operation of the read process.
         *
         * @param server:
         * Pointer to salt channel handle.
         * @param rrx_buffer:      
         * Pointer where to store received (clear text) data.
         * @param MAX_SIZE:   
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

        do {

            ret = salt_read_begin(&server, rrx_buffer, MAX_SIZE, &msg_in);
        } while (ret == SALT_PENDING);

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
         *  struct {
         *      uint8_t     *p_buffer;          < Message buffer. 
         *      uint8_t     *p_payload;         < Pointer to current message. 
         *      uint32_t    buffer_size;        < Message buffer size. 
         *      uint32_t    buffer_used;        < Index of how many bytes have been processed. 
         *      uint16_t    messages_left;      < Number of messages left to read. 
         *      uint32_t    message_size;       < Current message size. 
         *  } read;
         * } salt_msg_t;
         * 
         */

        if (ret == SALT_SUCCESS) 
        {
            printf("\nRecevied %d BLOCK/BLOCKS\r\n", msg_in.read.messages_left + 1);
 
           do {

                memcpy(&copy_buffer[decrypt_size], msg_in.read.p_payload, msg_in.read.message_size);

                decrypt_size += msg_in.read.message_size;
           } while (salt_read_next(&msg_in) == SALT_SUCCESS);
        }

        /* Verification of the decryption and data transmission process */
        if (ret == SALT_ERROR)
        {
            printf("\nError during reading:\r\n");

            break;
        }

        if (ret == SALT_SUCCESS)
        {   
            uint32_t begin = 0, sent_size = BLOCK_SIZE, k;

            /**
             * The server provides the toupper() service, 
             * converting characters to uppercase
             */
            for (k = 0; k < decrypt_size; k++) 
            {
                copy_buffer[k] = toupper(copy_buffer[k]);
            }
            
            printf("Encrypting data and sending it\n");

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
             * Pointer where to store clear text data
             * Cryptographic operations with data are performed in the tx_buffer, 
             * the buffer must be larger than the size of the data itself !!!
             * @param MAX_SIZE:
             * Size of tx_buffer.
             * @param msg_out:
             * Pointer to message state structure.
             *
             * @return SALT_SUCCESS Message state structure was initialized.
             * @return SALT_ERROR   Bad buffer size or bad state of channel session.
             *
             */

            ret = salt_write_begin(tx_buffer, MAX_SIZE, &msg_out);
            assert(ret == SALT_SUCCESS);

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
             * @param msg_out              Pointer to message state structure.
             * @param copy_buffer + begin  Pointer to clear text message.
             * @param sent_size            Size of clear text message.
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
             * in order for the data to be properly secured !!!
             *
             */

            while(begin < decrypt_size)
            {   
                /* 
                 * If file_size < sent_size (BLOCK_SIZE)
                 * then we use APP packet
                 */
                if (decrypt_size % sent_size == decrypt_size) 
                        sent_size = decrypt_size;
                        
                /*
                 * If left bytes less than sent_size(BLOCK_SIZE)
                 * send residue bytes
                 */
                if (begin + sent_size > decrypt_size)
                    sent_size = decrypt_size - begin;

                ret = salt_write_next(&msg_out, copy_buffer + begin, sent_size);
                assert(ret == SALT_SUCCESS);

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
             * @param server     Pointer to salt channel handle.
             * @param msg_out    Pointer to message structure.
             *
             * @return SALT_SUCCESS A message was successfully sent.
             * @return SALT_ERROR   If any error occured during the sending process. 
             *                      If this occured, the session is considered
             *                      closed and a new handshake must be performed.
             *                      I.e., the session must be initated
             *                      and then a handshake.
             */

            do {
                
                ret = salt_write_execute(&server, &msg_out, false);
            } while(ret == SALT_PENDING);

            /* Verification of the encryption and data transmission process */
            if (ret == SALT_ERROR)
            {
                printf("\nError during writing:\r\n");

                break;
            }
        }
    } 

/* ========  End of application  ========================= */

    printf("\nClosing connection...\n");
    CLOSESOCKET(socket_client);

    printf("Closing listening socket...\n");
    CLOSESOCKET(socket_listen);

    free(tx_buffer);
    free(copy_buffer);
    free(rrx_buffer);

    WSACleanup();

    printf("Finished.\n");

    return 0;
}
