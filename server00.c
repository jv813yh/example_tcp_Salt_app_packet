/**
 * ===============================================
 * server00.c   v.1.5
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
 * of GCC and MinGW-w64.
 *
 * Compileable on Linux with 
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
#include <stdlib.h>
#include <ctype.h>

/**
* Macro allows diagnostic information to be written 
* to the standard error file.
*/
#include <assert.h>

/* Libraries needed for networking work on Windows/Linux */
#include "win_linux_sockets.h"

/* ===== Salt-channel libraries ===== */
#include "salt.h"
#include "salt_io.h"

/* 
 * Created functions for implementing 
 * Salt channel protocol on TCP/IP  
 */
#include "example_tcp_salt.h"

/* ========== Ready sk_sec_key for server ======== */
#include "server_sk_key.h"

/* ======= Local Macro Definitions ======================= */

/* Maximum size of data transmitted */
#define MAX_SIZE            UINT16_MAX * 30

/* The port number on which the server is loading */
#define PORT                    "8080"




int main(void) 
{ 
    /* Initializing Winscok - Win32 apps , ONLY FOR WINDOWS !!! */
#if defined(_WIN32)
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        fprintf(stderr, "Failed to initialize.\n");
        return 1;
    }
#endif

    /* Basic description of the program */
    printf("\nDeployment of Salt-Channelv2 cryptographic\n" 
        "protocol on TCP communication channel.\n");
    printf("\nSERVER: The server establishes a TCP connection\n" 
        "the client connects, and a Salt handshake occurs\n" 
        "between the partners. The server provides the service\n"
        "using the toupper(), where it converts all data received\n"
        "from the client by the toupper() function and sends the\n" 
        "changed data back to the client. Cryptographic security\n" 
        "is provided by the salt channel protocol.\n");
    printf("\nThe maximum size that I can currently process depends\n"
        "on the constant MAX_SIZE and is: %u\n", MAX_SIZE);

/* ========  Variables ======== */
    /* 
     * tx_buffer: receive decrypted modified data, 
     * which is encrypted and sent back to the client
     * rrx_buffer: receive encrypted data from the client
     * copy_buffer: receive decrypted data from the client
     */
    uint8_t *tx_buffer, *rrx_buffer, *copy_buffer;

    /* The size of the decrypted data */
    uint32_t decrypt_size;

    /* 
     * client socket: is used to communicate with the client 
     * after a successful tcp handshake   
     *
     * socket_listen: socket for server for listen
     */
    SOCKET socket_client, socket_listen;

/* ====  Variables for working with salt-channel protocol ==== */

    /* Salt channel structure */
    salt_channel_t server_channel;

    /* Initiates to add information about supported protocols to host */
    salt_protocols_t protocols;

    /**
     * Structure used (protocol) for easier 
     * creating / reading / working with data 
     */
    salt_msg_t msg_out, msg_in;

    /* 
     * Verification of return values during working with protocol  
     *
     * typedef enum
     * which can obtain values:
     * SALT_SUCCESS, SALT_PENDING, SALT_ERROR            
     */
    salt_ret_t ret_hndshk = SALT_ERROR, ret_msg = SALT_ERROR;

/* ==== Creating socket and TCP connection ==== */
    
    /* 
     * Creates a socket (return this socket) with which it waits 
     * for a connection from the client   
     */
    socket_listen = create_socket_and_listen(PORT);

    printf("Waiting for connections...\n");

    /* Creating TCP connection with client */
    struct sockaddr_storage client_address;
    socklen_t client_len = sizeof(client_address);
    socket_client = accept(socket_listen,
                            (struct sockaddr*) &client_address,
                            &client_len);

    /* Verification of the correct establishment of the connection */
    if (!ISVALIDSOCKET(socket_client)) 
    {
        fprintf(stderr, "accept() failed. (%d)\n",
                GETSOCKETERRNO());
        return 1;
    } else 
    {
        /* Listing the ip address of the client */
        char address_buffer[AUXILIARY_FIELD_SIZE];
        int return_getnameinfo;
        return_getnameinfo = getnameinfo((struct sockaddr*)&client_address,
                client_len, address_buffer, sizeof(address_buffer), 0, 0,
                NI_NUMERICHOST);

        if (return_getnameinfo)
        {
            fprintf(stderr, "getnameinfo() failed. (%d)\n", GETSOCKETERRNO());
            return 1;
        }
        /*
         * TCP connection was successfully established in the 
         * client-server architecture, 
         * it is possible to access the data exchange.
         */
        printf("\nNew connection from %s\n\n", address_buffer);
    }

    /*
     * TCP connection was successfully established in the 
     * client-server architecture.
     * 
     * Now, We are implementing salt channelv2 
     * and We will try a Salt Handshake with the server
     * and exchange data.
     */

/* ======== Salt-channel implementation & Handshake ======== */

    /*
     * Created a function (server) for deploying the Salt channel and 
     * creating a Salt Handshake on TCP/IP using a socket
     */
    ret_hndshk = salt_impl_and_hndshk_server(&server_channel,
                                             &protocols,
                                             my_write,
                                             my_read,
                                             &socket_client,
                                             &my_time,
                                             host_sk_sec,
                                             TRESHOLD);
    /* Implementation and Handshake verification */
    assert(ret_hndshk == SALT_SUCCESS);

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

/* ======= Sending/receiving data in cycles ==================== */
/* ======= Encryption/decryption data ========================== */

    while(ret_hndshk == SALT_SUCCESS) 
    {
        decrypt_size = 0;

        /* Filling a block of memory with a particular value */
        memset(rrx_buffer, 0, MAX_SIZE);
        memset(tx_buffer, 0, MAX_SIZE);

        /*    
         * Created function (server) for data reception, 
         * authentication and decryption with protocol   
         */
        ret_msg = salt_read_and_decrypt(&server_channel,
                                        rrx_buffer,
                                        MAX_SIZE,
                                        &msg_in,
                                        copy_buffer,
                                        &decrypt_size,
                                        0);
        /* Verification */
        assert(ret_msg == SALT_SUCCESS);

        if (ret_msg == SALT_SUCCESS)
        {   
            /**
             * The server provides the toupper() service, 
             * converting characters to uppercase
             */
            for (uint32_t k = 0; k < decrypt_size; k++) 
                copy_buffer[k] = toupper(copy_buffer[k]);

            ret_msg = SALT_ERROR;
            /*   
             * Created function for buffer preparation, also data, 
             * encryption and sending using protocol 
             */
            ret_msg = salt_encrypt_and_send(&server_channel,
                                            tx_buffer,
                                            MAX_SIZE,
                                            decrypt_size,
                                            BLOCK_SIZE,
                                            copy_buffer,
                                            &msg_out);
            /* Verification */
            assert(ret_msg == SALT_SUCCESS);
        }

        /* If everything is OK, the cycle continues */
        ret_hndshk = ret_msg;
    } 

/* ========  End of application  ========================= */

    printf("\nClosing connection...\n");
    /* Socket closure */
    printf("Closing sockets...\n");
    CLOSESOCKET(socket_client);
    CLOSESOCKET(socket_listen);

    free(tx_buffer);
    free(copy_buffer);
    free(rrx_buffer);

    /* Cleanning Winsock, ONLY FOR WINDOWS !!! */
#if defined(_WIN32)
    WSACleanup();
#endif

    printf("Finished.\n");

    return 0;
}
