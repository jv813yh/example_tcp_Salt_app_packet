/*
 *  tcp_serve_toupper.c  
 *
 *  KEMT FEI TUKE 
 *  Diploma thesis
 *  
 *  Source code taken from:
 *  https://github.com/PacktPublishing/Hands-On-Network-Programming-with-C/tree/master/chap03
 *
 *  Deployment of the Salt channelv2 protocol with appPacket on the TCP communication channel
 *
 *  Windows/Linux 
 *  Date- 20.12.2021 
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <ctype.h>

//Constants for work with network on Windows/Linux
#include "win_linux_sockets.h"

//Libraries of Salt channelv2
#include "salt.h"
#include "salt_io.h"
#include "salti_util.h"

//Ready sk_sec key for server
#include "server_sk_key.h"

//Maximum size of data transmitted via TCP channel
#define MAX_SIZE            UINT16_MAX * 20
//
#define PROTOCOL_BUFFER     128
//Size, where the decrypted message starts in the buffer 
#define ENC_MSG             38
//Set treshold
#define TRESHOLD            20000

int main() {

    //Added variables to use Salt channelv2 protocol
    SOCKET socket_client;

    salt_channel_t server;
    salt_protocols_t protocols;

    salt_msg_t msg_out;
    salt_msg_t msg_in;
    salt_ret_t ret;
    salt_ret_t ret_msg;

    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE], *tx_buffer,
    *rx_buffer, protocol_buffer[PROTOCOL_BUFFER], verify = 0, decrypt_size,
    *rrx_buffer;

    //buffer for data before send
    tx_buffer = (uint8_t *) malloc(MAX_SIZE);
    //buffer for reads encrypted message
    rx_buffer = (uint8_t *) malloc(MAX_SIZE);
    //buffer for unencrypted message
    rrx_buffer = (uint8_t *) malloc(MAX_SIZE);

    if((tx_buffer == NULL) || (rx_buffer == NULL) || (rrx_buffer == NULL))
    {
        printf("Memory not allocated.\n");
        exit(0);   
    }

    clock_t start_t, end_t;

#if defined(_WIN32)
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        fprintf(stderr, "Failed to initialize.\n");
        return 1;
    }
#endif

    printf("Configuring local address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *bind_address;
    getaddrinfo(0, "8080", &hints, &bind_address);


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


    printf("Listening...\n");
    if (listen(socket_listen, 10) < 0) {
        fprintf(stderr, "listen() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    fd_set master;
    FD_ZERO(&master);
    FD_SET(socket_listen, &master);
    SOCKET max_socket = socket_listen;

    printf("Waiting for connections...\n");


    while(1) {
        fd_set reads;
        reads = master;
        if (select(max_socket+1, &reads, 0, 0, 0) < 0) {
            fprintf(stderr, "select() failed. (%d)\n", GETSOCKETERRNO());
            return 1;
        }

        SOCKET i;
        for(i = 1; i <= max_socket; ++i) {
            if (FD_ISSET(i, &reads)) {

                if (i == socket_listen) {
                    struct sockaddr_storage client_address;
                    socklen_t client_len = sizeof(client_address);
                    socket_client = accept(socket_listen,
                            (struct sockaddr*) &client_address,
                            &client_len);
                    if (!ISVALIDSOCKET(socket_client)) {
                        fprintf(stderr, "accept() failed. (%d)\n",
                                GETSOCKETERRNO());
                        return 1;
                    }

                    FD_SET(socket_client, &master);
                    if (socket_client > max_socket)
                        max_socket = socket_client;

                    char address_buffer[100];
                    getnameinfo((struct sockaddr*)&client_address,
                            client_len,
                            address_buffer, sizeof(address_buffer), 0, 0,
                            NI_NUMERICHOST);
                    printf("New connection from %s\n", address_buffer);

                    //A successful TCP connection is followed by a Salt handshake

                    //Creates a new salt channel
                    ret = salt_create(&server, SALT_SERVER, my_write, my_read, &my_time);
                    assert(ret == SALT_SUCCESS);

                    //Initiates to add information about supported protocols to host
                    ret = salt_protocols_init(&server, &protocols, protocol_buffer, sizeof(protocol_buffer));
                    assert(ret == SALT_SUCCESS);

                    //Add a protocol to supported protocols
                    ret = salt_protocols_append(&protocols, "ECHO", 4);
                    assert(ret == SALT_SUCCESS);

                    //Sets the signature used for the salt channel
                    ret = salt_set_signature(&server, host_sk_sec);
                    assert(ret == SALT_SUCCESS);

                    //New ephemeral key pair is generated and the read and write nonce  is reseted
                    ret = salt_init_session(&server, hndsk_buffer, sizeof(hndsk_buffer));
                    assert(ret == SALT_SUCCESS);

                    //Sets the context passed to the user injected read implementation
                    ret = salt_set_context(&server, &socket_client, &socket_client);
                    assert(ret == SALT_SUCCESS);

                    //Set threshold for delay protection
                    ret = salt_set_delay_threshold(&server, TRESHOLD);
                    assert(ret == SALT_SUCCESS);

                    //Salt handshake 
                    start_t = clock();
                    ret = salt_handshake(&server, NULL);
                    end_t = clock();

                    //Testing success for Salt handshake
                    while (ret != SALT_SUCCESS) {

                        if (ret == SALT_ERROR) {
                            printf("Error during handshake:\r\n");
                            printf("Salt error: 0x%02x\r\n", server.err_code);
                            printf("Salt error read: 0x%02x\r\n", server.read_channel.err_code);
                            printf("Salt error write: 0x%02x\r\n", server.write_channel.err_code);

                            printf("Connection closed.\r\n");
                            CLOSESOCKET(socket_client);
           
                            break;
                        }

                        ret = salt_handshake(&server, NULL);
                    }
                    if (ret == SALT_SUCCESS) {
                        printf("\nSalt handshake successful\r\n");
                        printf("\n");
                        printf("\t\n***** Server: Salt channelv2 handshake lasted: %6.6f sec. *****\n", ((double) (end_t -
                        start_t) / (CLOCKS_PER_SEC))); 
                        verify = 1;
                        printf("\n");
                    }

                    //If the Salt handshake passes successfully (verify = 1)
                    //you can accede to receive and send data 
                    } else if (verify){
                        ret_msg = SALT_ERROR;
                        memset(rx_buffer, 0, MAX_SIZE);
                        memset(rrx_buffer, 0, MAX_SIZE);
                        memset(tx_buffer, 0, MAX_SIZE);

                        //Reads encrypted message
                        ret_msg = salt_read_begin(&server, rx_buffer, MAX_SIZE, &msg_in);
                        assert(ret_msg == SALT_SUCCESS);

                        decrypt_size = strlen((const char *)&rx_buffer[ENC_MSG]);
                        memcpy(rrx_buffer, &rx_buffer[ENC_MSG], decrypt_size);
    
                        if (ret_msg == SALT_SUCCESS){ 
                            ret_msg = SALT_ERROR;

                            for (int j = 0; j < decrypt_size; j++) 
                                rrx_buffer[j] = toupper(rrx_buffer[j]);

                            //Prepare data before send
                            ret_msg = salt_write_begin(tx_buffer, MAX_SIZE, &msg_out);
                            assert(ret_msg == SALT_SUCCESS);
                            //Copy clear text message to be encrypted to next encrypted package
                            ret_msg = salt_write_next(&msg_out, rrx_buffer, decrypt_size);
                            assert(ret_msg == SALT_SUCCESS);
                            //Wrapping, creating encrpted messages
                            ret_msg = salt_write_execute(&server, &msg_out, false);
                        } 

                        if (ret_msg == SALT_ERROR){
                            printf("\nThe message could not be decrypted\nClosing the socket\n");
                            CLOSESOCKET(socket_client);
                            break;
                        } //Testing Salt error of messages
                    } //Exchange of secured data
            } //if FD_ISSET
        } //for i to max_socket
    } //while(1)

    // Free the memory
    free(tx_buffer);
    free(rx_buffer);
    free(rrx_buffer);

    printf("Closing listening socket...\n");
    CLOSESOCKET(socket_listen);

#if defined(_WIN32)
    WSACleanup();
#endif


    printf("Finished.\n");

    return 0;
}

