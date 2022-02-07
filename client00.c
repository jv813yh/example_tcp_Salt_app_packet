/*
 *	tcp_client.c  
 *
 *  KEMT FEI TUKE 
 *  Thesis
 *	
 *	Source code taken from:
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

//Constants for work with network on  Windows/Linux
#include "win_linux_sockets.h"

//Libraries of Salt channelv2
#include "salt.h"
#include "salt_io.h"
#include "salti_util.h"

#if defined(_WIN32)
#include <conio.h>
#endif


//Maximum size of data transmitted via TCP channel
#define MAX_SIZE            UINT16_MAX * 18
//Size, where the decrypted message starts in the buffer 
#define ENC_MSG             38
//Set treshold
#define TRESHOLD            1000

int main(int argc, char *argv[]) 
{
    //Added variables to use Salt channelv2 protocol
    salt_channel_t client_channel;
    salt_ret_t ret, ret_msg;
    salt_msg_t msg_out, msg_in;

    int verify = 0;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE],
    *tx_buffer, *rx_buffer, msg_size = 0, *input;

    //buffer for data before send
    tx_buffer = (uint8_t *) malloc(MAX_SIZE);
    //buffer for reads encrypted message
    rx_buffer = (uint8_t *) malloc(MAX_SIZE);
    //buffer for unencrypted message
    input = (uint8_t *) malloc(MAX_SIZE);

    if((tx_buffer == NULL) || (rx_buffer == NULL) || (input == NULL))
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

    if (argc < 3) {
        fprintf(stderr, "usage: tcp_client hostname port\n");
        return 1;
    }

    printf("Configuring remote address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *peer_address;
    if (getaddrinfo(argv[1], argv[2], &hints, &peer_address)) {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }


    printf("Remote address is: ");
    char address_buffer[100];
    char service_buffer[100];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
            address_buffer, sizeof(address_buffer),
            service_buffer, sizeof(service_buffer),
            NI_NUMERICHOST);
    printf("%s %s\n", address_buffer, service_buffer);


    printf("Creating socket...\n");
    SOCKET socket_peer;
    socket_peer = socket(peer_address->ai_family,
            peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_peer)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    printf("Connecting...\n");
    if (connect(socket_peer,
                peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }
    freeaddrinfo(peer_address);

    printf("Connected.\n");
    printf("TCP was successfully performed...\n\nCreating Salt hanshake...\n");

    //Added Salt channelv2 functions to set variables correctly and Salt handshake

    //Create Salt channel client
    ret = salt_create(&client_channel, SALT_CLIENT, my_write, my_read, &my_time);
    assert(ret == SALT_SUCCESS);

    //Creating pairs of signature keys
    ret = salt_create_signature(&client_channel); 
    assert(ret == SALT_SUCCESS);

    //Setting up other necessary cryptographic operations to use the protocol properly
    ret = salt_init_session(&client_channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

    //Setting up socket with function for read messages and write messages
    ret = salt_set_context(&client_channel, &socket_peer, &socket_peer);
    assert(ret == SALT_SUCCESS);

    //Setting up delay treshold 
    ret = salt_set_delay_threshold(&client_channel, TRESHOLD);
    assert(ret == SALT_SUCCESS);

    //Creating Salt handshake
    do {
        start_t = clock();
        ret = salt_handshake(&client_channel, NULL);
        end_t = clock();
        if (ret == SALT_ERROR) {
            printf("Salt error: 0x%02x\r\n", client_channel.err_code);
            printf("Salt error read: 0x%02x\r\n", client_channel.read_channel.err_code);
            printf("Salt error write: 0x%02x\r\n", client_channel.write_channel.err_code);
            assert(ret != SALT_ERROR);
        } else if (ret == SALT_SUCCESS) {
                printf("\nSalt handshake successful\r\n");
                printf("\n");
                printf("\t\n***** CLIENT: Salt channelv2 handshake lasted: %6.6f sec. *****\n", ((double) (end_t -
                        start_t) / (CLOCKS_PER_SEC))); 
                printf("\n");
                verify = 1;
        }
        } while (ret == SALT_PENDING);

    //The structure has changed slightly since the flood program
    //If the handshake was successful, we can proceed with the data exchange
    while(verify) {

        fd_set reads;
        FD_ZERO(&reads);
        FD_SET(socket_peer, &reads);

#if !defined(_WIN32)
        FD_SET(0, &reads);
#endif

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        if (select(socket_peer+1, &reads, 0, 0, &timeout) < 0) {
            fprintf(stderr, "select() failed. (%d)\n", GETSOCKETERRNO());
            return 1;
        }

        if (FD_ISSET(socket_peer, &reads)) {

        	//Instead of the recv() in TCP, 
        	//we use the Salt channel salt_read_begin function

            //Receiving encrypted messages, unwrapping, decrypting
            memset(rx_buffer, 0, MAX_SIZE);
            ret_msg = salt_read_begin(&client_channel, rx_buffer, MAX_SIZE, &msg_in);
            
            if(ret_msg == SALT_ERROR) {
                printf("Failed to dencrypt or receive message from server\n");
                break;
            }

            int decrypt_size = strlen((const char *) &rx_buffer[ENC_MSG]);
            //Print received decrypted data from server
            printf("Received modified data from server:\n");
            for(int i = ENC_MSG; i < ENC_MSG + decrypt_size; i++){
                printf("%c", rx_buffer[i]);
            }
            printf("\n");

        }

#if defined(_WIN32)
        if(_kbhit()) {
#else
//        if(FD_ISSET(0, &reads)) {
#endif  
            /*Instead of the send() function, it is necessary to use 3 functions 
              in the Salt channel protocol,
              the first two will prepare the message before encrypting and sending 
              and copy clear text message to be encrypted to next encrypted package
              The third function encrypts the data and sends it over the TCP channel 
			*/

            ret_msg = SALT_ERROR;
            memset(tx_buffer, 0, MAX_SIZE);
            memset(input, 0, MAX_SIZE);

            //Inputting clear text from CL from client
            if (!fgets((char *)input, MAX_SIZE, stdin)) break;

            msg_size = strlen((const char *)(input));

            //Prepare the message before encrypting and sending 
            ret_msg = salt_write_begin(tx_buffer, MAX_SIZE, &msg_out);
            assert(ret_msg == SALT_SUCCESS);

            //Copy clear text message to be encrypted to next encrypted package
            ret_msg = salt_write_next(&msg_out, input, msg_size);
            assert(ret_msg == SALT_SUCCESS);

            //Wrapping and creating encrypted messages, sending for server 
            ret_msg = salt_write_execute(&client_channel, &msg_out, false);

            if(ret_msg == SALT_ERROR) {
                printf("Failed to encrypt or send message from server\n");
                break;
            }

        }
    } //end while(1)

    // Free the memory
    free(tx_buffer);
    free(rx_buffer);
    free(input);

    printf("Closing socket...\n");
    CLOSESOCKET(socket_peer);

#if defined(_WIN32)
    WSACleanup();
#endif

    printf("Finished.\n");
    return 0;
}



