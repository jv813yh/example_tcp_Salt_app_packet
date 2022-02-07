/*
 * salt_io.c    v.0.4
 *
 * Input, Output, Timestamp
 *
 * Functions needed for sending messages, receiving messages, creating time stamps in the Salt channelv2 protocol
 *
 * Windows/Linux  
 *
 * Author-Jozef Vendel  Date- 1.5.2021 
 * ===============================================
 */

#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>

//Library of Salt channelv2
#include "salti_util.h"
#include "salt_io.h"

//Library for windows sockets programming 
#include "win_linux_sockets.h"

#define INFO        1

//Getting time
static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time);

salt_time_t my_time = {
    get_time,
    NULL
};

//Function for sending messages
salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
#if defined(_WIN32)

    uint32_t bytes_sent;

    //Decriptor of socket
    SOCKET sock = *((SOCKET *) p_wchannel->p_context);

    if (sock <= 0) {
        return SALT_ERROR;
    }
    
    //Sending messages through socket
    int begin = 0;
    while (begin < p_wchannel->size_expected) { 
        bytes_sent = send(sock,(char *) p_wchannel->p_data + begin, p_wchannel->size_expected - begin, 0);
        printf("Sent %d bytes.\n", bytes_sent);
        //Verification
        if (bytes_sent < 1) {
            printf("Less than 1 bytes was sent.\nSocket was closed\n");
            CLOSESOCKET(sock);
        }
        begin += bytes_sent;

        //Addition size of bytes
        p_wchannel->size += bytes_sent;
    
    }
    
    return SALT_SUCCESS;

#else 

    int sock = *((int *) p_wchannel->p_context);
    uint32_t to_write = p_wchannel->size_expected - p_wchannel->size;

    if (sock <= 0) {
        return SALT_ERROR;
    }

    int n = write(sock,
                  &p_wchannel->p_data[p_wchannel->size],
                  to_write);
    printf("Sent %d bytes.\n", n);

    if (n <= 0) {
        p_wchannel->err_code = SALT_ERR_CONNECTION_CLOSED;
        printf("Less than 1 bytes was sent.\nSocket was closed\n");
        return SALT_ERROR;
    }

    SALT_HEXDUMP_DEBUG(&p_wchannel->p_data[p_wchannel->size], n);

    p_wchannel->size += n;

    return (p_wchannel->size == p_wchannel->size_expected) ? SALT_SUCCESS : SALT_PENDING;

#endif   
}

////Function for receiving messages
salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
#if defined(_WIN32)

    uint32_t bytes_received;

    //Decriptor of socket
    SOCKET sock = *((SOCKET *) p_rchannel->p_context);

    if (sock <= 0) {
        return SALT_ERROR;
    }

    //Receiving messages through socket
    int begin = 0;
    while (begin < p_rchannel->size_expected){ 
        bytes_received = recv(sock,(char *) p_rchannel->p_data, p_rchannel->size_expected, 0);
       printf("Received %d bytes\n", bytes_received);
        //Verification
        if (bytes_received < 1) {
            printf("Less than 1 bytes was received.\nSocket was closed\n");
            CLOSESOCKET(sock);
        }
        begin += bytes_received;

        //Addition size of bytes
        p_rchannel->size += bytes_received;
    }

    return SALT_SUCCESS;

#else

    int sock = *((int *) p_rchannel->p_context);
    uint32_t to_read = p_rchannel->size_expected - p_rchannel->size;

    if (sock <= 0) {
        return SALT_ERROR;
    }

    int n = read(sock,
                 &p_rchannel->p_data[p_rchannel->size],
                 to_read);
    printf("Received %d bytes\n", n);

    if (n <= 0) {
        p_rchannel->err_code = SALT_ERR_CONNECTION_CLOSED;
        printf("Less than 1 bytes was received.\nSocket was closed\n");
        return SALT_ERROR;
    }

    SALT_HEXDUMP_DEBUG(&p_rchannel->p_data[p_rchannel->size], n);

    p_rchannel->size += n;

    return (p_rchannel->size == p_rchannel->size_expected) ? SALT_SUCCESS : SALT_PENDING;
    
#endif
}

//A function to create a timestamp that is included in sent/receivd messages
static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time){
    
    (void) *p_time;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t curr_time = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
    uint32_t rel_time = curr_time % 0xFFFFFFFF;
    *time = rel_time;
    return SALT_SUCCESS;
}

