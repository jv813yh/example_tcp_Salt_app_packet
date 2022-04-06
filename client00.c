/**
 * ===============================================
 * client00.c   v.1.7
 * 
 * KEMT FEI TUKE, Diploma thesis
 *
 * The program is used for a simple demonstration 
 * of the implementation of the Salt channel protocol 
 * on TCP and working with the protocol.
 *
 * CLIENT: input from client -> CLI or
 * creating / loading input file and creating
 * salt handshake proccess and sending data
 * from client with Salt channelv2 cryptographic
 * to the server,the server (which also uses the 
 * salt channel protocol) performs service and 
 * sending the changing data back to the client:
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
 * Author-Jozef Vendel  Create date- 24.12.2021 
 * ===============================================
 */

/* ======== Includes ===================================== */

/* Basic libraries for working in C. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

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

int main(int argc, char *argv[]) 
{
    /* Checking the correct program parameters */
    if (argc < 3) {
        fprintf(stderr, "usage: tcp_client hostname port\n");
        return 1;
    }

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
    printf("\nCLIENT: input from client -> CLI or\n"
        "creating / loading input file and creating\n"
        "salt handshake proccess and sending data\n"
        "from client with Salt channelv2 cryptographic\n"
        "to the server,the server (which also uses the\n" 
        "salt channel protocol) performs service and\n" 
        "sending the changing data back to the client\n\n");

/* ========  Variables & arrays ======== */

    /* Own file name */
    char own_file[AUXILIARY_FIELD_SIZE];     

    /* 
     * test: you can choose whether you want to 
     * enter your own data or use a test program
     *
     * repeat: for the decision on the continue/finish 
     * of the program
     *
     * print_out: statement of received data
     */
    int repeat, test, print_out = 0, free_input = 0;    

    /* 
     * Variables for auxiliary calculations when 
     * working with blocks for protocol (size of buffer)
     */
      uint32_t  count_of_read_blocks = 0,
        count_of_write_blocks = 0;

    /**
     * tx_buffer -> encrypted data
     * input -> loading input file 
     * rx_buffer -> received/decrypted data
     */ 
    uint8_t *tx_buffer, *input, *rx_buffer;

    /* The size of the transferred file. */    
    uint32_t file_size;

    /* Client socket for TCP */
    SOCKET socket_peer;

/* ====  Variables for working with salt-channel protocol ===== */

    /* Salt channel structure */
    salt_channel_t client_channel;

    /* 
     * Verification of return values during working with protocol  
     *
     * typedef enum
     * which can obtain values:
     * SALT_SUCCESS, SALT_PENDING, SALT_ERROR            
     */
    salt_ret_t ret_hndshk = SALT_ERROR, ret_msg = SALT_ERROR;

    /**
     * Structure used (protocol) for easier 
     * creating / reading / working with data 
     */
    salt_msg_t msg_out, msg_in;

/* ==== Creating client socket and TCP connection ==== */

    /* 
     * It will create a socket with which the client will 
     * connect to the server
     */
    socket_peer = create_socket_and_connect(argv[1], argv[2]);

    /* Connection control */
    if (ISVALIDSOCKET(socket_peer)) printf("\nConnection to the server :)\n");
    else printf("\nError connecting to server :(\n");

    /*
     * TCP connection was successfully established in the 
     * client-server architecture.
     * 
     * Now, We are implementing salt channel v2 
     * and We will try a salt handshake with the server
     */
    printf("Connected.\n");
    printf("TCP was successfully performed...\n\nCreating Salt Hanshake...\n");

/* ========  Salt-channel implementation and Salt Handshake  ======== */

    ret_hndshk = salt_impl_and_hndshk(&client_channel,
                                    my_write,
                                    my_read,
                                    &socket_peer,
                                    &my_time,
                                    TRESHOLD);
    /* Implementation and Handshake verification */
    assert(ret_hndshk == SALT_SUCCESS);

/* ======= Sending/receiving data in cycles ==================== */
/* ======= Encryption/decryption data ========================== */
    while(ret_hndshk == SALT_SUCCESS)
    {
        free_input = 0;
        printf("\n\nDo you want to use a random text file to test the application\n" 
            "or you want to use the application according to your needs\n"
            "Press number 0 or 1,\n'1' -> to test the application\n"
            "'0' -> own data\n");
        if (EOF == (scanf("%d", &test)))
        {
            printf("Bad choise :(\n");
            return -1;
        }

/* ========  Loading input data (file)  ================= */
        if (test)
        {  
            printf("\n\nYou have decided to create a test file to test the application.\n"
                "Follow this instructions:\n"
                "Please enter name of file with suffix, example: example.txt \n");
            if (EOF == scanf("%s", own_file))
            {
                printf("Bad name of file for create\n");
                return 0;
            }

            /* Random generate file and loading input data */
            input = loading_file(own_file, &file_size, 0); 

            printf("\nFile size is: %u\n", file_size);

            //Check if the memory has been successfully
            //allocated by malloc or not
            if (input == NULL)
            {
                printf("Memory not allocated in loading file\n");
                exit(0);
            }
            free_input++;
        } else 
        {   
/* =======  Loading data from client (CLI) === */
            uint8_t input_cli[AUXILIARY_FIELD_SIZE];
            input = input_cli;

            printf("To send data, enter text followed by enter.\n");
            /* Cleaning buffer from enter */
            while(getchar() != '\n')
                ;

            /* Receipt of input data from the client (CLI) */
           if (!fgets((char *)input, AUXILIARY_FIELD_SIZE, stdin)) break;
            file_size = strlen((const char *) input);

            printf("\nSize of data is: %u\n\n", file_size);
        }

        /* 
         * Calculating the number of blocks and the additional memory 
         * required to work with the data for protocol
         */

        count_of_write_blocks = calculated_count_of_blocks(file_size,
                                                           BLOCK_SIZE,
                                                           SALT_WRITE_OVRHD_SIZE);
        count_of_write_blocks = SALT_WRITE_OVRHD_SIZE + (count_of_write_blocks * 2);
        if (count_of_write_blocks <= 0)
        {
            printf("Error calculating memory size for blocks\n");
            return -1;
        }
        count_of_read_blocks = calculated_count_of_blocks(file_size,
                                                           BLOCK_SIZE,
                                                           SALT_READ_OVRHD_SIZE);
        count_of_read_blocks = SALT_READ_OVRHD_SIZE + (count_of_write_blocks * 2);
        if (count_of_write_blocks <= 0)
        {
            printf("Error calculating memory size for blocks\n");
            return -1;
        }

        /* Allocates the requested memory and returns a pointer to it */
        tx_buffer = (uint8_t *) malloc(file_size + count_of_write_blocks);
        rx_buffer = (uint8_t *) malloc(file_size + count_of_read_blocks);

        //Check if the memory has been successfully
        //allocated by malloc or not
        if((tx_buffer == NULL) || (rx_buffer == NULL))
        {
            printf("Memory not allocated.\n");
            exit(0);   
        }

/* ======= Sending/receiving data ==================== */
/* ======= Encryption/decryption data ================ */

        while(ret_hndshk == SALT_SUCCESS) 
        { 
            printf("Do you want to list the received data?\n"
                "If yes, press -> '1'\n"
                "Or no, press -> '0'\n");
            if (scanf("%d", &print_out) == EOF)
            {
                printf("Error: Do you want to list the received data?\n");
                return -1;
            }

            /* Filling a block of memory with a particular value */
            memset(tx_buffer, 0, file_size + count_of_write_blocks);
            memset(rx_buffer, 0, file_size + count_of_read_blocks);

            /* 
             * Created a function for preparing buffer and data,
             * then encrypting and sending data in the salt channel protocol
             */
            ret_msg = salt_encrypt_and_send(&client_channel,
                                        tx_buffer,
                                        file_size + count_of_write_blocks,
                                        file_size,
                                        BLOCK_SIZE,
                                        input,
                                        &msg_out);
            /* Verification */
            assert(ret_msg == SALT_SUCCESS);

            ret_msg = SALT_ERROR;
            /* 
             * Created function for data reception, decryption, 
             * verification and reading in the salt channel protocol
             */
            ret_msg = salt_read_and_decrypt(&client_channel,
                                            rx_buffer,
                                            file_size + count_of_read_blocks,
                                            &msg_in,
                                            NULL,
                                            NULL,
                                            print_out);
            assert(ret_msg == SALT_SUCCESS);

            /* End of sending and receiving data, encryption and decryption */ 
            printf("\nDo you want to finish?\nPress number, '1'-> to quit\n"
                "Press '0' -> to continue\n");
            if (EOF == scanf("%d", &repeat))
            {
                printf("Bad choice for reperat or continue\n");
                return 0;
            }

            if(free_input) 
                free(input);

            free(tx_buffer);
            free(rx_buffer);

            break;
        }
        if(repeat) break;

        /* If everything is OK, the cycle continues */
        ret_hndshk = ret_msg;
    }

/* ========  End of application  ========================= */

    printf("\nClosing connection...\n");
    printf("Closing socket...\n");
    /* Socket closure */
    CLOSESOCKET(socket_peer);

    /* Cleanning Winsock, ONLY FOR WINDOWS !!! */
#if defined(_WIN32)
    WSACleanup();
#endif

    printf("Finished.\n");

    return 0;
}
