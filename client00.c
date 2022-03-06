/**
 * ===============================================
 * client00.c   v.2.2
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

/**
* Macro allows diagnostic information to be written 
* to the standard error file.
*/
#include <assert.h>

/* Salt-channel handshake proccess is measured between devices. */
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


/* ======= Local Macro Definitions ======================= */

/*
 * The constant MAX_SIZE can be used to test the maximum 
 * size processed by the program
 */
//#define MAX_SIZE            UINT32_MAX 


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

/* Encryption buffer overhead size for read */
#define SALT_READ_OVRHD_SIZE     38   

/* Encryption buffer overhead size for write */  
#define SALT_WRITE_OVRHD_SIZE    42      


/*======= Global function implementation ===========*/

/* Function for calculated count of blocks */
int calculated_count_of_blocks(uint32_t file_size, 
                               int block_size, 
                               int overhead_size);

/* Function for creating / loading input file */
uint8_t *loading_file(char *file, 
                      uint32_t *fileSize, 
                      int my_file);


int main(int argc, char *argv[]) 
{
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
    char own_file[150];     

    /* 
     * test: you can choose whether you want to 
     * enter your own data or use a test program
     *
     * repeat: for the decision on the continue/finish 
     * of the program
     *
     * verify: if the salt handshake passes successfully, 
     * the verify is incremented and the data
     * is exchanged -> while (verify){ ... } 
     *
     * print_out: statement of received data
     */
    int repeat, test, verify = 0, print_out = 0,     

    /* 
     * Variables for auxiliary calculations when 
     * working with blocks 
     */
        count_of_read_blocks = 0,
        count_of_write_blocks = 0;

    /** 
     * Buffer for storing data during 
     * the handshake process. 
     */
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE],

    /**
     * tx_buffer -> encrypted data
     * input -> loading input file 
     * rx_buffer -> received/decrypted data
     */ 
    *tx_buffer, *input, *rx_buffer;

    /* The size of the transferred file. */    
    uint32_t file_size;

    /* Time measurement variables */
    clock_t start_t, end_t;

    /* ==  Variables for working with salt-channel protocol == */

    /* Salt channel structure */
    salt_channel_t client_channel;

    /*
     * typedef enum
     * which can obtain values:
     * SALT_SUCCESS, SALT_PENDING, SALT_ERROR            
     */
    salt_ret_t ret, ret_msg;

    /**
     * Structure used for easier 
     * creating/reading/working with messages 
     */
    salt_msg_t msg_out, msg_in;

    /* ==== Creating client socket and TCP connection ==== */

    /* Initializing Winscok - Win32 apps */
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        fprintf(stderr, "Failed to initialize.\n");
        return 1;
    }

    /* Checking the correct program parameters */
    if (argc < 3) {
        fprintf(stderr, "usage: tcp_client hostname port\n");
        return 1;
    }

    /* 
     * Configuring remote address with getaddrinfo - 
     * the parameters were entered from the command line 
     * like ip address and port number 
     */
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


    /* Creating client socket - socket_peer */
    printf("Creating socket...\n");
    SOCKET socket_peer;
    socket_peer = socket(peer_address->ai_family,
            peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_peer)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    /* Creating TCP connection with server */
    printf("Connecting...\n");
    if (connect(socket_peer,
                peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }


    freeaddrinfo(peer_address);

    /*
     * TCP connection was successfully established in the 
     * client-server architecture.
     * 
     * Now, We are implementing salt channel v2 
     * and We will try a salt handshake with the server
     */
    printf("Connected.\n");
    printf("TCP was successfully performed...\n\nCreating Salt hanshake...\n");

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
    ret = salt_create(&client_channel, SALT_CLIENT, my_write, my_read, &my_time);
    assert(ret == SALT_SUCCESS);

    /**
     * Creates and sets the signature used for the salt channel.
     *
     * @param client_channel Pointer to channel handle.
     *
     * @return SALT_SUCCESS The signature was successfully set.
     * @return SALT_ERROR   Any input pointer was a NULL pointer.
     */
    ret = salt_create_signature(&client_channel); 
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
    ret = salt_init_session(&client_channel, hndsk_buffer, sizeof(hndsk_buffer));
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
    ret = salt_set_context(&client_channel, &socket_peer, &socket_peer);
    assert(ret == SALT_SUCCESS);

    /* Set threshold for delay protection */
    ret = salt_set_delay_threshold(&client_channel, TRESHOLD);
    assert(ret == SALT_SUCCESS);

    /* ========  Salt-handshake process  ================= */
    do {

        /* Measurement salt handshake procces */
        start_t = clock();
        ret = salt_handshake(&client_channel, NULL);
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
            printf("Salt error: 0x%02x\r\n", client_channel.err_code);
            printf("Salt error read: 0x%02x\r\n", client_channel.read_channel.err_code);
            printf("Salt error write: 0x%02x\r\n", client_channel.write_channel.err_code);

            /* Closing application */
            assert(ret != SALT_ERROR);
        } else if (ret == SALT_SUCCESS) 
        {       

            printf("\nSalt handshake successful\r\n\n");
            printf("\t\n***** CLIENT: Salt channelv2 handshake lasted: %6.6f sec. *****\n", ((double) (end_t -
                start_t) / (CLOCKS_PER_SEC))); 
            printf("\n");

            /**
             * If the salt handshake passed successfully, 
             * we can access the data exchange. 
             */
            verify++;
        }
    } while (ret == SALT_PENDING);


    /* ======= Sending/receiving data ==================== */
    while(verify)
    {
        int free_input = 0;

        printf("\n\nDo you want to use a random text file to test the application\n" 
            "or you want to use the application according to your needs\n"
            "Press number 0 or 1,\n'1' -> to test the application\n"
            "'0' -> own data\n");

        scanf("%d", &test);

        /* ========  Loading input data  ================= */
        if (test)
        {  
            printf("\n\nYou have decided to create a test file to test the application\n"
                "follow this instructions:\n"
                "Please enter name of file with suffix, example: example.txt \n");

            scanf("%s", own_file);

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
            uint8_t input_cli[4096];
            input = input_cli;

            printf("To send data, enter text followed by enter.\n");

            /* Cleaning buffer from enter */
            while(getchar() != '\n')
                ;

            /* Receipt of input data from the client (CLI) */
            fgets((char *)input, 4096, stdin);
            file_size = strlen((const char *) input);

            printf("Size of data is: %u\n\n", file_size);
        }

        /* 
         * Calculating the number of blocks and the additional memory 
         * required to work with the data
         */

        count_of_write_blocks = calculated_count_of_blocks(file_size,
                                                           BLOCK_SIZE,
                                                           SALT_WRITE_OVRHD_SIZE);
        count_of_write_blocks = SALT_WRITE_OVRHD_SIZE + (count_of_write_blocks * 2);

        count_of_read_blocks = calculated_count_of_blocks(file_size,
                                                           BLOCK_SIZE,
                                                           SALT_READ_OVRHD_SIZE);
        count_of_read_blocks = SALT_READ_OVRHD_SIZE + (count_of_write_blocks * 2);

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

        while(verify) 
        { 
            printf("Do you want to list the received data?\n"
                "If yes, press -> '1'\n"
                "Or no, press -> '0'\n");
            scanf("%d", &print_out);

            /* Variables for working with data   */                                 
            uint32_t begin = 0, sent_size = BLOCK_SIZE;
            ret_msg = SALT_ERROR;

            /* Filling a block of memory with a particular value */
            memset(tx_buffer, 0, file_size + count_of_write_blocks);
            memset(rx_buffer, 0, file_size + count_of_read_blocks);
             
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

            ret_msg = salt_write_begin(tx_buffer, file_size + count_of_write_blocks, &msg_out);
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
                if (file_size % sent_size == file_size) 
                    sent_size = file_size;

                /*
                 * If left bytes less than sent_size(BLOCK_SIZE)
                 * send residue bytes
                 */
                if (begin + sent_size > file_size)
                    sent_size = file_size - begin;

                ret_msg = salt_write_next(&msg_out, input + begin, sent_size);
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

            do {

                ret_msg = salt_write_execute(&client_channel, &msg_out, false);
            } while(ret_msg == SALT_PENDING);

            /* Verification of the encryption and data transmission process */

            if (ret_msg == SALT_ERROR)
            {   
                printf("\nError during writting:\r\n");
                repeat = 1;

                if(free_input) 
                    free(input);

                free(tx_buffer);
                free(rx_buffer);

                break;
            }

            printf("\n");
            ret_msg = SALT_ERROR;
          
            printf("Data reception and decryption\n");

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

            do {

                ret_msg = salt_read_begin(&client_channel, rx_buffer, file_size + count_of_read_blocks, &msg_in);
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
                printf("\nRecevied %d BLOCK/BLOCKS:\n\n", ++msg_in.read.messages_left);

                do {
                    
                    /* Listing of received data */
                   if(print_out)
                        printf("%*.*s\r\n", 0, msg_in.read.message_size, (char*) msg_in.read.p_payload);
                } while (salt_read_next(&msg_in) == SALT_SUCCESS);

            }

            /* Verification of the decryption and data transmission process */
            if (ret == SALT_ERROR)
            {
                printf("\nError during reading:\r\n");
                repeat = 1;

                if(free_input) 
                    free(input);

                free(tx_buffer);
                free(rx_buffer);

                break;
            } 

            /* End of sending and receiving data, encryption and decryption */ 
            printf("\nDo you want to finish?\nPress number, '1'-> to quit\n"
                "Press '0' -> to continue\n");
                
            scanf("%d", &repeat);

            if(free_input) 
                free(input);

            free(tx_buffer);
            free(rx_buffer);

            break;
        }

        if(repeat) break;
    }

/* ========  End of application  ========================= */

    printf("\nClosing connection...\n");
    printf("Closing socket...\n");
    CLOSESOCKET(socket_peer);

    WSACleanup();

    printf("Finished.\n");
    return 0;
}

/* Function for calculated count of blocks */
int calculated_count_of_blocks(uint32_t file_size, 
                               int block_size, 
                               int overhead_size)
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

/* Function for creating / loading file */
uint8_t *loading_file(char *file, 
                      uint32_t *file_size, 
                      int my_file)
{   

    FILE *stream;

    int result1, result2;

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
        scanf("%u",&expected_size_file);
        expected_size_file = expected_size_file / 
                            (sizeof(expected_size_file) * sizeof(expected_size_file));
        printf("Enter max integer (range): \n");
        scanf("%u",&range);

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
     */

    /* If successful, return 0 */
    if ((result1 = _fseeki64(stream, 0L, SEEK_END)) != 0)
        printf("_fseeki64 error1\n");

    /* _ftelli64 return the current file position */
    *file_size = _ftelli64(stream);

    /* If successful, return 0 */
    if ((result2 = _fseeki64(stream, 0L, SEEK_SET)) != 0)
        printf("_fseeki64 error2\n");

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
    fread(input, 1, *file_size, stream);


    if(fclose(stream) == EOF) 
        printf("Failed to closed file\n");

    return input;
}


