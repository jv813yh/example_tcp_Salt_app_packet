# example_tcp_salt_channel

The program can be compiled using a makefile and they are added
.bat files for easy launch of server and client applications.
The server uses the loopback address and listens on port 8080.
Provides a toupper () function that converts lowercase letters received by clients
for large characters and sending to their clients, where the client receives lists of data
create CLI. The INC folder contains all the necessary header files to work with
SRC_LIB all code sources used by the application.

The application demonstrates the operation and deployment of the salt-channel protocol
to an insecure TCP communication channel 
(see example_tcp: https://github.com/jv813yh/example_tcp )
on which the salt channel protocol was deployed, resulting in this component -
example_tcp_salt_channel). The protocol ensures work on the application layer
with two types of packets, this folder works with both, depending on
from the transferred data, if they are in UINT16_MAX, we are working
with the App packet, if the data is larger, the Multi App packet is used.
The maximum amount of data transferred in an application depends on the MAX_SIZE 
constant on the server side, which is defined directly in the source code server00.c

Runable on Windows, after fine editing the makefile also on Linux.
(I'm working on a makefile that will work subcutaneously on both axes.

Salt-channel protocol: 
https://github.com/assaabloy-ppi/salt-channel-c

Salt crypto wrapper for modified version of TweetNaCl:
https://github.com/assaabloy-ppi/salt-channel-c/blob/master/src/external/tweetnacl_modified/tweetnacl_modified_wrapper.c

I am also working on an application where the server 
serves many connected clients simultaneously using the salt channel protocol
on TCP/IP:
https://github.com/jv813yh/TCP_salt-channel

