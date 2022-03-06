# example_tcp_Salt_app_packet

The application demonstrates the operation and deployment of the salt-channel protocol
to an insecure TCP communication channel (see example_tcp
on which the salt channel protocol was deployed, resulting in this component -
example_tcp_Salt_app). The protocol provides work with two at the application layer
packet types, this folder works with the AppPaket type.

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

