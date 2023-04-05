# XDP program for protecting a FiveM server

This XDP program protects a FiveM server running on port 30120 by filtering out non-FiveM traffic. The program inspects incoming packets and drops any packets that are not UDP packets destined for the FiveM server IP address and port. The program also includes safety nets, such as early exits for non-matching packets and a random probability-based drop rate, to prevent over-filtering and ensure that legitimate traffic is not inadvertently dropped.

## Requirements

This XDP program requires a Linux kernel with XDP support, as well as the clang compiler for compiling the XDP program.

## Installation

1. Modify the `FIVEM_SERVER_IP` and `FIVEM_SERVER_PORT` macros in the XDP program to match the IP address and port of your FiveM server. You don't have to use port `30120` and in fact, I recommend that you change this port to something else. 

3. Compile the XDP program using the following command:

```clang -O2 -target bpf -c xdp_program.c -o xdp_program.o```

3. Load the XDP program into the network driver using the `ip` command:

```ip link set dev <interface> xdp obj xdp_program.o sec xdp_program```

Replace `<interface>` with the name of the network interface that your FiveM server is using.

4. Test the XDP program by generating traffic to your FiveM server on port 30120. Verify that the XDP program correctly drops any non-FiveM traffic and allows FiveM traffic to pass.

## License

This XDP program is released under the MIT license. See the `LICENSE` file for more information.
