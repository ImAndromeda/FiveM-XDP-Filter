# XDP Program for Protecting a FiveM Server

This XDP program protects a FiveM server by filtering out non-FiveM traffic. The program inspects incoming packets and drops any packets that are not UDP packets destined for the FiveM server IP address and port. Additionally, it includes rate-limiting and safety checks to prevent legitimate traffic from being inadvertently dropped.

## Requirements

- Linux kernel with XDP support enabled.
- Clang compiler for compiling the XDP program.
- Basic knowledge of Linux networking and handling interfaces.

## Installation

### Step 1: Modify the XDP Program

Before compiling the program, update the FIVEM_SERVER_IP and FIVEM_SERVER_PORT macros in the XDP script to match your FiveM server's IP address and port.

1. Open the `xdp_program.c` file.
2. Modify the following macros:
   #define FIVEM_SERVER_IP  0x7F000001  // Replace with your server's IP in hex format (e.g., 192.168.1.1 -> 0xC0A80101 or 0x7F000001 for 172.0.0.1 (Localhost)
   #define FIVEM_SERVER_PORT 30120      // Replace with your server's port if different

`Note: Changing the default FiveM port (30120) to something else is recommended for better security.`

### Step 2: Compile the XDP Program

Use the clang compiler to compile the XDP program for your system:

```c 
clang -O2 -target bpf -c xdp_program.c -o xdp_program.o
```

This will produce the xdp_program.o object file that you can load into your network interface.

### Step 3: Load the XDP Program

Load the compiled XDP program into the network interface that your FiveM server uses. Replace `<interface>` with the name of your network interface (e.g., `eth0`):

```bash 
ip link set dev <interface> xdp obj xdp_program.o sec xdp_program
```

### Step 4: Verify the XDP Program

Test the XDP program by generating traffic to your FiveM server on the configured port (default: 30120). Ensure that non-FiveM traffic is being dropped and legitimate FiveM traffic is allowed to pass through.

You can use packet-capturing tools like tcpdump to verify traffic behavior:

```bash
tcpdump -i <interface>
```

### Step 5: Monitor Packet Counts

The program includes logging for tracking how many packets are dropped or passed. Use bpftool to check the statistics:

```bash
bpftool map dump name packet_count_map
```

## Unloading the XDP Program

If you need to unload the XDP program from the interface, run the following command:

```bash
ip link set dev <interface> xdp off
```

## License

This XDP program is released under the MIT license. See the LICENSE file for more information.
