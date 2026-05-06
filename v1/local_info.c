/*
Find local information:
- IPv4 and IPV6 addresses
- UIDs
*/

#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

void print_addresses(const int family) {
    /*
    Print local addresses.
    Only print one family at a time so the output can be wrapped.
    */

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if ((family==4) && (ifa->ifa_addr->sa_family == AF_INET)) {
            printf("// Interface: %s\n", ifa->ifa_name);
            struct sockaddr_in *sin4 = (struct sockaddr_in *)ifa->ifa_addr;
            uint32_t addr4 = ntohl(sin4->sin_addr.s_addr);

            printf("0x%08x, // %d.%d.%d.%d\n", addr4, addr4>>24, (addr4>>16)&0xff, (addr4>>8)&0xff, addr4&0xff);
        } else if((family==6) && (ifa->ifa_addr->sa_family == AF_INET6)) {
            printf("// Interface: %s\n", ifa->ifa_name);
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;

            printf("{ ");
            for(int i=0; i<16; i++) {
                printf("0x%02x, ", sin6->sin6_addr.s6_addr[i]);
            }
            printf("},\n");
        }
    }

    freeifaddrs(ifaddr);
}

int main() {
    printf("int addresses4[] = {\n");
    print_addresses(4);
    printf("};\n");

    printf("uint8_t addresses6[][16] = {\n");
    print_addresses(6);
    printf("};\n");

    return 0;
}
