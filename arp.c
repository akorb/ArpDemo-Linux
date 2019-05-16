#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>

// 14 bytes: Ethernet header
// 28 bytes: Arp data
#define ETHERNET_SIZE 14
#define ARP_SIZE 28
#define ARP_FRAME_SIZE (ETHERNET_SIZE + ARP_SIZE)

struct if_nameindex chooseInterface() {
  struct if_nameindex *if_array;

  if_array = if_nameindex();
  if (if_array == NULL) {
    perror("if_nameindex");
    exit(EXIT_FAILURE);
  }

  int i = 0;
  while (if_array[i].if_index != 0 && if_array[i].if_name != NULL) {
    printf("%i: %s\n", if_array[i].if_index, if_array[i].if_name);
    i++;
  }

  printf("Select index: ");
  int if_index;
  scanf("%i", &if_index);

  struct if_nameindex result;
  result.if_index = if_array[if_index - 1].if_index;
  result.if_name = strdup(if_array[if_index - 1].if_name);

  if_freenameindex(if_array);

  return result;
}

void fillArpPacket(unsigned char *buffer, unsigned char *srcMac,
                   unsigned char *dstIp, unsigned char *srcIp) {

  /***** ETHERNET *****/
  // Destination MAC address
  buffer[0] = 255;
  buffer[1] = 255;
  buffer[2] = 255;
  buffer[3] = 255;
  buffer[4] = 255;
  buffer[5] = 255;

  // Source MAC address
  buffer[6] = srcMac[0];
  buffer[7] = srcMac[1];
  buffer[8] = srcMac[2];
  buffer[9] = srcMac[3];
  buffer[10] = srcMac[4];
  buffer[11] = srcMac[5];
  // Type
  buffer[12] = 8;
  buffer[13] = 6;

  /***** ARP *****/
  // Hardware type
  buffer[ETHERNET_SIZE + 0] = 0;
  buffer[ETHERNET_SIZE + 1] = 1;
  // Protocol type
  buffer[ETHERNET_SIZE + 2] = 8;
  buffer[ETHERNET_SIZE + 3] = 0;
  // Hardware address length
  buffer[ETHERNET_SIZE + 4] = 6;
  // Protocol address length
  buffer[ETHERNET_SIZE + 5] = 4;
  // Operation
  buffer[ETHERNET_SIZE + 6] = 0;
  buffer[ETHERNET_SIZE + 7] = 1;

  // Sender hardware address
  buffer[ETHERNET_SIZE + 8] = srcMac[0];
  buffer[ETHERNET_SIZE + 9] = srcMac[1];
  buffer[ETHERNET_SIZE + 10] = srcMac[2];
  buffer[ETHERNET_SIZE + 11] = srcMac[3];
  buffer[ETHERNET_SIZE + 12] = srcMac[4];
  buffer[ETHERNET_SIZE + 13] = srcMac[5];

  // Source IP address
  buffer[ETHERNET_SIZE + 14] = srcIp[0];
  buffer[ETHERNET_SIZE + 15] = srcIp[1];
  buffer[ETHERNET_SIZE + 16] = srcIp[2];
  buffer[ETHERNET_SIZE + 17] = srcIp[3];

  // Destination hardware address
  buffer[ETHERNET_SIZE + 18] = 255;
  buffer[ETHERNET_SIZE + 19] = 255;
  buffer[ETHERNET_SIZE + 20] = 255;
  buffer[ETHERNET_SIZE + 21] = 255;
  buffer[ETHERNET_SIZE + 22] = 255;
  buffer[ETHERNET_SIZE + 23] = 255;

  // Destination IP address
  buffer[ETHERNET_SIZE + 24] = dstIp[0];
  buffer[ETHERNET_SIZE + 25] = dstIp[1];
  buffer[ETHERNET_SIZE + 26] = dstIp[2];
  buffer[ETHERNET_SIZE + 27] = dstIp[3];
}

struct sockaddr_ll getSocketAddress(int if_index) {
  struct sockaddr_ll socket_address;

  /* Index of the network device */
  socket_address.sll_ifindex = if_index;
  /* Address length*/
  socket_address.sll_halen = ETH_ALEN;
  /* Destination MAC */
  socket_address.sll_addr[0] = 255;
  socket_address.sll_addr[1] = 255;
  socket_address.sll_addr[2] = 255;
  socket_address.sll_addr[3] = 255;
  socket_address.sll_addr[4] = 255;
  socket_address.sll_addr[5] = 255;

  return socket_address;
}

void getLocalMac(unsigned char *mac, int sockfd, char *if_name) {
  struct ifreq if_mac;

  memset(&if_mac, 0, sizeof(struct ifreq));
  strncpy(if_mac.ifr_name, if_name, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
    perror("SIOCGIFHWADDR");

  const unsigned char *my_mac =
      (unsigned char *)&(((unsigned char *)&if_mac.ifr_ifru.ifru_data)[2]);
  memcpy(mac, my_mac, ETH_ALEN);
}

void getLocalIpAddr(unsigned char *ip, int sockfd, char *if_name) {
  struct ifreq if_ip;
  strncpy(if_ip.ifr_name, if_name, IFNAMSIZ - 1);
  if_ip.ifr_addr.sa_family = AF_INET;
  if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0)
    perror("SIOCGIFADDR");

  const unsigned char *my_ip = (unsigned char *)&if_ip.ifr_ifru.ifru_data;
  memcpy(ip, &my_ip[4], 4);
}

void receiveArp(int sockfd, unsigned char *srcIp) {
  unsigned char result[ARP_FRAME_SIZE];
  while (1) {
    int data_size = recvfrom(sockfd, result, sizeof(result), 0, NULL, NULL);
    if (data_size == -1) {
      perror("recvfrom");
      exit(1);
    }

    // Check if the packet comes from the target
    if (memcmp(&result[ETHERNET_SIZE + 14], srcIp, 4) ==
            0                             // Accept only target address
        && result[ETHERNET_SIZE + 7] == 2 // Accept only replies
    ) {
      // Print sender hardware address
      printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", result[ETHERNET_SIZE + 8],
             result[ETHERNET_SIZE + 9], result[ETHERNET_SIZE + 10],
             result[ETHERNET_SIZE + 11], result[ETHERNET_SIZE + 12],
             result[ETHERNET_SIZE + 13]);
      break;
    }
  }
}

int main() {
  struct if_nameindex if_struct = chooseInterface();

  int sockfd;
  // Open RAW socket to send on
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
    perror("socket");
    exit(1);
  }

  printf("Target IP Address: ");

  unsigned char dstIp[4];
  scanf("%hhu.%hhu.%hhu.%hhu", &dstIp[0], &dstIp[1], &dstIp[2], &dstIp[3]);

  unsigned char mac[ETH_ALEN];
  getLocalMac(mac, sockfd, if_struct.if_name);

  unsigned char srcIp[4];
  getLocalIpAddr(srcIp, sockfd, if_struct.if_name);

  unsigned char buffer[ARP_FRAME_SIZE];
  fillArpPacket(buffer, mac, dstIp, srcIp);

  struct sockaddr_ll socket_address = getSocketAddress(if_struct.if_index);

  // Send packet
  int res =
      sendto(sockfd, buffer, sizeof(buffer), 0,
             (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll));
  if (res == -1) {
    perror("sendto");
    exit(1);
  }

  receiveArp(sockfd, dstIp);

  close(sockfd);

  return EXIT_SUCCESS;
}
