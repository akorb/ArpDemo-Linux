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
#define ARP_PACKET_SIZE (14 + 28)

struct if_nameindex getInterface() {
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

void fillArpPacket(unsigned char buffer[ARP_PACKET_SIZE],
                   unsigned char ipAddr[4], struct ifreq localMac) {
  const unsigned char *mac = (unsigned char *)&(((unsigned char *)&localMac.ifr_ifru.ifru_data)[2]);

  /***** ETHERNET *****/
  // Destination MAC address
  buffer[0] = 255;
  buffer[1] = 255;
  buffer[2] = 255;
  buffer[3] = 255;
  buffer[4] = 255;
  buffer[5] = 255;

  // Source MAC address
  buffer[6] = mac[0];
  buffer[7] = mac[1];
  buffer[8] = mac[2];
  buffer[9] = mac[3];
  buffer[10] = mac[4];
  buffer[11] = mac[5];
  // Type
  buffer[12] = 8;
  buffer[13] = 6;

  /***** ARP *****/
  // Hardware type
  buffer[14 + 0] = 0;
  buffer[14 + 1] = 1;
  // Protocol type
  buffer[14 + 2] = 8;
  buffer[14 + 3] = 0;
  // Hardware address length
  buffer[14 + 4] = 6;
  // Protocol address length
  buffer[14 + 5] = 4;
  // Operation
  buffer[14 + 6] = 0;
  buffer[14 + 7] = 1;

  // Sender hardware address 08:00:27:53:5d:97
  buffer[14 + 8] = mac[0];
  buffer[14 + 9] = mac[1];
  buffer[14 + 10] = mac[2];
  buffer[14 + 11] = mac[3];
  buffer[14 + 12] = mac[4];
  buffer[14 + 13] = mac[5];
  // Sender protocol address
  buffer[14 + 14] = 192;
  buffer[14 + 15] = 168;
  buffer[14 + 16] = 178;
  buffer[14 + 17] = 24;
  // Target hardware address
  buffer[14 + 18] = 255;
  buffer[14 + 19] = 255;
  buffer[14 + 20] = 255;
  buffer[14 + 21] = 255;
  buffer[14 + 22] = 255;
  buffer[14 + 23] = 255;
  // Target protocol address
  buffer[14 + 24] = ipAddr[0];
  buffer[14 + 25] = ipAddr[1];
  buffer[14 + 26] = ipAddr[2];
  buffer[14 + 27] = ipAddr[3];
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

struct ifreq getLocalMac(int sockfd, char *if_name) {
  struct ifreq if_mac;

  memset(&if_mac, 0, sizeof(struct ifreq));
  strncpy(if_mac.ifr_name, if_name, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
    perror("SIOCGIFHWADDR");

  return if_mac;
}

void receiveArp(int sockfd, unsigned char ipAddr[4]) {
  unsigned char result[ARP_PACKET_SIZE];
  while (1) {
    int data_size = recvfrom(sockfd, result, sizeof(result), 0, NULL, NULL);
    if (data_size == -1) {
      perror("recvfrom");
      exit(1);
    }

    // Check if the packet comes from the target
    if (memcmp(&result[14 + 14], ipAddr, 4) == 0 // Accept only target address
        && result[14 + 7] == 2                   // Accept only replies
    ) {
      // Print sender hardware address
      printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", result[14 + 8],
             result[14 + 9], result[14 + 10], result[14 + 11], result[14 + 12],
             result[14 + 13]);
      break;
    }
  }
}

int main() {
  struct if_nameindex if_struct = getInterface();

  int sockfd;
  // Open RAW socket to send on
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
    perror("socket");
    exit(1);
  }

  struct ifreq localMac = getLocalMac(sockfd, if_struct.if_name);

  printf("Target IP Address: ");
  unsigned char ipAddr[4];
  scanf("%hhu.%hhu.%hhu.%hhu", &ipAddr[0], &ipAddr[1], &ipAddr[2], &ipAddr[3]);

  unsigned char buffer[ARP_PACKET_SIZE];
  fillArpPacket(buffer, ipAddr, localMac);

  struct sockaddr_ll socket_address = getSocketAddress(if_struct.if_index);

  // Send packet
  int res =
      sendto(sockfd, buffer, sizeof(buffer), 0,
             (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll));
  if (res == -1) {
    perror("sendto");
    exit(1);
  }

  receiveArp(sockfd, ipAddr);

  close(sockfd);

  return 0;
}