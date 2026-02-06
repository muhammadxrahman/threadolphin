#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <cctype>
#include <pcap.h>

// Ethernet Header
// Ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN 6
struct sniff_ethernet
{
    // compiler sees order already so we can make it show source first, no issue
    u_char ether_dhost[ETHER_ADDR_LEN]; // Dest MAC (Bytes 0-5)
    u_char ether_shost[ETHER_ADDR_LEN]; // Src MAC (Bytes 6-11)
    u_short ether_type;                 // Protocol Type (Bytes 12-13)
};

// IP Header (usually 20 bytes)
struct sniff_ip
{
    u_char ip_vhl;                 // Version (4 bits) + Header Length (4 bits)
    u_char ip_tos;                 // Type of service
    u_short ip_len;                // Total length
    u_short ip_id;                 // Identification
    u_short ip_off;                // Fragment offset field
    u_char ip_ttl;                 // Time to live
    u_char ip_p;                   // Protocol (TCP, UDP, ICMP)
    u_short ip_sum;                // Checksum
    struct in_addr ip_src, ip_dst; // Source and Dest IP addresses
};

// Helper macros to extract 4-bit values from ip_vhl
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

// TCP Header
typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport; // Source port
    u_short th_dport; // Destination port
    tcp_seq th_seq;   // Sequence number
    tcp_seq th_ack;   // Acknowledgement number
    u_char th_offx2;  // Data offset, rsvd
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02 // "Synchronize" - Start connection
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
    u_short th_win; // Window
    u_short th_sum; // Checksum
    u_short th_urp; // Urgent pointer
};

// Payload Address = Start of Packet + 14 + size_ip + size_tcp
void print_payload(const u_char *payload, int len)
{
    const u_char *ch = payload;

    std::cout << "   Payload (" << len << " bytes):\n   ";

    // Only first 64 bytes to keep output clean
    int print_len = (len > 64) ? 64 : len;

    for (int i = 0; i < print_len; i++)
    {
        if (isprint(*ch))
        {
            std::cout << *ch; // Print if char readable
        }
        else
        {
            std::cout << "."; // rip just .
        }
        ch++;
    }

    if (len > 64)
        std::cout << "... [truncated]";
    std::cout << std::endl;
}

// pcap_loop will call every time a packet arrives
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet_data)
{
    // 1. Ethernet
    const struct sniff_ethernet *ethernet;
    ethernet = (struct sniff_ethernet *)(packet_data);

    if (ntohs(ethernet->ether_type) != 0x0800)
        return; // skip non-ip

    // 2. IP
    // The IP header starts after the Ethernet header size (14 bytes)
    const struct sniff_ip *ip;
    ip = (struct sniff_ip *)(packet_data + 14);
    // The length is stored in the lower 4 bits of ip_vhl.
    // That number is in "4-byte words" (e.g., 5 means 5 * 4 = 20 bytes).
    int size_ip = IP_HL(ip) * 4;

    if (size_ip < 20)
    {
        std::cout << "   * Invalid IP header length: " << size_ip << " bytes" << std::endl;
        return;
    }

    // 3. TCP
    if (ip->ip_p == 6)
    {
        const struct sniff_tcp *tcp;

        // MATH: Packet Start + Ethernet Size + IP Size = TCP Start
        tcp = (struct sniff_tcp *)(packet_data + 14 + size_ip);

        // Calculate TCP Header size
        // The offset is in the high 4 bits of th_offx2.
        // We defined the macro TH_OFF() to extract that number for us.
        int size_tcp = TH_OFF(tcp) * 4;

        if (size_tcp < 20)
        {
            std::cout << "   * Invalid TCP header length: " << size_tcp << " bytes" << std::endl;
            return;
        }

        std::cout << "TCP: " << inet_ntoa(ip->ip_src)
                  << ":" << ntohs(tcp->th_sport)
                  << " -> " << inet_ntoa(ip->ip_dst)
                  << ":" << ntohs(tcp->th_dport);

        if (tcp->th_flags & TH_SYN)
            std::cout << " [SYN]";
        if (tcp->th_flags & TH_FIN)
            std::cout << " [FIN]";
        if (tcp->th_flags & TH_PUSH)
            std::cout << " [PUSH]";

        std::cout << std::endl;

        // 4. Payload
        // Calculate pointer to payload
        const u_char *payload = (u_char *)(packet_data + 14 + size_ip + size_tcp);
        // Size
        // Total Packet Length (from IP Header) - IP Header Size - TCP Header Size
        int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        if (size_payload > 0) {
            print_payload(payload, size_payload);
        }
    }

    // // IP Addresses
    // // inet_ntoa converts the raw number to a string like "192.168.1.1"
    // std::cout << "IP Packet: " << inet_ntoa(ip->ip_src)
    //           << " -> " << inet_ntoa(ip->ip_dst)
    //           << " | Protocol: " << (int)ip->ip_p << std::endl;

    // // src MAC
    // std::cout << "Source: ";
    // for(int i = 0; i < ETHER_ADDR_LEN; i++) {
    //     printf("%02x", ethernet->ether_shost[i]);
    //     if(i < ETHER_ADDR_LEN - 1) std::cout << ":";
    // }
    // // dest MAC
    // std::cout << " -> Dest: ";
    // for(int i = 0; i < ETHER_ADDR_LEN; i++) {
    //     printf("%02x", ethernet->ether_dhost[i]);
    //     if(i < ETHER_ADDR_LEN - 1) std::cout << ":";
    // }
    // // Type
    // std::cout << " | Type: " << std::hex << ntohs(ethernet->ether_type) << std::dec << std::endl;
}

int main()
{
    // struct to hold list of devices
    pcap_if_t *all_devices;
    char error_buffer[PCAP_ERRBUF_SIZE];

    // pcap_findalldevs takes a pointer to all_devices variable so it can fill it with data
    if (pcap_findalldevs(&all_devices, error_buffer) == -1)
    {
        std::cerr << "Error finding devices: " << error_buffer << std::endl;
        return 1;
    }

    // store names in vector
    std::vector<pcap_if_t *> devices;
    pcap_if_t *device = all_devices;

    std::cout << "Available Devices:" << std::endl;
    int i = 0;
    while (device != nullptr)
    {
        devices.push_back(device);
        std::cout << i + 1 << ". " << device->name;
        if (device->description)
        {
            std::cout << " (" << device->description << ")";
        }
        std::cout << std::endl;
        device = device->next;
        i++;
    }

    if (devices.empty())
    {
        std::cerr << "No devices found!" << std::endl;
        return 1;
    }

    // user selects device
    std::cout << "\nEnter the number of the device you want to sniff: ";
    int selection;
    std::cin >> selection;

    // specific check to make sure input is valid
    if (selection < 1 || selection > devices.size())
    {
        std::cerr << "Invalid selection." << std::endl;
        pcap_freealldevs(all_devices);
        return 1;
    }

    // get selected device name
    const char *selected_device_name = devices[selection - 1]->name;
    std::cout << "Opening device: " << selected_device_name << "..." << std::endl;

    // Open the device
    // Arguments:
    // 1. Device name
    // 2. Snaplen: 65535 (Capture the whole packet, not just the start)
    // 3. Promiscuous mode: 1 (On) - Listen to traffic meant for others
    // 4. Timeout: 1000ms (Wait 1s before delivering packets if buffer isn't full)
    // 5. Error buffer
    pcap_t *handle = pcap_open_live(selected_device_name, 65535, 1, 1000, error_buffer);

    if (handle == nullptr)
    {
        std::cerr << "Erroring opening: " << selected_device_name << ", " << error_buffer << std::endl;
        pcap_freealldevs(all_devices);
        return 1;
    }

    std::cout << "Listening on " << selected_device_name << "..." << std::endl;

    // Start the Capture Loop
    // Arguments:
    // 1. The handle (our connection)
    // 2. 0 = Loop forever (until error or break)
    // 3. The function to call when a packet arrives (packet_handler)
    // 4. User data (NULL for now - we don't need to pass extra data)
    pcap_loop(handle, 0, packet_handler, nullptr);

    // clean up
    pcap_close(handle);
    pcap_freealldevs(all_devices);

    return 0;
}