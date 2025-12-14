// Multi-threaded traceroute implementation using ICMP Echo Requests
// Supports both IPv4 and IPv6
// Uses C++17 standard
// Note: Requires root privileges to run due to raw socket usage
// Author: <Yueqiao Wang>
// Date: <12/14/2025>
// Compile: g++ -std=c++17 -Wall -Wextra -pedantic -pthread -o traceroute traceroute.cpp
// Usage: sudo ./traceroute <host> [max_ttl] [linger_ms_after_send] [--force|-f]
// Example: sudo ./traceroute www.example.com 30 5000 --force
// IPv6 checksum handling based on platform support, future implementation of pseudo-header checksum calculation may be needed.


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <thread>
#include <iostream>
#include <cctype>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

// ICMP_TIME_EXCEEDED is not defined in some platforms (e.g., macOS)
#ifndef ICMP_TIME_EXCEEDED
#ifdef ICMP_TIMXCEED
#define ICMP_TIME_EXCEEDED ICMP_TIMXCEED
#else
#define ICMP_TIME_EXCEEDED 11
#endif
#endif

// ICMP header structure
#pragma pack(push, 1)
struct IcmpEchoHeader
{
    uint8_t type;      // ICMP type
    uint8_t code;      // ICMP code
    uint16_t checksum; // ICMP checksum（ones' complement）
    uint16_t id;       // Echo: identifier
    uint16_t seq;      // Echo: sequence
};
#pragma pack(pop)


// Probe structure to track each sent probe
// Stores TTL, attempt index, and send time for RTT calculation
struct Probe
{
    int ttl = -1;
    int attempt = 0;
    std::chrono::steady_clock::time_point send_time;
};

// Result structure for each probe
// Stores information about each hop
// including IP address, RTT, ICMP type/code, and whether destination was reached

struct Result
{
    std::string hop_ip;
    double rrt_ms = -1;
    int icmp_type = -1;
    int icmp_code = -1;
    bool reached_destination = false;
};

constexpr int kProbesPerTtl = 3;

// Function to set TTL (IPv4) or Hops (IPv6) on a socket
// Parameters:
// - Socket file descriptor
// - Domain (AF_INET or AF_INET6)
// - TTL or Hops value
// Returns true if successful, false otherwise
static inline bool set_ttl_or_hops(int sock, int domain, int ttl)
{
    if (domain == AF_INET) // IPv4
    {
        if (::setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
            return false;
        return true;
    }
    else if (domain == AF_INET6) // IPv6
    {
        if (::setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0)
            return false;
        return true;
    }
    errno = EAFNOSUPPORT;
    return false;
}


// Function to compute ICMP checksum (ones' complement)
// Parameters:
// - Data buffer
// - Length of data buffer
// Returns: 16-bit checksum in network byte order
static uint16_t checksum16(const void *data, size_t len)
{
    const uint8_t *bytes = static_cast<const uint8_t *>(data);
    uint32_t sum = 0;

    while (len > 1)
    {
        uint16_t word = (static_cast<uint16_t>(bytes[0]) << 8) |
                        static_cast<uint16_t>(bytes[1]);
        sum += word;
        bytes += 2;
        len -= 2;
    }

    if (len == 1)
    {
        sum += static_cast<uint16_t>(bytes[0]) << 8;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return htons(static_cast<uint16_t>(~sum));
}

// Function to determine if input is IPv4, IPv6, or hostname
int get_address_type(const char *host)
{
    struct in_addr addr4;
    struct in6_addr addr6;

    // Check for IPv4 address
    if (inet_pton(AF_INET, host, &addr4) == 1)
    {
        return AF_INET;
    }

    // Check for IPv6 address
    if (inet_pton(AF_INET6, host, &addr6) == 1)
    {
        return AF_INET6;
    }

    // If neither, treat as hostname
    return 0;
}

// Function to locate ICMP offset
// Parameters:
// - Data buffer
// - Length of data buffer
// - Offset to ICMP header
// Returns true if ICMP header is found, false otherwise
static bool locate_icmp_offset(const uint8_t *data, size_t len, size_t &offset)
{
    if (len < sizeof(IcmpEchoHeader))
        return false;

    uint8_t version = data[0] >> 4;
    if (version == 4 && len >= sizeof(struct ip))
    {
        const struct ip *ip_hdr = reinterpret_cast<const struct ip *>(data);
        size_t ip_len = static_cast<size_t>(ip_hdr->ip_hl) * 4;
        if (ip_len < sizeof(struct ip) || ip_len >= len)
            return false;
        offset = ip_len;
        return (len - offset) >= sizeof(IcmpEchoHeader);
    }

    if (version == 6 && len >= sizeof(struct ip6_hdr))
    {
        offset = sizeof(struct ip6_hdr);
        if (offset >= len)
            return false;
        return (len - offset) >= sizeof(IcmpEchoHeader);
    }

    offset = 0;
    return len >= sizeof(IcmpEchoHeader);
}

// Function to perform a ping check to validate ICMP functionality
// Parameters:
// - Destination address
// - Domain (AF_INET or AF_INET6)
// - Protocol (IPPROTO_ICMP or IPPROTO_ICMPV6)
// - Identifier for ICMP packets
// Returns true if ping is successful, false otherwise
static bool perform_ping_check(const sockaddr *dst,
                               int domain,
                               int protocol,
                               uint16_t ident)
{
    int sock = ::socket(domain, SOCK_RAW, protocol);
    if (sock < 0)
    {
        perror("socket(ping)");
        return false;
    }

    timeval tv{};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        perror("setsockopt(SO_RCVTIMEO ping)");
    }

#ifdef IPV6_CHECKSUM
    if (domain == AF_INET6)
    {
        int offset = offsetof(IcmpEchoHeader, checksum);
        if (::setsockopt(sock, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) < 0)
        {
            perror("setsockopt(IPV6_CHECKSUM ping)");
        }
    }
#endif

    const char payload[] = "Ping validation payload";
    std::vector<uint8_t> pkt(sizeof(IcmpEchoHeader) + sizeof(payload), 0);
    auto *icmp = reinterpret_cast<IcmpEchoHeader *>(pkt.data());
    std::memset(icmp, 0, sizeof(*icmp));
    icmp->type = (protocol == IPPROTO_ICMP) ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    icmp->code = 0;
    icmp->id = htons(ident);
    uint16_t seq = 0;
    icmp->seq = htons(seq);
    std::memcpy(pkt.data() + sizeof(IcmpEchoHeader), payload, sizeof(payload));

    if (protocol == IPPROTO_ICMP)
    {
        icmp->checksum = checksum16(pkt.data(), pkt.size());
    }

    socklen_t dst_len = (domain == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (::sendto(sock, pkt.data(), pkt.size(), 0, dst, dst_len) < 0)
    {
        perror("sendto(ping)");
        ::close(sock);
        return false;
    }

    std::vector<uint8_t> buffer(1024);
    bool success = false;
    while (true)
    {
        ssize_t n = ::recvfrom(sock, buffer.data(), buffer.size(), 0, nullptr, nullptr);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            perror("recvfrom(ping)");
            break;
        }
        if (n == 0)
            continue;

        size_t icmp_off = 0;
        if (!locate_icmp_offset(buffer.data(), static_cast<size_t>(n), icmp_off))
            continue;

        const IcmpEchoHeader *reply = reinterpret_cast<const IcmpEchoHeader *>(buffer.data() + icmp_off);
        if (protocol == IPPROTO_ICMP)
        {
            if (reply->type == ICMP_ECHOREPLY && ntohs(reply->id) == ident && ntohs(reply->seq) == seq)
            {
                success = true;
                break;
            }
        }
        else if (protocol == IPPROTO_ICMPV6)
        {
            if (reply->type == ICMP6_ECHO_REPLY && ntohs(reply->id) == ident && ntohs(reply->seq) == seq)
            {
                success = true;
                break;
            }
        }
    }

    ::close(sock);
    return success;
}

// Function to send an ICMP probe with specified TTL
// Parameters:
// ttl: TTL value to set for the probe
// attempt_idx: Index of the current attempt for this TTL
// seq: Sequence number for the probe
// map_mu: Mutex for protecting seq_map
// seq_map: Map of sequence numbers to Probe info
// cv: Condition variable for synchronization
// ident: ICMP identifier
// domain: Address family (AF_INET or AF_INET6)
// protocol: Protocol (IPPROTO_ICMP or IPPROTO_ICMPV6)
// dst: Destination address
static void send_probe(int ttl,
                       int attempt_idx,
                       std::atomic<uint16_t> &g_seq,
                       std::mutex &map_mu,
                       std::unordered_map<uint16_t, Probe> &seq_map,
                       std::condition_variable &cv,
                       uint16_t ident,
                       int domain,
                       int protocol,
                       const sockaddr *dst)
{
    if (!dst)
    {
        errno = EINVAL;
        perror("dst");
        return;
    }

    // SOCK_RAW because we send ICMP packets directly
    int sock = ::socket(domain, SOCK_RAW, protocol);

    if (sock < 0)
    {
        perror("socket");
        return;
    }

    if (!set_ttl_or_hops(sock, domain, ttl))
    {
        perror("setsockopt(TTL/HOPS)");
        ::close(sock);
        return;
    }

#ifdef IPV6_CHECKSUM
    if (domain == AF_INET6)
    {
        int offset = offsetof(IcmpEchoHeader, checksum);
        if (::setsockopt(sock, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) < 0)
        {
            // Not fatal, just print a warning
            perror("setsockopt(IPV6_CHECKSUM)");
        }
    }
#endif

    uint16_t seq = g_seq.fetch_add(1, std::memory_order_relaxed);

    const char payload[] = "ICMP Probe Payload";
    std::vector<uint8_t> pkt(sizeof(IcmpEchoHeader) + sizeof(payload), 0);

    auto *icmp = reinterpret_cast<IcmpEchoHeader *>(pkt.data());
    std::memset(icmp, 0, sizeof(*icmp));

    icmp->type = (protocol == IPPROTO_ICMP) ? ICMP_ECHO : ICMP6_ECHO_REQUEST;

    icmp->code = 0;
    icmp->id = htons(ident);
    icmp->seq = htons(seq);
    std::memcpy(pkt.data() + sizeof(IcmpEchoHeader), payload, sizeof(payload));
    icmp->checksum = 0;

    if (protocol == IPPROTO_ICMP)
    {
        icmp->checksum = checksum16(pkt.data(), pkt.size());
    }
    else if (protocol == IPPROTO_ICMPV6)
    {
        // For ICMPv6, checksum is handled by kernel if IPV6_CHECKSUM is set
    }

    socklen_t dst_len = (domain == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    {
        std::lock_guard<std::mutex> lock(map_mu);
        seq_map[seq] = Probe{ttl, attempt_idx, std::chrono::steady_clock::now()}; // Record probe info for RTT calculation
    }

    cv.notify_all();

    if (::sendto(sock, pkt.data(), pkt.size(), 0, dst, dst_len) < 0)
    {
        perror("sendto");
        {
            std::lock_guard<std::mutex> lock(map_mu);
            seq_map.erase(seq);
        }
        cv.notify_all();
        ::close(sock);
        return;
    }

    ::close(sock);
}

// Function to receive ICMP replies and match them to sent probes
// Parameters:
// ident: ICMP identifier
// map_mu: Mutex for seq_map
// seq_map: Map of sequence numbers to Probe info
// cv: Condition variable for synchronization
// got_reply: Atomic flag indicating if any reply was received
// got_destination_reached: Atomic flag indicating if destination was reached
// results: Vector of results
// results_mu: Mutex for results
// all_done: Atomic flag indicating if all probes are done
// domain: Address family (AF_INET or AF_INET6)
// protocol: Protocol (IPPROTO_ICMP or IPPROTO_ICMPV6)
static void recv_probe(int ident,
                       std::mutex &map_mu,
                       std::unordered_map<uint16_t, Probe> &seq_map,
                       std::condition_variable &cv,
                       std::atomic<bool> &got_reply,
                       std::atomic<bool> &got_destination_reached,
                       std::vector<std::vector<Result>> &results,
                       std::mutex &results_mu,
                       std::atomic<bool> &all_done,
                       int domain,
                       int protocol)
{
    int sock = ::socket(domain, SOCK_RAW, protocol);
    if (sock < 0)
    {
        perror("socket(recv)");
        return;
    }

    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 500 * 1000; // 500ms so we periodically check all_done
    if (::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        perror("setsockopt(SO_RCVTIMEO)");
    }

    auto addr_to_string = [](const sockaddr_storage &ss) -> std::string
    {
        char buf[INET6_ADDRSTRLEN] = {0};
        if (ss.ss_family == AF_INET)
        {
            const sockaddr_in *sin = reinterpret_cast<const sockaddr_in *>(&ss);
            if (::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) == nullptr)
                return {};
        }
        else if (ss.ss_family == AF_INET6)
        {
            const sockaddr_in6 *sin6 = reinterpret_cast<const sockaddr_in6 *>(&ss);
            if (::inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) == nullptr)
                return {};
        }
        return std::string(buf);
    };

    std::vector<uint8_t> buffer(4096);

    while (!all_done.load(std::memory_order_acquire))
    {
        bool pending = false;
        {
            std::unique_lock<std::mutex> lk(map_mu);

            cv.wait_for(lk, std::chrono::milliseconds(50), [&]
                        { return all_done.load(std::memory_order_acquire) || !seq_map.empty(); });

            if (all_done.load(std::memory_order_acquire))
                break;

            pending = !seq_map.empty(); // 关键：拿到当前是否有待匹配的 probe
        }

        if (!pending)
            continue;

        sockaddr_storage from{};
        socklen_t from_len = sizeof(from);
        ssize_t n = ::recvfrom(sock, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr *>(&from), &from_len);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            perror("recvfrom");
            break;
        }
        if (n == 0)
            continue;

        size_t icmp_off = 0;
        if (!locate_icmp_offset(buffer.data(), static_cast<size_t>(n), icmp_off))
            continue;

        bool matched = false;
        bool reached_destination = false;
        uint16_t seq = 0;
        const IcmpEchoHeader *outer = reinterpret_cast<const IcmpEchoHeader *>(buffer.data() + icmp_off);
        int icmp_type = outer->type;
        int icmp_code = outer->code;

        // IPv4 ICMP parsing
        if (protocol == IPPROTO_ICMP)
        {
            // ICMP Echo Reply: reached destination
            if (icmp_type == ICMP_ECHOREPLY && ntohs(outer->id) == ident)
            {
                seq = ntohs(outer->seq);
                matched = true;
                reached_destination = true;
            }
            // ICMP Time Exceeded: reached hop
            else if (icmp_type == ICMP_TIME_EXCEEDED)
            {

                size_t inner_off = icmp_off + 8;                            // Skip outer ICMP Time Exceeded header
                if (static_cast<size_t>(n) < inner_off + sizeof(struct ip)) // Must be able to read "the quoted original IPv4 header"
                    continue;
                const struct ip *inner_ip = reinterpret_cast<const struct ip *>(buffer.data() + inner_off); // inner_ip: the quoted original IPv4 header
                size_t inner_ip_len = static_cast<size_t>(inner_ip->ip_hl) * 4;                             // Length of original IPv4 header
                if (inner_ip_len < sizeof(struct ip) || static_cast<size_t>(n) < inner_off + inner_ip_len + sizeof(IcmpEchoHeader))
                    continue;
                const IcmpEchoHeader *inner_icmp = reinterpret_cast<const IcmpEchoHeader *>(buffer.data() + inner_off + inner_ip_len);
                if (inner_icmp->type != ICMP_ECHO || ntohs(inner_icmp->id) != ident)
                    continue;
                seq = ntohs(inner_icmp->seq); // Get sequence number from original Echo Request
                matched = true;
            }
        }
        else if (protocol == IPPROTO_ICMPV6) // IPv6 ICMPv6 parsing
        {
            // ICMPv6 Echo Reply: reached destination
            if (icmp_type == ICMP6_ECHO_REPLY && ntohs(outer->id) == ident)
            {
                seq = ntohs(outer->seq);
                matched = true;
                reached_destination = true;
            }
            else if (icmp_type == ICMP6_TIME_EXCEEDED) // ICMPv6 Time Exceeded: reached hop
            {
                size_t inner_off = icmp_off + 8; // Skip outer ICMPv6 Time Exceeded header
                if (static_cast<size_t>(n) < inner_off + sizeof(struct ip6_hdr) + sizeof(IcmpEchoHeader))
                    continue;
                const IcmpEchoHeader *inner_icmp = reinterpret_cast<const IcmpEchoHeader *>(buffer.data() + inner_off + sizeof(struct ip6_hdr));
                if (inner_icmp->type != ICMP6_ECHO_REQUEST || ntohs(inner_icmp->id) != ident)
                    continue;
                seq = ntohs(inner_icmp->seq);
                matched = true;
            }
        }

        if (!matched) // Not an ICMP reply for us
            continue;

        Probe probe_info;
        bool have_probe = false;
        {
            std::lock_guard<std::mutex> lock(map_mu);
            auto it = seq_map.find(seq); // Look up the sequence number
            if (it != seq_map.end())     // Found: it's indeed one of our probes
            {
                probe_info = it->second; // Get ttl/send_time info
                seq_map.erase(it);       // Remove to prevent map growth and duplicate matches
                have_probe = true;       // Mark that we found the probe
            }
        }

        if (!have_probe)
            continue;

        cv.notify_all(); // Notify main threads about the updated seq_map

        auto now = std::chrono::steady_clock::now(); // Current time for RTT calculation
        double rtt_ms = std::chrono::duration<double, std::milli>(now - probe_info.send_time).count();

        std::string from_ip = addr_to_string(from);
        // fprintf(stderr,
        //         "[DEBUG] Received packet seq=%u ttl=%d attempt=%d from %s type=%d code=%d reached=%d\n",
        //         seq,
        //         probe_info.ttl,
        //         probe_info.attempt,
        //         from_ip.empty() ? "?" : from_ip.c_str(),
        //         icmp_type,
        //         icmp_code,
        //         reached_destination ? 1 : 0);

        bool stored = false;
        {
            std::lock_guard<std::mutex> results_lock(results_mu);

            if (probe_info.ttl > 0)
            {
                size_t idx = static_cast<size_t>(probe_info.ttl - 1);

                if (idx >= results.size()) // Resize results vector if needed
                {
                    results.resize(idx + 1, std::vector<Result>(kProbesPerTtl));
                }

                if (probe_info.attempt >= 0 && probe_info.attempt < kProbesPerTtl)
                {
                    Result &slot = results[idx][static_cast<size_t>(probe_info.attempt)]; // Get the result slot for this TTL attempt
                    slot.hop_ip = from_ip;                                                // Hop IP address
                    slot.rrt_ms = rtt_ms;                                                 // RTT in milliseconds
                    slot.icmp_type = icmp_type;                                           // ICMP type
                    slot.icmp_code = icmp_code;                                           // ICMP code
                    slot.reached_destination = reached_destination;                       // Mark if destination was reached
                    stored = true;
                }
            }
        }

        if (!stored)
            continue;

        got_reply.store(true, std::memory_order_release); // Indicate we got at least one reply

        // Mark if destination was reached
        if (reached_destination)
        {
            got_destination_reached.store(true, std::memory_order_release);
        }
    }

    ::close(sock);
}

// Function to start the receiver thread
// Parameters:
// ident: ICMP identifier
// map_mu: Mutex for protecting seq_map
// seq_map: Map of sequence numbers to Probe info
// cv: Condition variable for synchronization
// got_reply: Atomic flag indicating if any reply was received
// got_destination_reached: Atomic flag indicating if destination was reached
// results: Vector of results
// results_mu: Mutex for protecting results
// all_done: Atomic flag indicating if all probes are done
// domain: Address family (AF_INET or AF_INET6)
// protocol: Protocol (IPPROTO_ICMP or IPPROTO_ICMPV6)
static std::thread start_receiver_thread(int ident,
                                         std::mutex &map_mu,
                                         std::unordered_map<uint16_t, Probe> &seq_map,
                                         std::condition_variable &cv,
                                         std::atomic<bool> &got_reply,
                                         std::atomic<bool> &got_destination_reached,
                                         std::vector<std::vector<Result>> &results,
                                         std::mutex &results_mu,
                                         std::atomic<bool> &all_done,
                                         int domain,
                                         int protocol)
{
    return std::thread(recv_probe,
                       ident,
                       std::ref(map_mu),
                       std::ref(seq_map),
                       std::ref(cv),
                       std::ref(got_reply),
                       std::ref(got_destination_reached),
                       std::ref(results),
                       std::ref(results_mu),
                       std::ref(all_done),
                       domain,
                       protocol);
}

// Function to start sender threads for each attempt
// Parameters:
// max_ttl: Maximum TTL value
// g_seq: Global atomic sequence number
// map_mu: Mutex for protecting seq_map
// seq_map: Map of sequence numbers to Probe info
// cv: Condition variable for synchronization
// got_destination_reached: Atomic flag indicating if destination was reached
// results: Vector of results
// domain: Address family (AF_INET or AF_INET6)
// protocol: Protocol (IPPROTO_ICMP or IPPROTO_ICMPV6)
// dst: Destination address
// ident: ICMP identifier
// Returns: void
// Note: This function launches multiple threads, each sending probes for all TTLs

static void start_sender_threads(int max_ttl,
                                 std::atomic<uint16_t> &g_seq,
                                 std::mutex &map_mu,
                                 std::unordered_map<uint16_t, Probe> &seq_map,
                                 std::condition_variable &cv,
                                 std::atomic<bool> &got_destination_reached,
                                 std::atomic<bool> &all_done,
                                 int domain,
                                 int protocol,
                                 const sockaddr *dst,
                                 uint16_t ident)
{
    std::vector<std::thread> attempt_threads;
    attempt_threads.reserve(kProbesPerTtl);

    for (int attempt = 0; attempt < kProbesPerTtl; ++attempt)
    {
        attempt_threads.emplace_back([&, attempt]
                                     {
                                         for (int ttl = 1; ttl <= max_ttl; ++ttl)
                                         {
                                             if (all_done.load(std::memory_order_acquire) || got_destination_reached.load(std::memory_order_acquire))
                                                 break;

                                             send_probe(ttl,
                                                        attempt,
                                                        std::ref(g_seq),
                                                        std::ref(map_mu),
                                                        std::ref(seq_map),
                                                        std::ref(cv),
                                                        ident,
                                                        domain,
                                                        protocol,
                                                        dst);

                                             if (got_destination_reached.load(std::memory_order_acquire))
                                                 break;
                                         } });
    }

    for (auto &attempt_thread : attempt_threads)
    {
        if (attempt_thread.joinable())
            attempt_thread.join();
    }
}

// Function to print traceroute results
// Returns true if destination was reached
//
// Parameters:
//  results: Traceroute results
//  max_ttl: Maximum TTL value
//  final_output: True if this is the final output, false otherwise
//  print_num: Number of results printed so far
//  remaining_probes: Number of remaining probes to print
static bool print_traceroute_results(const std::vector<std::vector<Result>> &results,
                                     int max_ttl,
                                     bool final_output,
                                     int print_num,
                                     size_t remaining_probes)
{
    if (final_output)
    {
        printf("\nTraceroute results:\n");
    }
    else
    {
        printf("\nTraceroute results (partial update: %d):\n", print_num);
    }
    bool destination_reached = false;

    for (int ttl = 1; ttl <= max_ttl; ++ttl)
    {
        if (static_cast<size_t>(ttl - 1) >= results.size())
            break;

        const auto &ttl_results = results[static_cast<size_t>(ttl - 1)];
        printf("%2d  ", ttl);

        for (const Result &res : ttl_results)
        {
            if (res.rrt_ms < 0)
            {
                printf("|%-18s  %-30s  ", "*", "");
                continue;
            }

            const char *hop_ip = res.hop_ip.empty() ? "?" : res.hop_ip.c_str();
            printf("|%-18s  %8.2f ms  (type=%2d code=%2d)  ",
                   hop_ip,
                   res.rrt_ms,
                   res.icmp_type,
                   res.icmp_code);

            if (res.reached_destination)
            {
                destination_reached = true;
            }
        }

        printf("\n");
        if (destination_reached)
        {
            printf("%zu probes remaining unanswered.\n", remaining_probes);
            if (final_output)
                printf("Destination reached at TTL %d\n", ttl);
            break;
        }
    }

    if (!destination_reached && final_output)
    {
        printf("Max TTL (%d) reached without reaching destination.\n", max_ttl);
        printf("%zu probes remaining unanswered.\n", remaining_probes);
    }

    printf("--------------------------------------------------------------------\n");

    return destination_reached;
}

// Main function

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <host> [max_ttl, default=30] [linger_ms_after_send, default=5000ms] [--force|-f]\n", argv[0]);
        return 1;
    }

    char *host = argv[1];
    int max_ttl = 30; // default value
    int linger_ms = 5000;
    bool force_traceroute = false;
    bool max_ttl_overridden = false;
    bool linger_overridden = false;

    for (int i = 2; i < argc; ++i)
    {
        const char *arg = argv[i];
        if (strcmp(arg, "--force") == 0 || strcmp(arg, "-f") == 0)
        {
            force_traceroute = true;
            continue;
        }
        if (strcmp(arg, "--no-force") == 0)
        {
            force_traceroute = false;
            continue;
        }

        if (!max_ttl_overridden)
        {
            max_ttl = atoi(arg);
            if (max_ttl < 1 || max_ttl > 255)
            {
                fprintf(stderr, "max_ttl should be between 1 and 255\n");
                return 1;
            }
            max_ttl_overridden = true;
        }
        else if (!linger_overridden)
        {
            linger_ms = atoi(arg);
            if (linger_ms < 100)
            {
                fprintf(stderr, "linger_ms should be at least 100 ms\n");
                return 1;
            }
            linger_overridden = true;
        }
        else
        {
            fprintf(stderr, "Unexpected argument: %s\n", arg);
            return 1;
        }
    }

    std::string resolved_host = host;
    const char *host_str = resolved_host.c_str();
    sockaddr_storage resolved_addr{};
    socklen_t resolved_addr_len = 0;
    bool has_resolved_addr = false;

    // Determine address type
    int addr_type = get_address_type(host_str);

    // Create socket based on address type using variables
    int domain = AF_UNSPEC;
    int protocol = 0;

    printf("Input is a");

setup_address:
    if (addr_type == AF_INET)
    {
        printf("n IPv4 address: %s\n", host_str);
        domain = AF_INET;
        protocol = IPPROTO_ICMP;
    }
    else if (addr_type == AF_INET6)
    {
        printf("n IPv6 address: %s\n", host_str);
        domain = AF_INET6;
        protocol = IPPROTO_ICMPV6;
    }
    else // Resolve hostname
    {

        printf(" hostname: %s\n", host_str);
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        addrinfo *res = nullptr;
        int rc = ::getaddrinfo(host_str, nullptr, &hints, &res);
        if (rc != 0 || !res)
        {
            fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(rc));
            return 1;
        }

        for (addrinfo *p = res; p != nullptr; p = p->ai_next)
        {
            if (p->ai_family != AF_INET && p->ai_family != AF_INET6)
                continue;

            char buf[INET6_ADDRSTRLEN] = {0};
            void *addr_ptr = nullptr;
            if (p->ai_family == AF_INET)
            {
                auto *addr4 = reinterpret_cast<sockaddr_in *>(p->ai_addr);
                addr_ptr = &addr4->sin_addr;
            }
            else
            {
                auto *addr6 = reinterpret_cast<sockaddr_in6 *>(p->ai_addr);
                addr_ptr = &addr6->sin6_addr;
            }

            if (::inet_ntop(p->ai_family, addr_ptr, buf, sizeof(buf)) != nullptr)
            {
                resolved_host = buf;
            }
            else
            {
                resolved_host = host;
            }
            host_str = resolved_host.c_str();
            addr_type = p->ai_family;
            std::memcpy(&resolved_addr, p->ai_addr, static_cast<size_t>(p->ai_addrlen));
            resolved_addr_len = static_cast<socklen_t>(p->ai_addrlen);
            has_resolved_addr = true;
            break;
        }
        ::freeaddrinfo(res);

        if (addr_type == AF_UNSPEC)
        {
            fprintf(stderr, "Unable to resolve hostname to IPv4/IPv6\n");
            return 1;
        }

        printf("Resolved hostname to a");
        goto setup_address;
    }

    sockaddr_storage dst_storage{}; // Destination address storage
    socklen_t dst_len = 0;          // Length of destination address

    if (has_resolved_addr)
    {
        std::memcpy(&dst_storage, &resolved_addr, static_cast<size_t>(resolved_addr_len));
        dst_len = resolved_addr_len;
    }
    else if (domain == AF_INET)
    {
        sockaddr_in *addr4 = reinterpret_cast<sockaddr_in *>(&dst_storage); // Convert to sockaddr_in
        std::memset(addr4, 0, sizeof(*addr4));                              // Zero out the structure
        addr4->sin_family = AF_INET;                                        // Set address family
        if (::inet_pton(AF_INET, host_str, &addr4->sin_addr) != 1)          // Convert string to binary form
        {
            perror("inet_pton(AF_INET)");
            return 1;
        }
        dst_len = sizeof(sockaddr_in); // Set length
    }
    else if (domain == AF_INET6)
    {
        sockaddr_in6 *addr6 = reinterpret_cast<sockaddr_in6 *>(&dst_storage); // Convert to sockaddr_in6
        std::memset(addr6, 0, sizeof(*addr6));                                // Zero out the structure
        addr6->sin6_family = AF_INET6;                                        // Set address family
        if (::inet_pton(AF_INET6, host_str, &addr6->sin6_addr) != 1)          // Convert string to binary form
        {
            perror("inet_pton(AF_INET6)");
            return 1;
        }
        dst_len = sizeof(sockaddr_in6); // Set length
    }

    const sockaddr *dst = reinterpret_cast<const sockaddr *>(&dst_storage); // Destination address
    (void)dst_len;                                                          // currently unused but kept for clarity

    std::atomic<uint16_t> g_seq{1};                   // Global sequence number for probes
    std::mutex map_mu;                                // Mutex for protecting seq_map
    std::unordered_map<uint16_t, Probe> seq_map;      // Map of sequence numbers to Probe info
    std::condition_variable cv;                       // Condition variable for synchronization
    std::atomic<bool> got_reply{false};               // Flag indicating if any reply was received
    std::atomic<bool> got_destination_reached{false}; // Flag indicating if destination was reached
    std::atomic<bool> all_done{false};                // Flag indicating if all operations are done
    std::vector<std::vector<Result>> results(static_cast<size_t>(max_ttl),
                                             std::vector<Result>(kProbesPerTtl)); // Results storage
    std::mutex results_mu;                                                        // Protects results vector access
    uint16_t ident = static_cast<uint16_t>(::getpid() & 0xFFFF);                  // Identifier for ICMP packets

    bool ping_ok = perform_ping_check(dst, domain, protocol, ident);
    if (ping_ok)
    {
        printf("Ping check succeeded. Starting traceroute...\n");
    }
    else if (force_traceroute)
    {
        printf("Ping check failed or timed out, continuing due to --force.\n");
    }
    else
    {
        printf("Ping check failed or timed out. Re-run with --force to continue anyway.\n");
        return 1;
    }

    std::thread receiver_thread = start_receiver_thread(ident,
                                                        map_mu,
                                                        seq_map,
                                                        cv,
                                                        got_reply,
                                                        got_destination_reached,
                                                        results,
                                                        results_mu,
                                                        all_done,
                                                        domain,
                                                        protocol);

    start_sender_threads(max_ttl,
                         g_seq,
                         map_mu,
                         seq_map,
                         cv,
                         got_destination_reached,
                         all_done,
                         domain,
                         protocol,
                         dst,
                         ident);

    printf("Waiting up to %d ms for outstanding replies...\n", linger_ms);
    short report_num = 1;
    size_t remaining = 0;
    int report_interval_ms = linger_ms / 10;
    if (report_interval_ms < 100)
        report_interval_ms = 100;
    auto wait_start = std::chrono::steady_clock::now();
    auto wait_deadline = wait_start + std::chrono::milliseconds(linger_ms);
    auto next_report = wait_start + std::chrono::milliseconds(report_interval_ms);
    bool timed_out = false;
    std::unique_lock<std::mutex> lock(map_mu);
    while (true)
    {
        {

            remaining = seq_map.size(); // 当前 map 元素个数
        }

        if (remaining == 0)
            break;

        auto wake_time = (next_report < wait_deadline) ? next_report : wait_deadline;

        cv.wait_until(lock, wake_time, [&]
                      { return seq_map.size() != remaining ||
                               all_done.load(std::memory_order_acquire); });

        remaining = seq_map.size();
        if (remaining == 0)
            break;

        auto now = std::chrono::steady_clock::now();
        if (now >= next_report)
        {
            lock.unlock();

            std::vector<std::vector<Result>> snapshot;
            {
                std::lock_guard<std::mutex> rlk(results_mu);
                snapshot = results;
            }
            print_traceroute_results(snapshot, max_ttl, false, report_num++, remaining);

            lock.lock();
            now = std::chrono::steady_clock::now();
            next_report = now + std::chrono::milliseconds(report_interval_ms);
        }

        if (now >= wait_deadline)
        {
            timed_out = true;
            break;
        }
    }

    all_done.store(true, std::memory_order_release); // Signal receiver thread to finish
    cv.notify_all();                                 // Wake up receiver thread
    lock.unlock();

    if (receiver_thread.joinable()) // Wait for receiver thread to finish
    {
        receiver_thread.join(); // Wait for receiver thread to finish
    }

    if (timed_out && remaining > 0)
    {
        printf("Wait deadline reached with %zu pending probes still unanswered.\n", remaining);
    }

    {
        std::lock_guard<std::mutex> lk(results_mu);
        print_traceroute_results(results, max_ttl, true, report_num, remaining);
    }
    return 0;
}
