#include <iostream>
#include <unordered_map>
#include <cstring>
#include <climits>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

extern "C" {
#include "err.h"
}

/**
 * Constant defining biggest possible port number.
 */
#define MAX_PORT_NUM 65535

/**
 * Constant defining buffer size used by read function.
 */
#define BUF_SIZE 8192

using namespace std;

unordered_map<string, int> req_args;

string host_addr;
int radio_proxy_port;
int telnet_port;
int timeout = -1;

static void setup() {
    req_args.insert({"-P", 0});
    req_args.insert({"-H", 0});
    req_args.insert({"-p", 0});
}

/** @brief Parses string to number.
 * Returns -1 if string contains characters other than digits or number
 * is greater than INT_MAX.
 * @param s [in]   - reference to string.
 * @return Number represented by string or -1 if error occurred.
 */
static int parse_string_to_number(const string &s) {
    long long result = 0;
    for (char i : s) {
        result *= 10;
        if (i < '0' || i > '9')
            return -1;
        else
            result += (long long) (i - '0');
        if (result > INT_MAX)
            return -1;
    }
    return (int) result;
}

static int parse_args(int argc, char *argv[]) {
    if (argc != 7 && argc != 9)
        return -1;

    for (int i = 1; i < argc; i += 2) {
        auto search = req_args.find(argv[i]);
        if (search == req_args.end()) {
            if (strcmp("-T", argv[i]) == 0) {
                if (timeout != -1)
                    return -1;
                int t = parse_string_to_number(argv[i + 1]);
                if (t <= 0)
                    return -1;
                timeout = t;
            } else {
                // Invalid argument
                return -1;
            }
        } else {
            search->second++;
            if (strcmp("-P", argv[i]) == 0) {
                int p = parse_string_to_number(argv[i + 1]);
                if (p == -1 || p > MAX_PORT_NUM)
                    return -1;
                radio_proxy_port = p;
            } else if (strcmp("-H", argv[i]) == 0) {
                host_addr = argv[i + 1];
            } else if (strcmp("-p", argv[i]) == 0) {
                int p = parse_string_to_number(argv[i + 1]);
                if (p == -1 || p > MAX_PORT_NUM)
                    return -1;
                telnet_port = -1;
            } else {
                return -1; // Program shouldn't reach this code.
            }
        }
    }

    for (auto &req_arg : req_args) {
        if (req_arg.second != 1)
            return -1;
    }

    if (timeout == -1)
        timeout = 5;

    return 0;
}

string create_msg_to_client(uint16_t type, const string &data) {
    char msg_header[4];
    uint16_t msg_type = htons(type);
    uint16_t msg_len = htons(data.size());
    memmove(msg_header, &msg_type, 2);
    memmove(msg_header + 2, &msg_len, 2);
    string msg(msg_header, 4);
    msg.append(data);
    return msg;
}

static int connect_to_radio_proxy() {
    addrinfo addr_hints{};
    addrinfo *addr_result;

    sockaddr_in my_addr{};
    sockaddr_in srvr_addr{};

    char BUFFER[BUF_SIZE];

    int err;
    int sock;

    string s = create_msg_to_client(1, "");
    ssize_t snd_len;
    socklen_t rcva_len;
    int sflags;

    memset(&addr_hints, 0, sizeof(addrinfo));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_DGRAM;
    addr_hints.ai_protocol = IPPROTO_UDP;
    addr_hints.ai_flags = 0;
    addr_hints.ai_addrlen = 0;
    addr_hints.ai_addr = nullptr;
    addr_hints.ai_canonname = nullptr;
    addr_hints.ai_next = nullptr;

    err = getaddrinfo(host_addr.c_str(), nullptr, &addr_hints, &addr_result);

    if (err == EAI_SYSTEM) {
        syserr("getaddrinfo: %s", gai_strerror(err));
    } else if (err != 0) {
        fatal("getaddrinfo %s", gai_strerror(err));
    }

    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = ((sockaddr_in *) (addr_result->ai_addr))->sin_addr.s_addr;
    my_addr.sin_port = htons((uint16_t) radio_proxy_port);

    freeaddrinfo(addr_result);

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        syserr("socket");
    int i = 0;
    sflags = 0;
    rcva_len = (socklen_t) sizeof(my_addr);
    snd_len = sendto(sock, s.c_str(), s.size(), sflags,
                     (sockaddr *) &my_addr,
                     rcva_len);
    if (snd_len != s.size())
        syserr("partial / failed write");
    while (true) {
        int l = recvfrom(sock, BUFFER, BUF_SIZE, 0, (sockaddr *) &srvr_addr,
                         &rcva_len);
        uint16_t msg_type;
        uint16_t msg_len;
        memmove(&msg_type, BUFFER, 2);
        memmove(&msg_len, BUFFER + 2, 2);
        uint16_t type = ntohs(msg_type);
        uint16_t len = ntohs(msg_len);
        string rsp(BUFFER + 4, l - 4);
        cerr << "type is " << type << " len is " << len << endl;
        if (type == 2)
            cerr << "Radio is: " << rsp << endl;
        if (type == 4)
            cout << rsp;
        if (type == 6)
            cerr << rsp << endl;
        i++;
        if (i == 10) {
            s = create_msg_to_client(3, "");
            sflags = 0;
            rcva_len = (socklen_t) sizeof(my_addr);
            snd_len = sendto(sock, s.c_str(), s.size(), sflags,
                             (sockaddr *) &my_addr,
                             rcva_len);
            if (snd_len != s.size())
                syserr("partial / failed write");
            i = 0;
        }
    }


    if (close(sock) == -1)
        syserr("close");

    return 0;
}

int main(int argc, char *argv[]) {
    setup();
    if (parse_args(argc, argv) != 0) {
        fatal("Usage %s -H <radio-proxy address> -P <host port> -p <telnet port> "
              "[-T <radio-proxy timeout>]", argv[0]);
    }

    int sock = connect_to_radio_proxy();
    cout << "Hello world" << endl;
}