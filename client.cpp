#include <iostream>
#include <unordered_map>
#include <cstring>
#include <climits>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <csignal>
#include <vector>
#include <cassert>
#include <poll.h>
#include <chrono>
#include <map>
#include <algorithm>

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

#define clear_line "\033[0K"
#define move_down "\033[1B"
#define move_up "\033[1A"

#define DISCOVER 1
#define IAM 2
#define KEEPALIVE 3
#define AUDIO 4
#define METADATA 6

using namespace std;

unordered_map<string, int> req_args;
vector<string> radio_proxy_names;
vector<sockaddr_in> radio_proxy_addrs;

string host_addr;
int radio_proxy_port;
int telnet_port;
int timeout = -1;
int proxy_choice = -1;

size_t menu_lines_count = 0;
size_t telnet_curr_line = 1;
size_t total_telnet_lines = 0;
bool metadata_printed = false;

static bool finish_work = false;

char BUFFER[BUF_SIZE];

static void catch_int(int signal) {
    finish_work = true;
}

static void setup() {
    struct sigaction action{};
    sigset_t block_mask;
    req_args.insert({"-P", 0});
    req_args.insert({"-H", 0});
    req_args.insert({"-p", 0});

    sigemptyset(&block_mask);
    action.sa_handler = catch_int;
    action.sa_mask = block_mask;
    action.sa_flags = SA_RESTART;

    if (sigaction(SIGINT, &action, nullptr) == -1)
        syserr("sigaction");
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
                // todo check if it's correct.
                host_addr = argv[i + 1];
            } else if (strcmp("-p", argv[i]) == 0) {
                int p = parse_string_to_number(argv[i + 1]);
                if (p == -1 || p > MAX_PORT_NUM)
                    return -1;
                telnet_port = p;
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
        timeout = 5000;
    else
        timeout *= 1000;

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

    char BUFFER[BUF_SIZE];

    int err;
    int sock;


    int sflags;

    int i = 0;
    sflags = 0;
/*
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
            cerr << "KEEPALIVE" << endl;
            s = create_msg_to_client(3, "");
            cerr << "Succesfull" << endl;
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
*/

    if (close(sock) == -1)
        syserr("close");

    return 0;
}

string parse_stream_msg(uint16_t len, string &response, int sock) {
    string stream_msg;
    ssize_t rval;
    sockaddr_in srvr_addr{};
    socklen_t rcva_len;

    while (len > 0) {
        len -= response.size();
        stream_msg.append(response);
        if (len > 0) {
            int m = min(BUF_SIZE, (int) len);
            timeval tmp_timeval{};
            timeval curr_timeval{};
            tmp_timeval.tv_sec = 0;
            tmp_timeval.tv_usec = 1000;
            socklen_t curr_size;
            getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &curr_timeval,
                       &curr_size);
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &tmp_timeval,
                       sizeof(tmp_timeval));
            rval = recvfrom(sock, BUFFER, m, 0, (sockaddr *) &srvr_addr,
                            &rcva_len);
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &curr_timeval,
                       sizeof(curr_timeval));
            if (rval > 0) {
                string new_response(BUFFER, rval);
                response = new_response;
            } else {
                len = 0;
            }
        }
    }

    return stream_msg;
}

int write_msg_to_telnet(int telnet_sock, const string &msg) {
    int write_len = write(telnet_sock, msg.c_str(), msg.size());
    if (write_len != msg.size()) {
        // partial / failed write.
        return -1;
    }
    return 0;
}

string clearing_current_menu() {
    string clear_menu;
    for (int i = telnet_curr_line; i < menu_lines_count; i++)
        clear_menu.append(move_down);
    for (int i = menu_lines_count; i > 0; i--) {
        clear_menu.append(clear_line);
        if (i != 1)
            clear_menu.append(move_up);
    }
    return clear_menu;
}

int send_menu_to_telnet(int telnet_sock) {
    string menu = clearing_current_menu();
    menu.append("Szukaj pośrednika\r\n");
    for (int i = 0; i < radio_proxy_names.size(); i++) {
        menu.append("Pośrednik ");
        menu.append(radio_proxy_names[i]);
        if (proxy_choice == i)
            menu.append(" *");
        menu.append("\r\n");
    }
    menu.append("Koniec\r\n");
    menu_lines_count = radio_proxy_names.size() + 2;
    for (int i = 0; i < menu_lines_count; i++)
        menu.append(move_up);
    telnet_curr_line = 1;
    total_telnet_lines = max(total_telnet_lines, menu_lines_count);
    return write_msg_to_telnet(telnet_sock, menu);
}

int send_metadata_to_telnet(int telnet_sock, const string &data) {
    string msg;
    for (int i = telnet_curr_line; i < total_telnet_lines; i++)
        msg.append(move_down);
    if (metadata_printed)
        msg.append(clear_line);
    msg.append(data);
    msg.append("\r");
    for (int i = telnet_curr_line; i < total_telnet_lines; i++)
        msg.append(move_up);
    if (data.find('\n') != string::npos)
        msg.append(move_up);
    int ret = write_msg_to_telnet(telnet_sock, msg);
    if (ret == 0) {
        if (!metadata_printed) {
            metadata_printed = true;
            total_telnet_lines++;
        }
    }
    return ret;
}

void safe_close(int sock) {
    if (close(sock) < 0)
        syserr("close");
}

void restore_telnet_cursor(int sock) {
    string s;
    for (int i = telnet_curr_line; i <= total_telnet_lines; i++)
        s.append(move_down);
    write(sock, s.c_str(), s.size());
}

int get_proxy_list_num(sockaddr_in &srvr_addr) {
    for (int i = 0; i < radio_proxy_addrs.size(); i++) {
        if (srvr_addr.sin_addr.s_addr == radio_proxy_addrs[i].sin_addr.s_addr &&
            srvr_addr.sin_port == radio_proxy_addrs[i].sin_port)
            return i;
    }
    return -1;
}

void reset_lines_counter() {
    menu_lines_count = 0;
    telnet_curr_line = 1;
    total_telnet_lines = 0;
    metadata_printed = false;
}

int safe_menu_telnet_write(int *sock) {
    if (send_menu_to_telnet(*sock) != 0) {
        restore_telnet_cursor(*sock);
        safe_close(*sock);
        *sock = -1;
        reset_lines_counter();
        return -1;
    }
    return 0;
}

int safe_telnet_write(int *sock, const string &data) {
    if (write(*sock, data.c_str(), data.size()) != data.size()) {
        restore_telnet_cursor(*sock);
        safe_close(*sock);
        *sock = -1;
        reset_lines_counter();
        return -1;
    }
    return 0;
}

int safe_metadata_telnet_write(int *sock, const string &metadata) {
    if (send_metadata_to_telnet(*sock, metadata) != 0) {
        restore_telnet_cursor(*sock);
        safe_close(*sock);
        *sock = -1;
        reset_lines_counter();
        return -1;
    }
    return 0;
}

int handle_telnet_session() {
    pollfd clients[3];
    addrinfo addr_hints{};
    addrinfo *addr_result;

    sockaddr_in my_addr{};
    sockaddr_in srvr_addr{};
    sockaddr_in telnet_server{};

    int ret, msg_sock, err;
    int sock;
    ssize_t rval;
    ssize_t snd_len;
    socklen_t rcva_len;

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
    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &optval,
                   sizeof optval) < 0)
        syserr("broadcast");
    optval = 64;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void *) &optval,
                   sizeof optval) < 0)
        syserr("multicast ttl");

    if (inet_aton(host_addr.c_str(), &srvr_addr.sin_addr) == 0)
        syserr("inet aton");

    for (auto &i : clients) {
        i.fd = -1;
        i.events = POLLIN;
        i.revents = 0;
    }

    clients[0].fd = socket(PF_INET, SOCK_STREAM, 0);
    if (clients[0].fd == -1)
        syserr("opening socket stream");

    telnet_server.sin_family = AF_INET;
    telnet_server.sin_addr.s_addr = htonl(INADDR_ANY);
    telnet_server.sin_port = htons(telnet_port);
    if (bind(clients[0].fd, (sockaddr *) &telnet_server,
             (socklen_t) sizeof(telnet_server)) < 0)
        syserr("Binding stream socket");

    if (listen(clients[0].fd, 5) == -1)
        syserr("start listening failed");

    clients[2].fd = sock;

    do {
        for (auto &i : clients)
            i.revents = 0;

        ret = poll(clients, 3, -1);
        if (ret == -1) {
            if (errno != EINTR)
                syserr("poll");
        } else if (ret > 0) {
            if (!finish_work && (clients[0].revents & POLLIN)) {
                // Accepting telnet connection.
                msg_sock = accept(clients[0].fd, (sockaddr *) nullptr,
                                  (socklen_t *) nullptr);
                if (msg_sock == -1) {
                    syserr("accept");
                } else {
                    if (clients[1].fd == -1) {
                        char s[6] = {-1, -4, 1, -1, -4, 3};
                        /*s[0] = 255;
                        s[1] = 251;
                        s[2] = 1;
                        s[3] = 255;
                        s[4] = 251;
                        s[5] = 3;*/
                        if (write(msg_sock, s, 6) != 6 ||
                            send_menu_to_telnet(msg_sock) != 0) {
                            safe_close(msg_sock);
                        } else {
                            clients[1].fd = msg_sock;
                            clients[1].events = POLLIN;
                        }
                    } else {
                        // Telnet has already connected to client.
                        safe_close(msg_sock);
                    }
                }
            }
            if (clients[1].fd != -1 &&
                (clients[1].revents) & (POLLIN | POLLERR)) {
                rval = read(clients[1].fd, BUFFER, BUF_SIZE);
                if (rval <= 0) {
                    // read failed or telnet has closed connection
                    restore_telnet_cursor(clients[1].fd);
                    safe_close(clients[1].fd);
                    clients[1].fd = -1;
                    reset_lines_counter();
                } else {
                    if (rval == 2) {
                        if (BUFFER[0] == 13 && BUFFER[1] == 0) {
                            cerr << "RECEIVED ENTER" << endl;
                            if (telnet_curr_line == menu_lines_count) {
                                finish_work = true;
                            } else if (telnet_curr_line == 1) {
                                radio_proxy_names.clear();
                                radio_proxy_addrs.clear();
                                string s = create_msg_to_client(DISCOVER, "");
                                rcva_len = (socklen_t) sizeof(my_addr);
                                snd_len = sendto(sock, s.c_str(), s.size(), 0,
                                                 (sockaddr *) &my_addr,
                                                 rcva_len);
                                if (snd_len != s.size())
                                    syserr("partial / failed write");
                                //cerr << "DISCOVER sent" << endl;
                            } else {
                                proxy_choice = (int) telnet_curr_line - 2;
                                sockaddr_in proxy_addr = radio_proxy_addrs[proxy_choice];
                                send_menu_to_telnet(clients[1].fd);
                                // sending first discover
                                string s = create_msg_to_client(DISCOVER, "");
                                rcva_len = (socklen_t) sizeof(proxy_addr);
                                snd_len = sendto(sock, s.c_str(), s.size(), 0,
                                                 (sockaddr *) &proxy_addr,
                                                 rcva_len);
                                if (snd_len != s.size())
                                    syserr("partial / failed write");
                                // todo timeout and keepalive sending
                            }
                        }
                    } else if (rval == 3) {
                        if (BUFFER[0] == 27 && BUFFER[1] == 91) {
                            if (BUFFER[2] == 65 && telnet_curr_line != 1) {
                                telnet_curr_line--;
                                string s = move_up;
                                safe_telnet_write(&clients[1].fd, s);
                            }
                            if (BUFFER[2] == 66 &&
                                telnet_curr_line != menu_lines_count) {
                                telnet_curr_line++;
                                string s = move_down;
                                safe_telnet_write(&clients[1].fd, s);
                            }
                        }
                    }
                }
            }
            if (clients[2].fd != -1 &&
                (clients[2].revents) & (POLLIN | POLLERR)) {
                rval = recvfrom(clients[2].fd, BUFFER, BUF_SIZE, 0,
                                (sockaddr *) &srvr_addr,
                                &rcva_len);
                if (rval >= 4) {
                    uint16_t msg_type;
                    uint16_t msg_len;
                    memmove(&msg_type, BUFFER, 2);
                    memmove(&msg_len, BUFFER + 2, 2);
                    uint16_t type = ntohs(msg_type);
                    uint16_t len = ntohs(msg_len);
                    string response(BUFFER + 4, rval - 4);
                    int proxy_num = get_proxy_list_num(srvr_addr);

                    if (type == IAM) {
                        if (proxy_num == -1) {
                            radio_proxy_names.push_back(response);
                            if (safe_menu_telnet_write(&clients[1].fd) != 0)
                                radio_proxy_names.pop_back();
                            else
                                radio_proxy_addrs.push_back(srvr_addr);
                        }
                    }

                    if (type == AUDIO && proxy_num >= 0 &&
                        proxy_num == proxy_choice) {
                        cout << parse_stream_msg(len, response, clients[2].fd);
                    }

                    if (type == METADATA && proxy_num >= 0 &&
                        proxy_num == proxy_choice) {
                        string metadata = parse_stream_msg(len, response,
                                                           clients[2].fd);
                        safe_metadata_telnet_write(&clients[1].fd, metadata);
                    }
                    // Ignoring message of wrong type.
                }
            }
        } else {
            // timeout exceeded, program shouldn't reach this code.
            return 1;
        }
    } while (!finish_work);

    for (int i = 0; i < 3; i++) {
        if (i == 1)
            restore_telnet_cursor(clients[1].fd);
        if (clients[i].fd >= 0)
            safe_close(clients[i].fd);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    setup();
    if (parse_args(argc, argv) != 0) {
        fatal("Usage %s -H <radio-proxy address> -P <host port> -p <telnet port> "
              "[-T <radio-proxy timeout>]", argv[0]);
    }

    handle_telnet_session();
    cout << "Hello world" << endl;
}