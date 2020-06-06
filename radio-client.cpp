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
#include <poll.h>
#include <chrono>
#include <algorithm>

extern "C" {
#include "err.h"
}

/**
 * Constant defining biggest possible port number.
 */
const int MAX_PORT_NUM = 65535;

/**
 * Constant defining buffer size used by read function.
 */
const int BUF_SIZE = 8192;

/**
 * Macros defining ASCII Escape Code for clearing line and cursor move.
 */
#define clear_line "\033[0K"
#define move_down "\033[1B"
#define move_up "\033[1A"

/**
 * Macros defining which timeouts should be updated.
 */
#define PROXY_TIMEOUT 1
#define KEEPALIVE_TIMEOUT 2
#define ALL_TIMEOUTS 3

/**
 * Constant defining how often KEEPALIVE message is sent. Value is milliseconds.
 */
const int KEEPALIVE_TIMEOUT_VAL = 3500;

/**
 * Macros defining types of clients' messages in proxy mode.
 */
#define DISCOVER 1
#define IAM 2
#define KEEPALIVE 3
#define AUDIO 4
#define METADATA 6

using namespace std;
using namespace std::chrono;

/**
 * Map where keys are like '-P', '-H' and represent possible program arguments.
 * Values represent number of argument occurrences in program argument list.
 */
unordered_map<string, int> req_args;

/**
 * Vector of radio proxies found and presented in menu, with proxy address.
 */
vector<string> radio_proxy_names;
vector<sockaddr_in> radio_proxy_addrs;

/**
 * Values of program required arguments.
 */
string host_addr;
int radio_proxy_port;
int telnet_port;

/**
 * Time in milliseconds after which proxy is treated as not working.
 */
int timeout = -1;

/**
 * Remaining time to send next KEEPALIVE message.
 */
int keepalive_timeout_left = KEEPALIVE_TIMEOUT_VAL;

/**
 * Remaining time to treat proxy as not working.
 */
int proxy_timeout_left;

/**
 * True if @ref proxy_timeout_left < @ref keepalive_timeout_left.
 */
bool proxy_timeout_selected;

/**
 * Position of selected proxy in menu list, -1 if no proxy is selected.
 */
int proxy_choice = -1;

/**
 * Menu size (in lines) and line with cursor number (starting from 1).
 */
size_t menu_lines_count = 0;
size_t telnet_curr_line = 1;

/**
 * Last metadata printed in menu.
 */
string metadata_printed;

// Variable defining when program should finish work.
static bool finish_work = false;

char BUFFER[BUF_SIZE];

/** @brief Signal handler.
 * Marks that program after SIGINT should finish work.
 * @param signal [in]   - signal number.
 */
static void catch_int(int signal) {
    if (signal == SIGINT)
        finish_work = true;
}

/**
 * Initiates global variables and sets signal handler.
 */
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

/** @brief Parses and checks argument.
 * Return -1 if at least one argument is wrong.
 * @param argc [in]   - number of arguments,
 * @param argv [in]   - array of arguments.
 * @return Value @p 0 if arguments are correct or -1 if they are wrong.
 */
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

/** @brief Creates message to client.
 * Message contains header of first 16 bits indicating message's type and
 * next 16 bits indicating message's length.
 * @param type [in]   - message type,
 * @param data [in]   - message content.
 * @return Message with included header.
 */
static string create_msg_to_client(uint16_t type, const string &data) {
    char msg_header[4];
    uint16_t msg_type = htons(type);
    uint16_t msg_len = htons(data.size());
    memmove(msg_header, &msg_type, 2);
    memmove(msg_header + 2, &msg_len, 2);
    string msg(msg_header, 4);
    msg.append(data);
    return msg;
}

/** @brief Concatenates message content if message is larger than buffer.
 * @param len [in]        - expected message length,
 * @param response [in]   - read message,
 * @param sock [in]       - socket descriptor, from this socket rest of message
 *                          is read.
 * @return Concatenated message.
 */
static string parse_stream_msg(uint16_t len, string &response, int sock) {
    string stream_msg;
    ssize_t rval;
    sockaddr_in srvr_addr{};
    socklen_t rcva_len = (socklen_t) sizeof(srvr_addr);

    int len_left = len;

    while (len_left > 0) {
        len_left -= response.size();
        stream_msg.append(response);
        if (len_left > 0) {
            int m = min(BUF_SIZE, (int) len_left);
            // If message is larger than buffer should be reachable nearly immediately.
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
                len_left = 0;
            }
        }
    }

    return stream_msg;
}

/** @brief Select poll timeout.
 * @return Lowest of @ref proxy_timeout_left and @ref keeepalive_timeout_left,
 * or -1 if proxy wasn't selected.
 */
static int get_next_timeout() {
    if (proxy_choice == -1)
        return -1;
    proxy_timeout_selected = proxy_timeout_left < keepalive_timeout_left;
    return min(proxy_timeout_left, keepalive_timeout_left);
}

/** @brief Decreases selected timeouts values.
 * @param timeouts_type [in]   - selected timeouts,
 * @param timeout_ms [in]      - decrease value.
 */
static void decrease_timeouts(int timeouts_type, int timeout_ms) {
    if (timeouts_type == ALL_TIMEOUTS) {
        proxy_timeout_left -= timeout_ms;
        keepalive_timeout_left -= timeout_ms;
    } else if (timeouts_type == KEEPALIVE_TIMEOUT) {
        keepalive_timeout_left -= timeout_ms;
    } else if (timeouts_type == PROXY_TIMEOUT) {
        proxy_timeout_left -= timeout_ms;
    }

    proxy_timeout_left = proxy_timeout_left > 0 ? proxy_timeout_left : 0;
    keepalive_timeout_left =
            keepalive_timeout_left > 0 ? keepalive_timeout_left : 0;
}

/** @brief Send empty message to proxy.
 * Creates message of selected type and empty content.
 * Terminates program if error occurred.
 * @param socket [in]     - socket descriptor to write,
 * @param msg_type [in]   - message type,
 * @param addr [in]       - proxy's address.
 */
static void write_typemsg_to_proxy_socket(int socket, int msg_type,
                                          sockaddr_in addr) {
    string s = create_msg_to_client(msg_type, "");
    auto rcva_len = (socklen_t) sizeof(addr);
    ssize_t snd_len = sendto(socket, s.c_str(), s.size(), 0, (sockaddr *) &addr,
                             rcva_len);
    if (snd_len != (ssize_t) s.size())
        syserr("partial / failed write");
}

/** @brief Send message to telnet client.
 * @param telnet_sock [in]   - socket to write,
 * @param msg [in]           - message to send.
 * @return Value @p 0 on success, otherwise value @p -1.
 */
static int write_msg_to_telnet(int telnet_sock, const string &msg) {
    ssize_t write_len = write(telnet_sock, msg.c_str(), msg.size());
    if (write_len != (ssize_t) msg.size()) {
        // partial / failed write.
        return -1;
    }
    return 0;
}

/** @brief Creates string clearing current menu.
 * @return String clearing current menu.
 */
static string clearing_current_menu() {
    string clear_menu;
    for (size_t i = telnet_curr_line; i < menu_lines_count; i++)
        clear_menu.append(move_down);
    if (!metadata_printed.empty()) {
        clear_menu.append(move_down);
        clear_menu.append(clear_line);
        clear_menu.append(move_up);
    }
    for (size_t i = menu_lines_count; i > 0; i--) {
        clear_menu.append(clear_line);
        if (i != 1)
            clear_menu.append(move_up);
    }
    return clear_menu;
}

/** @brief Creates and sends new menu to telnet client.
 * Message contains part clearing current menu and part describing new menu.
 * @param telnet_sock [in]   - socket to write.
 * @return Value @p 0 on success, otherwise value @p -1.
 */
static int send_menu_to_telnet(int telnet_sock) {
    string menu = clearing_current_menu();
    menu.append("Szukaj pośrednika\r\n");
    for (size_t i = 0; i < radio_proxy_names.size(); i++) {
        menu.append("Pośrednik ");
        menu.append(radio_proxy_names[i]);
        if (proxy_choice == (int) i)
            menu.append(" *");
        menu.append("\r\n");
    }
    menu.append("Koniec\r\n");
    if (proxy_choice != -1 && !metadata_printed.empty()) {
        menu.append(metadata_printed);
        menu.append("\r\n");
        menu.append(move_up);
    }
    menu_lines_count = radio_proxy_names.size() + 2;
    for (size_t i = 0; i < menu_lines_count; i++)
        menu.append(move_up);

    telnet_curr_line = 1;

    return write_msg_to_telnet(telnet_sock, menu);
}

/** @brief Sends metadata to telnet client.
 * If any metadata was previously printed, clears it and prints new metadata.
 * @param telnet_sock [in]   - socket to write,
 * @param data [in]          - metadata to sent.
 * @return Value @p 0 on success, otherwise value @p -1.
 */
static int send_metadata_to_telnet(int telnet_sock, const string &data) {
    string msg;
    for (size_t i = telnet_curr_line; i <= menu_lines_count; i++)
        msg.append(move_down);
    if (!metadata_printed.empty())
        msg.append(clear_line);
    msg.append(data);
    msg.append("\r");
    for (size_t i = telnet_curr_line; i <= menu_lines_count; i++)
        msg.append(move_up);
    if (data.find('\n') != string::npos)
        msg.append(move_up);
    int ret = write_msg_to_telnet(telnet_sock, msg);
    if (ret == 0) {
        metadata_printed = data;
    }
    return ret;
}

/** @brief Closes socket and terminates if error occurred,
 * @param sock [in]   - socket to close.
 */
static void safe_close(int sock) {
    if (close(sock) < 0)
        syserr("close");
}

/** @brief Creates and sends message placing cursor in new line after menu.
 * @param sock [in]   - socket to write.
 */
static void restore_telnet_cursor(int sock) {
    string s;
    for (size_t i = telnet_curr_line; i <= menu_lines_count; i++)
        s.append(move_down);
    if (!metadata_printed.empty())
        s.append(move_down);
    write(sock, s.c_str(), s.size());
}

/** @brief Checks if proxy was previously found.
 * Returns its position in @ref radio_proxy_addrs or -1 if was not found.
 * @param srvr_addr [in]   - proxy sockaddr_in structure.
 * @return Its position in @ref radio_proxy_addrs or -1 if was not found.
 */
static int get_proxy_list_num(sockaddr_in srvr_addr) {
    for (size_t i = 0; i < radio_proxy_addrs.size(); i++) {
        if (srvr_addr.sin_addr.s_addr == radio_proxy_addrs[i].sin_addr.s_addr &&
            srvr_addr.sin_port == radio_proxy_addrs[i].sin_port)
            return i;
    }
    return -1;
}

/**
 * Reset variables describin menu state.
 */
static void reset_lines_counter() {
    menu_lines_count = 0;
    telnet_curr_line = 1;
    metadata_printed = "";
}

/** @brief Sends menu to telnet.
 * If error occurred, closes telnet socket.
 * @param sock [in]   - pointer to telnet socket.
 * @return Value @p 0 on success, otherwise value @p -1.
 */
static int safe_menu_telnet_write(int *sock) {
    if (send_menu_to_telnet(*sock) != 0) {
        restore_telnet_cursor(*sock);
        safe_close(*sock);
        *sock = -1;
        reset_lines_counter();
        return -1;
    }
    return 0;
}

/** @brief Sends message to telnet.
 * If error occurred, closes telnet socket.
 * @param sock [in]   - pointer to telnet socket,
 * @param data [in]   - message to send.
 * @return Value @p 0 on success, otherwise value @p -1.
 */
static int safe_telnet_write(int *sock, const string &data) {
    if (write(*sock, data.c_str(), data.size()) != (ssize_t)data.size()) {
        restore_telnet_cursor(*sock);
        safe_close(*sock);
        *sock = -1;
        reset_lines_counter();
        return -1;
    }
    return 0;
}

/** @brief Sends metadata to telnet.
 * If error occurred, closes telnet socket.
 * @param sock [in]       - pointer to telnet socket,
 * @param metadata [in]   - metadata to send.
 * @return Value @p 0 on success, otherwise value @p -1.
 */
static int safe_metadata_telnet_write(int *sock, const string &metadata) {
    if (send_metadata_to_telnet(*sock, metadata) != 0) {
        restore_telnet_cursor(*sock);
        safe_close(*sock);
        *sock = -1;
        reset_lines_counter();
        return -1;
    }
    return 0;
}

/** @brief Handles connection with telnet client.
 * @return Value @p on success, value @p 1 if error occurred and program was
 * not terminated.
 */
static int handle_telnet_session() {
    pollfd clients[3];
    addrinfo addr_hints{};
    addrinfo *addr_result;

    sockaddr_in my_addr{};
    sockaddr_in srvr_addr{};
    sockaddr_in telnet_server{};

    int ret, msg_sock, err, exitcode = 0;
    int sock;
    ssize_t rval;
    socklen_t rcva_len;

    bool update_timeouts = true;

    if (inet_aton(host_addr.c_str(), &srvr_addr.sin_addr) == 0) {
        cerr << "Ivalid host address" << endl;
        return 1;
    }

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


    for (auto &i : clients) {
        i.fd = -1;
        i.events = POLLIN;
        i.revents = 0;
    }

    // Socket accepting connections from client.
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

    // UDP socket to connect communicate with proxies.
    clients[2].fd = sock;

    do {
        for (auto &i : clients)
            i.revents = 0;
        update_timeouts = proxy_choice != -1;

        auto start = high_resolution_clock::now();
        ret = poll(clients, 3, get_next_timeout());
        auto end = high_resolution_clock::now();

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
                        // Forcing telnet to be in character mode.
                        char s[6];
                        s[0] = 255;
                        s[1] = 251;
                        s[2] = 1;
                        s[3] = 255;
                        s[4] = 251;
                        s[5] = 3;
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
            // Socket connected to active telnet client.
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
                            // ENTER was pressed.
                            if (telnet_curr_line == menu_lines_count) {
                                // Koniec selected
                                finish_work = true;
                            } else if (telnet_curr_line == 1) {
                                // Szukaj posrednika selected.
                                write_typemsg_to_proxy_socket(clients[2].fd,
                                                              DISCOVER,
                                                              my_addr);
                            } else {
                                // Proxy was chosen.
                                proxy_choice = (int) telnet_curr_line - 2;
                                sockaddr_in proxy_addr = radio_proxy_addrs[proxy_choice];
                                safe_menu_telnet_write(&clients[1].fd);
                                write_typemsg_to_proxy_socket(clients[2].fd,
                                                              DISCOVER,
                                                              proxy_addr);
                                // scheduling timeouts
                                proxy_timeout_left = timeout;
                                keepalive_timeout_left = KEEPALIVE_TIMEOUT_VAL;
                                update_timeouts = false;
                            }
                        }
                    } else if (rval == 3) {
                        if (BUFFER[0] == 27 && BUFFER[1] == 91) {
                            if (BUFFER[2] == 65 && telnet_curr_line != 1) {
                                // UP Arrow was pressed.
                                telnet_curr_line--;
                                string s = move_up;
                                safe_telnet_write(&clients[1].fd, s);
                            }
                            if (BUFFER[2] == 66 &&
                                telnet_curr_line != menu_lines_count) {
                                // DOWN Arrow was pressed.
                                telnet_curr_line++;
                                string s = move_down;
                                safe_telnet_write(&clients[1].fd, s);
                            }
                        }
                    }
                }
            }

            // UDP socket to communicate with proxy.
            if (clients[2].fd != -1 &&
                (clients[2].revents) & (POLLIN | POLLERR)) {
                // Message from proxy was received.
                rcva_len = sizeof(srvr_addr);
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
                        // Adding new proxy to menu.
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
                        cout.flush();
                        // timeouts updating
                        proxy_timeout_left = timeout;
                        decrease_timeouts(KEEPALIVE_TIMEOUT,
                                          duration_cast<milliseconds>(
                                                  end - start).count());
                        update_timeouts = false;
                    }

                    if (type == METADATA && proxy_num >= 0 &&
                        proxy_num == proxy_choice) {
                        string metadata = parse_stream_msg(len, response,
                                                           clients[2].fd);
                        safe_metadata_telnet_write(&clients[1].fd, metadata);
                        // timeouts update
                        if (update_timeouts) {
                            proxy_timeout_left = timeout;
                            decrease_timeouts(KEEPALIVE_TIMEOUT,
                                              duration_cast<milliseconds>(
                                                      end - start).count());
                            update_timeouts = false;
                        }
                    }
                    // Ignoring message of wrong type.
                }
            }

            // updating timeouts if not done before
            if (update_timeouts)
                decrease_timeouts(ALL_TIMEOUTS, duration_cast<milliseconds>(
                        end - start).count());
        } else {
            if (update_timeouts) {
                if (proxy_timeout_selected) {
                    // disabling proxy
                    radio_proxy_names.erase(
                            radio_proxy_names.cbegin() + proxy_choice);
                    radio_proxy_addrs.erase(
                            radio_proxy_addrs.cbegin() + proxy_choice);
                    proxy_choice = -1;
                    // proxy_choice = -1 implies that timeouts are disabled.
                    // printing new menu
                    safe_menu_telnet_write(&clients[1].fd);
                    metadata_printed = "";
                } else {
                    // sending KEEPALIVE
                    sockaddr_in proxy_addr = radio_proxy_addrs[proxy_choice];
                    write_typemsg_to_proxy_socket(clients[2].fd, KEEPALIVE,
                                                  proxy_addr);
                    // updating timeouts
                    decrease_timeouts(PROXY_TIMEOUT,
                                      duration_cast<milliseconds>(
                                              end - start).count());
                    keepalive_timeout_left = KEEPALIVE_TIMEOUT_VAL;
                }
            } else {
                // Program shouldn't reach this code.
                cerr << "Unexpected poll timeout" << endl;
                finish_work = true;
                exitcode = 1;
            }
        }
    } while (!finish_work);

    for (int i = 0; i < 3; i++) {
        if (i == 1)
            restore_telnet_cursor(clients[1].fd);
        if (clients[i].fd >= 0)
            safe_close(clients[i].fd);
    }
    return exitcode;
}

int main(int argc, char *argv[]) {
    setup();
    if (parse_args(argc, argv) != 0) {
        fatal("Usage %s -H <radio-proxy address> -P <host port> -p <telnet port> "
              "[-T <radio-proxy timeout>]", argv[0]);
    }

    return handle_telnet_session();
}