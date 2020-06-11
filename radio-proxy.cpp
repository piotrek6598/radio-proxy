/** @file
 * Radio-proxy program downloads music from given radio server and plays it
 * or redirects it further receivers. Program enables also downloading
 * of basic metadata. Program works in two modes, player and proxy mode.
 *
 * In player mode program prints downloaded audio to stdout and downloaded
 * metadata to stderr. Usage is:<br>
 * ./radio-proxy params<br>
 *
 * Params: <br>
 * -h   radio server name or address, required. <br>
 * -r   resource to download from radio server, required. <br>
 * -p   port number at server where audio is available, required.<br>
 * -m   metadata request, possible values are yes|no, optional, default is no.<br>
 * -t   timeout after which server is treated as unavailable, optional, default is 5s.<br>
 *
 * Example usage:<br>
 * ./radio-proxy -h waw02-03.ic.smcdn.pl -r /t050-1.mp3 -p 8000<br>
 *
 * In proxy mode, downloaded audio and metadata are redirected to connected receivers.
 * Usage is:<br>
 * ./radio-proxy params<br>
 *
 * Additional params are:<br>
 * -P   port number, where clients can connect, required.<br>
 * -B   listening multicast address, optional.<br>
 * -T   timeout after proxy doesn't send anything to client, optional, default is 5s.<br>
 *
 * example usage:<br>
 * ./radio-proxy -h waw02-03.ic.smcdn.pl -r /t050-1.mp3 -p 8000 -P 10000 -t 10<br>
 *
 * Connection between radio-proxy and radio server is made on TCP basis with
 * SHOUTcast (ICY) protocol, but data are transferred to clients on UDP basis.
 *
 * Program finishes work where SIGINT is received or radio server is unavailable.
 * Program terminates with exitcode 1, if wrong params are given, occurred any
 * error which makes further work impossible. In case of failure associated
 * message is printed to stderr.
 *
 * Detailed communication protocol is available at TODO.
 *
 * @author Piotr Jasinski <jasinskipiotr99@gmail.com>
 * @date 07.06.2020
 */

#include <iostream>
#include <unordered_map>
#include <cstring>
#include <climits>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <csignal>
#include <cassert>
#include <poll.h>
#include <chrono>
#include <map>

extern "C" {
#include "err.h"
}

using namespace std;
using namespace std::chrono;

/** Constant defining biggest possible port number. */
#define MAX_PORT_NUM 65535

/** Constant defining buffer size used by read function. */
#define BUF_SIZE 1024

/** Macro defining value of @ref metadata_interval when metadata aren't being sent. */
#define NO_METADATA -1

/** @name Clients' message type.
 * Macros defining types of clients' message type in proxy mode.
 */
//@{
#define DISCOVER 1
#define IAM 2
#define KEEPALIVE 3
#define AUDIO 4
#define METADATA 6
//@}


/** @name Player mode params
 * Arguments defining details of connection to radio server.
 */
//@{
/** Radio server name. */
string host_name;
/** Resource to download in radio server. */
string resource_name;
/** Port number where resource is available.*/
int port_num;
/** Flag indicating if metadata are requested. */
bool metadata_request;
/** Radio server timeout in milliseconds. */
int server_timeout;
//@}

/** @name Proxy mode params.
 * Arguments defining details of connection to clients in proxy mode.
 */
//@{
/** Port number where clients can connect. */
int proxy_port_num;
/** Possible multicast address, empty if not set. */
string multicast_address;
/** Time of client's inactivity after proxy stops to send anything. */
int client_timeout;
//@}

/** @name Radio description.
 * Description of transmitted radio.
 */
//@{
/** Radio name. */
static string radio_name;
/** Last not empty received metadata. */
string last_metadata_received;
//@}

/** @name Connection details.
 * Variables storing connection details.
 */
//@{
/** Structure describing proxy multicast group. */
ip_mreq multicast_group;
/** Current writing timeout on clients' socket. */
int clients_socket_current_timeout;
/** Structure describing proxy own address. */
sockaddr_in radio_proxy_addr;
//@}

/** Flag indicating that program should finish work. */
static bool finish_work = false;

/** Global variable defining number of bytes between two metadata blocks. */
static int metadata_interval = NO_METADATA;

/**
 * Map of active clients is updated every time data are sent or new client appears.
 * Used only in proxy mode. Keys are pairs of client address and port number.
 * Values are pairs of client's sockaddr_in struct and last activity timestamp.
 */
map<pair<uint32_t, uint16_t>, pair<sockaddr_in, time_point<high_resolution_clock>>> clients;


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

    clients_socket_current_timeout = 0;
    metadata_request = false;
    server_timeout = 5;
    proxy_port_num = -1;
    client_timeout = 5;

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
    unordered_map<string, int> req_args;
    unordered_map<string, int> opt_args;
    unordered_map<string, int> proxy_opt_args;

    req_args.insert({"-h", 0});
    req_args.insert({"-r", 0});
    req_args.insert({"-p", 0});
    opt_args.insert({"-m", 0});
    opt_args.insert({"-t", 0});
    proxy_opt_args.insert({"-B", 0});
    proxy_opt_args.insert({"-T", 0});

    if (argc < 7 || argc % 2 == 0)
        return -1;

    for (int i = 1; i < argc; i += 2) {
        auto search = req_args.find(argv[i]);
        if (search == req_args.end()) {
            search = opt_args.find(argv[i]);
            if (search == opt_args.end()) {
                search = proxy_opt_args.find(argv[i]);
                if (search == proxy_opt_args.end()) {
                    // This should be proxy required argument.
                    if (strcmp("-P", argv[i]) == 0) {
                        if (proxy_port_num != -1)
                            return -1;
                        int p = parse_string_to_number(argv[i + 1]);
                        if (p == -1 || p > MAX_PORT_NUM)
                            return -1;
                        proxy_port_num = p;
                    } else {
                        // Invalid argument.
                        return -1;
                    }
                } else {
                    // This is proxy optional argument.
                    search->second++;
                    if (strcmp("-B", argv[i]) == 0) {
                        multicast_address = argv[i + 1];
                    } else if (strcmp("-T", argv[i]) == 0) {
                        int t = parse_string_to_number(argv[i + 1]);
                        if (t <= 0)
                            return -1;
                        client_timeout = t;
                    } else {
                        return -1; // Program shouldn't reach this code.
                    }
                }
            } else {
                // This optional argument.
                search->second++;
                if (strcmp("-t", argv[i]) == 0) {
                    int t = parse_string_to_number(argv[i + 1]);
                    if (t <= 0)
                        return -1;
                    server_timeout = t;
                } else if (strcmp("-m", argv[i]) == 0) {
                    if (strcmp("yes", argv[i + 1]) == 0) {
                        metadata_request = true;
                    } else if (strcmp("no", argv[i + 1]) != 0) {
                        return -1;
                    }
                } else {
                    return -1; // Program shouldn't reach this code.
                }
            }
        } else {
            // This required argument
            search->second++;
            if (strcmp("-p", argv[i]) == 0) {
                int p = parse_string_to_number(argv[i + 1]);
                if (p == -1 || p > MAX_PORT_NUM)
                    return -1;
                port_num = p;
            } else if (strcmp("-h", argv[i]) == 0) {
                host_name = argv[i + 1];
            } else if (strcmp("-r", argv[i]) == 0) {
                resource_name = argv[i + 1];
            } else {
                return -1; // Program shouldn't reach this code.
            }
        }
    }

    // Checks if all required arguments appeared exactly ones.
    for (auto &req_arg : req_args) {
        if (req_arg.second != 1)
            return -1;
    }

    // Checks if all optional arguments appeared at most ones.
    for (auto &optional_arg : opt_args) {
        if (optional_arg.second > 1 || optional_arg.second < 0)
            return -1;
    }

    // Checks if all proxy optional arguments appeared at most ones or didn't
    // appear if proxy required args wasn't set.
    for (auto &proxy_opt_arg : proxy_opt_args) {
        if (proxy_opt_arg.second > 1 || proxy_opt_arg.second < 0)
            return -1;
        if (proxy_port_num == -1 && proxy_opt_arg.second != 0)
            return -1;
    }

    // Converting timeouts to milliseconds.
    client_timeout *= 1000;
    server_timeout *= 1000;

    return 0;
}

/** @brief Connects to radio server.
 * Creates a socket enabling communication with radio server via TCP.
 * If connection is impossible terminates program with exitcode 1.
 * @param server [in]   - server name,
 * @param port [in]     - port number.
 * @return Socket descriptor.
 */
static int connect_to_server(string &server, int port) {
    addrinfo addr_hints{};
    addrinfo *addr_result;
    int err;
    int sock;

    memset(&addr_hints, 0, sizeof(addrinfo));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;

    err = getaddrinfo(server.c_str(), to_string(port).c_str(), &addr_hints, &addr_result);
    if (err == EAI_SYSTEM) {
        syserr("getaddrinfo: %s", gai_strerror(err));
    } else if (err != 0) {
        fatal("getaddrinfo %s", gai_strerror(err));
    }

    sock = socket(addr_result->ai_family, addr_result->ai_socktype, addr_result->ai_protocol);
    if (sock < 0)
        syserr("socket");

    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) < 0)
        syserr("connect");

    freeaddrinfo(addr_result);
    return sock;
}

/** @brief Adds proxy to multicast group.
 * If connection is impossible returns -1.
 * @param sock [in]   - socket associated with multicast group.
 * @return Value @p 0 on success, value @p -1 if error occurred.
 */
static int add_multicast_membership(int sock) {
    multicast_group.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(multicast_address.c_str(), &multicast_group.imr_multiaddr) == 0)
        return -1;

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *) &multicast_group,
                   sizeof multicast_group) < 0) {
        return -1;
    }
    return 0;
}

/** @brief Creates socket which clients can connect.
 * Creates a socket enabling communication with clients via UDP.
 * If connection is impossible terminates program with exitcode 1.
 * @return Socket descriptor.
 */
static int create_proxy_socket() {

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0)
        syserr("sock");

    if (!multicast_address.empty()) {
        if (add_multicast_membership(sock) != 0)
            syserr("wrong multicast address");
    }


    radio_proxy_addr.sin_family = AF_INET;
    radio_proxy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    radio_proxy_addr.sin_port = htons(proxy_port_num);

    if (bind(sock, (sockaddr *) &radio_proxy_addr, (socklen_t) sizeof(radio_proxy_addr)) < 0)
        syserr("bind");

    return sock;
}

/** @brief Creates request to radio server.
 * @return String with request.
 */
static string create_radio_request() {
    string request = "GET ";
    request.append(resource_name);
    request.append(" HTTP/1.0 \r\n");

    request.append("Host: ");
    request.append(host_name);
    request.append("\r\n");

    if (metadata_request)
        request.append("Icy-MetaData: 1 \r\n");

    request.append("\r\n");
    return request;
}

/** @brief Check if server response is 200 OK.
 * @param status_line [in]   - line of server response with status code.
 * @return Value @p true if response is 200 OK, otherwise value @p false.
 */
static bool check_status_line(const string &status_line) {
    if (status_line == "ICY 200 OK")
        return true;
    if (status_line == "HTTP/1.0 200 OK")
        return true;
    return status_line == "HTTP/1.1 200 OK";
}

/** @brief Extracts interval between metadata blocks.
 * Returns -1 if size is greater than INT_MAX.
 * Assumes that given argument is part of line containing header icy-metaint,
 * starting from ':' ("icy-metaint[line]\r\n")
 * @param line [in]   - reference to part of line with icy-metaint header.
 * @return Interval between metadata blocks or -1 if interval is greater than
 * INT_MAX.
 */
static int extract_metadata_interval(string &line) {
    long long result = 0;
    bool first_num = false;
    for (size_t i = 1; i < line.size(); i++) {
        if (line[i] >= '0' && line[i] <= '9') {
            result *= 10;
            result += (long long) (line[i] - '0');
            first_num = true;
        } else if (line[i] != ' ' || first_num) {
            return (int) result;
        }
        if (result > INT_MAX)
            return -1;
    }
    return (int) result;
}

/** @brief Set timeout on writing to socket.
 * Set timeout min(timeout_ms, 500). Do nothing if new timeout is equal
 * to current timeout. Terminates with exitcode 1 if error occurred.
 * @param timeout_ms [in]   - new timeout in milliseconds,
 * @param sock [in]         - socket descriptor.
 */
static void set_socket_writing_timeout(int timeout_ms, int sock) {
    timeval timeout{};

    if (timeout_ms == clients_socket_current_timeout)
        return;

    if (timeout_ms > 500)
        timeout_ms = 500;

    timeout.tv_sec = 0;
    timeout.tv_usec = timeout_ms * 1000;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (void *) &timeout, sizeof(timeout)) < 0)
        syserr("sockopt failed");

    clients_socket_current_timeout = timeout_ms;
}

/** @brief Sends data received from radio server to active clients.
 * If requested, checks every client if he is still active. Client is treated
 * as active if he sent 'DISCOVER' or 'KEEPALIVE' message in last
 * @ref client_timeout milliseconds.
 * @param data            [in]   - data to send,
 * @param timeout_ms      [in]   - timeout per single send,
 * @param sock            [in]   - socket descriptor, where data are written,
 * @param check_if_active [in]   - flag indicates if client's activity is checked
 *                                 before sending data.
 * @return Duration of function runtime in milliseconds.
 */
static int
send_data_to_active_clients(const string &data, int timeout_ms, int sock, bool check_if_active) {
    auto start = high_resolution_clock::now();
    auto it = clients.begin();

    if (check_if_active) {
        while (it != clients.end()) {
            if (duration_cast<milliseconds>(start - it->second.second).count() > client_timeout) {
                auto new_it = clients.erase(it);
                it = new_it;
            } else {
                it++;
            }
        }
    }

    it = clients.begin();

    while (it != clients.end()) {
        size_t msg_len = data.size();
        size_t msg_sent = 0;
        int timeout_left = timeout_ms;
        do {
            set_socket_writing_timeout(timeout_left, sock);
            auto snda_len = (socklen_t) sizeof(it->second.first);

            auto send_start = high_resolution_clock::now();
            ssize_t len = sendto(sock, data.c_str() + msg_sent, data.size() - msg_sent, 0,
                                 (sockaddr *) &(it->second.first), snda_len);
            auto send_end = high_resolution_clock::now();

            if (len >= 0)
                msg_sent += len;

            timeout_left -= duration_cast<milliseconds>(send_end - send_start).count();
        } while (msg_sent < msg_len && timeout_left > 0);
        // Ignoring partial write or exceeding timeout.
        it++;
    }

    auto end = high_resolution_clock::now();
    return duration_cast<milliseconds>(end - start).count();
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

/** @brief Creates IAM response.
 * Response contains radio name and last not empty metadata separated
 * by 'MetaDataIncluded:'. If radio doesn't transmit metadata or proxy didn't
 * receive not empty metadata, response contains only radio name.
 * @param radio [in]      - radio name,
 * @param metadata [in]   - last not empty metadata.
 * @return IAM response.
 */
static string create_iam_response(string radio, const string &metadata) {
    string resp;
    if (metadata.empty())
        return radio;
    resp.append(radio);
    resp.append("MetaDataIncluded:");
    resp.append(metadata);
    return resp;
}

/** @brief Sends data to clients.
 * Data are written to @p sock socket. If @p sock is -1, prints audio data
 * to stdout and meta data to stderr.
 * @param audio_stream [in]   - audio data,
 * @param meta_stream  [in]   - meta data,
 * @param sock         [in]   - socket descriptor, where data are written.
 * @return Duration of sending data in milliseconds if @p sock is not -1,
 * otherwise returns 0.
 */
static int
sending_or_printing_data(const string &audio_stream, const string &meta_stream, int sock) {
    int audio_send_time = 0, meta_send_time = 0;
    int timeout_ms = server_timeout / 3;
    string msg;

    if (!clients.empty())
        timeout_ms /= clients.size();

    if (sock != -1) {
        if (!audio_stream.empty()) {
            msg = create_msg_to_client(AUDIO, audio_stream);
            audio_send_time = send_data_to_active_clients(msg, timeout_ms, sock, true);
        }
        if (!meta_stream.empty()) {
            msg = create_msg_to_client(METADATA, meta_stream);
            meta_send_time = send_data_to_active_clients(msg, timeout_ms, sock, false);
        }
        return audio_send_time + meta_send_time;
    } else {
        if (!audio_stream.empty())
            cout << audio_stream;
        if (!meta_stream.empty())
            cerr << meta_stream;
        return 0;
    }
}

/** @brief Parses radio server response.
 * Audio data are written to stdout and metadata to stderr.
 * If data are broken in block with metadata or in header. Data are saved
 * and parsed later, where full header or block is available.
 * @param status [in,out]               - pointer to flag indicating if status
 *                                        line was parsed,
 * @param audio [in,out]                - pointer to flag indicating if content
 *                                        section started,
 * @param remaining_response [in,out]   - pointer to previously saved data,
 * @param buffer_string [in,out]        - pointer to data received from socket,
 *                                        converted to string.
 * @param audio_left [in,out]           - pointer to number of audio data which
 *                                        come before next metadata block.
 * @param sock [in]                     - socket where data should be written,
 *                                        -1 if player mode is selected.
 * @return If error occurred value @p -1. Otherwise duration of sending data
 * in milliseconds if @p sock is not -1 or 0 if @p sock is -1.
 */
static int parse_response(bool *status, bool *audio, string *remaining_response,
                          const string &buffer_string, size_t *audio_left, int sock) {
    string response;
    string::size_type pos, pos2;

    if (remaining_response->empty())
        response = buffer_string;
    else
        response = remaining_response->append(buffer_string);
    *remaining_response = "";

    if (!*status) {
        pos = response.find("\r\n");
        if (pos == string::npos) {
            // Line is broken in the middle.
            *remaining_response = response;
            return 0;
        }
        string status_line = response.substr(0, pos);
        if (!check_status_line(status_line))
            return -1;
        *status = true;
        if (pos + 2 > response.size())
            return -1; // Shouldn't occur if line is not broken.
        response = response.substr(pos + 2);
    }

    while (!*audio) {
        pos = response.find("\r\n");
        if (pos == string::npos) {
            // Line is broken in the middle.
            *remaining_response = response;
            return 0;
        }
        if (pos != 0) {
            string header_line = response.substr(0, pos);
            if (header_line.find("icy-metaint") == 0) {
                if (metadata_request) {
                    pos2 = header_line.find(':');
                    if (pos2 == string::npos)
                        return -1; // Shouldn't occur, line doesn't match pattern.
                    header_line = header_line.substr(pos2);
                    metadata_interval = extract_metadata_interval(header_line);
                    if (metadata_interval == -1)
                        return -1;
                    *audio_left = metadata_interval;
                } else {
                    cerr << "Radio server tries to add not requested metadata"
                         << endl;
                    return -1;
                }
            }

            if (header_line.find("icy-name") == 0) {
                pos2 = header_line.find(':');
                if (pos2 == string::npos)
                    return -1; // Shouldn't occur, line doesn't match pattern.
                pos2++;

                // skipping spaces between ':' and radio name
                while (pos2 < header_line.size() && header_line[pos2] == ' ')
                    pos2++;

                // saving radio name
                radio_name = header_line.substr(pos2, pos - pos2);
            }
        } else {
            *audio = true;
        }
        if (pos + 2 > response.size())
            return -1; // Shouldn't occur if line is not broken.
        response = response.substr(pos + 2);
    }

    if (metadata_interval != -1) {
        string audio_stream;
        string meta_stream;
        while (*audio_left < response.size()) {
            audio_stream.append(response.substr(0, *audio_left));
            response = response.substr(*audio_left);
            assert(!response.empty());
            unsigned metadata_block_len = ((unsigned) response[0]) * 16;
            if (response.size() < metadata_block_len + 1) {
                // Metadata block is broken in the middle.
                *remaining_response = response;
                *audio_left = 0;
                return sending_or_printing_data(audio_stream, meta_stream, sock);
            } else {
                string curr_metadata = response.substr(1, metadata_block_len);
                if (!curr_metadata.empty())
                    last_metadata_received = curr_metadata;
                meta_stream.append(curr_metadata);
                *audio_left = metadata_interval;
                response = response.substr(metadata_block_len + 1);
            }
        }

        audio_stream.append(response);
        *audio_left -= response.size();
        return sending_or_printing_data(audio_stream, meta_stream, sock);
    } else {
        return sending_or_printing_data(response, "", sock);
    }
}

/** @brief Receives, parse and write further data.
 * Terminates immediately program with exitcode 1 if critical error occurred.
 * Returns 1 if program has to finish work due to error, otherwise 0.
 * @param radio_server_sock [in]   - socket used to communicate with radio server,
 * @param radio_proxy_sock [in]    - socket used to communicate with clients,
 *                                   -1 if player mode is selected.
 * @return Value @p 1 if program has to finish work due to error, otherwise
 * value @p 0.
 */
static int receiving_response(int radio_server_sock, int radio_proxy_sock) {
    pollfd client[2];
    sockaddr_in client_addr{};
    socklen_t rcva_len;
    int ret;
    ssize_t rval;
    bool status = false, audio = false;
    string remaining_response;
    size_t audio_left = 0;
    int exitcode = 0;
    int flags = 0;
    int timeout_used = 0;

    char BUFFER[BUF_SIZE];
    char CLIENTS_BUFFER[BUF_SIZE];

    for (int i = 0; i < 2; i++) {
        client[i].fd = i == 0 ? radio_server_sock : radio_proxy_sock;
        client[i].events = POLLIN;
        client[i].revents = 0;
    }

    string request = create_radio_request();

    if (write(radio_server_sock, request.c_str(), request.size()) != (int) request.size())
        syserr("partial / failed write");

    do {
        client[0].revents = 0;
        client[1].revents = 0;

        int waiting_time = server_timeout - timeout_used;
        if (waiting_time < 0)
            waiting_time = 0;

        auto start_poll_timeout = high_resolution_clock::now();
        ret = poll(client, 2, waiting_time);
        auto end_poll_timeout = high_resolution_clock::now();

        if (ret == -1) {
            if (errno != EINTR)
                syserr("poll");
        } else if (ret > 0) {
            if (client[1].fd != -1 &&
                (client[1].revents & (POLLIN | POLLERR))) {
                rcva_len = (socklen_t) sizeof(client_addr);
                flags = 0;
                rval = recvfrom(radio_proxy_sock, CLIENTS_BUFFER, BUF_SIZE, flags,
                                (sockaddr *) &client_addr, &rcva_len);

                pair<uint32_t, uint16_t> cl_addr;

                cl_addr.first = ntohl(client_addr.sin_addr.s_addr);
                cl_addr.second = ntohs(client_addr.sin_port);

                if (rval >= 4) {
                    uint16_t msg_type_bytes;
                    uint16_t msg_len_bytes;
                    memmove(&msg_type_bytes, CLIENTS_BUFFER, 2);
                    memmove(&msg_len_bytes, CLIENTS_BUFFER + 2, 2);
                    uint16_t msg_type = ntohs(msg_type_bytes);
                    uint16_t msg_len = ntohs(msg_len_bytes);

                    if ((msg_type == DISCOVER || msg_type == KEEPALIVE) && msg_len == 0) {
                        // Updating client activity timestamp.
                        auto search = clients.find(cl_addr);
                        if (search == clients.end()) {
                            clients.insert({cl_addr, {client_addr, end_poll_timeout}});
                        } else {
                            search->second.second = end_poll_timeout;
                        }
                        if (msg_type == DISCOVER) {
                            string iam_response;
                            iam_response = create_msg_to_client(IAM, create_iam_response(radio_name,
                                                                                         last_metadata_received));
                            if (server_timeout - timeout_used >= 500) {
                                set_socket_writing_timeout(500, radio_proxy_sock);
                            } else {
                                set_socket_writing_timeout(server_timeout - timeout_used,
                                                           radio_proxy_sock);
                            }
                            auto snda_len = (socklen_t) sizeof(client_addr);
                            auto start = high_resolution_clock::now();
                            sendto(radio_proxy_sock, iam_response.c_str(), iam_response.size(), 0,
                                   (sockaddr *) &(client_addr), snda_len);
                            auto end = high_resolution_clock::now();
                            timeout_used += duration_cast<milliseconds>(end - start).count();
                        }
                    }
                    // Ignoring message of wrong type.
                }
                // Ignoring too short message or reading failure.
            }
            if (client[0].revents & (POLLIN | POLLERR)) {
                rval = read(radio_server_sock, BUFFER, BUF_SIZE);
                string buffer_string(BUFFER, rval);
                if (rval == 0) {
                    cerr << "Radio server has closed connection" << endl;
                    exitcode = 1;
                } else if (rval > 0) {
                    timeout_used += parse_response(&status, &audio, &remaining_response,
                                                   buffer_string, &audio_left, radio_proxy_sock);
                    if (timeout_used < 0)
                        exitcode = 1;
                    else
                        exitcode = 0;
                } else {
                    // read failed, reducing possible timeout.
                    timeout_used += duration_cast<milliseconds>(
                            end_poll_timeout - start_poll_timeout).count();
                }
            }
        } else {
            cerr << "Radio server timeout exceeded" << endl;
            exitcode = 1;
        }
        if (exitcode == 1)
            finish_work = true;
    } while (!finish_work);
    return exitcode;
}

/** @brief Runs radio-proxy.
 * If any error occurred which makes further work impossible and program
 * didn't terminate before, returns 1. Detailed usage is described in TODO.
 * Finishes work after SIGINT was received or error occurred.
 * @param argc [in]   - number of arguments,
 * @param argv [in]   - array of arguments.
 * @return Value @p 0 in case of success, otherwise value @p 1.
 */
int main(int argc, char *argv[]) {
    int udp_sock;

    setup();

    if (parse_args(argc, argv) != 0) {
        fatal("Usage: %s -h <host name> -r <resource name> -p <port> [-m yes|no] "
              "[-t <server_timeout>] [-P <multicast port>] [-B <multicast address>]"
              "[-T <client response server_timeout>]", argv[0]);
    }

    int sock = connect_to_server(host_name, port_num);

    if (proxy_port_num == -1)
        udp_sock = -1;
    else
        udp_sock = create_proxy_socket();

    int exitcode = receiving_response(sock, udp_sock);

    if (close(sock) < 0)
        syserr("close");
    if (udp_sock != -1) {
        if (!multicast_address.empty()) {
            if (setsockopt(udp_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                           (void *) &multicast_group, sizeof multicast_group) <0) {
                syserr("setsockopt");
            }
        }
        if (close(udp_sock) < 0)
            syserr("close");
    }

    return exitcode;
}
