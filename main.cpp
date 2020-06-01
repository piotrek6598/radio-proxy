#include <iostream>
#include <unordered_map>
#include <cstring>
#include <climits>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <csignal>
#include <cassert>
#include <poll.h>

extern "C" {
#include "err.h"
}

using namespace std;

/**
 * Constant defining biggest possible port number.
 */
#define MAX_PORT_NUM 65535

/**
 * Constant defining buffer size used by read function.
 */
#define BUF_SIZE 8192
/**
 * Macro defining value of @ref metadata_interval when metadata aren't being sent.
 */
#define NO_METADATA -1


/**
 * Maps where keys are like '-P', '-h' and represent possible program arguments.
 * Values represent number of argument occurrences in program argument list.
 */
unordered_map<string, int> req_args;
unordered_map<string, int> opt_args;
unordered_map<string, int> intermediary_opt_args;

// Arguments defining details of connection to radio server.
string host_name;
string resource_name;
int port_num;
bool metadata_request = false;
int server_timeout = 5;

// Arguments defining details of connection to clients in intermediary mode.
int intermediary_port_num = -1;
string multicast_address;
int client_timeout = 5;

// Variable defining when program should finish work.
static bool finish_work = false;

// Size of audio block between two metadata blocks.
int metadata_interval = NO_METADATA;

/** @brieff Signal handler.
 * Marks that program should finish work.
 * @param signal [in]   - signal number (unused).
 */
static void catch_int(int signal) {
    finish_work = true;
}

/**
 * Initiates global variables and sets signal handler.
 */
static void setup() {
    struct sigaction action{};
    sigset_t block_mask;
    req_args.insert({"-h", 0});
    req_args.insert({"-r", 0});
    req_args.insert({"-p", 0});
    opt_args.insert({"-m", 0});
    opt_args.insert({"-t", 0});
    intermediary_opt_args.insert({"-B", 0});
    intermediary_opt_args.insert({"-T", 0});

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
 * @param argv [in]   = array of arguments.
 * @return Value @p 0 if arguments are correct or -1 if they are wrong.
 */
static int parse_args(int argc, char *argv[]) {
    if (argc < 7 || argc % 2 == 0)
        return -1;

    for (int i = 1; i < argc; i += 2) {
        auto search = req_args.find(argv[i]);
        if (search == req_args.end()) {
            search = opt_args.find(argv[i]);
            if (search == opt_args.end()) {
                search = intermediary_opt_args.find(argv[i]);
                if (search == intermediary_opt_args.end()) {
                    // This should be intermediary required argument.
                    if (strcmp("-P", argv[i]) == 0) {
                        int p = parse_string_to_number(argv[i + 1]);
                        if (p == -1 || p > MAX_PORT_NUM)
                            return -1;
                        intermediary_port_num = p;
                    } else {
                        // Invalid argument.
                        return -1;
                    }
                } else {
                    // This is intermediary optional argument.
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
    for (auto &mandatory_arg : req_args) {
        if (mandatory_arg.second != 1)
            return -1;
    }

    // Checks if all optional arguments appeared at most ones.
    for (auto &optional_arg : opt_args) {
        if (optional_arg.second > 1 || optional_arg.second < 0)
            return -1;
    }

    for (auto &intermediary_opt_arg : intermediary_opt_args) {
        if (intermediary_opt_arg.second > 1 || intermediary_opt_arg.second < 0)
            return -1;
    }

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

    err = getaddrinfo(server.c_str(), to_string(port).c_str(), &addr_hints,
                      &addr_result);
    if (err == EAI_SYSTEM) {
        syserr("getaddrinfo: %s", gai_strerror(err));
    } else if (err != 0) {
        fatal("getaddrinfo %s", gai_strerror(err));
    }

    sock = socket(addr_result->ai_family, addr_result->ai_socktype,
                  addr_result->ai_protocol);
    if (sock < 0)
        syserr("socket");

    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) < 0)
        syserr("connect");

    freeaddrinfo(addr_result);
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
 * @return Value @p 0 in case of success, value @p -1 if any error occurred.
 */
static int parse_response(bool *status, bool *audio, string *remaining_response,
                          const string &buffer_string, int *audio_left) {
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
        cerr << status_line << endl;
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
                    cerr << "Radio server tries to add not requested metadata" << endl;
                    return -1;
                }
            }
        } else {
            *audio = true;
        }
        if (pos + 2 > response.size())
            return -1; // Shouldn't occur if line is not broken.
        response = response.substr(pos + 2);
    }

    if (metadata_interval != -1) {
        while (*audio_left < response.size()) {
            cout << response.substr(0, *audio_left);
            response = response.substr(*audio_left);
            assert(response.size() > 0);
            int metadata_block_len = ((int) response[0]) * 16;
            if (response.size() < metadata_block_len + 1) {
                // Metadata block is broken in the middle.
                *remaining_response = response;
                *audio_left = 0;
                return 0;
            } else {
                cerr << response.substr(1, metadata_block_len);
                *audio_left = metadata_interval;
                response = response.substr(metadata_block_len + 1);
            }
        }

        cout << response;
        *audio_left -= response.size();
    } else {
        cout << response;
    }

    return 0;
}

/** @brief Receives, parse and write further data.
 * Terminates immediately program with exitcode 1 if critical error occurred.
 * Returns 1 if program has to finish work due to error, otherwise 0.
 * @param sock [in]   - sock descriptor from which data are read.
 * @return Value @p 1 if program has to finish work due to error, otherwise
 * value @p 0.
 */
static int receiving_response(int sock) {
    pollfd client[1];
    int ret;
    ssize_t rval;
    bool status = false, audio = false;
    string remaining_response;
    int audio_left = 0;
    int exitcode = 0;

    char BUFFER[BUF_SIZE];

    client[0].fd = sock;
    client[0].events = POLLIN;
    client[0].revents = 0;

    string request = create_radio_request();

    if (write(sock, request.c_str(), request.size()) != request.size())
        syserr("partial / failed write");


    do {
        client[0].revents = 0;

        ret = poll(client, 1, 1000 * server_timeout);
        if (ret == -1) {
            if (errno != EINTR)
                syserr("poll");
        } else if (ret > 0) {
            if (client[0].revents & (POLLIN | POLLERR)) {
                rval = read(sock, BUFFER, BUF_SIZE);
                string buffer_string(BUFFER, rval);
                if (rval == 0) {
                    cerr << "Radio server has closed connection" << endl;
                    exitcode = 1;
                } else if (rval > 0) {
                    exitcode = parse_response(&status, &audio,
                                              &remaining_response,
                                              buffer_string, &audio_left);
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

int main(int argc, char *argv[]) {
    setup();
    if (parse_args(argc, argv) != 0) {
        fatal("Usage: %s -h <host name> -r <resource name> -p <port> [-m yes|no] "
              "[-t <server_timeout>] [-P <multicast port>] [-B <multicast address>]"
              "[-T <client response server_timeout>]", argv[0]);
    }
    int sock = connect_to_server(host_name, port_num);
    int exitcode = receiving_response(sock);
    if (close(sock) < 0)
        syserr("close");
    return exitcode;
}
