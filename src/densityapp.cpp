#include <iostream>
#include <array>
#include <charconv>
#include <stdio.h>
#include <cstdlib>
#include <unistd.h>
#include <syslog.h>
#include <csignal>
#include <getopt.h>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/epoll.h>

#include "defs.h"

static std::string log_file_name;
static std::string pid_file_name;

static bool running {false};
static int64_t counter {0};
static int32_t pid_fd {-1};
static char* app_name {nullptr};
static FILE* log_stream;

#define MAXEVENTS 1024

static void write_log(const std::string& s)
{
    auto ret = ::fprintf(log_stream, s.c_str());
    if (ret < 0)
    {
        syslog(LOG_ERR, "Can not write to log stream: %s, error: %s",
          (log_stream == stdout) ? "stdout" : log_file_name.c_str(), strerror(errno));
    }
}

// Write message and raise SIGABORT
static NORETURN void write_log_fatal(const std::string& s)
{
    auto ret = ::fprintf(log_stream, s.c_str());
    if (ret < 0)
    {
        ::syslog(LOG_ERR, "Can not write to log stream: %s, error: %s",
          (log_stream == stdout) ? "stdout" : log_file_name.c_str(), strerror(errno));
    }
    abort();
}

static int32_t process_command(int32_t fd, const char* telstr, size_t count)
{
    switch (count)
    {
        case sizeof("xx INCR\n"):
        {
            std::string s {telstr};
            if (s[2] == ' ')
            {
                constexpr std::size_t numspace {sizeof("xx") - 1};
                constexpr std::int64_t maxcount {std::numeric_limits<int64_t>::max()};
                constexpr std::int64_t mincount {std::numeric_limits<int64_t>::min()};

                // Substring first two chars for integer
                std::string_view nums(s.c_str(), numspace);

                // Substring for the command
                std::string command(s.c_str() + numspace + 1, count - 5);

                int32_t result;
                bool err {true};

                try
                {
                    auto [p, ec] = std::from_chars(
                      nums.begin(),
                      nums.end(),
                      result);
                    if (ec == std::errc())
                    {
                        err = false;

                        std::string msg = "NUMBER = ";
                        msg += std::to_string(result);
                        msg += "\n";

                        ::write_log(msg);
                    }
                    else
                    {
                        write_log("Debug: OUT OF BOUNDS\n");
                    }
                }
                catch (const std::exception& e)
                {
                    write_log("Exception caught on conversion");
                }

                if (!err)
                {
                    if (command == "INCR")
                    {
                        // Increment
                        if (counter <= 0 || (maxcount - counter) >= result)
                        {
                            // Increase the counter
                            counter += result;
                            // Notify
                        }
                        else
                        {
                            err = true;
                        }
                    }
                    else if (command == "DECR")
                    {
                        // Decrement
                        if (counter >= 0 || (counter - mincount) >= result)
                        {
                            // Decrease the counter
                            counter -= result;
                            // Notify
                        }
                        else
                        {
                            err = true;
                        }
                    }

                    if (!err)
                    {
                        std::array<char, 120> str;
                        auto [ptr, ec] = std::to_chars(
                          str.data(),
                          str.data() + str.size(),
                          counter);

                        std::string samt;
                        samt.append(str.data(), ptr - str.data());
                        samt += "\n";
                        ::write(fd, samt.c_str(), samt.length());
                    }
                }
            }

            break;
        }

        case sizeof("xx OUTPUT\n"):
        {
            // Write counter to the fd
            write_log("SIZEOF XX OUTPUT");

            break;
        }

        default:
        {
            // Sanity check
            std::array<char, 120> str;
            auto [ptr, ec] = std::to_chars(
              str.data(),
              str.data() + str.size(),
              count);

            std::string samt = "SIZEOF XX COMMAND: ";
            samt.append(str.data(), ptr - str.data());
            samt += "\n";

            write_log(samt);
        }

        break;
    }

    auto s = ::write(1, telstr, count);
    return s;
}

static int32_t make_socket_non_blocking(int32_t sfd)
{
    int32_t ret {0};

    auto flags = ::fcntl(sfd, F_GETFL, 0);
    if (flags < 0)
    {
        ret = -1;
        write_log("Debug: fcntl F_GETFL failed");
    }
    else
    {
        flags |= O_NONBLOCK;
        auto s = ::fcntl(sfd, F_SETFL, flags);
        if (s < 0)
        {
            ret = -1;
            write_log("Debug: fcntl F_SETFL failed");
        }
    }

    return ret;
}

static int32_t create_and_bind(const std::string& port)
{
    addrinfo hints;
    addrinfo *result, *rp;
    int32_t sfd {-1};

    ::memset(&hints, 0, sizeof(addrinfo));
    hints.ai_family = AF_UNSPEC;        // Return IPv4 and IPv6 choices
    hints.ai_socktype = SOCK_STREAM;    // We want a TCP socket
    hints.ai_flags = AI_PASSIVE;        // All interfaces

    auto s = ::getaddrinfo(nullptr, port.c_str(), &hints, &result);
    if (s != 0)
    {
        fprintf(log_stream, "getaddrinfo: %s\n", gai_strerror(s));
    }
    else
    {
        for (rp = result; rp != nullptr; rp = rp->ai_next)
        {
            sfd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sfd == -1)
            {
                continue;
            }

            s = ::bind(sfd, rp->ai_addr, rp->ai_addrlen);
            if (s == 0)
            {
                // We managed to bind successfully!
                break;
            }

            ::close(sfd);
            sfd = -1;
        }

        if (rp == nullptr)
        {
            fprintf(log_stream, "Could not bind to port %s\n", port.c_str());
        }

        freeaddrinfo(result);
    }

    return sfd;
}

/// \brief Epoll till done
///
/// \param port The port number
static int do_epoll(const std::string& port)
{
    // Create and bind a tcp socket to the port
    auto sfd = create_and_bind(port);
    if (sfd == -1)
    {
        write_log_fatal("Debug: create_and_bind failed");
    }
    else
    {
        // Make the socket non blocking
        auto s = make_socket_non_blocking(sfd);
        if (s == -1)
        {
            write_log_fatal("Debug: make_socket_non_blocking failed");
        }
        else
        {
            epoll_event event;

            // Listen on the socket
            s = ::listen(sfd, SOMAXCONN);
            if (s == -1)
            {
                write_log_fatal("Debug: listen failed");
            }
            else
            {
                auto efd = ::epoll_create1(0);
                if (efd == -1)
                {
                    write_log_fatal("Debug: epoll_create failed");
                }
                else
                {
                    event.data.fd = sfd;
                    event.events = EPOLLIN | EPOLLET;
                    s = ::epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);

                    if (s == -1)
                    {
                        write_log_fatal("Debug: epoll_ctl failed");
                    }
                    else
                    {
                        // Buffer where events are returned
                        auto* events = new epoll_event[MAXEVENTS];
                        ::memset(events, 0, MAXEVENTS * sizeof(epoll_event));

                        // The event loop
                        while (running)
                        {
                            // Wait on the socket
                            int n = ::epoll_wait(efd, events, MAXEVENTS, -1);
                            for (int i = 0; i < n; ++i)
                            {
                                if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
                                {
                                    // An error has occured on this fd, or the socket is not
                                    // ready for reading (why were we notified then?)
                                    ::fprintf(log_stream, "epoll error\n");
                                    ::close(events[i].data.fd);
                                    continue;
                                }

                                else if (sfd == events[i].data.fd)
                                {
                                    // We have a notification on the listening socket, which
                                    // means one or more incoming connections.
                                    for (;;)
                                    {
                                        sockaddr in_addr;
                                        char hbuf[NI_MAXHOST];
                                        char sbuf[NI_MAXSERV];

                                        socklen_t in_len {sizeof(in_addr)};
                                        int infd = ::accept(sfd, &in_addr, &in_len);
                                        if (infd == -1)
                                        {
                                            if (errno == EAGAIN || errno == EWOULDBLOCK)
                                            {
                                                // We have processed all incoming
                                                // connections.
                                                break;
                                            }
                                            else
                                            {
                                                write_log("accept");
                                                break;
                                            }
                                        }

                                        s = ::getnameinfo(&in_addr, in_len,
                                          hbuf, sizeof(hbuf),
                                          sbuf, sizeof(sbuf),
                                          NI_NUMERICHOST | NI_NUMERICSERV);
                                        if (s == 0)
                                        {
                                            fprintf(log_stream, "Accepted connection on descriptor %d "
                                                                "(host=%s, port=%s)\n",
                                              infd, hbuf, sbuf);
                                        }

                                        // Make the incoming socket non-blocking and add it to the list of fds to monitor.
                                        s = make_socket_non_blocking(infd);
                                        if (s == -1)
                                        {
                                            write_log_fatal("Debug: make_socket_non_blocking");
                                        }

                                        event.data.fd = infd;
                                        event.events = EPOLLIN | EPOLLET;
                                        s = ::epoll_ctl(efd, EPOLL_CTL_ADD, infd, &event);
                                        if (s == -1)
                                        {
                                            write_log_fatal("Debug: epoll_ctl");
                                        }
                                    }
                                    continue;
                                }
                                else
                                {
                                    bool done {false};

                                    while (running)
                                    {
                                        ssize_t count;
                                        char buf[512];

                                        // Read from the fd
                                        count = ::read(events[i].data.fd, buf, sizeof(buf));
                                        if (count == -1)
                                        {
                                            // If errno == EAGAIN, that means we have read all
                                            // data. So go back to the main loop.
                                            if (errno != EAGAIN)
                                            {
                                                write_log("Debug: read");
                                                done = true;
                                            }
                                            // And break
                                            break;
                                        }

                                        if (count == 0)
                                        {
                                            // The remote has closed the connection.
                                            done = true;
                                            break;
                                        }

                                        // Process data
                                        s = process_command(events[i].data.fd, buf, count);

                                        if (s == -1)
                                        {
                                            write_log_fatal("Debug: write");
                                        }
                                    }

                                    if (done)
                                    {
                                        std::cout << "Closed connection on descriptor " << events[i].data.fd << std::endl;

                                        // Closing the descriptor will make epoll remove it
                                        // from the set of descriptors which are monitored.
                                        ::close(events[i].data.fd);
                                    }
                                }
                            }
                        }

                        delete[] events;
                    }
                }
            }
        }

        ::close(sfd);
    }

    return EXIT_SUCCESS;
}

/**
 * \brief This function will daemonize this app
 */
static void daemonize()
{
    int fd;

    // Fork off the parent process
    pid_t pid = fork();

    // An error occurred
    if (pid < 0)
    {
        exit(EXIT_FAILURE);
    }

    // Success: Let the parent terminate
    else if (pid > 0)
    {
        exit(EXIT_SUCCESS);
    }

    // On success: The child process becomes session leader
    else if (setsid() < 0)
    {
        exit(EXIT_FAILURE);
    }

    // Ignore signal sent from child to parent process
    signal(SIGCHLD, SIG_IGN);

    // Fork off for the second time
    pid = fork();

    // An error occurred
    if (pid < 0)
    {
        exit(EXIT_FAILURE);
    }

    // Success: Let the parent terminate
    else if (pid > 0)
    {
        exit(EXIT_SUCCESS);
    }

    // Set new file permissions
    ::umask(0);

    // Change the working directory to the root directory
    // or another appropriated directory
    ::chdir("/");

    // Close all open file descriptors
    for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--)
    {
        ::close(fd);
    }

    // Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2)
    stdin = ::fopen("/dev/null", "r");
    stdout = ::fopen("/dev/null", "w+");
    stderr = ::fopen("/dev/null", "w+");

    // Try to write PID of daemon to lockfile
    if (!pid_file_name.empty())
    {
        pid_fd = ::open(pid_file_name.c_str(), O_RDWR | O_CREAT, 0640);
        if (pid_fd < 0 || ::lockf(pid_fd, F_TLOCK, 0) < 0)
        {
            // Can't open lockfile
            exit(EXIT_FAILURE);
        }

        // Get current PID
        std::array<char, 10> pidstr;
        auto [ptr, ec] = std::to_chars(pidstr.data(), pidstr.data() + pidstr.size(), getpid());

        if (ec == std::errc())
        {
            // Can't open lockfile
            exit(EXIT_FAILURE);
        }

        // Write PID to lockfile
        ::write(pid_fd, pidstr.data(), ptr - pidstr.data());
    }
}

/**
 * \brief Print help for this application
 */
static const char* help_text = R"stop(
densityapp:
Options are:

    -h --help                 Print this help
    -l --log_file  filename   Write logs to the file
    -i --interface port      Port number
    -d --daemon               Daemonize this application
    -p --pid_file  filename   PID file used by daemonized app
)stop";

void print_help()
{
    std::cout << help_text << std::endl;
}

/**
 * \brief Callback function for handling signals.
 * \param	sig	identifier of signal
 */
static void s_signal_handler(int sig)
{
    if (sig == SIGINT)
    {
        fprintf(log_stream, "Debug: stopping daemon ...\n");

        // Unlock and close lockfile
        if (pid_fd != -1)
        {
            ::lockf(pid_fd, F_ULOCK, 0);
            ::close(pid_fd);
        }
        // Try to delete lockfile
        if (!pid_file_name.empty())
        {
            ::unlink(pid_file_name.c_str());
        }

        running = false;

        // Reset signal handling to default behavior
        ::signal(SIGINT, SIG_DFL);
    }
    else if (sig == SIGHUP)
    {
        ::fprintf(log_stream, "Debug: reloading daemon config file ...\n");
    }
    else if (sig == SIGCHLD)
    {
        ::fprintf(log_stream, "Debug: received SIGCHLD signal\n");
    }
}

static void s_catch_signals()
{
    struct sigaction action;
    action.sa_handler = s_signal_handler;
    action.sa_flags = 0;
    ::sigemptyset(&action.sa_mask);
    ::sigaction(SIGINT, &action, nullptr);
    ::sigaction(SIGTERM, &action, nullptr);
}

int main(int argc, char* const* argv)
{
    // Default port number
    std::string port {"8089"};

    const option long_opts[] = {
      {"log_file", required_argument, nullptr, 'l'},
      {"interface", required_argument, nullptr, 'i'},
      {"help", no_argument, nullptr, 'h'},
      {"daemon", no_argument, nullptr, 'd'},
      {"pid_file", required_argument, nullptr, 'p'},
      {nullptr, no_argument, nullptr, 0}};

    bool start_daemonized {false};

    app_name = argv[0];

    // Try to process all command line arguments
    const char* const short_opts {"i:l:p:dh"};

    while (true)
    {
        const auto opt = ::getopt_long(argc, argv, short_opts, long_opts, nullptr);

        if (-1 == opt)
            break;
        switch (opt)
        {
            case 'l':
                log_file_name = optarg;
                break;
            case 'p':
                pid_file_name = optarg;
                break;
            case 'i':
                // Override port
                port = optarg;
                break;
            case 'd':
                // Run as a daemon
                start_daemonized = true;
                break;
            case 'h':
            case '?':
            default:
                print_help();
                return EXIT_SUCCESS;
        }
    }

    if (start_daemonized)
    {
        daemonize();
    }

    // This global variable can be changed in function handling signal
    running = true;

    // Install a signal handler
    s_catch_signals();

    // Open system log and write message to it
    openlog(argv[0], LOG_PID | LOG_CONS, LOG_DAEMON);

    ::syslog(LOG_INFO, "Started %s", app_name);

    // Try to open log file to this daemon
    if (!log_file_name.empty())
    {
        log_stream = ::fopen(log_file_name.c_str(), "a+");
        if (log_stream == nullptr)
        {
            ::syslog(LOG_ERR, "Can not open log file: %s, error: %s",
              log_file_name.c_str(), strerror(errno));
            log_stream = stdout;
        }
    }
    else
    {
        log_stream = stdout;
    }

    auto retcode = do_epoll(port);

    // Close log file, when it is used.
    if (log_stream != stdout)
    {
        ::fclose(log_stream);
    }

    // Write system log and close it.
    ::syslog(LOG_INFO, "Stopped %s", app_name);
    ::closelog();

    return retcode;
}
