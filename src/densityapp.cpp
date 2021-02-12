#include <iostream>
#include <array>
#include <vector>
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
#include "utils.h"
#include "densityapp.h"

/// \brief Print help for this application
static const char* help_text = R"stop(
densityapp:
Options are:

    -h --help                 Print this help
    -l --log_file  filename   Write logs to the file
    -i --interface port      Port number
    -d --daemon               Daemonize this application
    -p --pid_file  filename   PID file used by daemonized app
)stop";

namespace density {

    FILE* DensityApp::s_log_stream_ {nullptr};
    int32_t DensityApp::s_pid_fd_ {-1};
    std::string DensityApp::s_pid_file_name_;
    bool DensityApp::s_running_ {false};

    auto DensityApp::write_log(const std::string& s) noexcept -> void
    {
        auto ret = ::fprintf(s_log_stream_, s.c_str());
        if (ret < 0)
        {
            syslog(LOG_ERR, "Can not write to log stream: %s, error: %s",
              (s_log_stream_ == stdout) ? "stdout" : log_file_name_.c_str(), strerror(errno));
        }
    }

    // Write message and raise SIGABORT
    auto DensityApp::write_log_fatal(const std::string& s) -> void
    {
        std::string err(s);
        err += "\n";

        write_log(err);
        // Raise an error
        throw std::logic_error(s);
    }

    /// \brief
    ///
    /// Remove an fd from the attached record
    auto DensityApp::remove_fd(int32_t fd) noexcept -> void
    {
        for (auto it = allfds_.begin(); it != allfds_.end(); ++it)
        {
            if (*it == fd)
            {
                allfds_.erase(it);
                break;
            }
        }
    }

    auto DensityApp::process_command(
      int32_t fd,
      const char* telstr,
      std::size_t count) -> int32_t
    {
        const char* end = telstr + count;
        while (end > telstr && (*end == '\r' || *end == '\n' || *end == 0))
        {
            end--;
        }

        if (end >= telstr)
        {
            std::string base(telstr, (end - telstr) + 1);

            // Split string into here
            std::vector<std::string> splits;
            auto components = density::split(base, splits);
            std::string reply;

            switch (components)
            {
                case 2:
                {
                    constexpr std::int64_t maxcount {std::numeric_limits<int64_t>::max()};
                    constexpr std::int64_t mincount {std::numeric_limits<int64_t>::min()};

                    // Substring first two chars for integer
                    const std::string& nums {splits[1]};

                    // Substring for the command
                    const std::string& command {splits[0]};

                    int64_t result {0};
                    auto success = density::from_chars(
                      nums.c_str(),
                      nums.c_str() + nums.length(),
                      result);
                    if (!success)
                    {
                        write_log("Debug: OUT OF BOUNDS\n");
                    }
                    else
                    {
                        if (command == "INCR")
                        {
                            // Increment
                            if (counter_ <= 0 || (maxcount - counter_) >= result)
                            {
                                // Increase the counter
                                counter_ += result;
                                // Notify
                            }
                            else
                            {
                                success = false;
                            }
                        }
                        else if (command == "DECR")
                        {
                            // Decrement
                            if (counter_ >= 0 || (counter_ - mincount) >= result)
                            {
                                // Decrease the counter
                                counter_ -= result;
                                // Notify
                            }
                            else
                            {
                                success = false;
                            }
                        }

                        if (success)
                        {
                            if (density::to_chars(reply, counter_))
                            {
                                reply += "\n";
                                // Write to the connection that sent it
                                ::write(fd, reply.c_str(), reply.length());

                                // Write to all connections
                                for (auto f : allfds_)
                                {
                                    if (f != fd)
                                    {
                                        // Tell other connections
                                        ::write(f, reply.c_str(), reply.length());
                                    }
                                }
                            }
                        }
                    }

                    break;
                }

                case 1:
                {
                    if (splits[0] == "OUTPUT")
                    {
                        if (density::to_chars(reply, counter_))
                        {
                            reply += "\n";
                            ::write(fd, reply.c_str(), reply.length());
                        }
                    }
                }
                break;

                default:
                {
                    reply = "RECIEVED UNKNOWN COMMAND";
                    write_log(reply);
                }

                break;
            }
        }

        return count;
    }

    auto DensityApp::make_socket_non_blocking(int32_t sock) noexcept -> bool
    {
        bool ret {true};

        auto flags = ::fcntl(sock, F_GETFL, 0);
        if (flags < 0)
        {
            ret = false;
            write_log("Debug: fcntl F_GETFL failed");
        }
        else
        {
            flags |= O_NONBLOCK;
            auto s = ::fcntl(sock, F_SETFL, flags);
            if (s < 0)
            {
                ret = false;
                write_log("Debug: fcntl F_SETFL failed");
            }
        }

        return ret;
    }

    auto DensityApp::create_and_bind() noexcept -> int32_t
    {
        addrinfo hints;
        addrinfo *result, *rp;
        int32_t sfd {-1};

        ::memset(&hints, 0, sizeof(addrinfo));
        hints.ai_family = AF_UNSPEC;        // Return IPv4 and IPv6 choices
        hints.ai_socktype = SOCK_STREAM;    // We want a TCP socket
        hints.ai_flags = AI_PASSIVE;        // All interfaces

        auto s = ::getaddrinfo(nullptr, port_.c_str(), &hints, &result);
        if (s != 0)
        {
            ::fprintf(s_log_stream_, "getaddrinfo: %s\n", gai_strerror(s));
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
                    // No bound to the port!
                    break;
                }

                ::close(sfd);
                sfd = -1;
            }

            if (rp == nullptr)
            {
                ::fprintf(s_log_stream_, "Could not bind to port %s\n", port_.c_str());
            }

            freeaddrinfo(result);
        }

        return sfd;
    }

    /// \brief Epoll till done
    ///
    /// \return success or fail
    auto DensityApp::do_epoll() -> bool
    {
        // Create and bind a tcp socket to the port
        sfd_ = create_and_bind();
        if (sfd_ == -1)
        {
            write_log_fatal("Debug: create_and_bind failed");
        }
        else
        {
            // Make the socket non blocking
            if (!make_socket_non_blocking(sfd_))
            {
                write_log_fatal("Debug: make_socket_non_blocking failed");
            }
            else
            {
                epoll_event event;

                // Listen on the socket
                auto s = ::listen(sfd_, SOMAXCONN);
                if (s == -1)
                {
                    write_log_fatal("Debug: listen failed");
                }
                else
                {
                    efd_ = ::epoll_create1(0);
                    if (efd_ == -1)
                    {
                        write_log_fatal("Debug: epoll_create failed");
                    }
                    else
                    {
                        event.data.fd = sfd_;
                        event.events = EPOLLIN | EPOLLET;

                        s = ::epoll_ctl(efd_, EPOLL_CTL_ADD, sfd_, &event);

                        if (s == -1)
                        {
                            write_log_fatal("Debug: epoll_ctl failed");
                        }
                        else
                        {
                            // Buffer where events are returned
                            auto* events = new epoll_event[s_max_events];
                            ::memset(events, 0, s_max_events * sizeof(epoll_event));

                            // The event loop
                            // Watch for signals
                            while (s_running_)
                            {
                                // Wait on the socket
                                int n = ::epoll_wait(efd_, events, s_max_events, -1);

                                for (int i = 0; i < n; ++i)
                                {
                                    auto thefd = events[i].data.fd;

                                    // Check for errors
                                    if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
                                    {
                                        ::fprintf(s_log_stream_, "epoll error for fd %d\n", thefd);

                                        // Remove the fd
                                        remove_fd(thefd);

                                        // Unregister epoll
                                        s = ::epoll_ctl(efd_, EPOLL_CTL_DEL, thefd, nullptr);

                                        if (s == -1)
                                        {
                                            write_log_fatal("Debug: epoll_ctl");
                                        }
                                        ::close(thefd);
                                    }
                                    else if (sfd_ == thefd)
                                    {
                                        // Event(s) on the main port
                                        sockaddr in_addr;
                                        socklen_t in_len {sizeof(in_addr)};
                                        char hbuf[NI_MAXHOST];
                                        char sbuf[NI_MAXSERV];

                                        for (;;)
                                        {
                                            int infd = ::accept(sfd_, &in_addr, &in_len);
                                            if (infd == -1)
                                            {
                                                if (errno == EAGAIN || errno == EWOULDBLOCK)
                                                {
                                                    // Poll again
                                                    break;
                                                }
                                                else
                                                {
                                                    write_log("Debug: accepted all connections\n");
                                                    break;
                                                }
                                            }

                                            s = ::getnameinfo(&in_addr, in_len,
                                              hbuf, sizeof(hbuf),
                                              sbuf, sizeof(sbuf),
                                              NI_NUMERICHOST | NI_NUMERICSERV);
                                            if (s == 0)
                                            {
                                                ::fprintf(s_log_stream_, "Accepted connection on descriptor %d "
                                                                         "(host=%s, port=%s)\n",
                                                  infd, hbuf, sbuf);
                                            }

                                            // Make the incoming socket non-blocking and add it to the list of fds to monitor.
                                            if (!make_socket_non_blocking(infd))
                                            {
                                                write_log_fatal("Debug: make_socket_non_blocking failed\n");
                                            }

                                            event.data.fd = infd;
                                            event.events = EPOLLIN | EPOLLET;
                                            s = ::epoll_ctl(efd_, EPOLL_CTL_ADD, infd, &event);

                                            if (s == -1)
                                            {
                                                write_log_fatal("Debug: epoll_ctl failed to add file handle");
                                            }
                                            else
                                            {
                                                // Monitor this fd
                                                allfds_.push_back(infd);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        bool done {false};

                                        while (s_running_)
                                        {
                                            ssize_t count;
                                            char buf[512];
                                            ::memset(buf, 0, sizeof(buf));

                                            // Read from the fd
                                            count = ::read(events[i].data.fd, buf, sizeof(buf));
                                            if (count == -1)
                                            {
                                                // If errno == EAGAIN, that means we have read all data. Keep going
                                                done = errno != EAGAIN;
                                                // And break from while loop
                                                break;
                                            }
                                            if (count == 0)
                                            {
                                                // The remote has closed the connection or no data
                                                done = true;
                                                break;
                                            }

                                            // Process data from this source
                                            s = process_command(events[i].data.fd, buf, count);

                                            if (s == -1)
                                            {
                                                write_log_fatal("Debug: write");
                                            }
                                        }

                                        if (done)
                                        {
                                            std::cout << "Closed connection on descriptor " << events[i].data.fd << std::endl;

                                            // Closing the descriptor will make epoll remove it from the set of descriptors which are monitored.
                                            remove_fd(events[i].data.fd);
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

            ::close(sfd_);
            sfd_ = -1;
        }

        return true;
    }

    /// \brief This function will daemonize this app
    auto DensityApp::daemonize() -> void
    {
        int fd;

        // Fork off the parent process
        pid_t pid = ::fork();

        // Success: Let the parent terminate
        if (pid > 0)
        {
            exit(EXIT_SUCCESS);
        }
        else if (pid < 0 || setsid() < 0)
        {
            // An error occurred
            if (pid < 0)
            {
                write_log_fatal("pid < 0");
            }
            else
            {
                write_log_fatal("setsid() < 0");
            }
        }
        // On success: The child process becomes session leader
        else
        {
            // Ignore signal sent from child to parent process
            ::signal(SIGCHLD, SIG_IGN);

            // Fork off for the second time
            pid = ::fork();

            // An error occurred
            if (pid < 0)
            {
                write_log_fatal("Daemonize: pid < 0");
            }

            // Success: Let the parent terminate
            else if (pid > 0)
            {
                ::exit(EXIT_SUCCESS);
            }
            else
            {
                // Set new file permissions
                ::umask(0);

                // Change the working directory to the root directory
                // or another appropriated directory
                ::chdir("/");

                // Close all open file descriptors
                for (fd = ::sysconf(_SC_OPEN_MAX); fd > 0; fd--)
                {
                    ::close(fd);
                }

                // Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2)
                stdin = ::fopen("/dev/null", "r");
                stdout = ::fopen("/dev/null", "w+");
                stderr = ::fopen("/dev/null", "w+");

                // Try to write PID of daemon to lockfile
                if (!s_pid_file_name_.empty())
                {
                    s_pid_fd_ = ::open(s_pid_file_name_.c_str(), O_RDWR | O_CREAT, 0640);
                    if (s_pid_fd_ < 0 || ::lockf(s_pid_fd_, F_TLOCK, 0) < 0)
                    {
                        // Can't open lockfile
                        write_log_fatal("Daemonize: Unable to opn pid file");
                    }

                    std::string asstring;
                    if (!density::to_chars(asstring, getpid()))
                    {
                        // Should never happen
                        write_log_fatal("Daemonize: to_chars failed");
                    }

                    // Write PID to lockfile
                    ::write(s_pid_fd_, asstring.c_str(), asstring.length());
                }
            }
        }
    }

    auto DensityApp::print_help() -> void
    {
        std::cout << help_text << std::endl;
    }

    /// \brief Callback function for handling signals.
    /// \param	sig	identifier of signal
    auto DensityApp::s_signal_handler(int sig) -> void
    {
        if (sig == SIGINT || sig == SIGTERM)
        {
            ::fprintf(s_log_stream_, "Debug: stopping daemon ...\n");

            // Unlock and close lockfile
            if (s_pid_fd_ != -1)
            {
                ::lockf(s_pid_fd_, F_ULOCK, 0);
                ::close(s_pid_fd_);
            }
            // Try to delete lockfile
            if (!s_pid_file_name_.empty())
            {
                ::unlink(s_pid_file_name_.c_str());
                s_pid_file_name_ = "";
            }

            s_running_ = false;

            // Reset signal handling to default behavior
            ::signal(SIGINT, SIG_DFL);
        }
        else if (sig == SIGHUP)
        {
            ::fprintf(s_log_stream_, "Debug: received SIGHUP signal\n");
        }
        else if (sig == SIGCHLD)
        {
            ::fprintf(s_log_stream_, "Debug: received SIGCHLD signal\n");
        }
    }

    /// \brief Set up signal handling
    auto DensityApp::s_catch_signals() -> void
    {
        struct sigaction action;

        action.sa_handler = s_signal_handler;
        action.sa_flags = 0;

        ::sigemptyset(&action.sa_mask);
        ::sigaction(SIGINT, &action, nullptr);
        ::sigaction(SIGTERM, &action, nullptr);
        ::sigaction(SIGHUP, &action, nullptr);
        ::sigaction(SIGCHLD, &action, nullptr);
    }

    DensityApp::DensityApp(int argc, char* const* argv)
        : port_("8089")
        , appname_(argv[0])
        , counter_(0)
        , helpmode_(false)
    {
        const option long_opts[] = {
          {"log_file", required_argument, nullptr, 'l'},
          {"interface", required_argument, nullptr, 'i'},
          {"help", no_argument, nullptr, 'h'},
          {"daemon", no_argument, nullptr, 'd'},
          {"pid_file", required_argument, nullptr, 'p'},
          {nullptr, no_argument, nullptr, 0}};

        bool start_daemonized {false};

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
                    log_file_name_ = optarg;
                    break;
                case 'p':
                    s_pid_file_name_ = optarg;
                    break;
                case 'i':
                    // Override port
                    port_ = optarg;
                    break;
                case 'd':
                    // Run as a daemon
                    start_daemonized = true;
                    break;
                case 'h':
                case '?':
                default:
                    helpmode_ = true;
                    // Print help and
                    print_help();
            }
        }

        if (!helpmode_)
        {
            if (start_daemonized)
            {
                daemonize();
            }

            // This static variable can be changed in function handling signal
            s_running_ = true;

            // Install the signal handler
            s_catch_signals();

            try
            {
                // Open system log and write message to it
                openlog(argv[0], LOG_PID | LOG_CONS, LOG_DAEMON);

                ::syslog(LOG_INFO, "Started %s", argv[0]);

                // Try to open log file
                if (!log_file_name_.empty())
                {
                    s_log_stream_ = ::fopen(log_file_name_.c_str(), "a+");
                    if (s_log_stream_ == nullptr)
                    {
                        ::syslog(LOG_ERR, "Can not open log file: %s, error: %s",
                          log_file_name_.c_str(), ::strerror(errno));
                        s_log_stream_ = stdout;
                    }
                }
                else
                {
                    // Backup to stdout
                    // When a daemon this will be /dev/null
                    s_log_stream_ = stdout;
                }
            }
            catch (const std::exception& e)
            {
                std::cout << "Caught exception " << e.what() << std::endl;
            }
        }
    }

    DensityApp::~DensityApp()
    {
        if (efd_ >= 0)
        {
            ::close(efd_);
        }
        if (sfd_ >= 0)
        {
            ::close(sfd_);
        }
    }

    auto DensityApp::close_log() noexcept -> void
    {
        // Close log file, when it is used.
        if (s_log_stream_ != stdout)
        {
            ::fclose(s_log_stream_);
        }

        // Write system log and close it.
        ::syslog(LOG_INFO, "Stopped %s", appname_.c_str());
        ::closelog();
    }

    // Run in main try block
    auto DensityApp::run() -> int32_t
    {
        int32_t retcode {0};
        if (!helpmode_)
        {
            try
            {
                retcode = do_epoll();
                close_log();
            }
            catch (const std::exception& e)
            {
                close_log();
                throw;
            }
        }

        return retcode;
    }

}    // namespace density

auto main(int argc, char* const* argv) -> int
{
    int32_t ret {EXIT_SUCCESS};

    try
    {
        density::DensityApp app(argc, argv);
        ret = app.run() ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        ret = EXIT_FAILURE;
    }

    return ret;
}
