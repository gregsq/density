#ifndef DENSITY_APP_H
#define DENSITY_APP_H

#include <string>
#include <vector>

namespace density {
    constexpr std::size_t s_max_events {1024};

    // All packaged into a class
    class DensityApp
    {
        // Default port number
        std::string port {"8089"};

        // The app name from argv
        std::string appname;

        std::string log_file_name;
        std::vector<int32_t> allfds;
        int64_t counter {0};

        static std::string pid_file_name;
        static bool running;
        static int32_t pid_fd;
        static FILE* log_stream;

        auto write_log(const std::string& s) -> void;

        NORETURN auto write_log_fatal(const std::string& s) -> void;

        auto remove_fd(int32_t fd) -> void;

        auto process_command(
          int32_t fd,
          const char* telstr,
          std::size_t count) -> int32_t;

        auto make_socket_non_blocking(int32_t sfd) -> int32_t;
        auto create_and_bind() -> int32_t;
        auto do_epoll() -> int32_t;

        // Run daemonized
        auto daemonize() -> void;

        auto print_help() -> void;

        /// \brief Callback function for handling signals.
        /// \param	sig	identifier of signal
        static auto s_signal_handler(int sig) -> void;
        static auto s_catch_signals() -> void;

      public:
        // Only CTOR allowed
        DensityApp(int argc, char* const* argv);

        DensityApp() = delete;
        DensityApp(const DensityApp&) = delete;
        DensityApp(DensityApp&&) = delete;
        ~DensityApp() = default;

        auto operator=(const DensityApp&) -> DensityApp& = delete;
        auto operator=(DensityApp&&) -> DensityApp& = delete;

        auto run() -> int32_t;
    };
}    // namespace density

#endif
