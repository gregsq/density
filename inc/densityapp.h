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
        std::string port_ {"8089"};

        // The app name from argv
        std::string appname_;

        std::string log_file_name_;
        std::vector<int32_t> allfds_;
        int64_t counter_ {0};
        bool helpmode_ {false};
        int32_t sfd_ {-1};
        int32_t efd_ {-1};

        static std::string s_pid_file_name_;
        static bool s_running_;
        static int32_t s_pid_fd_;
        static FILE* s_log_stream_;

        auto write_log(const std::string& s) noexcept -> void;
        auto close_log() noexcept -> void;

        // Write an error and exit
        auto write_log_fatal(const std::string& s) -> void;

        auto remove_fd(int32_t fd) noexcept -> void;

        auto process_command(
          int32_t fd,
          const char* telstr,
          std::size_t count) -> int32_t;

        auto set_socket_non_blocking(int32_t) noexcept -> bool;
        auto create_and_bind() noexcept -> int32_t;
        auto do_epoll() -> bool;

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
        ~DensityApp();

        auto operator=(const DensityApp&) -> DensityApp& = delete;
        auto operator=(DensityApp&&) -> DensityApp& = delete;

        auto run() -> int32_t;
    };
}    // namespace density

#endif
