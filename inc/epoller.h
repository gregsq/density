#ifndef EPOLLER_H
#define EPOLLER_H

#include <cstring>
#include <stdexcept>

#include <sys/epoll.h>

namespace density {
    class EPoller
    {
        static constexpr std::size_t s_max_epoll_events {1024};

        int32_t efd_;
        epoll_event event_;
        epoll_event* events_;

      public:
        EPoller();

        EPoller(const EPoller&) = delete;
        EPoller(EPoller&&) = delete;
        auto operator=(const EPoller&) -> EPoller& = delete;
        auto operator=(EPoller&&) -> EPoller& = delete;

        ~EPoller();

        auto init(int32_t fd) -> bool;

        // Wait on the socket
        auto wait() noexcept -> int32_t;

        auto delete_fd(int32_t fd) noexcept -> int32_t;
        auto add_fd(int32_t fd) noexcept -> int32_t;
        auto operator[](int32_t idx) -> const epoll_event&;
    };

    inline auto EPoller::operator[](int32_t idx) -> const epoll_event&
    {
        if (idx >= 0 && static_cast<std::size_t>(idx) < s_max_epoll_events)
        {
            return events_[idx];
        }
        throw std::range_error("epoll index out of range");
    }

    inline auto EPoller::wait() noexcept -> int32_t
    {
        return ::epoll_wait(efd_, events_, s_max_epoll_events, -1);
    }

    inline auto EPoller::delete_fd(int32_t fd) noexcept -> int32_t
    {
        // Unregister epoll
        return ::epoll_ctl(efd_, EPOLL_CTL_DEL, fd, nullptr);
    }

    inline auto EPoller::add_fd(int32_t fd) noexcept -> int32_t
    {
        event_.data.fd = fd;
        event_.events = EPOLLIN | EPOLLET;
        return ::epoll_ctl(efd_, EPOLL_CTL_ADD, fd, &event_);
    }

}    // namespace density

#endif
