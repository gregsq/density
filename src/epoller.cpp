#include "epoller.h"

#include <unistd.h>
#include <syslog.h>
#include <csignal>
#include <getopt.h>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace density {
    EPoller::EPoller()
        : efd_(-1)
        , events_(nullptr)
    {
    }

    EPoller::~EPoller()
    {
        if (efd_ >= 0)
        {
            ::close(efd_);
        }

        delete [] events_;
    }

    auto EPoller::init(int32_t fd) -> bool
    {
        bool ret {false};

        efd_ = ::epoll_create1(0);
        if (efd_ >= 0)
        {
            event_.data.fd = fd;
            event_.events = EPOLLIN | EPOLLET;

            auto s = ::epoll_ctl(efd_, EPOLL_CTL_ADD, fd, &event_);

            if (s != -1)
            {
                // Buffer where events are returned
                events_ = new epoll_event[s_max_epoll_events];
                ::memset(events_, 0, s_max_epoll_events * sizeof(epoll_event));
                ret = true;
            }
        }

        return ret;
    }

}    // namespace density
