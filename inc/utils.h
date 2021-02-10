#ifndef DENS_UTILS_H
#define DENS_UTILS_H

namespace density {

    template<typename container>
    size_t split(const std::string& str, container& cont, char delim = ' ')
    {
        size_t cnt {0};
        size_t previous {0};
        size_t current = str.find(delim);
        while (current != std::string::npos)
        {
            cnt++;
            cont.push_back(str.substr(previous, current - previous));
            previous = current + 1;
            current = str.find(delim, previous);
        }

        cont.push_back(str.substr(previous, current - previous));
        return ++cnt;
    }

}    // namespace density
#endif
