#ifndef DENS_UTILS_H
#define DENS_UTILS_H

#include <iostream>
#include <array>
#include <algorithm>
#include <charconv>
#include <cstdint>
#include <string>

namespace density {

    template<typename container>
    auto split(const std::string& str, container& cont, char delim = ' ') -> std::size_t
    {
        cont.clear();
		if (str.length())
        {
            std::size_t previous {0};
            std::size_t current = str.find(delim, previous);
            while (current != std::string::npos)
            {
				if (current != previous)
				{
                    cont.push_back(str.substr(previous, current - previous));
                }

				// Move to next
                previous = current + 1;
                current = str.find(delim, previous);
            }

			// Push back left over
            cont.push_back(str.substr(previous));
        }
		
        return cont.size();
    }

	/// \brief
	///
	/// Use std::from_chars with type
	///
	/// \param base - the start of the substring
	/// \param end - the end of the substring
	/// \param result - the plain old datatype to place the result
	/// \return Success or Fail
	///
    template<typename POD>
    auto from_chars(const char* base, const char* end, POD& result) -> bool
    {
		bool ret {false};
		
		try
		{
            auto [p, ec] = std::from_chars(base, end, result);
            ret = ec == std::errc();
        }
		catch(...)
		{
			// Error message
		}
		
		return ret;		
	}
	
	/// \brief
	///
	/// Use std::to_chars with type
	///
	/// \param base - the start of the substring
	/// \param end - the end of the substring
	/// \param result - the plain old datatype to place the result
	/// \return Success or Fail
	///
    template<typename POD>
    auto to_chars(std::string& samt, POD value) -> bool
    {
		bool ret {false};
		
		try
		{
			static constexpr std::size_t s_numsize {120};
			
			std::array<char, s_numsize> str;
			
            auto [ptr, ec] = std::to_chars(
              str.data(),
              str.data() + s_numsize,
              value);

            ret = ec == std::errc();
			if (ret)
			{
                samt.append(str.data(), ptr - str.data());
            }
        }
		catch(...)
		{
		}
		
		return ret;		
	}
}    // namespace density
#endif
