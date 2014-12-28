#ifndef _IPINFO_UTIL_HH_
#define _IPINFO_UTIL_HH_

#include <iostream>
#include <string>

namespace util {

enum color_type {
    NORMAL,
    RED,
    GREEN,
    YELLOW,
    BLUE,
    MAGENTA,
    CYAN,
    WHITE,
    RESET,
    NO_COLOR
};

inline const char * color_string(color_type color)
{
    switch(color) {
    case NORMAL: return "\x1B[0m";
    case RED: return "\x1B[31m";
    case GREEN: return "\x1B[32m";
    case YELLOW: return "\x1B[33m";
    case BLUE: return "\x1B[34m";
    case MAGENTA: return "\x1B[35m";
    case CYAN: return "\x1B[36m";
    case WHITE: return "\x1B[37m";
    case RESET:
    default:
        return "\033[0m";
    }
}

inline std::string colorize(color_type color, const std::string &text)
{
    return color_string(color) + text + color_string(RESET);
}

struct ct {
    ct(color_type color, char text)
        : ct(color, std::string(1, text)) {}

    ct(color_type color, const std::string &&text)
        : color(color), text(text) {}

    operator std::string() const { return color == NO_COLOR ? text : colorize(color, text); }
    friend std::ostream &operator<<(std::ostream &out, const ct &c)
    {
        out << std::string(c);
        return out;
    }

    const color_type color;
    const std::string text;
};

}

#endif
