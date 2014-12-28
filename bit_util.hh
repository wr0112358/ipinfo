#ifndef _BIT_UTIL_H__
#define _BIT_UTIL_H__

namespace bit_util {

template<size_t start, size_t end>
inline bool in_region(size_t val)
{
    return val >= start && val <= end;
}

/*
 — Built-in Function: int __builtin_clz (unsigned int x)

    Returns the number of leading 0-bits in x, starting at the most significant bit position. If x is 0, the result is undefined. 

— Built-in Function: int __builtin_ctz (unsigned int x)

    Returns the number of trailing 0-bits in x, starting at the least significant bit position. If x is 0, the result is undefined. 


*/

// TODO: use std::numeric_limits<T>::digits

template<typename value_type>
inline size_t count_leading_0(value_type value)
{
    return value == 0 ? sizeof(value) * 8 : __builtin_clz(value);
}

template<typename value_type>
inline size_t count_trailing_0(value_type value)
{
    return value == 0 ? sizeof(value) * 8 : __builtin_ctz(value);
}

// TODO: testing value for 0 is unnecessary since it would be all-1 after inverting
template<typename value_type>
inline size_t count_leading_1(value_type value)
{
    return value == 0 ? 0 : (~value == 0 ? 8 * sizeof(value_type) : __builtin_clz(~value));
}

template<typename value_type>
inline size_t count_trailing_1(value_type value)
{
    return value == 0 ? 0 : (~value == 0 ? 8 * sizeof(value_type) : __builtin_ctz(~value));
}

template<typename value_type>
uint32_t pad32_trailing_0(value_type value)
{
    const auto sz = 4 < sizeof(value) ? 0 : (4 - sizeof(value));
    return sz == 0 ? value : (sz == 1 ? value << 8 : (sz == 2 ? value << 16 : value << 24));
}
}

#endif

