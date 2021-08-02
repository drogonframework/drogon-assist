#pragma once

#include <string>
#include <drogon/utils/string_view.h>

namespace drassist
{
/// The SHA3 hash function
/**
 * \brief Computes the SHA3 bash
 * \param data the input of the hash function
 * \param dataLen the length of the data
 * \param hashLength the length of the output hash (in bytes), before HEX
 * \param key (optional) the key for BLAKE2 keying
 * \param keyLength
 * length of the key
 */
std::string getSha3(const char *data, const size_t dataLen, const size_t hashLength = 32);
// NOTE: Intentinally renamed to `sha3` otherwise getSha3("123", 16) will
// resolve into the above function, not the latter one
inline std::string sha3(const drogon::string_view &data, size_t hashLength = 32)
{
    return getSha3(data.data(), data.length(), hashLength);
}

/// The BLAKE2b hash function
/**
 * \brief Computes the BLAKE2b bash
 * \param data the input of the hash function
 * \param dataLen the length of the data
 * \param hashLength the length of the output hash (in bytes), before HEX
 * \param key (optional) the key for BLAKE2 keying
 * \param keyLength length of the key
 */
std::string getBlake2b(const char *data,
                       const size_t dataLen,
                       const size_t hashLength = 32,
                       const char *key = nullptr,
                       const size_t keyLength = 0);
// NOTE: Intentinally renamed to `blake2b` otherwise getBlake2b("123", 16) will
// resolve into the above function, not the latter one
inline std::string blake2b(const drogon::string_view &data,
                           size_t hashLength = 32,
                           const drogon::string_view &key = drogon::string_view())
{
    return getBlake2b(data.data(), data.length(), hashLength, key.data(), key.size());
}

}
