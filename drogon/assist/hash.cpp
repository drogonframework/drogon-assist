#include "hash.hpp"
#include <vector>

#include <drogon/utils/Utilities.h>

#include "crypto/Blake2b.h"
#include "crypto/Sha3.h"

using namespace drogon;
using namespace drassist;

std::string drassist::getBlake2b(const char *data,
                       const size_t dataLen,
                       const size_t hashLength,
                       const char *key,
                       const size_t keyLength)
{
    assert(hashLength <= 64);
    std::vector<unsigned char> hash_buffer(hashLength);
    internal::blake2b(hash_buffer.data(), hashLength, data, dataLen, key, keyLength);
    return utils::binaryStringToHex(hash_buffer.data(), hashLength);
}

std::string drassist::getSha3(const char *data, const size_t dataLen, const size_t hashLength)
{
    assert(hashLength >= 28 && hashLength <= 64);
    std::vector<unsigned char> hash_buffer(hashLength);
    internal::sha3(data, dataLen, hash_buffer.data(), hash_buffer.size());
    return utils::binaryStringToHex(hash_buffer.data(), hashLength);
}