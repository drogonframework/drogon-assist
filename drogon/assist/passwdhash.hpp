#pragma once

#include <string>
#include <stdint.h>
#include <limits>

namespace drassist
{

uint32_t secureRandom(uint32_t lower=0, uint32_t upper=std::numeric_limits<uint32_t>::max());
std::string secureRandomString(size_t length=16);

namespace passwdhash
{
/**
 * \brief Computes a password hash that could be verifed later
 * \param passwd the password to hash
 * \param algo The hashing algorithm. For now only 'ARGON2' is supported
 * \param salt_length the length of the salt added to the hash (in addition to the built-in salf
 * of some hash functions)
 * \return the hash of the pasword
 */
std::string hash(const std::string& passwd, const std::string& algo="ARGON2", size_t salt_length=16);
/**
 * \brief Verifies a password against a password hash
 * \param passwd the password
 * \param passwd_hash The hash generated by `drassist::passwdhash::hash()`
 * \return True if the password matches the hash. Otherwise false
 */
bool verify(const std::string& passwd, const std::string& passwd_hash);

// NOTE: Expand the selection of algorithms here in the future to comidate new standards
// while maintaining compatibility
std::string argon2(const std::string& passwd, size_t salt_length);
bool argon2_verify(const std::string& passwd, const std::string& passwd_hash);

}

}