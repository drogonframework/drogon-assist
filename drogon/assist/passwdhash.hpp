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
std::string hash(const std::string& passwd, const std::string& algo="ARGON2", size_t salt_length=16);
bool verify(const std::string& passwd, const std::string& passwd_hash);

// NOTE: Expand the selection of algorithms here in the future to comidate new standards
// while maintaining compatibility
std::string argon2(const std::string& passwd, size_t salt_length);
bool argon2_verify(const std::string& passwd, const std::string& passwd_hash);

}

}