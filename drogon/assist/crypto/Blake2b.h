// Taken from https://github.com/Sachin-A/Blake2
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace drassist::internal
{
void blake2b(void* out, size_t outlen, const void* in, size_t inlen, const void* key, size_t keylen);
}