#include <drogon/drogon_test.h>
#include <drogon/assist/hash.hpp>
#include <drogon/assist/passwdhash.hpp>
using namespace drassist;

DROGON_TEST(hashes)
{
    CHECK(sha3("1337 c0de") == "B58BE191A134E75DCD602EA591132DAACB01CD1D77A38C8AE0AAE49681F77D9C");
    CHECK(blake2b("einy miny miny mo") == "DD02B85A1F29733C71EF230D701E6BE8FE517D53CDAF4AF509ADD64A5D7001CE");
}

DROGON_TEST(password_hash)
{
    auto hash = passwdhash::hash("correct horse battery staple", "ARGON2", 16);
    CHECK(passwdhash::verify("correct horse battery staple", hash) == true);
    CHECK(passwdhash::verify("iron gold silver titanium", hash) == false);
}


