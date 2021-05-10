#include "passwdhash.hpp"
#include <regex>
#include <drogon/utils/Utilities.h>

#include <bsd/stdlib.h>
#include <botan/argon2.h>
#include <botan/system_rng.h>

static Botan::System_RNG rng;
using namespace drogon;
using namespace drassist;

uint32_t drassist::secureRandom(uint32_t lower, uint32_t upper)
{
	return lower+arc4random_uniform(upper-lower);
}

std::string drassist::secureRandomString(size_t length)
{
	const std::string_view alphabet = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	std::string result;
	result.resize(length);
	for(auto& ch : result)
		ch = alphabet[secureRandom(0, alphabet.size())];
	return result;
}

static std::tuple<std::string, std::string, std::string> parse_passwdhash(const std::string& str)
{
	auto parts = drogon::utils::splitString(str, ":", true);
	if(parts.size() < 3)
		throw std::runtime_error("Bad password hash format");
	
	// Just incase there's a : in the hash
	auto hash = parts[2];
	for(size_t i=3;i<parts.size();i++)
		hash = hash + ":" + parts[i];
	return {parts[0], parts[1], hash};
}

std::string passwdhash::argon2(const std::string& passwd, size_t salt_length)
{
	// Still add out own salt to keep the format same with the fallback algorithms
	auto salt = secureRandomString(salt_length);
	auto salted_passwd = salt + passwd;
	auto hash = Botan::argon2_generate_pwhash(salted_passwd.c_str(), salted_passwd.size(), rng, 1, 65536, 2, 2, 16, 32);
	return "ARGON2:"+salt+":"+hash;
}

bool passwdhash::argon2_verify(const std::string& passwd, const std::string& passwd_hash)
{
	std::string algo, salt, hash;
	std::tie(algo, salt, hash) = parse_passwdhash(passwd_hash);
	std::string full_password = salt+passwd;
	if(algo != "ARGON2")
		throw std::runtime_error("Not Argon2");
	return Botan::argon2_check_pwhash(full_password.c_str(), full_password.size(), hash);
}

std::string passwdhash::hash(const std::string& passwd, const std::string& algo, size_t salt_length)
{
	if(algo == "ARGON2")
		return argon2(passwd, salt_length);
	
	throw std::domain_error("Unknown password hash algorithm: " + algo);
}

bool passwdhash::verify(const std::string& passwd, const std::string& passwd_hash)
{
	std::string algo, salt, hash;
	std::tie(algo, salt, hash) = parse_passwdhash(passwd_hash);
	if(algo == "ARGON2")
		return argon2_verify(passwd, passwd_hash);
	
	throw std::domain_error("Unknown password hash algorithm: " + algo);
}