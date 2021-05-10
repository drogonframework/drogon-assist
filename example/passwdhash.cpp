#include <drogon/assist/passwdhash.hpp>
#include <iostream>

int main()
{
	std::cout << "Please enter your password: " << std::flush;
	std::string passwd;
	std::getline(std::cin, passwd);

	std::cout << "Your password is \'" << passwd << "\' Hashing..." << std::endl;
	std::string hashed = drassist::passwdhash::hash(passwd);
	std::cout << "The hash is:\n  " << hashed << std::endl;

	std::cout << "Please retype your password to verify: " << std::flush;
	std::string new_passwd;
	std::getline(std::cin, new_passwd);
	std::cout << "The password is \'" << new_passwd << "\' Verifying..." << std::endl;
	bool ok = drassist::passwdhash::verify(new_passwd, hashed);
	if(ok)
		std::cout << "They are the same" << std::endl;
	else
		std::cout << "They are NOT the same" << std::endl;
}