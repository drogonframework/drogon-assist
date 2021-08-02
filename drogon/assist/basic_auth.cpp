#include "basic_auth.hpp"
#include <drogon/utils/Utilities.h>

using namespace drassist;
using namespace drogon;

optional<std::pair<std::string, std::string>> drassist::parseBasicAuth(const drogon::HttpRequestPtr& req)
{
	const std::string& auth = req->getHeader("Authorization");
	auto auth_parts = utils::splitString(auth, " ");
	bool auth_success = false;
	if(auth_parts.size() != 2 || (auth_parts[0] != "basic" && auth_parts[0] != "Basic")) {
		return {};
	}
	else {
		auto auth_data = utils::base64Decode(auth_parts[1]);
		auto data = utils::splitString(auth_data, ":", true);
		if(data.size() == 2) {
			const auto& user = data[0];
			const auto& passwd = data[1];

			return std::pair<std::string, std::string>{user, passwd};
		}
	}

	return {};
}

drogon::HttpResponsePtr drassist::makeBasicAuthResponse(const std::string& realm)
{
	auto resp = HttpResponse::newHttpResponse();
	resp->setStatusCode(k401Unauthorized);
	if(!realm.empty())
		resp->addHeader("WWW-authenticate", "Basic realm=\"" + realm + "\"");
	return resp;
}