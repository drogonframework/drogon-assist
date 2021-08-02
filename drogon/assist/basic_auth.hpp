#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/utils/optional.h>
#include <tuple>

namespace drassist
{

drogon::optional<std::pair<std::string, std::string>> parseBasicAuth(const drogon::HttpRequestPtr& req);
drogon::HttpResponsePtr makeBasicAuthResponse(const std::string& realm="");

}