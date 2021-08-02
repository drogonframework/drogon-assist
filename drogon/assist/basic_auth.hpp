#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/utils/optional.h>
#include <tuple>

namespace drassist
{

/**
 * \brief parses a bacic auth request and extracts the username and password
 * \param req the basic auth request
 * \return A pair of string. The first element being the user name and the seond being the password
 */
drogon::optional<std::pair<std::string, std::string>> parseBasicAuth(const drogon::HttpRequestPtr& req);

/**
 * \brief Generates a 401 Unauthorized response
 * \param realm the realm.
 * \return A 401 response
 */
drogon::HttpResponsePtr makeBasicAuthResponse(const std::string& realm="");

}