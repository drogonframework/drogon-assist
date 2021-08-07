#include <drogon/HttpController.h>
#include <drogon/assist/basic_auth.hpp>
#include <drogon/HttpClient.h>
#include <drogon/drogon_test.h>

using namespace drogon;
using namespace drassist;

class BasicAuthTestController : public HttpController<BasicAuthTestController>
{
public:
    void endpoint(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);

    METHOD_LIST_BEGIN
    ADD_METHOD_TO(BasicAuthTestController::endpoint, "/basicauth", {Get});
    METHOD_LIST_END
};

void BasicAuthTestController::endpoint(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback)
{
    auto basicAuth = parseBasicAuth(req);
    std::string user, password;

    if(!basicAuth.has_value()) {
        callback(makeBasicAuthResponse("test"));
        return;
    }

    std::tie(user, password) = basicAuth.value();
    if(user == "user" && password == "password")
        callback(HttpResponse::newHttpResponse());
    else
        callback(makeBasicAuthResponse("test"));

}

DROGON_TEST(basic_auth_test)
{
    auto client = HttpClient::newHttpClient("http://127.0.0.1:8848");
    auto req = HttpRequest::newHttpRequest();
    req->setPath("/basicauth");
    client->sendRequest(req, [TEST_CTX](ReqResult result, const HttpResponsePtr& resp) {
        REQUIRE(result == ReqResult::Ok);
        CHECK(resp->statusCode() == k401Unauthorized);
    });

    std::string auth_str = "user:password";
    req = HttpRequest::newHttpRequest();
    req->setPath("/basicauth");
    req->addHeader("Authorization", "Basic " + utils::base64Encode((unsigned char*)auth_str.c_str(), auth_str.size()));
    client->sendRequest(req, [TEST_CTX](ReqResult result, const HttpResponsePtr& resp) {
        REQUIRE(result == ReqResult::Ok);
        CHECK(resp->statusCode() == k200OK);
    });

    std::string auth_str2 = "not_user:not_password";
    req = HttpRequest::newHttpRequest();
    req->setPath("/basicauth");
    req->addHeader("Authorization", "Basic " + utils::base64Encode((unsigned char*)auth_str2.c_str(), auth_str2.size()));
    client->sendRequest(req, [TEST_CTX](ReqResult result, const HttpResponsePtr& resp) {
        REQUIRE(result == ReqResult::Ok);
        CHECK(resp->statusCode() == k401Unauthorized);
    });
}