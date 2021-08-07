#include <drogon/HttpController.h>
#include <drogon/drogon_test.h>
#include <drogon/assist/http_signature.hpp>

#include <botan/auto_rng.h>
#include <botan/rsa.h>

#include <memory>

using namespace drogon;
using namespace drassist;

static Botan::AutoSeeded_RNG rng;
static std::unique_ptr<Botan::Private_Key> private_key;
static std::unique_ptr<Botan::Public_Key> public_key;

static std::unique_ptr<Botan::Private_Key> private_key2;

class HttpSignatureTestController : public HttpController<HttpSignatureTestController>
{
public:
    HttpSignatureTestController();
    void endpoint(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);

    METHOD_LIST_BEGIN
    ADD_METHOD_TO(HttpSignatureTestController::endpoint, "/httpsignature", {Get});
    METHOD_LIST_END
};

HttpSignatureTestController::HttpSignatureTestController()
{
    Botan::RSA_PrivateKey rsa_private_key(rng, 2048);
    Botan::RSA_PrivateKey rsa_private_key2(rng, 2048);
    Botan::RSA_PublicKey rsa_public_Key(rsa_private_key);

    private_key = std::unique_ptr<Botan::Private_Key>(new Botan::RSA_PrivateKey(rsa_private_key));
    public_key = std::unique_ptr<Botan::Public_Key>(new Botan::RSA_PublicKey(rsa_public_Key));
    private_key2 = std::unique_ptr<Botan::Private_Key>(new Botan::RSA_PrivateKey(rsa_private_key2));
}

void HttpSignatureTestController::endpoint(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback)
{
    if(http_signature::verify(req, *public_key)) {
        callback(HttpResponse::newHttpResponse());
    }
    else {
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k401Unauthorized);
        callback(resp);
    }
}

DROGON_TEST(http_signature)
{
    auto client = HttpClient::newHttpClient("http://127.0.0.1:8848");

    // No signatue at all. Should fail
    auto req = HttpRequest::newHttpRequest();
    req->setPath("/httpsignature");
    client->sendRequest(req, [TEST_CTX](ReqResult result, const HttpResponsePtr& resp) {
        REQUIRE(result == ReqResult::Ok);
        CHECK(resp->statusCode() == k401Unauthorized);
    });

    // Default signature
    req = HttpRequest::newHttpRequest();
    req->setPath("/httpsignature");
    http_signature::sign(req, client, "some_key", *private_key);
    client->sendRequest(req, [TEST_CTX](ReqResult result, const HttpResponsePtr& resp) {
        REQUIRE(result == ReqResult::Ok);
        CHECK(resp->statusCode() == k200OK);
    });

    // ActivityPub style signactures
    req = HttpRequest::newHttpRequest();
    req->setPath("/httpsignature");
    http_signature::sign(req, client, "some_key", *private_key, {"(request-target)", "date", "host"});
    client->sendRequest(req, [TEST_CTX](ReqResult result, const HttpResponsePtr& resp) {
        REQUIRE(result == ReqResult::Ok);
        CHECK(resp->statusCode() == k200OK);
    });

    // Headers modified after signing
    req = HttpRequest::newHttpRequest();
    req->setPath("/httpsignature");
    req->addHeader("some_header", "123");
    http_signature::sign(req, client, "some_key", *private_key, {"date", "host", "request-line", "some_header"});
    req->removeHeader("some_header");
    client->sendRequest(req, [TEST_CTX](ReqResult result, const HttpResponsePtr& resp) {
        REQUIRE(result == ReqResult::Ok);
        CHECK(resp->statusCode() == k401Unauthorized);
    });

    // SHA-512 as hash
    req = HttpRequest::newHttpRequest();
    req->setPath("/httpsignature");
    http_signature::sign(req, client, "some_key", *private_key, {"date"}, "SHA-512");
    client->sendRequest(req, [TEST_CTX](ReqResult result, const HttpResponsePtr& resp) {
        REQUIRE(result == ReqResult::Ok);
        CHECK(resp->statusCode() == k200OK);
    });

    // SHA1 as hash
    req = HttpRequest::newHttpRequest();
    req->setPath("/httpsignature");
    http_signature::sign(req, client, "some_key", *private_key, {"date"}, "SHA1");
    client->sendRequest(req, [TEST_CTX](ReqResult result, const HttpResponsePtr& resp) {
        REQUIRE(result == ReqResult::Ok);
        CHECK(resp->statusCode() == k200OK);
    });

    // Sign with a different key, should fail
    req = HttpRequest::newHttpRequest();
    req->setPath("/httpsignature");
    http_signature::sign(req, client, "some_key", *private_key2);
    client->sendRequest(req, [TEST_CTX](ReqResult result, const HttpResponsePtr& resp) {
        REQUIRE(result == ReqResult::Ok);
        CHECK(resp->statusCode() == k401Unauthorized);
    });

    req = HttpRequest::newHttpRequest();
    CHECK_THROWS(http_signature::sign(req, client, "some_key", *private_key2, {"date"}, "not_a_hash"));
}