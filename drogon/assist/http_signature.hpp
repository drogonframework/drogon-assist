#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpClient.h>
#include <botan/pkcs8.h>


namespace drassist
{

namespace http_signature
{

struct SignatureData
{
    std::string key_id;
    std::string algorithm;
    std::vector<std::string> headers;
    std::string signature;
};

void sign(drogon::HttpRequestPtr& req, const drogon::HttpClientPtr& client, const std::string& key_id
          , const Botan::Private_Key& private_key
          , const std::vector<std::string>& headers = {"request-line", "host", "date"});

bool verify(const drogon::HttpRequestPtr& req, const Botan::Public_Key& public_key);

}
}