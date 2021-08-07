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
    std::string ext;
};

/**
 * \brief Parses HTTP signature in a request
 * \param req The request containint the HTTP signature
 * \return nullopt if parsing failed. The signature and related information if success
 */
drogon::optional<SignatureData> parse(const drogon::HttpRequestPtr& req);

/**
 * \brief Signs a request
 * \param req the request to be signed
 * \param client the client that will be used to send the request
 * \param key_id the keyId of the key
 * \param headers which headers are included in the signature
 * \param algorithm The hashing algorithm used in the signature
 */
void sign(drogon::HttpRequestPtr& req, const drogon::HttpClientPtr& client, const std::string& key_id
          , const Botan::Private_Key& private_key
          , const std::vector<std::string>& headers = {"request-line", "host", "date"}
          , std::string algorithm = "SHA-256");

/**
 * \brief verifes if a request matches it;s signature
 * \param req the request
 * \param public_key the PK of the signature
 * \param signature_data the parsed signature data
 * \return true is signature matches, false otherwise
 */
bool verify(const drogon::HttpRequestPtr& req, const Botan::Public_Key& public_key, const SignatureData& signature_data);

/**
 * \brief verifes if a request matches it;s signature
 * \param req the request
 * \param public_key the PK of the signature
 * \return true is signature matches, false otherwise
 */
bool verify(const drogon::HttpRequestPtr& req, const Botan::Public_Key& public_key);

}
}