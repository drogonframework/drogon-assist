#include "http_signature.hpp"

#include <drogon/HttpRequest.h>
#include <drogon/HttpClient.h>
#include <drogon/utils/Utilities.h>

#include <botan/pkcs8.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>

#include <regex>


using namespace drogon;
using namespace drassist;

namespace drassist
{

namespace http_signature
{

namespace internal
{
inline std::string to_lower(const std::string& str)
{
	std::string lower_str = str;
	std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), tolower);
	return lower_str;
}

inline std::string join(const std::vector<std::string>& lst, const std::string& sep = " ")
{
    std::string res;
    for(const auto& str : lst)
        res += str + sep;
    if(!res.empty())
        res.resize(res.size()-1);
    return res;
}

std::string makeSignString(const drogon::HttpRequestPtr& req, const std::vector<std::string>& headers
   , const drogon::HttpClient* client = nullptr)
{
	std::string res;
	for(const auto& header : headers) {
		std::string value;
		const std::string lower_header = to_lower(header);
		if(lower_header == "request-line") {
			std::string version_string = (req->version() == Version::kHttp10) ? "HTTP/1.0" : "HTTP/1.1";
			value = std::string(req->methodString()) + " " + req->path() + " " + version_string;
		}
		else if(lower_header == "(request-target)") { // extension for ActivityPub
			value = to_lower(req->methodString()) + " " + req->path();
		}
		else if(lower_header == "host") {
		    if(client != nullptr)
			    value = client->host() + (client->onDefaultPort() ? "" : (":" + std::to_string(client->port())));
		    else
		        value = req->getHeader("host");
		}
        else if(lower_header == "date") {
            if(req->getHeader("date").empty())
                value = utils::getHttpFullDate(req->getCreationDate());
            else
                value = req->getHeader("date");
        }
		else {
		    value = req->getHeader(lower_header);
		}

        res += lower_header + ": " + value + "\n";
	}
	if(!res.empty())
		res.resize(res.size()-1);

	return res;
}
}

void sign(drogon::HttpRequestPtr& req, const drogon::HttpClientPtr& client, const std::string& key_id, const Botan::Private_Key& private_key,
     const std::vector<std::string>& headers, std::string algorithm)
{
    if(private_key.algo_name() != "RSA")
        throw std::invalid_argument("Must use RSA in drassist::http_signature::sign");

    std::string algo;
    algorithm = internal::to_lower(algorithm);
    if(algorithm == "sha-256" || algorithm == "sha256")
        algo = "EMSA3(SHA-256)";
    else if(algorithm == "sha-1" || algorithm == "sha1")
        algo = "EMSA3(SHA1)";
    else if(algorithm == "sha-512" || algorithm == "sha512")
        algo = "EMSA3(SHA-512)";
    else
        throw std::domain_error(algorithm + " is not a valid for HTTP Signature. Please use sha-256, sha1 or sha-512");

    thread_local static Botan::AutoSeeded_RNG rng;
    std::string sign_str = internal::makeSignString(req, headers, client.get());
    Botan::PK_Signer signer(private_key, rng, algo);

    signer.update(sign_str);
    auto signature = signer.signature(rng);

    std::string algo_string;
    if(algo == "EMSA3(SHA-256)")
        algo_string = "rsa-sha256";
    else if(algo == "EMSA3(SHA1)")
        algo_string = "rsa-sha1";
    else if(algo == "EMSA3(SHA-512)")
        algo_string = "rsa-sha512";

    req->addHeader("Authorization", "Signature keyId=\"" + key_id + "\",algorithm=\""+ algo_string + "\""
        ",headers=\"" + internal::join(headers) + "\",signature=\"" + utils::base64Encode(signature.data(), signature.size(), false) + "\"");
}

drogon::optional<SignatureData> parse(const drogon::HttpRequestPtr& req)
{
    SignatureData data;
    const auto& auth = req->getHeader("Authorization");
    if(auth.empty()) {
        LOG_TRACE << "Request doesn't have an Authorization header";
        return {};
    }
    auto signature_it = auth.find("Signature");
    if (signature_it != 0) {
        LOG_TRACE << "Authorization header is not for HTTP Signature";
        return {};
    }

    auto auth_view = string_view(auth).substr(signature_it+1+string_view("Signature").size());

    size_t begin = 0;
    bool in_quotes = false;
    // NOTE: The HTTP signature spec does not support escape characters
    for(size_t i=0;i<auth_view.size()+1;i++) {
        char ch = i < auth_view.size() ? auth_view[i] : '\0';
        if(!in_quotes) {
            if(ch == ' ' || ch == '\t' || ch == '\0' || ch == ',') {
                if(begin == i) {
                    begin = i+1;
                    continue;
                }

                // Parse the KV pair
                size_t end = i;
                std::string kv_str(auth_view.begin()+begin, auth_view.begin()+end);
                auto it = kv_str.find('=');
                if(it == string_view::npos) {
                    LOG_TRACE << "Bad Authorization header format";
                    return {};
                }

                static const std::regex re(R"AA(([^\"]+)[ \t]*=[ \t]*"([^\"]*)")AA");
                std::smatch sm;
                if(!std::regex_match(kv_str, sm, re)) {
                    LOG_TRACE << "header element format error";
                    return {};
                }
                std::string key = sm[1].str();
                std::string value = sm[2].str();

                if(key == "keyId")
                    data.key_id = value;
                else if(key == "algorithm")
                    data.algorithm = value;
                else if(key == "headers")
                    data.headers = utils::splitString(value, " ", false);
                else if(key == "signature")
                    data.signature = value;
                else if(key == "ext")
                    data.ext = value;
                else {
                    LOG_TRACE << key + "is not a valid item for HTTP Signature";
                    return {};
                }

                begin = i+1;

            }
            else if(ch == '"')
                in_quotes = true;
        }
        else {
            if(ch == '"')
                in_quotes = false;
        }
    }

    if(data.headers.size() == 0)
        data.headers = {"date"};

    return data;
}

bool verify(const drogon::HttpRequestPtr& req, const Botan::Public_Key& public_key, const SignatureData& signature_data)
{
    static const std::regex re("rsa-([\\w]+)");
    std::smatch sm;
    if(!std::regex_match(signature_data.algorithm, sm, re)) {
        LOG_WARN << "Drogon Assist does not support non RSA signing alogirthms for HTTP Signature";
        return false;
    }
    std::string algo = sm[1];
    std::string algo_str;
    if(algo == "sha256")
        algo_str = "EMSA3(SHA-256)";
    else if(algo == "sha1")
        algo_str = "EMSA3(SHA1)";
    else if(algo == "sha512")
        algo_str = "EMSA3(SHA-512)";
    else {
        LOG_TRACE << algo << " is not supported as a hash for HTTP Signatures";
        return false;
    }

    Botan::PK_Verifier verifier(public_key, algo_str);
    auto sign_str = internal::makeSignString(req, signature_data.headers);
    auto signature = utils::base64Decode(signature_data.signature);

    verifier.update(sign_str);
    return verifier.check_signature((uint8_t*)signature.data(), signature.size());
}

bool verify(const drogon::HttpRequestPtr& req, const Botan::Public_Key& public_key)
{
    auto data = parse(req);
    if(data.has_value() == false)
        return false;
    const auto& signature_data = data.value();
    return verify(req, public_key, signature_data);
}

}
}
