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
     const std::vector<std::string>& headers)
{
    thread_local static Botan::AutoSeeded_RNG rng;
    std::string sign_str = internal::makeSignString(req, headers, client.get());
    Botan::PK_Signer signer(private_key, rng, "EMSA3(SHA-256)");

    signer.update(sign_str);
    auto signature = signer.signature(rng);

    req->addHeader("Authorization", "Signature keyId=\"" + key_id + "\",algorithm=\"rsa-sha256\""
        ",headers=\"" + internal::join(headers) + "\",signature=\"" + utils::base64Encode(signature.data(), signature.size(), false) + "\"");
}

optional<SignatureData> parse(const drogon::HttpRequestPtr& req)
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

    auto auth_view = std::string_view(auth).substr(signature_it+1+std::string_view("Signature").size());

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
                if(it == std::string_view::npos) {
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

    return data;
}

bool verify(const drogon::HttpRequestPtr& req, const Botan::Public_Key& public_key)
{
    auto data = parse(req);
    if(data.has_value() == false)
        return false;
    const auto& signature_data = data.value();
    if(signature_data.algorithm != "rsa-sha256") {
        LOG_WARN << "DrAssist does not support non RSA-SHA256 alogirhms";
        return false;
    }
    Botan::PK_Verifier verifier(public_key, "EMSA3(SHA-256)");
    auto sign_str = internal::makeSignString(req, signature_data.headers);
    auto signature = utils::base64Decode(signature_data.signature);

    verifier.update(sign_str);
    return verifier.check_signature((uint8_t*)signature.data(), signature.size());
}

}
}