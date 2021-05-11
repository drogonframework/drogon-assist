#include <drogon/assist/plugin/BOMRemover.hpp>
#include <drogon/HttpAppFramework.h>
#include <set>

using namespace drogon;
using namespace drassist;

void BOMRemover::initAndStart(const Json::Value &config)
{
	std::vector<ContentType> defaults = {CT_APPLICATION_JSON, CT_APPLICATION_X_JAVASCRIPT
			, CT_TEXT_PLAIN, CT_TEXT_XML, CT_TEXT_CSS, CT_TEXT_HTML, CT_APPLICATION_XML};
	for(auto ct : defaults)
		actions_types.insert(ct);

	app().registerSyncAdvice([this](const HttpRequestPtr &req) {
        return this->doAdvice(req);
    });
}

static bool startsWith(const string_view str, const string_view target)
{
	if(str.size() < target.size())
		return false;
	return memcmp(str.begin(), target.begin(), target.size()) == 0;
}

static std::string removeFirstN(const string_view str, size_t n)
{
	assert(str.size() >= n);
	return std::string(str.begin()+n, str.end());
}

HttpResponsePtr BOMRemover::doAdvice(const HttpRequestPtr &req) const
{
	if(actions_types.find(req->getContentType()) == actions_types.end())
		return nullptr;

	string_view body = req->getBody();

	if(startsWith(body, "\xEF\xBB\xBF")) // UTF-8
		req->setBody(removeFirstN(body, 3));
	else if(startsWith(body, "\xFE\xFF")) // UTF-16 BE
		req->setBody(removeFirstN(body, 2));
	else if(startsWith(body, "\xFF\xFE")) // UTF-16 LE
		req->setBody(removeFirstN(body, 2));
	else if(startsWith(body, "\x00\x00\xFE\xFF")) // UTF-32 BE
		req->setBody(removeFirstN(body, 4));
	else if(startsWith(body, "\x00\x00\xFF\xFE")) // UTF-32 LE
		req->setBody(removeFirstN(body, 4));
	else if(startsWith(body, "\x2B\x2F\x76")) // UTF-7
		req->setBody(removeFirstN(body, 3));
	else if(startsWith(body, "\xF7\x64\x4C")) // UTF-1
		req->setBody(removeFirstN(body, 3));
	else if(startsWith(body, "\x84\x31\x95\x33")) // GB-18030
		req->setBody(removeFirstN(body, 4));
	else if(startsWith(body, "\xEF\xBB\fBF")) // BIG-5
		req->setBody(removeFirstN(body, 3));
	return nullptr;
}

void BOMRemover::shutdown()
{
}
