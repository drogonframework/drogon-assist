#include <drogon/assist/plugin/ParameterPollutionProtector.hpp>
#include <drogon/HttpAppFramework.h>
#include <set>

using namespace drogon;
using namespace drassist;

void ParameterPollutionProtector::initAndStart(const Json::Value &config)
{
	app().registerSyncAdvice([this](const HttpRequestPtr &req) {
        return this->doAdvice(req);
    });
}

HttpResponsePtr ParameterPollutionProtector::doAdvice(const HttpRequestPtr &req) const
{
	auto parameters = req->parameters();
	std::set<std::string> unique_keys;
	
	for(const auto& kv : parameters)
		unique_keys.insert(kv.first);

	if (unique_keys.size() == parameters.size())
		return nullptr;
	
	// Otherwise there's HTTP parameter pollution. We throw an error back
	auto resp = app().getCustomErrorHandler()(k406NotAcceptable);
	return resp;
}