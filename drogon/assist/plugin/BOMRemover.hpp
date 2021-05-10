#pragma once

#include <drogon/plugins/Plugin.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpRequest.h>
#include <set>

namespace drassist
{
/**
 * @brief A plugin that removes BOMs from request body for common text formats
 * It deals with UTF-8
 */
class BOMRemover : public drogon::Plugin<BOMRemover>
{
public:
    virtual void initAndStart(const Json::Value &config) override;
    virtual void shutdown() override;

protected:
    drogon::HttpResponsePtr doAdvice(const drogon::HttpRequestPtr &req) const;
	std::set<drogon::ContentType> actions_types;
};
}  // namespace drogon