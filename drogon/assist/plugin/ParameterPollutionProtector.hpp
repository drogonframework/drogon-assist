#pragma once

#include <drogon/plugins/Plugin.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpRequest.h>

namespace drassist
{
/**
 * @brief A plugin that prohibit HTTP parameter pollution
 */
class ParameterPollutionProtector : public drogon::Plugin<ParameterPollutionProtector>
{
public:
    virtual void initAndStart(const Json::Value &config) override;
    virtual void shutdown() override;

protected:
    drogon::HttpResponsePtr doAdvice(const drogon::HttpRequestPtr &req) const;
};
}  // namespace drogon