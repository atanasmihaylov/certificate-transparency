#include "monitoring/gcm/exporter.h"

#include <glog/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "monitoring/monitoring.h"
#include "net/mock_url_fetcher.h"
#include "util/json_wrapper.h"
#include "util/testing.h"
#include "util/thread_pool.h"

namespace cert_trans {

const char kPushUrl[] = "http://example.com/push";
const int kPushInterval = 1;
const char kMetadataUrl[] = "http://example.com/metadata";
const char kServiceAccount[] = "default";

const char kCredentialsJson[] =
    "{\n"
    "  \"access_token\":\"token\",\n"
    "  \"expires_in\":3599,\n"
    "  \"token_type\":\"Bearer\"\n"
    "}";

DECLARE_string(google_compute_monitoring_push_url);
DECLARE_int32(google_compute_monitoring_push_interval_seconds);
DECLARE_string(google_compute_metadata_url);
DECLARE_string(google_compute_monitoring_service_account);

using std::bind;
using std::make_pair;
using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;
using std::string;
using std::vector;
using testing::_;
using testing::AllOf;
using testing::ElementsAre;
using testing::HasSubstr;
using testing::Invoke;
using testing::IsEmpty;
using util::Status;
using util::Task;

namespace {


void HandleFetch(Status status, int status_code,
                 const UrlFetcher::Headers& headers, const string& body,
                 const UrlFetcher::Request& req, UrlFetcher::Response* resp,
                 Task* task) {
  resp->status_code = status_code;
  resp->headers = headers;
  resp->body = body;
  if (!req.body.empty()) {
    // It should be valid JSON
    JsonObject request(req.body);
    CHECK(request.Ok());
  }
  task->Return(status);
}


}  // namespace


class GCMExporterTest : public ::testing::Test {
 public:
  GCMExporterTest() : pool_(2) {
    FLAGS_google_compute_monitoring_push_url = kPushUrl;
    FLAGS_google_compute_monitoring_push_interval_seconds = kPushInterval;
    FLAGS_google_compute_metadata_url = kMetadataUrl;
    FLAGS_google_compute_monitoring_service_account = kServiceAccount;

    ON_CALL(fetcher_, Fetch(_, _, _))
        .WillByDefault(Invoke(bind(&HandleFetch, util::Status::OK, 200,
                                   UrlFetcher::Headers{}, "", _1, _2, _3)));
  }

 protected:
  string GetBearerToken(const GCMExporter& e) {
    return e.bearer_token_;
  }

  ThreadPool pool_;
  MockUrlFetcher fetcher_;
};


TEST_F(GCMExporterTest, TestGetsCredentials) {
  EXPECT_CALL(fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::GET,
                        URL(string(kMetadataUrl) + "/" + kServiceAccount),
                        UrlFetcher::Headers{
                            make_pair("Metadata-Flavor", "Google")},
                        ""),
                    _, _))
      .WillRepeatedly(
          Invoke(bind(&HandleFetch, util::Status::OK, 200,
                      UrlFetcher::Headers{}, kCredentialsJson, _1, _2, _3)));
  GCMExporter exporter(&fetcher_, &pool_);
  EXPECT_EQ("token", GetBearerToken(exporter));
}


TEST_F(GCMExporterTest, TestUsesCredentials) {
  EXPECT_CALL(fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::GET,
                        URL(string(kMetadataUrl) + "/" + kServiceAccount),
                        UrlFetcher::Headers{
                            make_pair("Metadata-Flavor", "Google")},
                        ""),
                    _, _))
      .WillRepeatedly(
          Invoke(bind(&HandleFetch, util::Status::OK, 200,
                      UrlFetcher::Headers{}, kCredentialsJson, _1, _2, _3)));
  EXPECT_CALL(fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::POST, URL(kPushUrl),
                        UrlFetcher::Headers{
                            make_pair("Content-Type", "application/json"),
                            make_pair("Authorization", "Bearer token")},
                        _),
                    _, _))
      .WillRepeatedly(Invoke(bind(&HandleFetch, util::Status::OK, 200,
                                  UrlFetcher::Headers{}, "", _1, _2, _3)));
  GCMExporter exporter(&fetcher_, &pool_);
  sleep(2);
}


// TODO(alcutter): Add some more detailed tests on exactly what gets sent.
TEST_F(GCMExporterTest, TestPushesMetrics) {
  std::unique_ptr<Counter<>> one(Counter<>::New("one", "help1"));
  one->Increment();
  std::unique_ptr<Gauge<>> two(Gauge<>::New("two", "help2"));
  two->Set(2);
  EXPECT_CALL(fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::GET,
                        URL(string(kMetadataUrl) + "/" + kServiceAccount),
                        UrlFetcher::Headers{
                            make_pair("Metadata-Flavor", "Google")},
                        ""),
                    _, _))
      .WillRepeatedly(
          Invoke(bind(&HandleFetch, util::Status::OK, 200,
                      UrlFetcher::Headers{}, kCredentialsJson, _1, _2, _3)));
  EXPECT_CALL(fetcher_,
              Fetch(IsUrlFetchRequest(
                        UrlFetcher::Verb::POST, URL(kPushUrl),
                        UrlFetcher::Headers{
                            make_pair("Content-Type", "application/json"),
                            make_pair("Authorization", "Bearer token")},
                        AllOf(HasSubstr("one"), HasSubstr("two"))),
                    _, _))
      .WillRepeatedly(Invoke(bind(&HandleFetch, util::Status::OK, 200,
                                  UrlFetcher::Headers{}, "", _1, _2, _3)));
  GCMExporter exporter(&fetcher_, &pool_);
  sleep(2);
}


}  // namespace cert_trans


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
