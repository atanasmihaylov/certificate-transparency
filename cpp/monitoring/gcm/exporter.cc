#include "monitoring/gcm/exporter.h"

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <sstream>

#include "monitoring/registry.h"
#include "net/url.h"
#include "util/json_wrapper.h"
#include "util/sync_task.h"

namespace cert_trans {

const char kWritePreamble[] =
    "{\n"
    "  \"kind\": \"cloudmonitoring#writeTimeseriesRequest\",\n"
    "  \"timeseries\": [\n";


const char kWritePostamble[] =
    "  ]\n"
    "}\n";

DEFINE_string(google_compute_monitoring_push_url, "",
              "GCM custom timeseries write URL.");
DEFINE_int32(google_compute_monitoring_push_interval_seconds, 5,
             "Seconds between pushing metric values to GCM.");
DEFINE_string(google_compute_metadata_url,
              "http://metadata/computeMetadata/v1/instance/service-accounts",
              "URL of GCE metadata server.");
DEFINE_string(google_compute_monitoring_service_account, "default",
              "Which GCE service account to use for pushing metrics.");

using std::chrono::seconds;
using std::chrono::system_clock;
using std::chrono::minutes;
using std::make_pair;
using std::mutex;
using std::ostringstream;
using std::string;
using std::thread;
using std::unique_lock;
using util::Executor;
using util::SyncTask;


GCMExporter::GCMExporter(UrlFetcher* fetcher, Executor* executor)
    : fetcher_(CHECK_NOTNULL(fetcher)),
      executor_(CHECK_NOTNULL(executor)),
      exiting_(false) {
  RefreshCredentials();
  push_thread_.reset(new thread(&GCMExporter::PushMetrics, this));
}


GCMExporter::~GCMExporter() {
  {
    unique_lock<mutex> lock(mutex_);
    exiting_ = true;
  }
  exit_cv_.notify_all();
  push_thread_->join();
}


void GCMExporter::RefreshCredentials() {
  VLOG(1) << "Refreshing GCM credentials...";
  UrlFetcher::Request req(
      (URL(FLAGS_google_compute_metadata_url + "/" +
           FLAGS_google_compute_monitoring_service_account)));
  req.headers.insert(make_pair("Metadata-Flavor", "Google"));

  UrlFetcher::Response resp;
  SyncTask task(executor_);
  fetcher_->Fetch(req, &resp, task.task());
  task.Wait();

  // TODO(alcutter): Handle this better
  CHECK_EQ(util::Status::OK, task.status());
  CHECK_EQ(200, resp.status_code);
  token_refreshed_at_ = system_clock::now();

  JsonObject reply(resp.body);
  CHECK(reply.Ok());
  JsonString bearer(reply, "access_token");
  CHECK(bearer.Ok());
  bearer_token_ = bearer.Value();

  VLOG(1) << "GCM credentials refreshed";
}


void GCMExporter::CreateMetrics() {
}


void GCMExporter::PushMetrics() {
  while (true) {
    {
      unique_lock<mutex> lock(mutex_);
      exit_cv_.wait_for(
          lock, seconds(FLAGS_google_compute_monitoring_push_interval_seconds),
          [this]() { return exiting_; });
      if (exiting_) {
        return;
      }
    }

    if (system_clock::now() - token_refreshed_at_ > minutes(3)) {
      RefreshCredentials();
    }

    ostringstream oss;
    oss << kWritePreamble;
    CHECK_NOTNULL(Registry::Instance())->Export(&oss);
    oss << kWritePostamble;

    UrlFetcher::Request req((URL(FLAGS_google_compute_monitoring_push_url)));
    req.verb = UrlFetcher::Verb::POST;
    req.headers.insert(make_pair("Content-Type", "application/json"));
    req.headers.insert(make_pair("Authorization", "Bearer " + bearer_token_));
    req.body = oss.str();

    UrlFetcher::Response resp;
    SyncTask task(executor_);
    VLOG(1) << "Pushing metrics...";
    fetcher_->Fetch(req, &resp, task.task());
    task.Wait();
    CHECK_EQ(util::Status::OK, task.status());
    CHECK_EQ(200, resp.status_code);
    VLOG(1) << "Metrics pushed.";
  }
}


}  // namespace cert_trans
