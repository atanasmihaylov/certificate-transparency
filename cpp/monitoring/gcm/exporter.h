#ifndef CERT_TRANS_MONITORING_GCM_EXPORTER_H_
#define CERT_TRANS_MONITORING_GCM_EXPORTER_H_

#include <chrono>
#include <condition_variable>
#include <memory>
#include <thread>

#include "net/url_fetcher.h"
#include "util/executor.h"

namespace cert_trans {

class GCMExporter {
 public:
  GCMExporter(UrlFetcher* fetcher, util::Executor* executor);
  ~GCMExporter();

 private:
  void RefreshCredentials();
  void CreateMetrics();
  void PushMetrics();

  UrlFetcher* fetcher_;
  util::Executor* executor_;
  std::mutex mutex_;
  bool exiting_;
  std::condition_variable exit_cv_;
  std::unique_ptr<std::thread> push_thread_;
  std::chrono::system_clock::time_point token_refreshed_at_;
  std::string bearer_token_;

  friend class GCMExporterTest;
};


}  // namespace cert_trans

#endif  // CERT_TRANS_MONITORING_GCM_EXPORTER_H_
