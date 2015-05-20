#ifndef CERT_TRANS_MONITORING_GCM_COUNTER_H_
#define CERT_TRANS_MONITORING_GCM_COUNTER_H_

#include "monitoring/counter.h"

#include <gflags/gflags.h>
#include <memory>
#include <mutex>
#include <string>

#include "base/macros.h"
#include "monitoring/gcm/gauge.h"

namespace cert_trans {

template <class... LabelTypes>
class GCMCounter : public Counter<LabelTypes...> {
 public:
  static GCMCounter<LabelTypes...>* New(
      const std::string& name,
      const typename NameType<LabelTypes>::name&... labels,
      const std::string& help);

  void Export(std::ostream* os) const override;

  void ExportText(std::ostream* os) const override;

  void Increment(const LabelTypes&... labels) override;

  void IncrementBy(const LabelTypes&... labels, double amount) override;

  double Get(const LabelTypes&... labels) const override;

 private:
  GCMCounter(const std::string& name,
             const typename NameType<LabelTypes>::name&... labels,
             const std::string& help);

  mutable std::mutex mutex_;
  // All Google Cloud Monitoring custom metrics are Gauges...
  std::unique_ptr<GCMGauge<LabelTypes...>> gauge_;

  DISALLOW_COPY_AND_ASSIGN(GCMCounter);
};


// static
template <class... LabelTypes>
GCMCounter<LabelTypes...>* GCMCounter<LabelTypes...>::New(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... labels,
    const std::string& help) {
  return new GCMCounter(name, labels..., help);
}


template <class... LabelTypes>
GCMCounter<LabelTypes...>::GCMCounter(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... labels,
    const std::string& help)
    : Counter<LabelTypes...>(name, labels..., help),
      gauge_(GCMGauge<LabelTypes...>::New(name, labels..., help)) {
}


template <class... LabelTypes>
void GCMCounter<LabelTypes...>::Export(std::ostream* os) const {
  std::lock_guard<std::mutex> lock(mutex_);
  gauge_->Export(os);
}


template <class... LabelTypes>
void GCMCounter<LabelTypes...>::ExportText(std::ostream* os) const {
  std::lock_guard<std::mutex> lock(mutex_);
  gauge_->ExportText(os);
}


template <class... LabelTypes>
void GCMCounter<LabelTypes...>::Increment(const LabelTypes&... labels) {
  IncrementBy(labels..., 1);
}


template <class... LabelTypes>
void GCMCounter<LabelTypes...>::IncrementBy(const LabelTypes&... labels,
                                            double amount) {
  std::lock_guard<std::mutex> lock(mutex_);
  gauge_->Set(labels..., gauge_->Get(labels...) + amount);
}


template <class... LabelTypes>
double GCMCounter<LabelTypes...>::Get(const LabelTypes&... labels) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return gauge_->Get(labels...);
}


}  // namespace cert_trans

#endif  // CERT_TRANS_MONITORING_GCM_COUNTER_H_
