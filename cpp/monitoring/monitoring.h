#ifndef CERT_TRANS_MONITORING_MONITORING_H_
#define CERT_TRANS_MONITORING_MONITORING_H_

#include "monitoring/counter.h"
#include "monitoring/gauge.h"

// default concrete implementations:
#include "monitoring/prometheus/counter.h"
#include "monitoring/prometheus/gauge.h"

#include "monitoring/gcm/counter.h"
#include "monitoring/gcm/exporter.h"
#include "monitoring/gcm/gauge.h"

namespace cert_trans {

template <class... LabelTypes>
Counter<LabelTypes...>* Counter<LabelTypes...>::New(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... label_names,
    const std::string& help) {
  // return PrometheusCounter<LabelTypes...>::New(name, label_names..., help);
  return GCMCounter<LabelTypes...>::New(name, label_names..., help);
}


// Default concrete implemenation:
template <class... LabelTypes>
Gauge<LabelTypes...>* Gauge<LabelTypes...>::New(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... label_names,
    const std::string& help) {
  // return PrometheusGauge<LabelTypes...>::New(name, label_names..., help);
  return GCMGauge<LabelTypes...>::New(name, label_names..., help);
}


}  // namespace cert_trans

#endif  // CERT_TRANS_MONITORING_MONITORING_H_
