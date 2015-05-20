#ifndef CERT_TRANS_MONITORING_GCM_GAUGE_H_
#define CERT_TRANS_MONITORING_GCM_GAUGE_H_

#include "monitoring/gauge.h"

#include <chrono>
#include <mutex>
#include <string>

#include "base/macros.h"

namespace cert_trans {

static const char kCustomMonitoringRoot[] =
    "custom.cloudmonitoring.googleapis.com/certificate-transparency.org/"
    "super-duper/";


template <class... LabelTypes>
class GCMGauge : public Gauge<LabelTypes...> {
 public:
  static GCMGauge<LabelTypes...>* New(
      const std::string& name,
      const typename NameType<LabelTypes>::name&... labels,
      const std::string& help);

  void Export(std::ostream* os) const override;

  void ExportText(std::ostream* os) const override;

  double Get(const LabelTypes&...) const override;

  void Set(const LabelTypes&... labels, double value) override;

 protected:
  mutable std::mutex mutex_;

 private:
  GCMGauge(const std::string& name,
           const typename NameType<LabelTypes>::name&... labels,
           const std::string& help);

  std::map<std::tuple<LabelTypes...>, double> values_;

  DISALLOW_COPY_AND_ASSIGN(GCMGauge);
};


namespace {


template <std::size_t>
struct i__ {};


template <class Tuple>
void label_values(const Tuple& t, std::vector<std::string>* values, i__<0>) {
}


template <class Tuple, size_t Pos>
void label_values(const Tuple& t, std::vector<std::string>* values, i__<Pos>) {
  std::ostringstream oss;
  oss << std::get<std::tuple_size<Tuple>::value - Pos>(t);
  CHECK_NOTNULL(values)->push_back(oss.str());
  label_values(t, values, i__<Pos - 1>());
}


template <class... Types>
std::vector<std::string> label_values(const std::tuple<Types...>& t) {
  std::vector<std::string> ret;
  label_values(t, &ret, i__<sizeof...(Types)>());
  return ret;
}


inline std::string RFC3339Time(
    const std::chrono::system_clock::time_point& when) {
  const std::time_t now_c(std::chrono::system_clock::to_time_t(when));
  char buf[256];
  CHECK(std::strftime(buf, sizeof(buf), "%FT%T.00Z", std::localtime(&now_c)));
  return buf;
}


}  // namespace


// static
template <class... LabelTypes>
GCMGauge<LabelTypes...>* GCMGauge<LabelTypes...>::New(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... labels,
    const std::string& help) {
  return new GCMGauge(name, labels..., help);
}


template <class... LabelTypes>
GCMGauge<LabelTypes...>::GCMGauge(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... labels,
    const std::string& help)
    : Gauge<LabelTypes...>(name, labels..., help) {
}


template <class... LabelTypes>
void GCMGauge<LabelTypes...>::Export(std::ostream* os) const {
  const std::string timestamp(RFC3339Time(std::chrono::system_clock::now()));

  std::unique_lock<std::mutex> lock(mutex_);

  for (const auto& p : values_) {
    const std::vector<std::string> label_strings(label_values(p.first));
    CHECK_EQ(label_strings.size(), this->LabelNames().size());
    *os << "{\n";
    *os << "  \"timeseriesDesc\": {\n";
    *os << "    \"metric\": \"" << kCustomMonitoringRoot << this->Name()
        << "\",\n";
    *os << "    \"labels\": {\n";

    for (int i(0); i < label_strings.size(); ++i) {
      *os << "      \"" << this->LabelName(i) << "\": \"" << label_strings[i]
          << "\",\n";
    }

    *os << "    },\n";  // labels
    *os << "  },\n";    // timeseriesDesc
    *os << "  \"point\": {\n";
    *os << "    \"start\": \"" << timestamp << "\",\n";
    *os << "    \"end\": \"" << timestamp << "\",\n";
    *os << "    \"doubleValue\": \"" << p.second << "\",\n";
    *os << "  },\n";  // point
    *os << "},\n";
  }
}


template <class... LabelTypes>
void GCMGauge<LabelTypes...>::ExportText(std::ostream* os) const {
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& p : values_) {
    const std::vector<std::string> label_strings(label_values(p.first));
    CHECK_EQ(label_strings.size(), this->LabelNames().size());
    *os << this->Name() << "{";
    for (int i(0); i < label_strings.size(); ++i) {
      *os << this->LabelName(i) << "=" << label_strings[i];
      if (i < label_strings.size() - 1) {
        *os << ",";
      }
    }
    *os << "} = " << p.second << "\n";
  }
}


template <class... LabelTypes>
double GCMGauge<LabelTypes...>::Get(const LabelTypes&... labels) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const std::tuple<LabelTypes...> key(labels...);
  const auto it(values_.find(key));
  if (it == values_.end()) {
    return 0;
  }
  return it->second;
}


template <class... LabelTypes>
void GCMGauge<LabelTypes...>::Set(const LabelTypes&... labels, double value) {
  std::lock_guard<std::mutex> lock(mutex_);
  values_[std::tuple<LabelTypes...>(labels...)] = value;
}


}  // namespace cert_trans


#endif  // CERT_TRANS_MONITORING_GCM_GAUGE_H_
