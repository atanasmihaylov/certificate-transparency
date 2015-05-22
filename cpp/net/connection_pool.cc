#include "net/connection_pool.h"

#include <gflags/gflags.h>
#include <glog/logging.h>

using std::bind;
using std::lock_guard;
using std::move;
using std::mutex;
using std::pair;
using std::string;
using std::unique_ptr;

DEFINE_int32(url_fetcher_max_conn_per_host_port, 4,
             "maximum number of URL fetcher connections per host:port");

namespace cert_trans {
namespace internal {

ConnectionPool::Connection::Connection(evhtp_connection_t* conn,
                                       HostPortPair&& other_end)
    : conn_(CHECK_NOTNULL(conn)), other_end_(other_end) {
}


const HostPortPair& ConnectionPool::Connection::other_end() const {
  return other_end_;
}


ConnectionPool::ConnectionPool(libevent::Base* base)
    : base_(CHECK_NOTNULL(base)), cleanup_scheduled_(false) {
}


unique_ptr<ConnectionPool::Connection> ConnectionPool::Get(const URL& url) {
  // TODO(pphaneuf): Add support for other protocols.
  CHECK_EQ(url.Protocol(), "http");
  HostPortPair key(url.Host(), url.Port() != 0 ? url.Port() : 80);
  lock_guard<mutex> lock(lock_);

  auto it(conns_.find(key));
  if (it == conns_.end() || it->second.empty()) {
    VLOG(1) << "new evhtp_connection for " << key.first << ":" << key.second;
    return unique_ptr<ConnectionPool::Connection>(
        new Connection(base_->HttpConnectionNew(key.first, key.second),
                       move(key)));
  }

  VLOG(1) << "cached evhtp_connection for " << key.first << ":" << key.second;
  unique_ptr<ConnectionPool::Connection> retval(move(it->second.back()));
  it->second.pop_back();

  return retval;
}


void ConnectionPool::Put(unique_ptr<ConnectionPool::Connection>&& conn) {
  if (!conn) {
    VLOG(1) << "returned null Connection";
    return;
  }

  const HostPortPair& key(conn->other_end());
  VLOG(1) << "returned Connection for " << key.first << ":" << key.second;
  lock_guard<mutex> lock(lock_);
  auto& entry(conns_[key]);

  CHECK_GE(FLAGS_url_fetcher_max_conn_per_host_port, 0);
  entry.emplace_back(move(conn));
  if (!cleanup_scheduled_ &&
      entry.size() >
          static_cast<uint>(FLAGS_url_fetcher_max_conn_per_host_port)) {
    cleanup_scheduled_ = true;
    base_->Add(bind(&ConnectionPool::Cleanup, this));
  }
}


void ConnectionPool::Cleanup() {
  lock_guard<mutex> lock(lock_);
  cleanup_scheduled_ = false;

  // std::map<HostPortPair, std::deque<unique_ptr<Connection>>> conns_;
  for (auto& entry : conns_) {
    while (entry.second.size() >
           static_cast<uint>(FLAGS_url_fetcher_max_conn_per_host_port)) {
      entry.second.pop_front();
    }
  }

}


}  // namespace internal
}  // namespace cert_trans
