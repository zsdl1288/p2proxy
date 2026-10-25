#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

#include "util.h"

namespace p2px {

// Loss of the packets one side sends, and round-trip time and jitter, over
// the last 30 seconds. Each side can only measure the direction it sends;
// the other direction comes from the peer (see kStats).
class LinkMeter {
public:
  // Cumulative counters from msquic: packets sent, and packets lost (suspected
  // minus those later found not lost).
  void addCounters(uint64_t sent, uint64_t lost) {
    std::lock_guard lk(mu_);
    uint64_t now = msNow();
    pts_.push_back({now, sent, lost});
    while (pts_.size() > 2 && now - pts_[1].t >= kWindowMs) pts_.pop_front();
  }

  void addRtt(double ms) {
    std::lock_guard lk(mu_);
    uint64_t now = msNow();
    rtts_.push_back({now, ms});
    while (!rtts_.empty() && now - rtts_.front().t > kWindowMs) rtts_.pop_front();
  }

  void clear() {
    std::lock_guard lk(mu_);
    pts_.clear();
    rtts_.clear();
  }

  // Percent of sent packets lost; -1 when too little was sent to tell.
  double lossPct() const {
    std::lock_guard lk(mu_);
    if (pts_.size() < 2) return -1;
    uint64_t sent = pts_.back().sent - pts_.front().sent;
    if (sent < kMinPackets) return -1;
    int64_t lost = (int64_t)pts_.back().lost - (int64_t)pts_.front().lost;
    return std::max<int64_t>(lost, 0) * 100.0 / sent;
  }

  // Mean difference between consecutive round trips; -1 without enough samples.
  double jitterMs() const {
    std::lock_guard lk(mu_);
    if (rtts_.size() < 3) return -1;
    double sum = 0;
    for (size_t i = 1; i < rtts_.size(); i++) sum += std::fabs(rtts_[i].ms - rtts_[i - 1].ms);
    return sum / (rtts_.size() - 1);
  }

  // Median round trip; -1 without samples.
  double rttMs() const {
    std::lock_guard lk(mu_);
    if (rtts_.empty()) return -1;
    std::vector<double> v;
    for (auto& r : rtts_) v.push_back(r.ms);
    std::nth_element(v.begin(), v.begin() + v.size() / 2, v.end());
    return v[v.size() / 2];
  }

private:
  static constexpr uint64_t kWindowMs = 30000, kMinPackets = 200;
  struct Point {
    uint64_t t, sent, lost;
  };
  struct Sample {
    uint64_t t;
    double ms;
  };
  mutable std::mutex mu_;
  std::deque<Point> pts_;
  std::deque<Sample> rtts_;
};

// Packets msquic really lost (suspected minus spurious).
inline uint64_t lostPackets(uint64_t suspected, uint64_t spurious) {
  return suspected > spurious ? suspected - spurious : 0;
}

} // namespace p2px
