/* dio.cc
 * -----------------------------------------
 * Wireless RPL-DIO Replay Attack Simulation
 * -----------------------------------------
 * - Root node sends DIO messages (deterministic or randomized)
 * - Attacker captures and replays them
 * - DRM component detects duplicates, increments suspicion, and blacklists
 * - Simulation uses WiFi ad-hoc network, so only nearby nodes receive replays
 *
 * Build: ./waf build
 * Run example (attack + mitigation):
 * ./waf --run "scratch/dio --deterministicRoot=true --randomizeAttacker=false --disableRootProtection=false --simTime=80 --attackStart=12 --attackerRate=5"
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/udp-socket-factory.h"

#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <cstdlib>
#include <ctime>
#include <algorithm>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("RplDioReplayDemo");

// ===================================================
// Helper: CRC16 (XMODEM)
// ===================================================
uint16_t Crc16(const uint8_t *data, size_t len) {
  uint16_t crc = 0x0000;
  for (size_t i = 0; i < len; ++i) {
    crc ^= (uint16_t)data[i] << 8;
    for (int j = 0; j < 8; ++j)
      crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1;
  }
  return crc & 0xFFFF;
}

// ===================================================
// DRM (Detection & Response Module)
// ===================================================
struct DrmNeighborInfo {
  uint16_t dio_hash[8];
  Time dio_ts[8];
  uint8_t cache_idx = 0;
  uint8_t suspicion = 0;
  Time blacklist_until = Seconds(0);
  Time last_seen = Seconds(0);
  DrmNeighborInfo() {
    for (int i = 0; i < 8; ++i) dio_hash[i] = 0;
  }
};

class DrmComponent : public Object {
public:
  DrmComponent(Ptr<Node> node) : m_node(node) {}
  void Setup(Ptr<Ipv4> ipv4);
  void SetRootIp(const std::string &rootIp) { m_rootIp = rootIp; }
  void SetDisableRootProtection(bool v) { m_disableRootProtection = v; }
  void SendDioBroadcast(const std::vector<uint8_t>& payload);
  void RecvDio(Ptr<Socket> sock);
  uint32_t GetControlDioCount() const { return m_controlDioCount; }
  uint32_t GetDroppedDioCount() const { return m_droppedDioCount; }

  // New metric getters
  uint32_t GetSuspiciousEvents() const { return m_suspiciousEvents; }
  uint32_t GetBlacklistCount() const { return m_blacklistCount; }
  Time GetFirstBlacklistTime() const { return m_firstBlacklistTime; }
  uint32_t GetTotalReceived() const { return m_totalReceived; }
  uint32_t GetDroppedDueToMitigation() const { return m_droppedDueToMitigation; }
  uint8_t GetSuspicionForNode(const std::string &ip) {
      return m_neighbors.count(ip) ? m_neighbors.at(ip).suspicion : 0;
  }

private:
  void PruneGlobal(Time now);

  Ptr<Node> m_node;
  Ptr<Ipv4> m_ipv4;
  Ptr<Socket> m_socket;
  std::map<std::string, DrmNeighborInfo> m_neighbors;
  std::map<uint16_t, std::pair<std::string, Time>> m_recentGlobal;

  uint32_t m_controlDioCount = 0;
  uint32_t m_droppedDioCount = 0;
  uint64_t m_recvCounter = 0;
  std::string m_rootIp;
  bool m_disableRootProtection = false;

  // Metrics added
  uint32_t m_suspiciousEvents = 0;
  uint32_t m_blacklistCount = 0;
  Time m_firstBlacklistTime = Seconds(-1);
  uint32_t m_totalReceived = 0;

  // New: count only drops caused by DRM mitigation (blacklist/replay)
  uint32_t m_droppedDueToMitigation = 0;
};

void DrmComponent::Setup(Ptr<Ipv4> ipv4) {
  m_ipv4 = ipv4;
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  m_socket = Socket::CreateSocket(m_node, tid);
  InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 12345);
  m_socket->Bind(local);
  m_socket->SetRecvCallback(MakeCallback(&DrmComponent::RecvDio, this));
}

void DrmComponent::SendDioBroadcast(const std::vector<uint8_t>& payload) {
  Ptr<Socket> tx = Socket::CreateSocket(m_node, UdpSocketFactory::GetTypeId());
  tx->SetAllowBroadcast(true);
  InetSocketAddress dst = InetSocketAddress(Ipv4Address("255.255.255.255"), 12345);
  tx->Connect(dst);
  Ptr<Packet> p = Create<Packet>(payload.data(), payload.size());
  tx->Send(p);
  tx->Close();
  m_controlDioCount++;
}

void DrmComponent::RecvDio(Ptr<Socket> sock) {
  Address from;
  Ptr<Packet> packet = sock->RecvFrom(from);
  InetSocketAddress addr = InetSocketAddress::ConvertFrom(from);
  Ipv4Address src = addr.GetIpv4();
  std::ostringstream oss; oss << src; std::string key = oss.str();

  uint32_t pktSize = packet->GetSize();
  std::vector<uint8_t> buf(pktSize);
  packet->CopyData(buf.data(), pktSize);
  uint16_t h = Crc16(buf.data(), buf.size());
  Time now = Simulator::Now();
  m_recvCounter++;

  // metric: total received DIOs by this DRM
  m_totalReceived++;

  auto it = m_neighbors.find(key);
  if (it == m_neighbors.end()) m_neighbors[key] = DrmNeighborInfo();
  DrmNeighborInfo &info = m_neighbors[key];

  // If mitigation is disabled, simply accept and store the hash (no detection)
  if (m_disableRootProtection) {
    // store for completeness (so neighbor stats still exist)
    info.dio_hash[info.cache_idx] = h;
    info.dio_ts[info.cache_idx] = now;
    info.cache_idx = (info.cache_idx + 1) % 8;
    NS_LOG_INFO("Node " << m_node->GetId() << " (DRM disabled) accepted DIO from " << key);
    return;
  }

  // blacklisted sender
  if (info.blacklist_until > now) {
    NS_LOG_INFO("Node " << m_node->GetId() << " DROPPED DIO from " << key << " (blacklisted)");
    m_droppedDioCount++;
    m_droppedDueToMitigation++; // count this as mitigation drop
    return;
  }

  // global duplicate detection
  auto g = m_recentGlobal.find(h);
  if (g != m_recentGlobal.end() && (now - g->second.second) < Seconds(60)) {
    std::string lastSrc = g->second.first;
    if (lastSrc != key) {
      NS_LOG_WARN("Node " << m_node->GetId() << " detected cross-source replay: " << key << " vs " << lastSrc);
      info.suspicion++;
      m_suspiciousEvents++; // metric
      if (info.suspicion >= 5) {
        info.blacklist_until = now + Seconds(60);
        m_blacklistCount++;
        if (m_firstBlacklistTime == Seconds(-1)) {
            m_firstBlacklistTime = now;
        }
        NS_LOG_WARN("Node " << m_node->GetId() << " blacklisted " << key);
      }
      m_droppedDioCount++;
      m_droppedDueToMitigation++; // count mitigation drop
      return;
    }
  }
  m_recentGlobal[h] = {key, now};

  // same-source duplicates
  bool dup = false;
  for (int i = 0; i < 8; ++i)
    if (info.dio_hash[i] == h && (now - info.dio_ts[i]) < Seconds(60)) dup = true;

  if (dup) {
    double r = (std::rand() % 10000) / 100.0;
    if (r < 30.0) { // 30% suspicion chance
      info.suspicion++;
      m_suspiciousEvents++; // metric
      NS_LOG_WARN("Node " << m_node->GetId() << " suspicious same-source from " << key << " susp=" << (int)info.suspicion);
      if (info.suspicion >= 5) {
        info.blacklist_until = now + Seconds(60);
        m_blacklistCount++;
        if (m_firstBlacklistTime == Seconds(-1)) {
            m_firstBlacklistTime = now;
        }
        NS_LOG_WARN("Node " << m_node->GetId() << " blacklisted " << key);
      }
    }
    m_droppedDioCount++;
    m_droppedDueToMitigation++; // count mitigation drop
    return;
  } else {
    info.dio_hash[info.cache_idx] = h;
    info.dio_ts[info.cache_idx] = now;
    info.cache_idx = (info.cache_idx + 1) % 8;
    NS_LOG_INFO("Node " << m_node->GetId() << " accepted DIO from " << key);
  }
}

void DrmComponent::PruneGlobal(Time now) {
  for (auto it = m_recentGlobal.begin(); it != m_recentGlobal.end();) {
    if ((now - it->second.second) > Seconds(60)) it = m_recentGlobal.erase(it);
    else ++it;
  }
}

// ===================================================
// DioRootApp (root node)
// ===================================================
class DioRootApp : public Application {
public:
  DioRootApp() {}
  void Setup(Ptr<DrmComponent> drm, Time interval, bool deterministic) {
    m_drm = drm; m_interval = interval; m_deterministic = deterministic;
  }
  void StartApplication() override { SendDio(); }
  void StopApplication() override { Simulator::Cancel(m_event); }

private:
  void SendDio() {
    uint8_t payload[8];
    if (m_deterministic) {
      uint8_t fixed[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44};
      memcpy(payload, fixed, 8);
    } else {
      for (int i = 0; i < 8; ++i) payload[i] = std::rand() % 256;
    }
    std::vector<uint8_t> vec(payload, payload + 8);
    m_drm->SendDioBroadcast(vec);
    NS_LOG_INFO("Root sent DIO (hash=" << Crc16(vec.data(), vec.size()) << ") t=" << Simulator::Now().GetSeconds());
    m_event = Simulator::Schedule(m_interval, &DioRootApp::SendDio, this);
  }
  Ptr<DrmComponent> m_drm;
  EventId m_event;
  Time m_interval;
  bool m_deterministic;
};

// ===================================================
// Attacker (captures and replays DIOs)
// ===================================================
class AttackerApp : public Application {
public:
  AttackerApp() {}
  void Setup(Ptr<Node> node, double rate, Time start, bool perturb) {
    m_node = node; m_rate = rate; m_start = start; m_perturb = perturb;
  }
  void StartApplication() override {
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    m_socket = Socket::CreateSocket(m_node, tid);
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 12345);
    m_socket->Bind(local);
    m_socket->SetRecvCallback(MakeCallback(&AttackerApp::RecvDio, this));
    Simulator::Schedule(m_start, &AttackerApp::Replay, this);
  }
  void StopApplication() override { if (m_socket) m_socket->Close(); }

private:
  void RecvDio(Ptr<Socket> sock) {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    std::vector<uint8_t> buf(p->GetSize()); p->CopyData(buf.data(), buf.size());
    m_last = buf;
    NS_LOG_INFO("Attacker captured DIO len=" << buf.size());
  }
  void Replay() {
    if (m_last.empty()) { Simulator::Schedule(Seconds(0.5), &AttackerApp::Replay, this); return; }
    std::vector<uint8_t> msg = m_last;
    if (m_perturb && !msg.empty()) msg[std::rand() % msg.size()] ^= (std::rand() % 4);
    Ptr<Socket> tx = Socket::CreateSocket(m_node, UdpSocketFactory::GetTypeId());
    tx->SetAllowBroadcast(true);
    InetSocketAddress dst = InetSocketAddress(Ipv4Address("255.255.255.255"), 12345);
    tx->Connect(dst);
    Ptr<Packet> pkt = Create<Packet>(msg.data(), msg.size());
    tx->Send(pkt);
    tx->Close();
    Simulator::Schedule(Seconds(1.0 / m_rate), &AttackerApp::Replay, this);
  }

  Ptr<Node> m_node;
  Ptr<Socket> m_socket;
  std::vector<uint8_t> m_last;
  double m_rate;
  Time m_start;
  bool m_perturb;
};

// ===================================================
// main()
// ===================================================
int main(int argc, char *argv[]) {
  uint32_t nNodes = 20;
  double spacing = 20.0;
  uint32_t gridWidth = 5;
  double simTime = 60.0;
  bool deterministicRoot = true;
  bool randomizeAttacker = false;
  bool disableRootProtection = true;
  double attackerRate = 5.0;
  double attackStart = 12.0;

  CommandLine cmd;
  cmd.AddValue("nNodes", "Number of nodes", nNodes);
  cmd.AddValue("spacing", "Grid spacing (m)", spacing);
  cmd.AddValue("gridWidth", "Nodes per row", gridWidth);
  cmd.AddValue("simTime", "Simulation time", simTime);
  cmd.AddValue("deterministicRoot", "Fixed DIO payloads (true/false)", deterministicRoot);
  cmd.AddValue("randomizeAttacker", "Replay with small changes", randomizeAttacker);
  cmd.AddValue("disableRootProtection", "Disable root protection", disableRootProtection);
  cmd.AddValue("attackerRate", "Replay rate", attackerRate);
  cmd.AddValue("attackStart", "Replay start time", attackStart);
  cmd.Parse(argc, argv);

  std::srand((unsigned)time(nullptr));
  LogComponentEnable("RplDioReplayDemo", LOG_LEVEL_INFO);

  NodeContainer nodes;
  nodes.Create(nNodes);

  // WiFi setup
  YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy;
  phy.SetChannel(channel.Create());
  WifiHelper wifi;
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                               "DataMode", StringValue("OfdmRate6Mbps"),
                               "ControlMode", StringValue("OfdmRate6Mbps"));
  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");
  NetDeviceContainer devs = wifi.Install(phy, mac, nodes);

  // Mobility setup
  MobilityHelper mobility;
  mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                "MinX", DoubleValue(0.0),
                                "MinY", DoubleValue(0.0),
                                "DeltaX", DoubleValue(spacing),
                                "DeltaY", DoubleValue(spacing),
                                "GridWidth", UintegerValue(gridWidth),
                                "LayoutType", StringValue("RowFirst"));
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(nodes);

  // IP stack
  InternetStackHelper internet;
  internet.Install(nodes);
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer ifs = ipv4.Assign(devs);

  // DRM setup
  std::vector<Ptr<DrmComponent>> drm(nNodes);
  for (uint32_t i = 0; i < nNodes; ++i) {
    Ptr<DrmComponent> c = CreateObject<DrmComponent>(nodes.Get(i));
    c->Setup(nodes.Get(i)->GetObject<Ipv4>());
    c->SetDisableRootProtection(disableRootProtection);
    drm[i] = c;
  }

  // Root node
  Ptr<DioRootApp> root = CreateObject<DioRootApp>();
  root->Setup(drm[0], Seconds(5.0), deterministicRoot);
  nodes.Get(0)->AddApplication(root);
  root->SetStartTime(Seconds(1.0));
  root->SetStopTime(Seconds(simTime));

  // Attacker (last node)
  Ptr<AttackerApp> attacker = CreateObject<AttackerApp>();
  attacker->Setup(nodes.Get(nNodes - 1), attackerRate, Seconds(attackStart), randomizeAttacker);
  nodes.Get(nNodes - 1)->AddApplication(attacker);
  attacker->SetStartTime(Seconds(0.5));
  attacker->SetStopTime(Seconds(simTime));

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();

  uint32_t totalControl = 0, totalDropped = 0;
  for (auto &d : drm) {
    totalControl += d->GetControlDioCount();
    totalDropped += d->GetDroppedDioCount();
  }

  // New mitigation-only counts
  uint32_t totalMitigationDrops = 0;
  for (auto &d : drm) {
    totalMitigationDrops += d->GetDroppedDueToMitigation();
  }

  std::cout << "\n=== SIMULATION COMPLETE ===\n";
  std::cout << "Total DIOs processed: " << totalControl << "\n";
  std::cout << "Total DIOs dropped (blacklisted + others): " << totalDropped << "\n";
  std::cout << "DIOs dropped due to mitigation: " << totalMitigationDrops << "\n";
  std::cout << "Attack rate: " << attackerRate << " per sec, started at " << attackStart << "s\n";

  // New aggregated metrics
  uint32_t totalSuspicious = 0;
  uint32_t totalBlacklists = 0;
  uint32_t totalReceivedDios = 0;
  Time earliestDetection = Seconds(-1);

  for (auto &d : drm) {
    totalSuspicious += d->GetSuspiciousEvents();
    totalBlacklists += d->GetBlacklistCount();
    totalReceivedDios += d->GetTotalReceived();

    Time t = d->GetFirstBlacklistTime();
    if (t != Seconds(-1)) {
      if (earliestDetection == Seconds(-1) || t < earliestDetection)
        earliestDetection = t;
    }
  }

  std::cout << "Total DIOs received: " << totalReceivedDios << "\n";
  std::cout << "Total suspicious events: " << totalSuspicious << "\n";
  std::cout << "Total blacklist events: " << totalBlacklists << "\n";

  if (earliestDetection != Seconds(-1))
    std::cout << "Detection time (first blacklist): " << earliestDetection.GetSeconds() << "s\n";
  else
    std::cout << "Detection time: NONE (no node blacklisted attacker)\n";

  std::cout << "============================\n";

  Simulator::Destroy();
}
