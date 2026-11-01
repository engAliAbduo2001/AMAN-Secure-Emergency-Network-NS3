#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"
#include "ns3/energy-module.h"
#include "ns3/wifi-radio-energy-model-helper.h"
#include "ns3/traffic-control-module.h"
#include <iomanip>
#include <fstream>
#include <map>
#include <string>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("AmanEmergencyNetwork");

#define AES_OVERHEAD      16
#define HMAC_OVERHEAD     32
#define SECURITY_OVERHEAD (AES_OVERHEAD + HMAC_OVERHEAD)

// ================================================================
//  IDS — Dynamic Trace Sources
// ================================================================
struct NodeTrafficStats {
  uint64_t txCount   = 0;
  uint64_t dropCount = 0;
};

std::map<uint32_t, NodeTrafficStats> g_trafficStats;
static bool g_blackholeActive = false;

void OnMacTx (uint32_t nodeId, Ptr<const Packet> packet)
{
  g_trafficStats[nodeId].txCount++;
}

void OnMacTxDrop (uint32_t nodeId, Ptr<const Packet> packet)
{
  g_trafficStats[nodeId].dropCount++;
}

void ConnectIdsTraces (NodeContainer nodes)
{
  for (uint32_t i = 0; i < nodes.GetN (); ++i)
    {
      Ptr<Node> node = nodes.Get (i);
      uint32_t  nid  = node->GetId ();
      for (uint32_t d = 0; d < node->GetNDevices (); ++d)
        {
          Ptr<NetDevice> dev = node->GetDevice (d);
          dev->TraceConnectWithoutContext (
              "MacTx",     MakeBoundCallback (&OnMacTx,     nid));
          dev->TraceConnectWithoutContext (
              "MacTxDrop", MakeBoundCallback (&OnMacTxDrop, nid));
        }
    }
}

// ================================================================
//  Malicious QueueDisc (IP-Level Data Filter)
// ================================================================
class BlackholeQueueDisc : public QueueDisc {
private:
  uint32_t m_nodeId; 

public:
  static TypeId GetTypeId (void)
  {
    static TypeId tid = TypeId ("ns3::BlackholeQueueDisc")
      .SetParent<QueueDisc> ()
      .AddConstructor<BlackholeQueueDisc> ();
    return tid;
  }

  BlackholeQueueDisc () : m_nodeId (0) {} 
  virtual ~BlackholeQueueDisc () {}

  void SetNodeId (uint32_t id)
  {
    m_nodeId = id;
  }

  virtual bool DoEnqueue (Ptr<QueueDiscItem> item) override
  {
    if (g_blackholeActive)
      {
        Ptr<Ipv4QueueDiscItem> ipItem = DynamicCast<Ipv4QueueDiscItem> (item);
        if (ipItem)
          {
            if (ipItem->GetHeader ().GetProtocol () == 17) 
              {
                if (item->GetPacket ()->GetSize () > 200)
                  {
                    DropBeforeEnqueue (item, "BlackholeDrop");
                    g_trafficStats[m_nodeId].dropCount++;
                    return false; 
                  }
              }
          }
      }
    return GetInternalQueue (0)->Enqueue (item);
  }

  virtual Ptr<QueueDiscItem> DoDequeue (void) override
  {
    if (GetInternalQueue (0)->GetNPackets () > 0)
      {
        return GetInternalQueue (0)->Dequeue ();
      }
    return nullptr;
  }

  virtual Ptr<const QueueDiscItem> DoPeek (void) override
  {
    if (GetInternalQueue (0)->GetNPackets () > 0)
      {
        return GetInternalQueue (0)->Peek ();
      }
    return nullptr;
  }

  virtual bool CheckConfig (void) override
  {
    if (GetNInternalQueues () == 0)
      {
        AddInternalQueue (CreateObject<DropTailQueue<QueueDiscItem>> ());
      }
    return true;
  }

  virtual void InitializeParams (void) override {}
};

// ================================================================
//  IDS Report
// ================================================================
void PrintIDSReport (bool blackholeEnabled)
{
  std::cout << "\n+--------------------------------------------------+\n";
  std::cout <<   "|        [IDS] تقرير كشف الاختراق النهائي          |\n";
  std::cout <<   "+--------------------------------------------------+\n";
  std::cout << std::left
            << std::setw (8)  << "Node"
            << std::setw (12) << "TX"
            << std::setw (12) << "Drop"
            << std::setw (10) << "Drop%"
            << "Status\n";
  std::cout << std::string (56, '-') << "\n";

  uint32_t detected = 0;
  for (auto &kv : g_trafficStats)
    {
      uint32_t id    = kv.first;
      uint64_t tx    = kv.second.txCount;
      uint64_t drop  = kv.second.dropCount;
      uint64_t total = tx + drop;
      double ratio   = (total > 0) ? ((double)drop / total) : 0.0;

      bool suspect = (total >= 5) && (ratio > 0.50);
      if (suspect) detected++;

      std::cout << std::left
                << std::setw (8)  << id
                << std::setw (12) << tx
                << std::setw (12) << drop
                << std::setw (9)  << std::fixed << std::setprecision (1)
                                  << (ratio * 100.0) << "%"
                << (suspect ? "  *** BLACKHOLE DETECTED ***" : "  OK")
                << "\n";
    }
  std::cout << std::string (56, '-') << "\n";
  std::cout << "  Blackhole nodes detected: " << detected << "\n";
  std::cout << std::string (56, '=') << "\n\n";
}

// ================================================================
//  Blackhole Setup
// ================================================================
void InstallBlackholeOnNodes (NodeContainer bhNodes)
{
  BlackholeQueueDisc::GetTypeId ();
  g_blackholeActive = true;

  for (uint32_t i = 0; i < bhNodes.GetN (); ++i)
    {
      Ptr<Node> bhNode = bhNodes.Get (i);
      Ptr<NetDevice> dev = bhNode->GetDevice (0);
      
      TrafficControlHelper tch;
      tch.Uninstall (dev);
      tch.SetRootQueueDisc ("ns3::BlackholeQueueDisc");
      QueueDiscContainer qdc = tch.Install (dev);
      
      Ptr<BlackholeQueueDisc> bq = DynamicCast<BlackholeQueueDisc> (qdc.Get (0));
      if (bq)
        {
          bq->SetNodeId (bhNode->GetId ());
        }
      
      std::cout << "[Blackhole] *** Attack ACTIVE on node "
                << bhNode->GetId ()
                << " — Routing intact, dropping DATA packets ***\n";
    }
  std::cout << "\n";
}

// ================================================================
//  Energy Model
// ================================================================
void InstallEnergyModel (NodeContainer      mobileNodes,
                         NetDeviceContainer mobileDevices)
{
  BasicEnergySourceHelper energyHelper;
  energyHelper.Set ("BasicEnergySourceInitialEnergyJ", DoubleValue (100.0));
  EnergySourceContainer sources = energyHelper.Install (mobileNodes);

  WifiRadioEnergyModelHelper radioHelper;
  radioHelper.Set ("TxCurrentA",   DoubleValue (0.0174));
  radioHelper.Set ("RxCurrentA",   DoubleValue (0.0197));
  radioHelper.Set ("IdleCurrentA", DoubleValue (0.0030));
  radioHelper.Install (mobileDevices, sources);

  std::cout << "[Energy] Model installed on " << mobileNodes.GetN ()
            << " nodes — 100 J each\n\n";
}

// ================================================================
//  Energy Report
// ================================================================
void PrintEnergyReport (NodeContainer mobileNodes,
                        bool enableSecurity,
                        bool enableBlackhole)
{
  std::cout << "\n+--------------------------------------------------+\n";
  std::cout <<   "|         [Energy] تقرير استهلاك الطاقة            |\n";
  std::cout <<   "+--------------------------------------------------+\n";

  double totalInit = 0.0, totalLeft = 0.0;
  for (uint32_t i = 0; i < mobileNodes.GetN (); ++i)
    {
      Ptr<Node> node = mobileNodes.Get (i);
      Ptr<EnergySourceContainer> esc =
          node->GetObject<EnergySourceContainer> ();
      if (!esc || esc->GetN () == 0) continue;
      Ptr<BasicEnergySource> src =
          DynamicCast<BasicEnergySource> (esc->Get (0));
      if (!src) continue;
      totalInit += src->GetInitialEnergy ();
      totalLeft += src->GetRemainingEnergy ();
    }

  double consumed = totalInit - totalLeft;
  double pct = (totalInit > 0) ? (consumed / totalInit * 100.0) : 0.0;

  std::cout << "  Initial energy  : " << totalInit << " J\n";
  std::cout << "  Consumed energy : " << consumed  << " J\n";
  std::cout << "  Remaining energy: " << totalLeft << " J\n";
  std::cout << "  Consumption     : "
            << std::fixed << std::setprecision (2) << pct << "%\n";
  std::cout << std::string (56, '=') << "\n\n";

  std::string energyFile = "energy_aodv";
  if  (enableSecurity && enableBlackhole) energyFile = "energy_secure_bh";
  else if (enableSecurity)               energyFile = "energy_secure";
  else if (enableBlackhole)              energyFile = "energy_blackhole";
  energyFile += ".txt";

  std::ofstream ef (energyFile);
  ef << std::fixed << std::setprecision (4) << pct;
  ef.close ();
  std::cout << "[Energy] Saved to: " << energyFile << "\n\n";
}

// ================================================================
//  main()
// ================================================================
int main (int argc, char *argv[])
{
  bool   enableSecurity  = false;
  bool   enableBlackhole = false;
  double simulationTime  = 50.0;

  CommandLine cmd;
  cmd.AddValue ("security",  "Enable AES+HMAC+IDS",     enableSecurity);
  cmd.AddValue ("blackhole", "Enable Blackhole attack", enableBlackhole);
  cmd.AddValue ("simTime",   "Simulation time (s)",     simulationTime);
  cmd.Parse (argc, argv);

  LogComponentDisableAll (LOG_LEVEL_ALL);

  std::cout << "\n+----------------------------------------------------------------------------------------+\n";
  std::cout <<   "|   شبكة اتصالات طارئة وطنية لتعزيز السلامة والجاهزية في أوقات الكوارث  —  AODV/MANET    |\n";
  std::cout <<   "+----------------------------------------------------------------------------------------+\n";
  std::cout << "  Security : " << (enableSecurity  ? "ON" : "OFF") << "\n";
  std::cout << "  Blackhole: " << (enableBlackhole ? "ON" : "OFF") << "\n";
  std::cout << "  SimTime  : " << simulationTime << " s\n\n";

  // تقليل العقد إلى 51 (50 عقدة طبيعية + 1 خبيثة)
  NodeContainer allNodes;
  allNodes.Create (51);

  NodeContainer groupA;
  for (uint32_t i = 0;  i <= 24; ++i) groupA.Add (allNodes.Get (i));

  NodeContainer groupB;
  for (uint32_t i = 25; i <= 49; ++i) groupB.Add (allNodes.Get (i));

  NodeContainer blackholeNodes;
  blackholeNodes.Add (allNodes.Get (50));

  NodeContainer mobileNodes;
  for (uint32_t i = 0; i <= 49; ++i) mobileNodes.Add (allNodes.Get (i));

  WifiHelper wifi;
  wifi.SetStandard (WIFI_STANDARD_80211b);

  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
  YansWifiPhyHelper wifiPhy;
  wifiPhy.SetChannel (wifiChannel.Create ());
  wifiPhy.Set ("TxPowerStart", DoubleValue (30.0));
  wifiPhy.Set ("TxPowerEnd",   DoubleValue (30.0));

  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac");

  NetDeviceContainer allDevices = wifi.Install (wifiPhy, wifiMac, allNodes);
  NetDeviceContainer mobileDevices;
  for (uint32_t i = 0; i <= 49; ++i)
    mobileDevices.Add (allDevices.Get (i));

  InstallEnergyModel (mobileNodes, mobileDevices);

  MobilityHelper mobility;

  // تثبيت العقدة الخبيثة الوحيدة في المنتصف كعنق زجاجة (X=200, Y=200)
  Ptr<ListPositionAllocator> bhPos = CreateObject<ListPositionAllocator> ();
  bhPos->Add (Vector (200.0, 200.0, 0.0)); // Node 50
  mobility.SetPositionAllocator (bhPos);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (blackholeNodes);

  // المجموعة A تتحرك في المربعين على اليسار (X من 0 إلى 180)
  Ptr<RandomRectanglePositionAllocator> posA = CreateObject<RandomRectanglePositionAllocator> ();
  Ptr<UniformRandomVariable> xA = CreateObject<UniformRandomVariable> ();
  xA->SetAttribute ("Min", DoubleValue (0.0));
  xA->SetAttribute ("Max", DoubleValue (180.0));
  posA->SetX (xA);
  Ptr<UniformRandomVariable> yA = CreateObject<UniformRandomVariable> ();
  yA->SetAttribute ("Min", DoubleValue (0.0));
  yA->SetAttribute ("Max", DoubleValue (400.0));
  posA->SetY (yA);

  mobility.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
                             "Speed", StringValue ("ns3::UniformRandomVariable[Min=2.0|Max=8.0]"),
                             "Pause", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"),
                             "PositionAllocator", PointerValue (posA));
  mobility.Install (groupA);

  // المجموعة B تتحرك في المربعين على اليمين (X من 220 إلى 400)
  Ptr<RandomRectanglePositionAllocator> posB = CreateObject<RandomRectanglePositionAllocator> ();
  Ptr<UniformRandomVariable> xB = CreateObject<UniformRandomVariable> ();
  xB->SetAttribute ("Min", DoubleValue (220.0));
  xB->SetAttribute ("Max", DoubleValue (240.0));
  posB->SetX (xB);
  Ptr<UniformRandomVariable> yB = CreateObject<UniformRandomVariable> ();
  yB->SetAttribute ("Min", DoubleValue (0.0));
  yB->SetAttribute ("Max", DoubleValue (400.0));
  posB->SetY (yB);

  mobility.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
                             "Speed", StringValue ("ns3::UniformRandomVariable[Min=2.0|Max=8.0]"),
                             "Pause", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"),
                             "PositionAllocator", PointerValue (posB));
  mobility.Install (groupB);

  AodvHelper aodv;
  aodv.Set ("HelloInterval",      TimeValue (Seconds (1.0)));
  aodv.Set ("ActiveRouteTimeout", TimeValue (Seconds (10.0)));

  InternetStackHelper internet;
  internet.SetRoutingHelper (aodv);
  internet.Install (allNodes);

  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = ipv4.Assign (allDevices);

  ConnectIdsTraces (allNodes);
  std::cout << "[IDS] Trace Sources connected to "
            << allNodes.GetN () << " nodes\n\n";

  if (enableBlackhole)
    InstallBlackholeOnNodes (blackholeNodes);

  uint16_t port    = 5000;
  uint32_t pktSize = enableSecurity ? (1024 - SECURITY_OVERHEAD) : 1024;

  if (enableSecurity)
    {
      std::cout << "[Security] AES-128  overhead : " << AES_OVERHEAD      << " B/pkt\n";
      std::cout << "[Security] HMAC-256 overhead : " << HMAC_OVERHEAD     << " B/pkt\n";
      std::cout << "[Security] Total    overhead : " << SECURITY_OVERHEAD << " B/pkt\n";
      std::cout << "[Security] Effective pkt size: " << pktSize           << " B\n\n";
    }

  PacketSinkHelper sink ("ns3::UdpSocketFactory",
      InetSocketAddress (Ipv4Address::GetAny (), port));
  ApplicationContainer sinkApps = sink.Install (allNodes.Get (0));
  sinkApps.Start (Seconds (1.0));
  sinkApps.Stop  (Seconds (simulationTime));

  OnOffHelper onoff ("ns3::UdpSocketFactory",
      InetSocketAddress (interfaces.GetAddress (0), port));
  onoff.SetAttribute ("OnTime",
      StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
  onoff.SetAttribute ("OffTime",
      StringValue ("ns3::ExponentialRandomVariable[Mean=0.5]"));
  onoff.SetAttribute ("DataRate",   DataRateValue (DataRate ("10kbps")));
  onoff.SetAttribute ("PacketSize", UintegerValue (pktSize));

  ApplicationContainer clientApps;
  for (uint32_t i = 1; i <= 49; ++i)
    clientApps.Add (onoff.Install (allNodes.Get (i)));
  clientApps.Start (Seconds (2.0));
  clientApps.Stop  (Seconds (simulationTime));

  std::string animFile = "aman-anim"
      + std::string (enableSecurity  ? "-secure"    : "")
      + std::string (enableBlackhole ? "-blackhole" : "")
      + ".xml";

  AnimationInterface anim (animFile);

  for (uint32_t i = 0; i <= 24; ++i)
    {
      anim.UpdateNodeDescription (i, "A" + std::to_string (i));
      anim.UpdateNodeColor (i, 0, 100, 255);
      anim.UpdateNodeSize  (i, 15.0, 15.0);
    }

  for (uint32_t i = 25; i <= 49; ++i)
    {
      anim.UpdateNodeDescription (i, "B" + std::to_string (i));
      anim.UpdateNodeColor (i, 0, 200, 80);
      anim.UpdateNodeSize  (i, 15.0, 15.0);
    }

  // تمييز العقدة الخبيثة باللون الأحمر
  anim.UpdateNodeDescription (50, "BH-1");
  anim.UpdateNodeColor (50, 255, 0, 0); 
  anim.UpdateNodeSize  (50, 35.0, 35.0);
  
  anim.EnablePacketMetadata (true);

  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

  std::cout << "[Sim] Starting simulation (" << simulationTime << "s)...\n\n";
  Simulator::Stop (Seconds (simulationTime));
  Simulator::Run ();

  PrintIDSReport (enableBlackhole);
  PrintEnergyReport (mobileNodes, enableSecurity, enableBlackhole);

  std::string flowFile = "aman-flow-aodv"
      + std::string (enableSecurity  ? "-secure"    : "")
      + std::string (enableBlackhole ? "-blackhole" : "")
      + ".xml";

  monitor->SerializeToXmlFile (flowFile, true, true);
  std::cout << "[Done] Results saved to: " << flowFile << "\n\n";

  Simulator::Destroy ();
  return 0;
}
