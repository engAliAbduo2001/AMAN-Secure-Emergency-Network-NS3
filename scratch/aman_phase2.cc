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
//  IDS — Dynamic Trace Sources & Global Stats
// ================================================================
struct NodeTrafficStats {
  uint64_t txCount   = 0;
  uint64_t dropCount = 0;
};

std::map<uint32_t, NodeTrafficStats> g_trafficStats;
static bool g_blackholeActive = false;
static bool g_grayholeActive  = false;

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
//  Malicious QueueDisc (IP-Level Data Filter for Blackhole & Grayhole)
// ================================================================
class MaliciousQueueDisc : public QueueDisc {
private:
  uint32_t                   m_nodeId;
  double                     m_dropProbability; // 1.0 = Blackhole, 0.15 = Grayhole
  Ptr<UniformRandomVariable> m_uv;

public:
  static TypeId GetTypeId (void)
  {
    static TypeId tid = TypeId ("ns3::MaliciousQueueDisc")
      .SetParent<QueueDisc> ()
      .AddConstructor<MaliciousQueueDisc> ();
    return tid;
  }

  MaliciousQueueDisc () : m_nodeId (0), m_dropProbability (1.0)
  {
    m_uv = CreateObject<UniformRandomVariable> ();
  }

  virtual ~MaliciousQueueDisc () {}

  void SetNodeId (uint32_t id)
  {
    m_nodeId = id;
  }

  void SetDropProbability (double prob)
  {
    m_dropProbability = prob;
  }

  virtual bool DoEnqueue (Ptr<QueueDiscItem> item) override
  {
    if (g_blackholeActive || g_grayholeActive)
      {
        Ptr<Ipv4QueueDiscItem> ipItem = DynamicCast<Ipv4QueueDiscItem> (item);
        if (ipItem)
          {
            if (ipItem->GetHeader ().GetProtocol () == 17) // UDP Data
              {
                if (item->GetPacket ()->GetSize () > 200)
                  {
                    double randVal = m_uv->GetValue (0.0, 1.0);
                    if (randVal < m_dropProbability)
                      {
                        DropBeforeEnqueue (item, "MaliciousDrop");
                        g_trafficStats[m_nodeId].dropCount++;
                        return false; 
                      }
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

NS_OBJECT_ENSURE_REGISTERED (MaliciousQueueDisc);

// ================================================================
//  IDS Report (Multi-Threat Detection: Blackhole & Grayhole)
// ================================================================
void PrintIDSReport ()
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

  uint32_t bhDetected = 0;
  uint32_t ghDetected = 0;
  for (auto &kv : g_trafficStats)
    {
      uint32_t id    = kv.first;
      uint64_t tx    = kv.second.txCount;
      uint64_t drop  = kv.second.dropCount;
      uint64_t total = tx + drop;
      double ratio   = (total > 0) ? ((double)drop / total) : 0.0;

      std::string status = "   OK";
      if (total >= 3) // تخفيض العتبة لضمان الكشف في الشبكات الكبيرة
        {
          if (ratio > 0.50)
            {
              status = "   *** BLACKHOLE DETECTED ***";
              bhDetected++;
            }
          else if (ratio >= 0.10)
            {
              status = "   *** GRAYHOLE DETECTED ***";
              ghDetected++;
            }
        }

      std::cout << std::left
                << std::setw (8)  << id
                << std::setw (12) << tx
                << std::setw (12) << drop
                << std::setw (9)  << std::fixed << std::setprecision (1)
                                  << (ratio * 100.0) << "%"
                << status
                << "\n";
    }
  std::cout << std::string (56, '-') << "\n";
  std::cout << "  Blackhole nodes detected: " << bhDetected << "\n";
  std::cout << "  Grayhole nodes detected : " << ghDetected << "\n";
  std::cout << std::string (56, '=') << "\n\n";
}

// ================================================================
//  Malicious Attack Setup (Blackhole & Grayhole)
// ================================================================
void InstallMaliciousNodes (NodeContainer bhNodes, NodeContainer ghNodes, bool enableBH, bool enableGH)
{
  if (enableBH)
    {
      g_blackholeActive = true;
      for (uint32_t i = 0; i < bhNodes.GetN (); ++i)
        {
          Ptr<Node> bhNode = bhNodes.Get (i);
          Ptr<NetDevice> dev = bhNode->GetDevice (0);
          
          TrafficControlHelper tch;
          tch.Uninstall (dev);
          tch.SetRootQueueDisc ("ns3::MaliciousQueueDisc");
          QueueDiscContainer qdc = tch.Install (dev);
          
          Ptr<MaliciousQueueDisc> bq = DynamicCast<MaliciousQueueDisc> (qdc.Get (0));
          if (bq)
            {
              bq->SetNodeId (bhNode->GetId ());
              bq->SetDropProbability (1.0); // 100% Drop
            }
          
          std::cout << "[Blackhole] *** Attack ACTIVE on node "
                    << bhNode->GetId ()
                    << " — Routing intact, dropping 100% DATA packets ***\n";
        }
    }

  if (enableGH)
    {
      g_grayholeActive = true;
      for (uint32_t i = 0; i < ghNodes.GetN (); ++i)
        {
          Ptr<Node> ghNode = ghNodes.Get (i);
          Ptr<NetDevice> dev = ghNode->GetDevice (0);
          
          TrafficControlHelper tch;
          tch.Uninstall (dev);
          tch.SetRootQueueDisc ("ns3::MaliciousQueueDisc");
          QueueDiscContainer qdc = tch.Install (dev);
          
          Ptr<MaliciousQueueDisc> gq = DynamicCast<MaliciousQueueDisc> (qdc.Get (0));
          if (gq)
            {
              gq->SetNodeId (ghNode->GetId ());
              gq->SetDropProbability (0.15); // 15% Selective Drop
            }
          
          std::cout << "[Grayhole] *** Attack ACTIVE on node "
                    << ghNode->GetId ()
                    << " — Routing intact, dropping ~15% DATA packets (Selective) ***\n";
        }
    }
  std::cout << "\n";
}

// ================================================================
//  Energy Model
// ================================================================
void InstallEnergyModel (NodeContainer         mobileNodes,
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
//  Energy Report (Dynamic File Output)
// ================================================================
void PrintEnergyReport (NodeContainer mobileNodes, std::string energyFileName)
{
  std::cout << "\n+--------------------------------------------------+\n";
  std::cout <<   "|          [Energy] تقرير استهلاك الطاقة            |\n";
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

  std::ofstream ef (energyFileName);
  ef << std::fixed << std::setprecision (4) << pct;
  ef.close ();
  std::cout << "[Energy] Saved to: " << energyFileName << "\n\n";
}

// ================================================================
//  main()
// ================================================================
int main (int argc, char *argv[])
{
  bool     enableSecurity  = false;
  bool     enableBlackhole = false;
  bool     enableGrayhole  = false;
  double   simulationTime  = 30.0;
  uint32_t nNodes          = 49; // عدد العقد المتحركة الافتراضي

  CommandLine cmd;
  cmd.AddValue ("security",  "Enable AES+HMAC+IDS",             enableSecurity);
  cmd.AddValue ("blackhole", "Enable Blackhole attack",         enableBlackhole);
  cmd.AddValue ("grayhole",  "Enable Grayhole attack",          enableGrayhole);
  cmd.AddValue ("simTime",   "Simulation time (s)",             simulationTime);
  cmd.AddValue ("nNodes",    "Number of mobile nodes in simulation", nNodes);
  cmd.Parse (argc, argv);

  LogComponentDisableAll (LOG_LEVEL_ALL);

  // توليد الأسماء الديناميكية للملفات لتجنب الكتابة فوق نتائج السيناريوهات
  std::string secTag   = enableSecurity  ? "-secure" : "";
  std::string bhTag    = enableBlackhole ? "-blackhole" : "";
  std::string ghTag    = enableGrayhole  ? "-grayhole" : "";
  std::string nodeTag  = (nNodes != 49)  ? "-" + std::to_string(nNodes) + "nodes" : "";

  std::string xmlFileName    = "aman-flow-aodv" + secTag + bhTag + ghTag + nodeTag + ".xml";
  std::string energyFileName = "energy" + secTag + bhTag + ghTag + nodeTag + ".txt";
  std::string animFile       = "aman-anim" + secTag + bhTag + ghTag + nodeTag + ".xml";

  std::cout << "\n+--------------------------------------------------+\n";
  std::cout <<   "|        شبكة أمان الطوارئ الوطنية  —  AODV/MANET    |\n";
  std::cout <<   "+--------------------------------------------------+\n";
  std::cout << "  Security : " << (enableSecurity  ? "ON" : "OFF") << "\n";
  std::cout << "  Blackhole: " << (enableBlackhole ? "ON" : "OFF") << "\n";
  std::cout << "  Grayhole : " << (enableGrayhole  ? "ON" : "OFF") << "\n";
  std::cout << "  SimTime  : " << simulationTime << " s\n";
  std::cout << "  Nodes    : " << nNodes << " mobile + 2 malicious\n\n";

  // إجمالي العقد = العقد المتحركة + 2 (عقدتان خبيثتان)
  uint32_t totalNodes = nNodes + 2;
  uint32_t ghNodeId   = nNodes;     // معرف عقدة Grayhole
  uint32_t bhNodeId   = nNodes + 1; // معرف عقدة Blackhole

  NodeContainer allNodes;
  allNodes.Create (totalNodes);

  // تقسيم العقد المتحركة ديناميكياً بين المجموعتين A و B
  NodeContainer groupA;
  for (uint32_t i = 0; i < nNodes / 2; ++i) groupA.Add (allNodes.Get (i));

  NodeContainer groupB;
  for (uint32_t i = nNodes / 2; i < nNodes; ++i) groupB.Add (allNodes.Get (i));

  NodeContainer grayholeNodes;
  grayholeNodes.Add (allNodes.Get (ghNodeId));

  NodeContainer blackholeNodes;
  blackholeNodes.Add (allNodes.Get (bhNodeId));

  NodeContainer mobileNodes;
  for (uint32_t i = 0; i < nNodes; ++i) mobileNodes.Add (allNodes.Get (i));

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
  for (uint32_t i = 0; i < nNodes; ++i)
    mobileDevices.Add (allDevices.Get (i));

  InstallEnergyModel (mobileNodes, mobileDevices);

  MobilityHelper mobility;

  // تثبيت العقد الخبيثة في نقاط الاختناق في المنتصف
  Ptr<ListPositionAllocator> bhPos = CreateObject<ListPositionAllocator> ();
  bhPos->Add (Vector (200.0, 200.0, 0.0)); // Blackhole
  mobility.SetPositionAllocator (bhPos);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (blackholeNodes);

  Ptr<ListPositionAllocator> ghPos = CreateObject<ListPositionAllocator> ();
  ghPos->Add (Vector (210.0, 200.0, 0.0)); // Grayhole
  mobility.SetPositionAllocator (ghPos);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (grayholeNodes);

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
  xB->SetAttribute ("Max", DoubleValue (400.0));
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
  aodv.Set ("HelloInterval",   TimeValue (Seconds (1.0)));
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

  if (enableBlackhole || enableGrayhole)
    InstallMaliciousNodes (blackholeNodes, grayholeNodes, enableBlackhole, enableGrayhole);

  uint16_t port    = 5000;
  uint32_t pktSize = enableSecurity ? (1024 - SECURITY_OVERHEAD) : 1024;

  if (enableSecurity)
    {
      std::cout << "[Security] AES-128   overhead : " << AES_OVERHEAD      << " B/pkt\n";
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
  onoff.SetAttribute ("DataRate",   DataRateValue (DataRate ("20kbps"))); // زيادة المعدل لضمان حركة مرور كافية
  onoff.SetAttribute ("PacketSize", UintegerValue (pktSize));

  ApplicationContainer clientApps;
  for (uint32_t i = 1; i < nNodes; ++i)
    clientApps.Add (onoff.Install (allNodes.Get (i)));
  clientApps.Start (Seconds (2.0));
  clientApps.Stop  (Seconds (simulationTime));

  AnimationInterface anim (animFile);

  for (uint32_t i = 0; i < nNodes / 2; ++i)
    {
      anim.UpdateNodeDescription (i, "A" + std::to_string (i));
      anim.UpdateNodeColor (i, 0, 100, 255);
      anim.UpdateNodeSize  (i, 15.0, 15.0);
    }

  for (uint32_t i = nNodes / 2; i < nNodes; ++i)
    {
      anim.UpdateNodeDescription (i, "B" + std::to_string (i));
      anim.UpdateNodeColor (i, 0, 200, 80);
      anim.UpdateNodeSize  (i, 15.0, 15.0);
    }

  // تمييز العقدة 0 كمركز استقبال (Sink/HQ)
  anim.UpdateNodeDescription (0, "Sink-HQ");
  anim.UpdateNodeColor (0, 255, 215, 0); // لون ذهبي
  anim.UpdateNodeSize  (0, 25.0, 25.0);

  // تمييز العقدة الخبيثة Grayhole باللون البرتقالي
  anim.UpdateNodeDescription (ghNodeId, "GH-" + std::to_string (ghNodeId));
  anim.UpdateNodeColor (ghNodeId, 255, 140, 0); 
  anim.UpdateNodeSize  (ghNodeId, 30.0, 30.0);

  // تمييز العقدة الخبيثة Blackhole باللون الأحمر
  anim.UpdateNodeDescription (bhNodeId, "BH-" + std::to_string (bhNodeId));
  anim.UpdateNodeColor (bhNodeId, 255, 0, 0); 
  anim.UpdateNodeSize  (bhNodeId, 35.0, 35.0);
  
  anim.EnablePacketMetadata (true);

  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

  std::cout << "[Sim] Starting simulation (" << simulationTime << "s)...\n\n";
  Simulator::Stop (Seconds (simulationTime));
  Simulator::Run ();

  PrintIDSReport ();
  PrintEnergyReport (mobileNodes, energyFileName);

  monitor->SerializeToXmlFile (xmlFileName, true, true);
  std::cout << "[Done] Results saved to: " << xmlFileName << "\n\n";

  Simulator::Destroy ();
  return 0;
}
