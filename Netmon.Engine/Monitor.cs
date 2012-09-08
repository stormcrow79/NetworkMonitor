#region Using directives

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Collections.Generic;

using WinPcap;
using Packets;
using System.Diagnostics;

#endregion

namespace Netmon.Engine {
  public class Flow : ICloneable {
    public IPEndPoint Source;
    public IPEndPoint Destination;
    public IPProtocol Protocol;

    public Flow() {
    }
    public Flow(IPHeader ip, TcpHeader tcp) {
      Assign(ip, tcp);
    }
    public Flow(IPHeader ip, UdpHeader udp) {
      Assign(ip, udp);
    }

    public void Assign(IPHeader ip, TcpHeader tcp) {
      Source = new IPEndPoint(ip.SourceIp, tcp.SourcePort);
      Destination = new IPEndPoint(ip.DestinationIp, tcp.DestinationPort);
      Protocol = ip.Protocol;
    }
    public void Assign(IPHeader ip, UdpHeader udp) {
      Source = new IPEndPoint(ip.SourceIp, udp.SourcePort);
      Destination = new IPEndPoint(ip.DestinationIp, udp.DestinationPort);
      Protocol = ip.Protocol;
    }
    public override int GetHashCode() {
      return Source.GetHashCode() ^ Destination.GetHashCode() ^ (int)Protocol;
    }
    public override bool Equals(object obj) {
      Flow f = (Flow)obj;
      return Source.Equals(f.Source) && Destination.Equals(f.Destination) && Protocol == f.Protocol;
    }
    public override string ToString() {
      return Protocol.ToString() + ": " + Source.ToString() + " -> " + Destination.ToString();
    }

    #region ICloneable Members

    public object Clone() {
      Flow result = new Flow();
      result.Source = new IPEndPoint(Source.Address, Source.Port);
      result.Destination = new IPEndPoint(Destination.Address, Destination.Port);
      result.Protocol = Protocol;
      return result;
    }

    #endregion
  }

  public class FlowStats {
    public Flow Key;

    public long First;
    public long Last;

    public long Packets;
    public long Bytes;

    public FlowStats Next;
    public FlowStats Prev;

    public FlowStats(Flow key) {
      this.Key = key;
    }
  }

  internal class FlowQueue {
    private FlowStats head;
    private FlowStats tail;
    private int count;

    public void Add(FlowStats flow) {
      if (count == 0) {
        head = flow;
        tail = flow;
        flow.Next = null;
        flow.Prev = null;
      } else {
        flow.Next = head;
        head.Prev = flow;
        head = flow;
      }
      count++;
    }
    public void Remove(FlowStats flow) {
      if (count == 0) {
        // Nothing to do ...
        //throw new InvalidOperationException("Remove from empty list");
        return;
      } else if (count == 1) {
        if (flow != head) {
          // Nothing to do ...
          //throw new InvalidOperationException("Remove item not in list");
          return;
        } else {
          head = null;
          tail = null;
        }
      } else {
        if (flow == head) {
          head = flow.Next;
          head.Prev = null;
        } else if (flow == tail) {
          tail = flow.Prev;
          tail.Next = null;
        } else {
          flow.Prev.Next = flow.Next;
          flow.Next.Prev = flow.Prev;
        }
      }
      flow.Next = null;
      flow.Prev = null;
      count--;
    }
    public void Promote(FlowStats flow) {
      // TODO: Remove, then add
      Remove(flow);
      Add(flow);
    }
    public void Purge(long age, StreamWriter w) {
    }

    public FlowStats Head {
      get {
        return head;
      }
    }
    public FlowStats Tail {
      get {
        return tail;
      }
    }
    public int Count {
      get {
        return count;
      }
    }
  }

  internal class FlowTracker {
    private Dictionary<Flow, FlowStats> flows = new Dictionary<Flow, FlowStats>();
    private FlowQueue queue = new FlowQueue();

    public FlowStats Resolve(Flow key, long packetTime) {
      FlowStats stats;
      if ((queue.Count > 0) && queue.Head.Key.Equals(key)) {
        stats = queue.Head;
      } else {
        stats = flows.ContainsKey(key) ? flows[key] : null;

        if (stats == null) {
          stats = new FlowStats(key);
          stats.First = packetTime;
          flows.Add(key, stats);
        } else if (queue.Count > 0) {
          queue.Remove(stats);
        }
        queue.Add(stats);
      }
      return stats;
    }

    public void Remove(FlowStats stats) {
      queue.Remove(stats);
      flows.Remove(stats.Key);
    }

    public FlowStats Tail {
      get {
        return queue.Tail;
      }
    }
    public int Count {
      get {
        return queue.Count;
      }
    }
  }

  public class Monitor {
    FlowTracker tracker = new FlowTracker();
    Pcap pcap = new Pcap();
    long packets = 0;

    StreamWriter writer;
    BinaryWriter dump; // packet log

    public Monitor() {
    }

    private string logFile;

    protected void OpenLogfile() {
      string name = DateTime.Now.ToString("yyyyMMdd'.log'");
      if (name != logFile) {
        if (writer != null) writer.Close();
        if (dump != null) dump.Close();
        logFile = name;
        if (!File.Exists(logFolder + logFile)) {
          writer = new StreamWriter(new FileStream(logFolder + logFile, FileMode.Create, FileAccess.Write, FileShare.Read));
          writer.WriteLine("#Software: NetMon");
          writer.WriteLine("#Version: 1.1.0000");
          writer.WriteLine("#Fields: Start\tDuration (ms)\tSource IP\tSource Port\tDestination IP\tDestination Port\tIP Protocol\tPackets\tOctets");
          writer.Flush();
        } else {
          writer = new StreamWriter(new FileStream(logFolder + logFile, FileMode.Append, FileAccess.Write, FileShare.Read));
        }

        if (packetFolder != null && packetFolder != "")
          dump = new BinaryWriter(new FileStream(Path.Combine(packetFolder, Path.ChangeExtension(logFile, ".dat")), FileMode.Create, FileAccess.Write, FileShare.Read));
      }
    }

    internal void Dump(FlowStats stats) {
      OpenLogfile();

      writer.Write(new DateTime(stats.First).ToString("yyyy-MM-dd HH:mm:ss.fff"));
      writer.Write("\t");
      TimeSpan duration = new TimeSpan(stats.Last - stats.First);
      writer.Write(duration.TotalMilliseconds.ToString("F0"));
      writer.Write("\t");
      writer.Write(stats.Key.Source.Address);
      writer.Write("\t");
      writer.Write(stats.Key.Source.Port);
      writer.Write("\t");
      writer.Write(stats.Key.Destination.Address);
      writer.Write("\t");
      writer.Write(stats.Key.Destination.Port);
      writer.Write("\t");
      writer.Write((int)stats.Key.Protocol);
      writer.Write("\t");
      writer.Write(stats.Packets);
      writer.Write("\t");
      writer.Write(stats.Bytes);
      writer.WriteLine();
    }

    public void Open() {
      if (!Directory.Exists(logFolder))
        Directory.CreateDirectory(logFolder);
      if (packetFolder != null && !Directory.Exists(packetFolder))
        Directory.CreateDirectory(packetFolder);
      OpenLogfile();
      pcap.Open(adapter);
      terminated = false;
    }
    public void Execute() {
      Packet packet;
      EthernetHeader eth;
      IPHeader ip;

      Flow key = new Flow();
      FlowStats stats;

      try {
        //BinaryReader log = new BinaryReader(new FileStream(@"c:\users\gavin\desktop\20081006.dat", FileMode.Open, FileAccess.Read));
        while (!terminated) {
          try {
            /*packet = new Packet();
            packet.Time = log.ReadInt64();
            packet.Length = log.ReadInt32();
            packet.Data = log.ReadBytes(log.ReadInt32());*/
            packet = pcap.Next();
          } catch (Exception e) {
            packet = null;
            throw;
          }
          if (packet != null) {
            if (dump != null) {
              dump.Write(packet.Time);
              dump.Write(packet.Length);
              int i = Math.Min(packet.Data.Length, 64);
              dump.Write(i);
              dump.Write(packet.Data, 0, i);
              dump.Flush();
            }

            eth = new EthernetHeader(packet.Data);

            if (eth.Protocol == (int)EthernetProtocol.IP) {
              ip = new IPHeader(eth);
              if (ip.Protocol == IPProtocol.Tcp) {
                TcpHeader tcp = new TcpHeader(ip);
                key = new Flow(ip, tcp);

                stats = tracker.Resolve(key, packet.Time);

                stats.Last = packet.Time;
                stats.Packets++;
                // Bytes at IP, including IP header
                stats.Bytes += ip.Length;

                #region debugging
                /*
              // TODO: Verify sorted order of queue - should be right now
              FlowStats check = queue.Head;
              while (check != null) {
                if (check.Next != null) Debug.Assert(check.Last >= check.Next.Last);
                check = check.Next;
              }
              */
                #endregion
              } else if (ip.Protocol == IPProtocol.Udp) {
                try {
                  UdpHeader udp = new UdpHeader(ip);
                  key = new Flow(ip, udp);

                  stats = tracker.Resolve(key, packet.Time);

                  stats.Last = packet.Time;
                  stats.Packets++;
                  // Bytes at IP, including IP header
                  stats.Bytes += ip.Length;
                } catch (IndexOutOfRangeException e) {
                  using (StreamWriter errorLog = new StreamWriter(Path.Combine(LogFolder, "error.log"), true)) {
                    errorLog.WriteLine(DateTime.Now);
                    errorLog.WriteLine(e.Message);
                    errorLog.WriteLine(e.StackTrace);
                    errorLog.WriteLine();
                  }

                  if (dump != null) {
                    dump.Write(packet.Time);
                    dump.Write(packet.Length);
                    dump.Write(packet.Data.Length);
                    dump.Write(packet.Data, 0, packet.Data.Length);
                    dump.Flush();
                  }
                } catch (Exception ex) {

                }
              } else if (ip.Protocol == IPProtocol.Icmp) {
                // TODO: Deal with ICMP
              } else if (ip.Protocol == IPProtocol.Gre) {
                // TODO: Deal with GRE
              }
            } else {
              // TODO: deal with non-IP
            }

            #region Age flows
            /**/
            while (tracker.Count > 0 && tracker.Tail.Last < packet.Time - ExpiryInterval) {
              stats = tracker.Tail;
              Dump(stats);
              tracker.Remove(stats);
            }
            writer.Flush();
            /**/
            #endregion
          }
          packets++;
        }
      } catch (EndOfStreamException e) {
        // TODO: nothing
      } catch (Exception e) {
        //debug.WriteLine("ERROR: " + e.Message);
        //debug.Flush();
        throw e;
      }
    }
    public void Close() {
      pcap.Close();

      #region Dump log
      while (tracker.Count > 0) {
        FlowStats stats = tracker.Tail;
        Dump(stats);
        tracker.Remove(stats);
      }
      #endregion

      writer.Close();
    }

    public string Adapter {
      get {
        return adapter;
      }
      set {
        adapter = value;
      }
    }
    private string adapter;

    public string LogFolder {
      get {
        return logFolder;
      }
      set {
        logFolder = value;
      }
    }
    private string logFolder;

    public string PacketFolder {
      get { return packetFolder; }
      set { packetFolder = value; }
    }
    private string packetFolder;

    public long ExpiryInterval {
      get {
        return expiryInterval;
      }
      set {
        expiryInterval = value;
      }
    }
    private long expiryInterval = (long)1 * 30 * 1000 * 1000 * 10; // 30 sec

    public bool Terminated {
      get {
        return terminated;
      }
      set {
        terminated = value;
      }
    }
    private bool terminated;
  }
}