using System;
using System.IO;
using System.Net;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Diagnostics;

using ICSharpCode.SharpZipLib.GZip;

namespace Analyzer
{
  // #Fields: Start, Duration, Source IP, Source Port, Destination IP, Destination Port, IP Protocol, Packets, Octets
  class NetmonRecord
  {
    public DateTime start;
    public TimeSpan duration;
    public IPAddress sourceAddress;
    public int sourcePort;
    public IPAddress destinationAddress;
    public int destinationPort;
    public int protocol;
    public long packets;
    public long octets;

    static DateTimeFormatInfo dateParser = new DateTimeFormatInfo();

    static NetmonRecord()
    {
      dateParser.ShortDatePattern = "yyyy-MM-dd";
      dateParser.ShortTimePattern = "HH:mm:ss.fff";
    }

    internal void Parse(string line)
    {
      string[] fields = line.Split('\t');
      start = DateTime.ParseExact(fields[0], "yyyy-MM-dd HH:mm:ss.fff", dateParser);
      duration = new TimeSpan(0, 0, 0, 0, Int32.Parse(fields[1]));

      sourceAddress = IPAddress.Parse(fields[2]);
      if (fields[3] != "")
        sourcePort = Int32.Parse(fields[3]);

      destinationAddress = IPAddress.Parse(fields[4]);
      if (fields[5] != "")
        destinationPort = Int32.Parse(fields[5]);

      if (fields[6] == "Tcp" || fields[6] == "6")
        protocol = 6;
      else if (fields[6] == "Udp" || fields[6] == "17")
        protocol = 17;
      else if (fields[6] == "Gre" || fields[6] == "47")
        protocol = 47;

      packets = Int64.Parse(fields[7]);
      octets = Int64.Parse(fields[8]);
    }
    internal void Write(BinaryWriter writer)
    {
      writer.Write(start.Ticks);
      writer.Write(duration.Ticks);

      byte[] data = BitConverter.GetBytes(sourceAddress.Address);
      writer.Write(data, 0, 4);

      writer.Write((short)sourcePort);

      data = BitConverter.GetBytes(destinationAddress.Address);
      writer.Write(data, 0, 4);

      writer.Write((short)destinationPort);

      writer.Write(protocol);
      writer.Write(packets);
      writer.Write(octets);
    }
    internal void Read(BinaryReader reader)
    {
      byte[] data = reader.ReadBytes(48);
      start = new DateTime(BitConverter.ToInt64(data, 0));
      duration = new TimeSpan(BitConverter.ToInt64(data, 8));
      sourceAddress = new IPAddress(BitConverter.ToUInt32(data, 16));
      sourcePort = BitConverter.ToUInt16(data, 20);
      destinationAddress = new IPAddress(BitConverter.ToUInt32(data, 22));
      destinationPort = BitConverter.ToUInt16(data, 26);
      protocol = BitConverter.ToInt32(data, 28);
      packets = BitConverter.ToInt64(data, 32);
      octets = BitConverter.ToInt64(data, 40);
    }
  }

  public class Subnet
  {
    private IPAddress address;
    public IPAddress Address
    {
      get { return address; }
      set { address = value; }
    }
    private int maskLength;
    public int MaskLength
    {
      get { return maskLength; }
      set
      {
        maskLength = value;
        mask = 1 << maskLength - 1;
      }
    }
    private long mask;
    public Subnet(IPAddress address, int maskLength)
    {
      this.address = address;
      this.maskLength = maskLength;
      mask = 1 << maskLength - 1;
    }
    public static Subnet Parse(string value)
    {
      string[] fields = value.Split('/');
      IPAddress address = IPAddress.Parse(fields[0]);
      int maskLength = -1;
      if (fields.Length > 1)
      {
        maskLength = Int32.Parse(fields[1]);
      }
      else {
        byte first = address.GetAddressBytes()[0];
        if (1 <= first && first <= 126)
        {
          maskLength = 8;
        }
        else if (128 <= first && first <= 223)
        {
          maskLength = 16;
        }
        else if (192 <= first && first <= 223)
        {
          maskLength = 24;
        }
        else if (224 <= first && first <= 239)
        {
        }
        else if (240 <= first && first <= 254)
        {
        }
        // Validate the default mask, and assume we're a host address
        // if there are any host bits set.
        long mask = ~((1 << maskLength) - 1) & 0xffffffff;
        if ((IPAddress.NetworkToHostOrder((int)address.Address) & mask) != 0)
        {
          maskLength = 32;
        }
      }
      return new Subnet(address, maskLength);
    }
    public override string ToString()
    {
      return address + "/" + maskLength;
    }
  }

  class Summary
  {
    public long Hits;
    public long Bytes;
    public long Packets;
    public TimeSpan Duration;
    public void Process(NetmonRecord r)
    {
      Hits += 1;
      Bytes += r.octets;
      Packets += r.packets;
      Duration += r.duration;
    }
  }
  class Entry
  {
    Summary peak = new Summary();
    public Summary Peak { get { return peak; } }
    Summary offpeak = new Summary();
    public Summary Offpeak { get { return offpeak; } }
  }

  class Analyzer
  {
    //static PerformanceCounter readCounter = new PerformanceCounter("WebSpy5", "Storage Reads/sec", false);
    //static PerformanceCounter parseCounter = new PerformanceCounter("WebSpy5", "Hits Loaded/sec", false);
    static Dictionary<IPAddress, string>[] subnets = new Dictionary<IPAddress, string>[33];
    static string Resolve(IPAddress address)
    {
      for (int i = 32; i >= 0; i--)
      {
        long mask = i == 32 ? 0xffffffff : ((1 << i) - 1) & 0xffffffff;
        long addr = address.Address & mask;
        var ip = new IPAddress(addr);
        string result;
        if (subnets[i].TryGetValue(ip, out result))
          return result;
      }
      return null;
    }
    static Summary Process<K>(Dictionary<K, Summary> d, K k)
    {
      Summary s;
      if (!d.TryGetValue(k, out s))
        d.Add(k, s = new Summary());
      return s;
    }
    static Summary Process(Hashtable d, object k)
    {
      Summary s = (Summary)d[k];
      if (s == null)
        d.Add(k, s = new Summary());
      return s;
    }
    static void Main(string[] args)
    {
      #region Aliases setup
      for (int i = 0; i < subnets.Length; i++)
        subnets[i] = new Dictionary<IPAddress, string>();

      subnets[0].Add(IPAddress.Any, "[Internet]");

      /*using (StreamReader reader = new StreamReader("sh_ip_bgp_nei_198.32.212.253_routes.txt")) {
        string line = null;
        while ((line = reader.ReadLine()) != null) {
          if (!line.StartsWith("*> "))
            continue;
          string[] parts = line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
          Subnet sn = Subnet.Parse(parts[1]);
          subnets[sn.MaskLength][sn.Address.Address] = "[WAIX]";
        }
      }*/

      #region Imaging Central
      subnets[32].Add(IPAddress.Parse("192.168.19.108"), "ICP-RISSQL");
      subnets[32].Add(IPAddress.Parse("192.168.19.109"), "ICP-RISAPP");
      subnets[32].Add(IPAddress.Parse("192.168.19.110"), "ICP-RISAGT");

      subnets[32].Add(IPAddress.Parse("192.168.19.62"), "IC-CONSULTING");
      subnets[32].Add(IPAddress.Parse("192.168.10.69"), "ICENT-MOR-RWS1");

      subnets[24].Add(IPAddress.Parse("192.168.19.0"), "[Claremont]");
      subnets[24].Add(IPAddress.Parse("192.168.10.0"), "[Morley]");
      #endregion

      #region Kestral
      /*subnets[24].Add(IPAddress.Parse("10.250.1.0"), "Perth Servers");
      subnets[24].Add(IPAddress.Parse("10.250.2.0"), "Perth Workstations");
      subnets[24].Add(IPAddress.Parse("10.252.1.0"), "Melbourne Servers");
      subnets[24].Add(IPAddress.Parse("10.252.2.0"), "Melbourne Workstations");
      subnets[24].Add(IPAddress.Parse("10.254.1.0"), "Sydney Servers");
      subnets[24].Add(IPAddress.Parse("10.254.2.0"), "Sydney Workstations");

      subnets[32].Add(IPAddress.Parse("10.250.1.69"), "PER-HQ");
      subnets[32].Add(IPAddress.Parse("10.250.1.73"), "PER-HQ-AGENT");*/
      #endregion

      #region almostpurple
      /*subnets[24].Add(IPAddress.Parse("192.168.1.0"), "[Local]");

      subnets[32].Add(IPAddress.Parse("192.168.1.254"), "tyrant");
      subnets[32].Add(IPAddress.Parse("192.168.1.253"), "templar");
      subnets[32].Add(IPAddress.Parse("192.168.1.252"), "troy");
      subnets[32].Add(IPAddress.Parse("192.168.1.251"), "archon");
      subnets[32].Add(IPAddress.Parse("192.168.1.250"), "toshiba");
      subnets[32].Add(IPAddress.Parse("192.168.1.249"), "triso");
      subnets[32].Add(IPAddress.Parse("192.168.1.248"), "tristan");
      subnets[32].Add(IPAddress.Parse("192.168.1.247"), "raptor");
      subnets[32].Add(IPAddress.Parse("192.168.1.246"), "raptor");
      subnets[32].Add(IPAddress.Parse("192.168.1.245"), "oni");
      subnets[32].Add(IPAddress.Parse("192.168.1.244"), "oni");
      subnets[32].Add(IPAddress.Parse("192.168.1.243"), "hawkes");
      subnets[32].Add(IPAddress.Parse("192.168.1.242"), "arbiter");
      subnets[32].Add(IPAddress.Parse("192.168.1.241"), "solzak");      
      subnets[32].Add(IPAddress.Parse("192.168.1.240"), "wifi");
      subnets[32].Add(IPAddress.Parse("192.168.1.239"), "gavinm");
      subnets[32].Add(IPAddress.Parse("192.168.1.238"), "gavinm");
      subnets[32].Add(IPAddress.Parse("192.168.1.237"), "gav-n80");
      subnets[32].Add(IPAddress.Parse("192.168.1.236"), "vitalstatistix");
      subnets[32].Add(IPAddress.Parse("192.168.1.235"), "ixy");
      subnets[32].Add(IPAddress.Parse("192.168.1.234"), "bullet-pc");
      //subnets[32].Add(IPAddress.Parse("192.168.1.233"), "evilspyn");
      subnets[32].Add(IPAddress.Parse("192.168.1.232"), "evilspyn");
      subnets[32].Add(IPAddress.Parse("192.168.1.231"), "obelix");
      subnets[32].Add(IPAddress.Parse("192.168.1.230"), "gav-iphone");
      subnets[32].Add(IPAddress.Parse("192.168.1.229"), "dogmatix");
      subnets[32].Add(IPAddress.Parse("192.168.1.228"), "dogmatix");
      subnets[32].Add(IPAddress.Parse("192.168.1.227"), "ixy");
      subnets[32].Add(IPAddress.Parse("192.168.1.226"), "phoenix");
      subnets[32].Add(IPAddress.Parse("192.168.1.225"), "adsl");

      // World of Warcraft uses the TCP protocol on port 3724.
      // The Blizzard Downloader, which downloads patches, also uses TCP ports 6112 and the range 6881-6999
      subnets[32].Add(IPAddress.Parse("12.129.233.56"), "WoW:Gurubashi");
      subnets[32].Add(IPAddress.Parse("12.129.225.78"), "WoW:Blackrock");
      subnets[32].Add(IPAddress.Parse("203.206.95.15"), "TeamSpeak");

      // EVE uses TCP 26000 to it's only server cluster
      subnets[32].Add(IPAddress.Parse("157.157.139.10"), "EVE:Tranquility");

      // DDO
      // Ports 9000-9010 UDP
      // Ports 2900-2910 UDP*/
      #endregion

      Dictionary<string, int> ignoredSenders = new Dictionary<string, int>();
      ignoredSenders.Add("[Local]", 0);
      ignoredSenders.Add("[None]", 0);
      ignoredSenders.Add("[Broadcast]", 0);
      ignoredSenders.Add("tyrant", 0);
      ignoredSenders.Add("templar", 0);
      ignoredSenders.Add("troy", 0);
      ignoredSenders.Add("archon", 0);
      ignoredSenders.Add("toshiba", 0);
      ignoredSenders.Add("triso", 0);
      ignoredSenders.Add("tristan", 0);
      ignoredSenders.Add("raptor", 0);
      ignoredSenders.Add("oni", 0);
      ignoredSenders.Add("hawkes", 0);
      ignoredSenders.Add("arbiter", 0);
      ignoredSenders.Add("solzak", 0);
      ignoredSenders.Add("wifi", 0);
      ignoredSenders.Add("gavinm", 0);
      ignoredSenders.Add("gav-n80", 0);
      ignoredSenders.Add("vitalstatistix", 0);
      ignoredSenders.Add("ixy", 0);
      ignoredSenders.Add("bullet-pc", 0);
      ignoredSenders.Add("evilspyn", 0);
      ignoredSenders.Add("obelix", 0);
      ignoredSenders.Add("gav-itouch", 0);
      ignoredSenders.Add("dogmatix", 0);
      #endregion

      subnets[32].Add(IPAddress.Parse("0.0.0.0"), "[None]");
      subnets[32].Add(IPAddress.Parse("255.255.255.255"), "[Broadcast]");

      Dictionary<string, Dictionary<string, Entry>> summaryTable = new Dictionary<string, Dictionary<string, Entry>>();

      //string path = @"\\archon\g$\logs";
      //string path = @"C:\Logs\Netmon@WebSpy";
      //string path = @"\\tyrant\logs\netmon";
      //string path = @"C:\Performance\kestral-hq";
      string path = @"c:\incoming\ic-netmon";
      //string filter = "2005090?.log.gz";
      //string filter = "*.log.gz";
      string filter = "*.log";

      foreach (string fileName in Directory.GetFiles(path, filter))
      {
        try
        {
          Console.WriteLine(fileName);

          var timer = Stopwatch.StartNew();
          var lines = 0;

          Stream s = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
          if (Path.GetExtension(fileName) == ".gz")
            s = new GZipInputStream(s);

          using (StreamReader reader = new StreamReader(s))
          {
            summaryTable.Clear();
            string line;
            NetmonRecord record = new NetmonRecord();

            TimeSpan offpeakStart = new TimeSpan(2, 0, 0);
            TimeSpan offpeakEnd = new TimeSpan(10, 0, 0);

            while ((line = reader.ReadLine()) != null)
            {
              if (line.Length == 0 || line[0] == '#')
                continue;

              record.Parse(line);

              if (record.protocol != 6)
                continue;
              if (!(record.sourcePort == 40100 || record.destinationPort == 40100))
                continue;

              string source = Resolve(record.sourceAddress);
              string dest = Resolve(record.destinationAddress);

              Dictionary<string, Entry> child;
              if (!summaryTable.TryGetValue(source, out child))
              {
                child = new Dictionary<string, Entry>();
                summaryTable.Add(source, child);
              }
              Entry entry;
              if (!child.TryGetValue(dest, out entry))
              {
                entry = new Entry();
                child.Add(dest, entry);
              }

              TimeSpan recTime = record.start.AddHours(9).TimeOfDay;
              Summary summary = offpeakStart < recTime && recTime < offpeakEnd ?
                entry.Offpeak : entry.Peak;
              summary.Bytes += record.octets;
              summary.Duration += record.duration;
            }

            lines++;
          }
          timer.Stop();
          Console.WriteLine(lines + " lines in " + timer.Elapsed);

          foreach (KeyValuePair<string, Dictionary<string, Entry>> parent in summaryTable)
          {
            foreach (KeyValuePair<string, Entry> child in parent.Value)
            {
              if (child.Value.Peak.Bytes > 0 || child.Value.Offpeak.Bytes > 0)
              {
                if (!ignoredSenders.ContainsKey(parent.Key))
                  Console.WriteLine(String.Format("{0} -> {1} = Peak: {2:n0} MB, Offpeak: {3:n0} MB", parent.Key, child.Key,
                    (child.Value.Peak.Bytes >> 20), (child.Value.Offpeak.Bytes >> 20),
                    child.Value.Peak.Duration + child.Value.Offpeak.Duration));
              }
            }
          }
        }
        catch
        {
        }
      }
      Console.ReadLine();
    }
  }
}
