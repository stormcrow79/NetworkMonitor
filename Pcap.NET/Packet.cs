using System;
using System.Net;

namespace Packets {

  public class PacketFormatException : ApplicationException {
    public PacketFormatException(string message) : base(message) { }
  }

  // Layer 1 = Physical
  // Layer 2 = Data link (Ethernet)
  // Layer 3 = Network (IP)
  // Layer 4 = Transport (TCP, UDP)
  // Layer 5 = Session
  // Layer 6 = Presentation
  // Layer 7 = Application (HTTP, SMTP)

  public enum EthernetProtocol { IP = 0x800 }

  public class EthernetHeader {
    private byte[] data;
    private byte[] sourceMac = new byte[6];
    private byte[] destinationMac = new byte[6];    
    private int protocol;

    public EthernetHeader(byte[] packet) {
      data = packet;
      
      Buffer.BlockCopy(data, 0, sourceMac, 0, 6);
      Buffer.BlockCopy(data, 6, destinationMac, 0, 6);      
      protocol = data[12] << 8 | data[13];
    }

    public byte[] SourceMac {
      get { return sourceMac; }
    }
    public byte[] DestinationMac {
      get { return destinationMac; }
    }
    public int Protocol {
      get { return protocol; }
    }
    
    internal byte[] Data {
      get { return data; }
    }
    internal int DataOffset {
      get {
        return 14;
      }
    }
  }

/*
  0                   1                   2                   3   
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Version|  IHL  |Type of Service|          Total Length         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Identification        |Flags|      Fragment Offset    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Time to Live |    Protocol   |         Header Checksum       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       Source Address                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Destination Address                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Options                    |    Padding    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

  public enum IPProtocol {
    /// <summary>Internet protocol</summary>
    Ip = 0,
    /// <summary>Internet control message protocol</summary>
    Icmp = 1,
    /// <summary>Gateway-gateway protocol</summary>
    Ggp = 3,
    /// <summary>Transmission control protocol</summary>
    Tcp = 6,
    /// <summary>Exterior gateway protocol</summary>
    Egp = 8,
    /// <summary>PARC universal packet protocol</summary>
    Pup = 12,
    /// <summary>User datagram protocol</summary>
    Udp = 17,
    /// <summary>Host monitoring protocol</summary>
    Hmp = 20,
    /// <summary>Xerox NS internet datagram protocol</summary>
    Xns_Idp = 22,
    /// <summary>Reliable datagram protocol</summary>
    Rdp = 27,
    /// <summary>Generic routing encapsulation</summary>
    Gre = 47,
    /// <summary>MIT remote virtual disk</summary>
    Rvd = 66
  }

  public class IPHeader {
    private byte[] data;
    
    private IPProtocol protocol;
    private IPAddress sourceIp;
    private IPAddress destinationIp;
    private int length;

    private int headerOffset = -1;
    private int dataOffset = -1;

    public IPHeader(EthernetHeader eth) {
      if (eth.Protocol == (int)EthernetProtocol.IP) {
        headerOffset = eth.DataOffset;
        data = eth.Data;

        long addr = (long)data[headerOffset + 15] << 24 | (long)data[headerOffset + 14] << 16 | 
          (long)data[headerOffset + 13] << 8 | (long)data[headerOffset + 12];
        sourceIp = new IPAddress(addr);
        addr = (long)data[headerOffset + 19] << 24 | (long)data[headerOffset + 18] << 16 | 
          (long)data[headerOffset + 17] << 8 | (long)data[headerOffset + 16];
        destinationIp = new IPAddress(addr);

        protocol = (IPProtocol)data[headerOffset + 9];
        length = data[headerOffset + 2] << 8 | data[headerOffset + 3];

        dataOffset = headerOffset + ((data[headerOffset] & 0xF) << 2);
      } else {
        throw new PacketFormatException("Packet is not IP");
      }
    }

    public IPAddress SourceIp {
      get { return sourceIp; }
    }
    public IPAddress DestinationIp {
      get { return destinationIp; }
    }
    public IPProtocol Protocol {
      get { return protocol; }
    }
    
    internal byte[] Data {
      get { return data; }
    }
    public int Length {
      get {
        return length;
      }
    }
    public int DataOffset {
      get {
        return dataOffset;
      }
    }
    public int HeaderLength {
      get {
        return dataOffset - headerOffset;
      }
    }
    public int DataLength {
      get {
        return length - dataOffset;
      }
    }
  }

/*
  0                   1                   2                   3   
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Source Port          |       Destination Port        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Sequence Number                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Acknowledgment Number                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Data |           |U|A|P|R|S|F|                               |
  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
  |       |           |G|K|H|T|N|N|                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Checksum            |         Urgent Pointer        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Options                    |    Padding    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                             data                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

  [Flags()]
  public enum TcpFlags { Fin = 1, Syn = 2, Rst = 4, Psh = 8, Ack = 16, Urg = 32 }

  public class TcpHeader {
    private byte[] data;

    private int sourcePort;
    private int destinationPort;
    private TcpFlags flags;

    private int headerOffset = -1;
    private int dataOffset = -1;
    private int dataLength = -1;

    public TcpHeader(IPHeader ip) {
      if (ip.Protocol == IPProtocol.Tcp) {
        data = ip.Data;
        headerOffset = ip.DataOffset;        
        sourcePort = data[headerOffset] << 8 | data[headerOffset + 1];
        destinationPort = data[headerOffset + 2] << 8 | data[headerOffset + 3];
        flags = (TcpFlags)(data[headerOffset + 13] & 0x3f);
        dataOffset = headerOffset + ((data[headerOffset + 12] & 0xF0) >> 2);
        dataLength = ip.DataLength - (dataOffset - headerOffset);
      } else {
        throw new PacketFormatException("Packet is not TCP");
      }
    }

    public int SourcePort {
      get { return sourcePort; }
    }
    public int DestinationPort {
      get { return destinationPort; }
    }
    public TcpFlags Flags {
      get { return flags; }
    }

    public int DataOffset {
      get {
        return dataOffset;
      }
    }
    public int HeaderLength {
      get {
        return dataOffset - headerOffset;
      }
    }
    public int DataLength {
      get {
        return dataLength;
      }
    }
    public int Length {
      get {
        return HeaderLength + DataLength;
      }
    }
  }

  public class UdpHeader {
    private byte[] data;

    private int sourcePort;
    private int destinationPort;

    private int headerOffset = -1;
    private int dataOffset = -1;
    private int dataLength = -1;

    public UdpHeader(IPHeader ip) {
      headerOffset = ip.DataOffset;
      if (ip.Protocol == IPProtocol.Udp) {
        data = ip.Data;
        if (data.Length < headerOffset + 2) throw new PacketFormatException("Packet too short: sourcePort");
        sourcePort = data[headerOffset] << 8 | data[headerOffset + 1];
        if (data.Length < headerOffset + 4) throw new PacketFormatException("Packet too short: destinationPort");
        destinationPort = data[headerOffset + 2] << 8 | data[headerOffset + 3];
        dataOffset = headerOffset + 14;
        dataLength = ip.DataLength - (dataOffset - headerOffset);
      } else {
        throw new PacketFormatException("Packet is not UDP");
      }
    }

    public int SourcePort {
      get {
        return sourcePort;
      }
      set {
        sourcePort = value;
      }
    }
    public int DestinationPort {
      get {
        return destinationPort;
      }
      set {
        destinationPort = value;
      }
    }
    public int DataOffset {
      get {
        return dataOffset;
      }
    }
  }
}
