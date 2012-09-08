using System;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;

namespace WinPcap {

  internal struct pcap_t { }

  [StructLayout(LayoutKind.Sequential)]
  internal struct timeval {
    public int tv_sec;  /* seconds since Jan. 1, 1970 */
    public int tv_usec; /* and microseconds */
  }

  [StructLayout(LayoutKind.Sequential)]
  internal struct pcap_pkthdr {
    public timeval ts;  /* time stamp */
    public int caplen;  /* length of portion present */
    public int len;     /* length this packet (off wire) */
  }

  internal class LibPcapException : ApplicationException {
    public LibPcapException(string message) : base(message) { }
  }

  internal unsafe class LibPcap {
    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern pcap_t* pcap_open(string source, int snaplen, int flags, int read_timeout,
      void* auth, void* errbuf);

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_close(pcap_t* handle);
    
    /*
     * 1  if the packet has been read without problems
     * 0  if the timeout set with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet
     * -1 if an error occurred
     * -2 if EOF was reached reading from an offline capture
     */

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_next_ex(pcap_t* handle, ref pcap_pkthdr* header, ref byte* data);
  }

  public class Packet {
    private long time;
    private int len;
    private byte[] data;

    public Packet() {
    }

    static readonly long BaseTime = new DateTime(1970, 1, 1, 0, 0, 0, 0).Ticks;
    internal unsafe Packet(ref pcap_pkthdr header, byte* pkt) {
      len = header.len;
      time = BaseTime + (long)header.ts.tv_sec * 10000000 + (long)header.ts.tv_usec * 10;
      
      data = new byte[header.caplen];
      for (int i = 0; i < header.caplen; i++) data[i] = pkt[i];
    }

    public int Length {
      get { return len; }
      set { len = value; }
    }
    public byte[] Data {
      get { return data; }
      set { data = value; }
    }

    /// <summary>
    /// Timestamp of packet converted to .NET DateTime Ticks format.
    /// </summary>
    public long Time {
      get { return time; }
      set { time = value; }
    }
  }

  public unsafe class Pcap {
    private pcap_t* handle;
    
    public Pcap() { }

    public void Open(string name) {
      byte[] err = new byte[256];
      fixed (byte* pErr = &err[0]) {
        handle = LibPcap.pcap_open(name, 68, 0, 0, null, pErr);
        if (handle == null) {
          throw new LibPcapException(Encoding.ASCII.GetString(err));
        }
      }
    }
    public Packet Next() {
      pcap_pkthdr *header = null;
      byte* data = null;
      int result = LibPcap.pcap_next_ex(handle, ref header, ref data);
      if (result == 1) {
        return new Packet(ref *header, data);
      } else if (result == 0) {
        return null;
      } else if (result == -2) {
        throw new EndOfStreamException();
      } else {
        throw new LibPcapException("error");
      }
    }
    public void Close() {
      LibPcap.pcap_close(handle);
    }
  }
}
