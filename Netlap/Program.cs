using Packets;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using WinPcap;

namespace Netlap
{
  class Kernel32
  {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", EntryPoint = "PeekConsoleInputW", CharSet = CharSet.Unicode)]
    public static extern bool PeekConsoleInput(IntPtr hConsoleInput, [Out] InputRecord[] lpBuffer, int nLength, out int lpNumberOfEventsRead);
    [DllImport("kernel32.dll", EntryPoint = "ReadConsoleInputW", CharSet = CharSet.Unicode)]
    public static extern bool ReadConsoleInput(IntPtr hConsoleInput, [Out] InputRecord[] lpBuffer, int nLength, out int lpNumberOfEventsRead);
    [DllImport("kernel32.dll")]
    public static extern bool GetNumberOfConsoleInputEvents(IntPtr hConsoleInput, out int lpcNumberOfEvents);
  }

  class Program
  {
    static bool KeyPressed()
    {
      var stdin = Kernel32.GetStdHandle(-10);
      int count;

      if (!Kernel32.GetNumberOfConsoleInputEvents(stdin, out count))
        throw new Win32Exception();

      if (count > 0)
      {
        InputRecord[] buf = new InputRecord[count];
        if (!Kernel32.ReadConsoleInput(stdin, buf, buf.Length, out count))
          throw new Win32Exception();

        for (int i = 0; i < count; i++)
        {
          if (buf[i].EventType == 1 && !buf[i].KeyEvent.bKeyDown)
            return true;
        }
      }

      return false;
    }
    static void Main(string[] args)
    {
      var pcap = new Pcap();
      pcap.Open(ConfigurationManager.AppSettings["Adapter"]);

      var address = IPAddress.Parse(ConfigurationManager.AppSettings["Address"]);
      var port = UInt16.Parse(ConfigurationManager.AppSettings["Port"]);

      Packet packet = null;

      long tx = 0, rx = 0;

      while (true)
      {
        if ((packet = pcap.Next()) != null)
        {
          var eth = new EthernetHeader(packet.Data);
          if (eth.Protocol == (int)EthernetProtocol.IP)
          {
            var ip = new IPHeader(eth);
            if (ip.Protocol == IPProtocol.Tcp)
            {
              var tcp = new TcpHeader(ip);
              if (ip.SourceIp.Equals(address) && tcp.SourcePort == port) rx += tcp.Length;
              else if (ip.DestinationIp.Equals(address) && tcp.DestinationPort == port) tx += tcp.Length;
            }
          }
        }

        if (KeyPressed())
        {
          Console.WriteLine("{0},{1}", tx, rx);
          tx = 0;
          rx = 0;
        }
      }
    }
  }

  [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
  struct KeyEventRecord
  {
    [FieldOffset(0), MarshalAs(UnmanagedType.Bool)]
    public bool bKeyDown;
    [FieldOffset(4)]
    public short wRepeatCount;
    [FieldOffset(6)]
    public short wVirtualKeyCode;
    [FieldOffset(8)]
    public short wVirtualScanCode;
    [FieldOffset(10)]
    public char UnicodeChar; // union char AsciiChar
    [FieldOffset(12)]
    public int dwControlKeyState;
  }

  [StructLayout(LayoutKind.Explicit, Size = 4)]
  struct FocusEventRecord
  {
    [FieldOffset(0), MarshalAs(UnmanagedType.Bool)]
    public bool bSetFocus;
  }

  [StructLayout(LayoutKind.Explicit, Size = 4)]
  struct MenuEventRecord
  {
    [FieldOffset(0)]
    public int dwCommandId;
  }

  [StructLayout(LayoutKind.Explicit, Size = 4)]
  struct Coord
  {
    [FieldOffset(0)]
    public short X;
    [FieldOffset(2)]
    public short Y;
  }

  [StructLayout(LayoutKind.Explicit, Size = 16)]
  struct MouseEventRecord
  {
    [FieldOffset(0)]
    public Coord dwMousePosition;
    [FieldOffset(4)]
    public int dwButtonState;
    [FieldOffset(8)]
    public int dwControlKeyState;
    [FieldOffset(12)]
    public int dwEventFlags;
  }

  [StructLayout(LayoutKind.Explicit, Size = 4)]
  struct WindowBufferSizeRecord
  {
    [FieldOffset(0)]
    public Coord dwSize;
  }

  [StructLayout(LayoutKind.Explicit)]
  struct InputRecord
  {
    [FieldOffset(0)]
    public short EventType;
    [FieldOffset(4)]
    public KeyEventRecord KeyEvent;
    [FieldOffset(4)]
    public MouseEventRecord MouseEvent;
    [FieldOffset(4)]
    public WindowBufferSizeRecord WindowBufferSizeEvent;
    [FieldOffset(4)]
    public MenuEventRecord MenuEvent;
    [FieldOffset(4)]
    public FocusEventRecord FocusEvent;
  }
}
