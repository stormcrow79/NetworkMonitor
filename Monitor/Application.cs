using System;
using System.IO;
using System.Net;
using System.Diagnostics;
using System.Collections;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Configuration;

using Netmon.Engine;

namespace Netmon {
  class Application {
    public void ControlEvent(ConsoleCtrl.ConsoleEvent consoleEvent) {
      monitor.Terminated = true;
    }

    public Monitor Monitor {
      get {
        return monitor;
      }
    }
    private Monitor monitor = new Monitor();

    public void Run() {
      /*Dictionary<int, Int32> ih = new Dictionary<int, Int32>();
      for (int i = 0; i < (16 << 10) + 1; i++)
        ih[-i] = i;
      Console.ReadLine();*/

      NameValueCollection settings = ConfigurationSettings.AppSettings;
      monitor.Adapter = settings["Adapter"];
      monitor.LogFolder = settings["LogFolder"];
      monitor.ExpiryInterval = Int64.Parse(settings["Timeout"]);
      monitor.PacketFolder = settings["PacketFolder"];

      ConsoleCtrl ctrl = new ConsoleCtrl();
      ctrl.ControlEvent += new ConsoleCtrl.ControlEventHandler(ControlEvent);
      using (ctrl) {
        monitor.Open();
        try {
          monitor.Execute();
        } finally {
          monitor.Close();
        }
      }
    }

    [STAThread]
    static void Main(string[] args) {
      new Application().Run();
    }
  }
}
