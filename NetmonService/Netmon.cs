#region Using directives

using System;
using System.IO;
using System.Data;
using System.Text;
using System.Threading;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Diagnostics;
using System.Configuration;
using System.ComponentModel;
using System.ServiceProcess;

using Netmon.Engine;

#endregion

namespace NetmonService {
  public partial class Netmon : ServiceBase {
    public Netmon() {
      InitializeComponent();
    }

    Thread thread;
    global::Netmon.Engine.Monitor monitor;

    //bool terminated;

    protected void Execute() {
      monitor = new global::Netmon.Engine.Monitor();

      NameValueCollection settings = ConfigurationSettings.AppSettings;
      monitor.Adapter = settings["Adapter"];
      monitor.LogFolder = settings["LogFolder"];
      monitor.ExpiryInterval = Int64.Parse(settings["Timeout"]);
      monitor.PacketFolder = settings["PacketFolder"];

      monitor.Open();
      try {
        monitor.Execute();
      } finally {
        monitor.Close();
      }
    }

    protected override void OnStart(string[] args) {
      thread = new Thread(new ThreadStart(Execute));
      thread.Start();
    }

    protected override void OnStop() {
      monitor.Terminated = true;
    }
  }
}
