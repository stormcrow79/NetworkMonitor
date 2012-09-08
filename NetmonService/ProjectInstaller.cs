#region Using directives

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration.Install;

#endregion

namespace NetmonService {
  [RunInstaller(true)]
  public partial class ProjectInstaller : Installer {
    public ProjectInstaller() {
      InitializeComponent();
    }
  }
}