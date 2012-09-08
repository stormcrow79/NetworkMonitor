#region Using directives

using System;
using System.Collections.Generic;
using System.Text;

#endregion

namespace WebSpy.Syslog {
/*
 Numerical    Facility
 Code

  0    kernel messages
  1    user-level messages
  2    mail system
  3    system daemons
  4    security/authorization messages (note 1)
  5    messages generated internally by syslogd
  6    line printer subsystem
  7    network news subsystem
  8    UUCP subsystem
  9    clock daemon (note 2)
 10    security/authorization messages (note 1)
 11    FTP daemon
 12    NTP subsystem
 13    log audit (note 1)
 14    log alert (note 1)
 15    clock daemon (note 2)
 16    local use 0  (local0)
 17    local use 1  (local1)
 18    local use 2  (local2)
 19    local use 3  (local3)
 20    local use 4  (local4)
 21    local use 5  (local5)
 22    local use 6  (local6)
 23    local use 7  (local7)
*/

  public enum SyslogFacility {
    Kernel = 0,
    User = 1,
    Mail = 2,
    System = 3,
    Security1 = 4,
    Syslogd = 5,
    LinePrinter = 6,
    NetworkNews = 7,
    UUCP = 8,
    Clock1 = 9,
    Security2 = 10,
    Ftp = 11,
    Ntp = 12,
    Audit = 13,
    Alert = 14,
    Clock2 = 15,
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23
  }

  public class SyslogClient {
    public SyslogClient() {

    }
  }
}
