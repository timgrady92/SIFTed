// Artifact glossary data
const artifactData = {
  prefetch: {
    name: "Prefetch",
    os: ["windows"],
    takeaway: "Strong execution indicator with run counts and timestamps.",
    what: "Windows Prefetch (.pf) files are created when an executable runs and store run counts, last run timestamps, and referenced file paths.",
    why: "Helps confirm execution and frequency; use it to anchor timelines with other artifacts.",
    question: "Did this program execute on this system, and when?",
    corroborate: ["UserAssist entries and Event Logs", "AppCompatCache or Amcache for file presence"],
    location: ["C:\\Windows\\Prefetch\\", "Win10/11 may limit Prefetch on SSDs or when SysMain is off; absence is not proof."]
  },
  lnk: {
    name: "LNK Files",
    os: ["windows"],
    takeaway: "Proves a user opened a file path and captures volume context.",
    what: "Windows shortcut files created when a user opens a file or folder; store target path, timestamps, volume serials, and network share metadata.",
    why: "Proves user interaction even if the file moved or was deleted, and adds volume context for removable media.",
    question: "Was this file opened or accessed by a user?",
    corroborate: ["Jump Lists and $MFT timestamps", "Browser history if the file came from a download"],
    location: ["C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\", "...\\Recent\\AutomaticDestinations\\ (Jump Lists)"]
  },
  recentdocs: {
    name: "RecentDocs",
    os: ["windows"],
    takeaway: "Fast view of recently opened file names grouped by extension.",
    what: "Per-user registry lists of recently opened files grouped by extension, storing MRU order and entry names.",
    why: "Quickly surfaces filenames and usage order when higher-fidelity artifacts are missing.",
    question: "What files did the user open recently?",
    corroborate: ["LNK files and Jump Lists", "Shellbags for folder paths"],
    location: [
      "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
      "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU"
    ]
  },
  userassist: {
    name: "UserAssist",
    os: ["windows"],
    takeaway: "Shows GUI-launched programs per user with last run time.",
    what: "Per-user registry data tracking GUI launches (ROT13 encoded values) with run counts and timestamps.",
    why: "Shows user-driven execution and rough timing for GUI-launched programs.",
    question: "What programs did the user launch from the GUI?",
    corroborate: ["Prefetch entries and Event Logs", "AppCompatCache or Amcache for presence"],
    location: ["NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"]
  },
  shimcache: {
    name: "AppCompatCache (Shimcache)",
    os: ["windows"],
    takeaway: "Useful for file presence; execution inference varies by OS.",
    what: "Legacy compatibility cache entries populated by AppCompat routines, recording file paths and metadata rather than guaranteed execution.",
    why: "Useful evidence of file presence or compatibility checks; treat timestamps cautiously and corroborate.",
    question: "Was this binary or path present on the system?",
    corroborate: ["Amcache and Prefetch/UserAssist entries", "$MFT timestamps for file creation"],
    location: [
      "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
      "Parsing varies by Windows version; treat as legacy evidence."
    ]
  },
  amcache: {
    name: "Amcache",
    os: ["windows"],
    takeaway: "Reliable record of program presence and install metadata.",
    what: "Registry hive tracking installed applications and executed binaries with file paths, hashes, publisher info, and timestamps.",
    why: "Strong program presence evidence that often persists after deletion or uninstall.",
    question: "Was this program installed or executed on the host?",
    corroborate: ["Prefetch/UserAssist execution hints", "$MFT timestamps and file hashes"],
    location: ["C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf (Win7)"]
  },
  runkeys: {
    name: "Run Keys",
    os: ["windows"],
    takeaway: "Common persistence path; entries should map to known binaries.",
    what: "Registry keys that auto-start programs at logon for machine or user contexts, mapping value names to commands.",
    why: "Highlights persistence and auto-start command lines that need validation.",
    question: "What starts automatically at logon, and is it legitimate?",
    corroborate: ["Scheduled Tasks and Services", "File timestamps for referenced binaries"],
    location: ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
  },
  scheduledtasks: {
    name: "Scheduled Tasks",
    os: ["windows"],
    takeaway: "Triggers and actions reveal automated execution paths.",
    what: "Task definitions that run on schedule or triggers, stored as XML with actions, triggers, and principal context.",
    why: "Reveals automated execution paths and the account/context used to run them.",
    question: "Is anything running on a schedule that should not?",
    corroborate: ["Run keys and Startup folder items", "Event Logs for task registration"],
    location: ["C:\\Windows\\System32\\Tasks\\", "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"]
  },
  eventlogs: {
    name: "Event Logs",
    os: ["windows"],
    takeaway: "Authoritative event timeline for logons, processes, and services.",
    what: "Structured Windows event records from Security, System, and Application logs, keyed by Event ID and timestamp.",
    why: "Authoritative timeline for authentication, process, and service activity; confirm key events here.",
    question: "When did the user log in, and what changed on the system?",
    corroborate: ["Timeline output around the incident window", "Prefetch and services for execution context"],
    location: ["C:\\Windows\\System32\\winevt\\Logs\\", "Focus on logon events and service install/start events"]
  },
  timeline: {
    name: "Timeline (Plaso/Log2Timeline)",
    os: ["windows", "cross"],
    takeaway: "Best pivot to see multi-source activity around a time window.",
    what: "Aggregated timeline produced by tools like Plaso, combining file system, registry, event logs, and browser data into one sequence.",
    why: "Fastest way to pivot around incident windows and spot gaps or inconsistencies across sources.",
    question: "What happened before, during, and after the incident?",
    corroborate: ["Event Logs for authoritative events", "$MFT/USN for file changes"],
    location: ["Plaso storage file (.plaso) and CSV/JSON exports", "Timeline output from the Artifact Timeline workflow"]
  },
  defender: {
    name: "Windows Defender",
    os: ["windows"],
    takeaway: "Confirms detections and remediation actions.",
    what: "Detection history, scan metadata, and quarantine records with threat names, paths, and remediation status.",
    why: "Confirms security detections and the exact files or paths affected, with timestamps.",
    question: "Did Defender detect or quarantine relevant files?",
    corroborate: ["Event Logs: Windows Defender/Operational", "File system artifacts or malware samples"],
    location: [
      "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\",
      "C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\"
    ]
  },
  browser: {
    name: "Browser History",
    os: ["windows"],
    takeaway: "Shows user intent, downloads, and browsing context.",
    what: "Per-profile databases (often SQLite) tracking URLs, downloads, searches, and visit times.",
    why: "Reveals user intent, initial access, and download sources tied to suspected activity.",
    question: "What did the user search for, download, or visit?",
    corroborate: ["Downloads folder timestamps", "URL hits in Bulk Extractor outputs"],
    location: ["AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", "AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\"]
  },
  mft: {
    name: "$MFT + USN Journal",
    os: ["windows"],
    takeaway: "Reconstructs file lifecycle even after deletion.",
    what: "NTFS metadata ($MFT) storing file records and timestamps; the USN Journal records change events and reasons.",
    why: "Reliable evidence of file creation, movement, and deletion even when content is gone.",
    question: "What changed on disk, and when?",
    corroborate: ["Timeline entries for file creation or deletes", "Relevant LNK files for user access"],
    location: ["$MFT and $Extend\\$UsnJrnl on NTFS volumes"]
  },
  recyclebin: {
    name: "Recycle Bin",
    os: ["windows"],
    takeaway: "Captures deleted file names, original paths, and deletion times.",
    what: "Metadata ($I) and content ($R) for deleted items per SID, including original path and deletion time.",
    why: "Shows user-initiated deletion and original location for timeline reconstruction.",
    question: "What was deleted, and when?",
    corroborate: ["$MFT/USN delete events", "LNK/Jump Lists for pre-delete access"],
    location: ["C:\\$Recycle.Bin\\<SID>\\$I* and $R*", "$Recycle.Bin on each volume"]
  },
  jumplists: {
    name: "Jump Lists",
    os: ["windows"],
    takeaway: "App-focused record of recent files and tasks.",
    what: "Per-user, per-app automatic/custom destination files capturing recent files and tasks with timestamps and paths.",
    why: "Highlights app-specific user activity and the files opened through that app.",
    question: "Which files or folders were opened through a specific app?",
    corroborate: ["LNK files and Recent Items", "$MFT/USN timestamps for target paths"],
    location: [
      "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\",
      "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\"
    ]
  },
  shellbags: {
    name: "Shellbags",
    os: ["windows"],
    takeaway: "Evidence of folder browsing, even for deleted or remote folders.",
    what: "Per-user registry artifacts recording folder view settings and navigation, including folder paths and sometimes timestamps.",
    why: "Evidence of folder access, including deleted or removable locations, even without file artifacts.",
    question: "Which folders did the user browse?",
    corroborate: ["LNK files and Jump Lists", "$MFT/USN for folder creation or deletion"],
    location: [
      "NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
      "USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"
    ]
  },
  srum: {
    name: "SRUM",
    os: ["windows"],
    takeaway: "Timeline of app and network usage per user.",
    what: "SRUM database tracking app usage, network activity, and resource consumption per user over time.",
    why: "Builds time-based evidence tying users to apps and network usage.",
    question: "Which apps used the network or ran during the timeframe?",
    corroborate: ["Event Logs for network or logon activity", "Browser history or firewall logs"],
    location: ["C:\\Windows\\System32\\sru\\SRUDB.dat", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SRUM"]
  },
  usb: {
    name: "USB Device History",
    os: ["windows"],
    takeaway: "Identifies removable devices and connection history.",
    what: "Registry and setup logs recording USB device installs, vendor/product IDs, serials, and last connection details.",
    why: "Identifies removable media usage and device identity, supporting data movement analysis.",
    question: "Which USB storage devices were connected to this host?",
    corroborate: ["Shellbags for volume browsing", "$MFT/USN for removable drive activity"],
    location: ["HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", "HKLM\\SYSTEM\\MountedDevices", "C:\\Windows\\inf\\setupapi.dev.log"]
  },
  services: {
    name: "Services",
    os: ["windows"],
    takeaway: "Persistent system startup artifacts with binary paths.",
    what: "Service and driver configuration stored in the registry, including start type, image path, and account context.",
    why: "Surfaces persistent services and launch context for suspicious binaries.",
    question: "What services or drivers are configured to start automatically?",
    corroborate: ["Event Logs for service install/start", "File timestamps for service binaries"],
    location: ["HKLM\\SYSTEM\\CurrentControlSet\\Services", "C:\\Windows\\System32\\"]
  },
  wmi: {
    name: "WMI Subscriptions",
    os: ["windows"],
    takeaway: "Stealthy persistence via filters/consumers/bindings.",
    what: "WMI event filters, consumers, and bindings that can execute scripts or commands on triggers.",
    why: "Stealthy persistence that bypasses common startup lists; bindings show trigger/action pairs.",
    question: "Is WMI being used for persistence or tasking?",
    corroborate: ["Event Logs (WMI-Activity)", "Scheduled Tasks and Run keys"],
    location: ["root\\subscription namespace", "C:\\Windows\\System32\\wbem\\Repository\\"]
  },
  powershell: {
    name: "PowerShell Logs",
    os: ["windows"],
    takeaway: "Script block and transcription logs reveal executed commands.",
    what: "Event logs capturing PowerShell script execution including Script Block Logging (Event ID 4104), Module Logging, and optional transcription files.",
    why: "Critical for reconstructing attacker commands, decoded payloads, and obfuscated script content.",
    question: "What PowerShell commands or scripts were executed?",
    corroborate: ["Prefetch for powershell.exe execution", "Event Logs for process creation (4688)"],
    location: [
      "Microsoft-Windows-PowerShell/Operational",
      "Windows PowerShell (legacy)",
      "Transcripts: C:\\Users\\<user>\\Documents\\PowerShell_transcript.*"
    ]
  },
  bits: {
    name: "BITS Jobs",
    os: ["windows"],
    takeaway: "Background transfers used for downloads and persistence.",
    what: "Background Intelligent Transfer Service jobs that download or upload files asynchronously, surviving reboots and network interruptions.",
    why: "Attackers abuse BITS for stealthy downloads and persistence; jobs persist across reboots.",
    question: "Were BITS jobs used to download payloads or maintain persistence?",
    corroborate: ["Event Logs: Microsoft-Windows-Bits-Client/Operational", "Browser history for download sources"],
    location: [
      "C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr.db",
      "bitsadmin /list /allusers /verbose",
      "Get-BitsTransfer -AllUsers"
    ]
  },
  rdp: {
    name: "RDP Artifacts",
    os: ["windows"],
    takeaway: "Tracks remote desktop connections in and out.",
    what: "Registry keys, event logs, and bitmap cache files recording Remote Desktop connections, including source IPs and usernames.",
    why: "Essential for tracking lateral movement and remote access activity.",
    question: "Who connected via RDP, from where, and when?",
    corroborate: ["Event Logs: Security (4624/4625), TerminalServices-*", "Auth logs on source systems"],
    location: [
      "NTUSER.DAT\\Software\\Microsoft\\Terminal Server Client\\Servers",
      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations",
      "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\*.bmc"
    ]
  },
  bam: {
    name: "BAM/DAM",
    os: ["windows"],
    takeaway: "Records program execution with timestamps per user.",
    what: "Background Activity Moderator (BAM) and Desktop Activity Moderator (DAM) registry keys tracking executed programs with last execution timestamps.",
    why: "Provides execution evidence with user context and timestamps, useful when Prefetch is disabled.",
    question: "What programs did users execute recently?",
    corroborate: ["Prefetch and UserAssist entries", "Amcache for program metadata"],
    location: [
      "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\<SID>",
      "SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings\\<SID>",
      "Available on Windows 10 1709+ and Server 2019+"
    ]
  },
  typedpaths: {
    name: "TypedPaths / TypedURLs",
    os: ["windows"],
    takeaway: "Records paths and URLs typed by the user.",
    what: "Per-user registry keys storing Explorer address bar paths (TypedPaths) and Internet Explorer URLs (TypedURLs) entered manually.",
    why: "Shows intentional user navigation to specific paths or sites, indicating knowledge and intent.",
    question: "What paths or URLs did the user manually navigate to?",
    corroborate: ["Shellbags for folder access", "Browser history for web navigation"],
    location: [
      "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
      "NTUSER.DAT\\Software\\Microsoft\\Internet Explorer\\TypedURLs"
    ]
  },
  startupfolder: {
    name: "Startup Folder",
    os: ["windows"],
    takeaway: "Simple persistence via shortcuts in startup directories.",
    what: "Per-user and system-wide folders containing shortcuts or executables that run at logon.",
    why: "Common and simple persistence mechanism; contents should match known legitimate software.",
    question: "What programs start automatically via startup folders?",
    corroborate: ["Run keys and Scheduled Tasks", "LNK file analysis for target paths"],
    location: [
      "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
      "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    ]
  },
  vss: {
    name: "Volume Shadow Copies",
    os: ["windows"],
    takeaway: "Point-in-time snapshots for recovering deleted or modified files.",
    what: "System restore points and shadow copies containing previous versions of files, registry hives, and system state.",
    why: "Enables recovery of deleted files and comparison of system state before/after an incident.",
    question: "What did the system look like before the incident?",
    corroborate: ["Current artifacts compared to shadow copy versions", "$MFT for file timeline"],
    location: [
      "System Volume Information on each NTFS volume",
      "vssadmin list shadows",
      "Access via mklink or forensic mounting"
    ]
  },
  ads: {
    name: "Alternate Data Streams",
    os: ["windows"],
    takeaway: "Hidden data attached to files, including Zone.Identifier for downloads.",
    what: "NTFS feature allowing multiple data streams per file; commonly used for Zone.Identifier (Mark of the Web) and sometimes for hiding data.",
    why: "Zone.Identifier proves a file was downloaded from the internet; malicious ADS can hide payloads.",
    question: "Where did this file come from, and is data hidden in alternate streams?",
    corroborate: ["Browser downloads for source URLs", "$MFT for stream metadata"],
    location: [
      "dir /r to list streams",
      "Get-Item -Stream * in PowerShell",
      "Zone.Identifier contains ZoneId and often ReferrerUrl"
    ]
  },
  searchindex: {
    name: "Windows Search Index",
    os: ["windows"],
    takeaway: "Indexed file content and metadata, including deleted files.",
    what: "Windows Search database (Windows.edb) containing indexed content, file paths, and metadata for files that may no longer exist.",
    why: "Can reveal file content and existence even after deletion; useful for keyword searches.",
    question: "What files existed or contained specific content?",
    corroborate: ["$MFT for file existence", "RecentDocs for user access"],
    location: [
      "C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb",
      "Use ESEDatabaseView or dedicated forensic tools to parse"
    ]
  },
  thumbcache: {
    name: "Thumbnail Cache",
    os: ["windows"],
    takeaway: "Image previews persist even after original files are deleted.",
    what: "Cached thumbnail images generated when viewing folders in Explorer, stored in thumbcache_*.db files.",
    why: "Proves images existed on the system even if deleted; can recover preview versions of deleted pictures.",
    question: "What images were viewed or existed on this system?",
    corroborate: ["$MFT for original file paths", "Shellbags for folder access"],
    location: [
      "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db",
      "Use Thumbcache Viewer or similar tools"
    ]
  },
  networkshares: {
    name: "Network Shares / Mapped Drives",
    os: ["windows"],
    takeaway: "Evidence of network resource access and lateral movement.",
    what: "Registry keys and MRU lists tracking mapped network drives, recent network paths, and share connections.",
    why: "Shows network resources accessed, supporting lateral movement or data access analysis.",
    question: "What network shares or remote systems did the user access?",
    corroborate: ["Shellbags for UNC paths", "LNK files pointing to network locations"],
    location: [
      "NTUSER.DAT\\Network (mapped drives)",
      "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU",
      "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"
    ]
  },
  wer: {
    name: "Windows Error Reporting",
    os: ["windows"],
    takeaway: "Crash reports can reveal exploitation or malware behavior.",
    what: "Crash dump files and reports generated when applications crash, containing process state and exception information.",
    why: "Exploitation attempts often cause crashes; reports may capture malicious process state.",
    question: "Did any applications crash suspiciously, and what was their state?",
    corroborate: ["Event Logs for application errors", "Prefetch for crashed process execution"],
    location: [
      "C:\\ProgramData\\Microsoft\\Windows\\WER\\",
      "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\WER\\",
      "Event Log: Application (Event ID 1000, 1001)"
    ]
  },
  muicache: {
    name: "MUICache",
    os: ["windows"],
    takeaway: "Records executable display names, proving program presence.",
    what: "Registry cache of executable display names populated when programs run, mapping paths to friendly names.",
    why: "Evidence of program execution; persists even after the executable is deleted.",
    question: "What programs were executed on this system?",
    corroborate: ["Prefetch and UserAssist for execution", "Amcache for file metadata"],
    location: [
      "NTUSER.DAT\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
      "USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"
    ]
  },
  wordwheelquery: {
    name: "WordWheelQuery",
    os: ["windows"],
    takeaway: "Records searches performed in Explorer.",
    what: "Per-user registry key storing recent search terms entered in Windows Explorer search boxes.",
    why: "Reveals what the user was looking for; can indicate intent or awareness of specific files.",
    question: "What did the user search for in Explorer?",
    corroborate: ["Shellbags for folders browsed", "RecentDocs for files accessed"],
    location: ["NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"]
  },
  lastvisitedmru: {
    name: "LastVisitedMRU",
    os: ["windows"],
    takeaway: "Tracks applications and folders used in Open/Save dialogs.",
    what: "Registry keys recording which applications were used to open files and which folders were accessed via Open/Save dialogs.",
    why: "Shows application-to-file relationships and folder access patterns.",
    question: "Which applications opened or saved files, and where?",
    corroborate: ["RecentDocs for file access", "Prefetch for application execution"],
    location: [
      "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
      "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU"
    ]
  },
  networkprofiles: {
    name: "Network Profiles",
    os: ["windows"],
    takeaway: "History of networks the system connected to.",
    what: "Registry and event log records of network connections including SSIDs, first/last connection times, and network types.",
    why: "Shows where the system has been connected; useful for timeline and location analysis.",
    question: "What networks has this system connected to, and when?",
    corroborate: ["Event Logs for network events", "SRUM for network usage"],
    location: [
      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures",
      "Event Log: Microsoft-Windows-WLAN-AutoConfig/Operational"
    ]
  },
  bashhistory: {
    name: "Bash History",
    os: ["linux"],
    takeaway: "Direct record of user commands (if not cleared).",
    what: "Per-user bash command history written to HISTFILE on shell exit or periodically depending on settings.",
    why: "Direct view of commands and intent; can reveal tools used and paths touched.",
    question: "What commands did the user run?",
    corroborate: ["Auth logs for session timing", "File timestamps for touched files"],
    location: ["/home/<user>/.bash_history", "/root/.bash_history", "History can be cleared or disabled."]
  },
  authlogs: {
    name: "Auth Logs",
    os: ["linux"],
    takeaway: "Logons, sudo use, and failures by source.",
    what: "Authentication and sudo logs for SSH and local logins, including source IPs and failure reasons.",
    why: "Confirms access paths and privilege escalation; useful for detecting brute-force or abuse.",
    question: "Who authenticated, from where, and when?",
    corroborate: ["wtmp/btmp/lastlog records", "SSH authorized_keys and bash history"],
    location: ["/var/log/auth.log (Debian/Ubuntu)", "/var/log/secure (RHEL/CentOS)"]
  },
  syslog: {
    name: "Syslog",
    os: ["linux"],
    takeaway: "Broad system and service activity baseline.",
    what: "Plaintext system and service messages (kernel, daemons, apps), typically rotated by logrotate.",
    why: "Provides a broad timeline and context when specialized logs are sparse.",
    question: "What system events occurred around the incident?",
    corroborate: ["systemd journal entries", "Auth logs for login context"],
    location: ["/var/log/syslog (Debian/Ubuntu)", "/var/log/messages (RHEL/CentOS)"]
  },
  journal: {
    name: "systemd Journal",
    os: ["linux"],
    takeaway: "Centralized log source, even when text logs rotate.",
    what: "Binary systemd journal with structured fields for services and kernel events, queryable via journalctl.",
    why: "Centralized evidence even if text logs are disabled; supports filtering by unit or time.",
    question: "What services or system events were recorded?",
    corroborate: ["Syslog and auth logs", "Service unit files for configuration"],
    location: ["/var/log/journal/", "/run/log/journal/ (volatile)"]
  },
  cron: {
    name: "Cron Jobs",
    os: ["linux"],
    takeaway: "Scheduled tasks used for automation or persistence.",
    what: "Scheduled tasks defined in system/user crontabs and /etc/cron.* directories, sometimes via anacron.",
    why: "Common automation and persistence mechanism; shows periodic execution of scripts or commands.",
    question: "What tasks run on a schedule?",
    corroborate: ["Auth logs for cron edits", "Bash history for creation commands"],
    location: ["/etc/crontab", "/etc/cron.d/", "/var/spool/cron/crontabs/<user>"]
  },
  packages: {
    name: "Package Manager Logs",
    os: ["linux"],
    takeaway: "Records software installs/removals with timestamps.",
    what: "Package manager logs recording installs, upgrades, and removals with package versions and timestamps.",
    why: "Shows software changes and timing of tool installation or removal.",
    question: "What software changes happened recently?",
    corroborate: ["Auth logs for sudo install activity", "Bash history for install commands"],
    location: ["/var/log/apt/history.log", "/var/log/dpkg.log", "/var/log/yum.log"]
  },
  sshkeys: {
    name: "SSH Keys",
    os: ["linux"],
    takeaway: "Persistent access via trusted keys and known hosts.",
    what: "Authorized_keys and known_hosts files storing trusted public keys and remote host fingerprints.",
    why: "Reveals persistent access paths and trusted hosts tied to lateral movement.",
    question: "Which keys were trusted or used for access?",
    corroborate: ["Auth logs for key-based logins", "Bash history for session activity"],
    location: ["/home/<user>/.ssh/authorized_keys", "/root/.ssh/authorized_keys", "/home/<user>/.ssh/known_hosts"]
  },
  wtmp: {
    name: "Login Records",
    os: ["linux"],
    takeaway: "Durable login evidence even after text logs rotate.",
    what: "Binary login databases tracking successful and failed sessions (wtmp, btmp, lastlog), used by last/lastb.",
    why: "Durable login evidence even after text logs rotate; helps confirm session timelines.",
    question: "When were logins successful or failed?",
    corroborate: ["Auth logs and journal entries", "Bash history for session activity"],
    location: ["/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"]
  },
  auditd: {
    name: "Audit Logs (auditd)",
    os: ["linux"],
    takeaway: "Detailed syscall and file access logging when configured.",
    what: "Linux Audit Framework logs capturing syscalls, file access, user commands, and security events based on configured rules.",
    why: "Provides granular evidence of process execution, file access, and privilege use beyond standard logs.",
    question: "What specific actions were taken at the syscall level?",
    corroborate: ["Auth logs for user context", "Bash history for command correlation"],
    location: ["/var/log/audit/audit.log", "ausearch and aureport for parsing", "/etc/audit/audit.rules for configuration"]
  },
  systemdunits: {
    name: "Systemd Units",
    os: ["linux"],
    takeaway: "Service definitions reveal persistence and startup behavior.",
    what: "Systemd unit files (.service, .timer, .socket) defining services, timers, and socket activation for automatic execution.",
    why: "Common persistence mechanism; malicious units may hide in user directories or override legitimate services.",
    question: "What services or timers are configured to run automatically?",
    corroborate: ["Journal entries for unit activity", "Cron jobs for additional scheduling"],
    location: [
      "/etc/systemd/system/",
      "/lib/systemd/system/",
      "/home/<user>/.config/systemd/user/",
      "systemctl list-unit-files"
    ]
  },
  procfs: {
    name: "/proc Filesystem",
    os: ["linux"],
    takeaway: "Live process and system state for running system analysis.",
    what: "Virtual filesystem exposing kernel and process information including command lines, environment variables, file descriptors, and memory maps.",
    why: "Essential for live response to identify running processes, open files, network connections, and deleted-but-open files.",
    question: "What processes are running and what resources are they using?",
    corroborate: ["Auth logs for process ownership", "Network connections via /proc/net or ss"],
    location: [
      "/proc/<pid>/cmdline, environ, fd/, maps, exe",
      "/proc/net/tcp, /proc/net/udp",
      "Live system only; not available in disk images"
    ]
  },
  envfiles: {
    name: "Environment Files",
    os: ["linux"],
    takeaway: "Shell startup files used for persistence and environment manipulation.",
    what: "Per-user and system-wide shell configuration files (.bashrc, .bash_profile, .profile, /etc/profile.d/) executed on login or shell start.",
    why: "Attackers inject malicious commands or PATH manipulation for persistence; changes may be subtle.",
    question: "Were shell startup files modified for persistence?",
    corroborate: ["File timestamps for recent modifications", "Bash history for editing commands"],
    location: [
      "/home/<user>/.bashrc, .bash_profile, .profile",
      "/root/.bashrc, .bash_profile",
      "/etc/profile, /etc/profile.d/, /etc/bash.bashrc"
    ]
  },
  passwdshadow: {
    name: "User Accounts",
    os: ["linux"],
    takeaway: "User and group definitions reveal account creation and privilege.",
    what: "System files defining user accounts (passwd), password hashes (shadow), groups, and sudoers configuration.",
    why: "Shows account creation, UID/GID assignments, and privilege escalation paths via sudo.",
    question: "What accounts exist and what privileges do they have?",
    corroborate: ["Auth logs for account activity", "Bash history for useradd/usermod commands"],
    location: [
      "/etc/passwd",
      "/etc/shadow",
      "/etc/group",
      "/etc/sudoers, /etc/sudoers.d/"
    ]
  },
  webserverlogs: {
    name: "Web Server Logs",
    os: ["linux"],
    takeaway: "HTTP request logs for web shell and exploitation analysis.",
    what: "Access and error logs from Apache, Nginx, or other web servers recording requests, response codes, user agents, and errors.",
    why: "Critical for identifying web shell access, exploitation attempts, and initial access vectors.",
    question: "What web requests indicate malicious activity?",
    corroborate: ["File system for web shells in document root", "Auth logs for related user activity"],
    location: [
      "/var/log/apache2/access.log, error.log",
      "/var/log/nginx/access.log, error.log",
      "/var/log/httpd/ (RHEL/CentOS)"
    ]
  },
  tmpshm: {
    name: "/tmp and /dev/shm",
    os: ["linux"],
    takeaway: "World-writable locations often used for staging and execution.",
    what: "Temporary filesystems (/tmp disk-backed, /dev/shm memory-backed) writable by all users, commonly used for staging tools or payloads.",
    why: "Attackers frequently stage tools, scripts, or payloads here; memory-backed /dev/shm avoids disk writes.",
    question: "Are there suspicious files or recently executed tools in temp directories?",
    corroborate: ["Bash history for commands referencing /tmp", "Process listing for executables in temp paths"],
    location: [
      "/tmp/",
      "/dev/shm/",
      "/var/tmp/",
      "Check file timestamps and ownership"
    ]
  },
  etchosts: {
    name: "/etc/hosts",
    os: ["linux"],
    takeaway: "Static DNS overrides for redirection or blocking.",
    what: "Static hostname-to-IP mappings that override DNS resolution, used legitimately for local aliases or maliciously for redirection.",
    why: "Attackers may redirect security update servers or C2 domains; defenders may block known-bad domains.",
    question: "Has DNS resolution been manipulated via /etc/hosts?",
    corroborate: ["Network traffic for actual connections", "File timestamps for recent modifications"],
    location: ["/etc/hosts", "Compare against known-good baseline"]
  },
  kernellogs: {
    name: "Kernel Logs",
    os: ["linux"],
    takeaway: "Hardware, driver, and kernel-level events including security messages.",
    what: "Kernel ring buffer (dmesg) and persistent logs (kern.log) containing hardware events, driver messages, and kernel security events.",
    why: "Can reveal hardware attacks, driver exploits, kernel module loading, and security subsystem events.",
    question: "What kernel-level events occurred, including module loads or security alerts?",
    corroborate: ["systemd journal for correlated events", "Auth logs for related user activity"],
    location: ["/var/log/kern.log", "/var/log/dmesg", "dmesg command for ring buffer"]
  },
  coredumps: {
    name: "Core Dumps",
    os: ["linux"],
    takeaway: "Crash dumps can reveal exploitation or malware behavior.",
    what: "Process memory dumps generated on crashes, containing program state, memory contents, and crash context.",
    why: "Exploitation attempts cause crashes; core dumps capture process state at time of failure.",
    question: "Did any processes crash, and what was their state?",
    corroborate: ["Syslog for crash messages", "Auth logs for process ownership"],
    location: [
      "/var/lib/systemd/coredump/",
      "/var/crash/",
      "coredumpctl list (systemd systems)"
    ]
  },
  suidsgid: {
    name: "SUID/SGID Binaries",
    os: ["linux"],
    takeaway: "Privilege escalation vectors via setuid/setgid executables.",
    what: "Executables with SUID or SGID bits set, running with elevated privileges regardless of the calling user.",
    why: "Attackers add SUID bits to backdoors or exploit vulnerable SUID binaries for privilege escalation.",
    question: "Are there unexpected SUID/SGID binaries or recent changes?",
    corroborate: ["Package manager to verify legitimate SUID files", "File timestamps for recent changes"],
    location: [
      "find / -perm -4000 -type f (SUID)",
      "find / -perm -2000 -type f (SGID)",
      "Compare against known-good baseline"
    ]
  },
  atjobs: {
    name: "at Jobs",
    os: ["linux"],
    takeaway: "One-time scheduled tasks, alternative to cron.",
    what: "Jobs scheduled via the at command for one-time execution at a specified time.",
    why: "Less commonly monitored than cron; attackers may use for delayed execution or persistence.",
    question: "Are there scheduled one-time jobs that shouldn't exist?",
    corroborate: ["Cron jobs for other scheduled tasks", "Auth logs for job creation"],
    location: ["/var/spool/at/", "atq command to list pending jobs"]
  },
  capabilities: {
    name: "Linux Capabilities",
    os: ["linux"],
    takeaway: "Fine-grained privileges that can enable escalation without full root.",
    what: "POSIX capabilities assigned to executables or processes, granting specific privileges without full root access.",
    why: "Misconfigured capabilities (e.g., CAP_SETUID) can enable privilege escalation.",
    question: "Do any binaries have dangerous capabilities assigned?",
    corroborate: ["SUID/SGID binaries for other escalation paths", "File timestamps for recent changes"],
    location: [
      "getcap -r / 2>/dev/null",
      "/usr/sbin/getcap",
      "Look for CAP_SETUID, CAP_NET_RAW, CAP_DAC_OVERRIDE"
    ]
  },
  ldpreload: {
    name: "LD_PRELOAD / Library Injection",
    os: ["linux"],
    takeaway: "Shared library hijacking for persistence or credential theft.",
    what: "Environment variables and configuration files that force loading of malicious shared libraries before legitimate ones.",
    why: "Attackers inject malicious libraries to intercept function calls, steal credentials, or maintain persistence.",
    question: "Are there unauthorized preload configurations or suspicious libraries?",
    corroborate: ["Environment files (.bashrc, .profile)", "Bash history for export commands"],
    location: [
      "/etc/ld.so.preload",
      "LD_PRELOAD environment variable",
      "/etc/ld.so.conf.d/",
      "Check library timestamps in /lib and /usr/lib"
    ]
  },
  fsevents: {
    name: "FSEvents",
    os: ["macos"],
    takeaway: "File system change journal with historical activity.",
    what: "macOS file system event store recording file and folder changes, used by Spotlight and Time Machine.",
    why: "Provides historical record of file system activity even after files are deleted.",
    question: "What file system changes occurred on this system?",
    corroborate: ["Spotlight metadata for file content", "Unified logs for related activity"],
    location: [
      "/.fseventsd/",
      "Use FSEventsParser or similar tools",
      "Gzip-compressed event records"
    ]
  },
  spotlight: {
    name: "Spotlight Metadata",
    os: ["macos"],
    takeaway: "Indexed file content and metadata, including deleted files.",
    what: "macOS search index containing file metadata, content snippets, and attributes for indexed files.",
    why: "May contain evidence of files that no longer exist; useful for keyword searches.",
    question: "What files existed or contained specific content?",
    corroborate: ["FSEvents for file activity", "Quarantine events for downloads"],
    location: [
      "/.Spotlight-V100/",
      "mdls command for file metadata",
      "mdfind for searching the index"
    ]
  },
  quarantine: {
    name: "Quarantine Events",
    os: ["macos"],
    takeaway: "Records downloaded files with source URLs and timestamps.",
    what: "Database tracking files downloaded from the internet, including source URLs, download timestamps, and application used.",
    why: "Proves files were downloaded from specific URLs; similar to Windows Zone.Identifier.",
    question: "What files were downloaded, from where, and when?",
    corroborate: ["Browser history for download context", "FSEvents for file creation"],
    location: [
      "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
      "Extended attribute: com.apple.quarantine"
    ]
  },
  unifiedlogs: {
    name: "Unified Logs",
    os: ["macos"],
    takeaway: "Centralized logging for all system and application events.",
    what: "macOS unified logging system consolidating kernel, system, and application logs with structured data and timestamps.",
    why: "Primary source for system activity on modern macOS; replaces traditional log files.",
    question: "What system and application events occurred?",
    corroborate: ["FSEvents for file activity", "Launch agents for persistence"],
    location: [
      "/var/db/diagnostics/",
      "log show command",
      "log collect for export"
    ]
  },
  launchagents: {
    name: "Launch Agents / Daemons",
    os: ["macos"],
    takeaway: "Primary persistence mechanism on macOS.",
    what: "Property list files defining programs that run at login (agents) or boot (daemons), with triggers and configurations.",
    why: "Most common macOS persistence mechanism; malicious plists may hide in user directories.",
    question: "What programs are configured to run automatically?",
    corroborate: ["Unified logs for launch events", "File timestamps for recent additions"],
    location: [
      "~/Library/LaunchAgents/",
      "/Library/LaunchAgents/",
      "/Library/LaunchDaemons/",
      "/System/Library/LaunchDaemons/"
    ]
  },
  tccdb: {
    name: "TCC Database",
    os: ["macos"],
    takeaway: "Privacy permission grants for applications.",
    what: "Transparency, Consent, and Control database tracking which applications have been granted privacy permissions (camera, microphone, full disk access, etc.).",
    why: "Shows which apps have sensitive permissions; attackers may grant permissions to malicious tools.",
    question: "Which applications have been granted sensitive permissions?",
    corroborate: ["Launch agents for persistence", "Application signatures and paths"],
    location: [
      "~/Library/Application Support/com.apple.TCC/TCC.db",
      "/Library/Application Support/com.apple.TCC/TCC.db"
    ]
  },
  keychain: {
    name: "Keychain",
    os: ["macos"],
    takeaway: "Stored credentials and certificates.",
    what: "macOS credential storage containing passwords, certificates, keys, and secure notes, protected by user password.",
    why: "Attackers with user access may dump keychain contents; shows what credentials were stored.",
    question: "What credentials were stored on this system?",
    corroborate: ["Auth attempts using stored credentials", "Browser history for related accounts"],
    location: [
      "~/Library/Keychains/",
      "/Library/Keychains/",
      "security dump-keychain command"
    ]
  },
  knownnetworks: {
    name: "Known Networks",
    os: ["macos"],
    takeaway: "WiFi connection history with timestamps.",
    what: "Database of WiFi networks the system has connected to, including SSIDs, security types, and connection timestamps.",
    why: "Shows location history based on network connections; useful for timeline analysis.",
    question: "What WiFi networks has this system connected to?",
    corroborate: ["Unified logs for network events", "Network profiles"],
    location: [
      "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
      "/Library/Preferences/com.apple.wifi.known-networks.plist"
    ]
  },
  loginitems: {
    name: "Login Items",
    os: ["macos"],
    takeaway: "Applications launched at user login.",
    what: "User-configured applications that launch automatically when the user logs in, separate from Launch Agents.",
    why: "Simple persistence mechanism; check for unexpected applications.",
    question: "What applications start at user login?",
    corroborate: ["Launch Agents for other persistence", "Application signatures"],
    location: [
      "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
      "System Preferences > Users & Groups > Login Items"
    ]
  }
};

const escapeHtml = (value) => String(value)
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#39;");

const buildDetailMarkup = (data) => `
  <h3>${escapeHtml(data.name)}</h3>
  <div class="detail-section">
    <div class="detail-label">Key takeaway</div>
    <p class="detail-text">${escapeHtml(data.takeaway)}</p>
  </div>
  <div class="detail-section">
    <div class="detail-label">What it is</div>
    <p class="detail-text">${escapeHtml(data.what)}</p>
  </div>
  <div class="detail-section">
    <div class="detail-label">Why it matters</div>
    <p class="detail-text">${escapeHtml(data.why)}</p>
  </div>
  <div class="detail-section">
    <div class="detail-label">Analyst question</div>
    <p class="detail-text">${escapeHtml(data.question)}</p>
  </div>
  <div class="detail-section">
    <div class="detail-label">Corroborate with</div>
    <ul class="detail-list">
      ${data.corroborate.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
    </ul>
  </div>
  <div class="detail-section">
    <div class="detail-label">Where to look</div>
    <ul class="detail-list">
      ${data.location.map((item) => `<li><code>${escapeHtml(item)}</code></li>`).join("")}
    </ul>
  </div>
`;

const initGlossarySurface = (surface) => {
  const mode = surface.dataset.glossaryMode || "stack";
  const grid = surface.querySelector("[data-glossary-grid]");
  const detail = surface.querySelector("[data-glossary-detail]");
  const detailContent = surface.querySelector("[data-glossary-detail-content]");
  const back = surface.querySelector("[data-glossary-back]");
  const search = surface.querySelector("[data-glossary-search]");
  const count = surface.querySelector("[data-glossary-count]");
  const filterGroups = Array.from(surface.querySelectorAll("[data-glossary-filter-group]"));
  const tiles = Array.from(surface.querySelectorAll("[data-glossary-tile]"));

  if (!grid || !detail || !detailContent || tiles.length === 0) {
    return null;
  }

  const total = tiles.length;
  const activeFilters = {};
  const availableFilters = {};

  Object.values(artifactData).forEach((data) => {
    (data.os || []).forEach((value) => {
      if (!availableFilters.os) {
        availableFilters.os = new Set();
      }
      availableFilters.os.add(value);
    });
  });

  const setView = (view) => {
    surface.dataset.glossaryState = view;
    if (mode === "stack") {
      grid.hidden = view !== "grid";
      detail.hidden = view !== "detail";
    } else {
      grid.hidden = false;
      detail.hidden = false;
    }
  };

  const updateCount = (visible, query) => {
    if (!count) {
      return;
    }
    if (!query) {
      count.textContent = `${total} artifacts`;
      return;
    }
    count.textContent = `${visible} of ${total} artifacts`;
  };

  const showDetail = (artifactId, options = {}) => {
    const data = artifactData[artifactId];
    if (!data) {
      return;
    }
    tiles.forEach((tile) => {
      tile.classList.toggle("active", tile.dataset.artifact === artifactId);
    });
    detailContent.innerHTML = buildDetailMarkup(data);
    if (options.updateState !== false) {
      setView("detail");
    }
  };

  const showGrid = () => {
    setView("grid");
    tiles.forEach((tile) => tile.classList.remove("active"));
  };

  const filterTiles = () => {
    const query = search?.value.toLowerCase().trim() || "";
    let visible = 0;
    tiles.forEach((tile) => {
      const name = tile.querySelector(".glossary-tile-name")?.textContent.toLowerCase() || "";
      const hint = tile.querySelector(".glossary-tile-hint")?.textContent.toLowerCase() || "";
      const artifactId = tile.dataset.artifact || "";
      const data = artifactData[artifactId];
      const extraText = data
        ? `${data.what} ${data.takeaway || ""} ${data.why} ${data.question}`.toLowerCase()
        : "";
      const osFilter = activeFilters.os;
      const osMatches = !osFilter || (data?.os || []).includes(osFilter);

      const matches = !query ||
        name.includes(query) ||
        hint.includes(query) ||
        artifactId.includes(query) ||
        extraText.includes(query);

      const shouldShow = matches && osMatches;

      tile.classList.toggle("filter-hidden", !shouldShow);
      if (shouldShow) {
        visible += 1;
      }
    });
    updateCount(visible, query);
  };

  tiles.forEach((tile) => {
    tile.addEventListener("click", () => {
      const artifactId = tile.dataset.artifact;
      if (artifactId) {
        showDetail(artifactId);
      }
    });
  });

  if (back) {
    back.addEventListener("click", showGrid);
  }

  if (search) {
    search.addEventListener("input", filterTiles);
  }

  filterGroups.forEach((group) => {
    const groupName = group.dataset.glossaryFilterGroup;
    const buttons = Array.from(group.querySelectorAll("[data-glossary-filter-value]"));

    if (!groupName || buttons.length === 0) {
      return;
    }

    const available = availableFilters[groupName] || new Set();

    buttons.forEach((button) => {
      const value = button.dataset.glossaryFilterValue || "";
      if (value === "all") {
        return;
      }
      if (!available.has(value)) {
        button.classList.add("disabled");
        button.setAttribute("aria-disabled", "true");
      }
    });

    const setActiveFilter = (value) => {
      activeFilters[groupName] = value === "all" ? null : value;
      buttons.forEach((button) => {
        button.classList.toggle(
          "active",
          button.dataset.glossaryFilterValue === value,
        );
      });
      filterTiles();
    };

    const defaultButton = buttons.find((button) => button.dataset.glossaryFilterValue === "all");
    if (defaultButton) {
      setActiveFilter("all");
    }

    buttons.forEach((button) => {
      button.addEventListener("click", () => {
        if (button.classList.contains("disabled")) {
          return;
        }
        setActiveFilter(button.dataset.glossaryFilterValue || "all");
      });
    });
  });

  setView("grid");
  filterTiles();

  if (mode === "split" && tiles[0]?.dataset.artifact) {
    showDetail(tiles[0].dataset.artifact, { updateState: false });
  }

  return { showDetail, showGrid, setView };
};

const glossarySurfaces = Array.from(document.querySelectorAll("[data-glossary-surface]"));
const surfaceApis = {};

glossarySurfaces.forEach((surface, index) => {
  const key = surface.dataset.glossarySurface || `surface-${index}`;
  const api = initGlossarySurface(surface);
  if (api) {
    surfaceApis[key] = api;
  }
});

const sidebar = document.querySelector('[data-glossary-surface="sidebar"]');
const layout = document.querySelector(".guides-layout");
const toggleButtons = Array.from(document.querySelectorAll('[data-glossary-toggle="sidebar"]'));
const closeButton = sidebar?.querySelector("[data-glossary-close]");
const sidebarApi = surfaceApis.sidebar;

const openSidebar = () => {
  if (!sidebar) {
    return;
  }
  sidebar.classList.add("open");
  sidebar.setAttribute("aria-hidden", "false");
  document.body.classList.add("glossary-open");
  layout?.classList.add("sidebar-open");
};

const closeSidebar = () => {
  if (!sidebar) {
    return;
  }
  sidebar.classList.remove("open");
  sidebar.setAttribute("aria-hidden", "true");
  document.body.classList.remove("glossary-open");
  layout?.classList.remove("sidebar-open");
};

if (toggleButtons.length) {
  toggleButtons.forEach((button) => {
    button.addEventListener("click", openSidebar);
  });
}

if (closeButton) {
  closeButton.addEventListener("click", closeSidebar);
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && sidebar?.classList.contains("open")) {
    closeSidebar();
  }
});

// Artifact link tooltips
const tooltip = document.getElementById("artifactTooltip");
const tooltipContent = document.getElementById("artifactTooltipContent");

let tooltipTimeout = null;

const showTooltip = (element, artifactId) => {
  const data = artifactData[artifactId];
  if (!data || !tooltip || !tooltipContent) {
    return;
  }

  tooltipContent.innerHTML = `
    <h4>${escapeHtml(data.name)}</h4>
    <p><span class="tooltip-label">What:</span> ${escapeHtml(data.what)}</p>
    <p><span class="tooltip-label">Why:</span> ${escapeHtml(data.why)}</p>
  `;

  const rect = element.getBoundingClientRect();
  const tooltipRect = tooltip.getBoundingClientRect();

  let left = rect.left + (rect.width / 2) - 160;
  let top = rect.bottom + 8;

  // Keep tooltip in viewport
  if (left < 10) left = 10;
  if (left + 320 > window.innerWidth - 10) {
    left = window.innerWidth - 330;
  }
  if (top + 150 > window.innerHeight) {
    top = rect.top - 150;
  }

  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${top}px`;
  tooltip.hidden = false;

  requestAnimationFrame(() => {
    tooltip.classList.add("visible");
  });
};

const hideTooltip = () => {
  if (tooltip) {
    tooltip.classList.remove("visible");
    setTimeout(() => {
      tooltip.hidden = true;
    }, 150);
  }
};

// Initialize tooltips for artifact links within a container
// container defaults to document if not provided
const initArtifactTooltips = (container = document) => {
  // When initializing a specific container (not document), clear stale init markers
  // This handles the case where innerHTML was copied from elements that had the attribute
  // but the new DOM elements don't have the event listeners
  if (container !== document) {
    const staleLinks = Array.from(container.querySelectorAll(".artifact-link[data-tooltip-init]"));
    staleLinks.forEach((link) => {
      delete link.dataset.tooltipInit;
    });
  }

  // Now find and initialize links that haven't been initialized
  const links = Array.from(container.querySelectorAll(".artifact-link:not([data-tooltip-init])"));

  links.forEach((link) => {
    link.dataset.tooltipInit = "true";

    link.addEventListener("mouseenter", () => {
      clearTimeout(tooltipTimeout);
      tooltipTimeout = setTimeout(() => {
        showTooltip(link, link.dataset.artifact);
      }, 200);
    });

    link.addEventListener("mouseleave", () => {
      clearTimeout(tooltipTimeout);
      tooltipTimeout = setTimeout(hideTooltip, 100);
    });

    // Click to open sidebar and show detail
    link.addEventListener("click", (event) => {
      event.preventDefault();
      hideTooltip();
      openSidebar();
      sidebarApi?.showDetail(link.dataset.artifact);
    });
  });
};

// Initialize tooltips for all existing artifact links
initArtifactTooltips();

// Expose globally for use by other scripts (e.g., guide modal)
window.initArtifactTooltips = initArtifactTooltips;

// Keep tooltip visible when hovering over it
if (tooltip) {
  tooltip.addEventListener("mouseenter", () => {
    clearTimeout(tooltipTimeout);
  });

  tooltip.addEventListener("mouseleave", () => {
    tooltipTimeout = setTimeout(hideTooltip, 100);
  });
}
