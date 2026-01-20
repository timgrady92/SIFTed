// Artifact category definitions
const artifactCategories = {
  execution: {
    name: "Execution",
    artifacts: ["prefetch", "userassist", "shimcache", "amcache", "bam", "muicache", "sysmon", "iconcache"]
  },
  fileAccess: {
    name: "File Access",
    artifacts: ["lnk", "recentdocs", "jumplists", "shellbags", "lastvisitedmru", "typedpaths", "wordwheelquery", "thumbcache", "searchindex", "activitiescache", "officedocs", "knowledgec", "dockfinder"]
  },
  persistence: {
    name: "Persistence",
    artifacts: ["runkeys", "scheduledtasks", "services", "wmi", "wbemrepository", "startupfolder", "bits", "launchagents", "loginitems", "systemdunits", "cron", "atjobs", "envfiles", "ldpreload"]
  },
  accountActivity: {
    name: "Account Activity",
    artifacts: ["eventlogs", "powershell", "authlogs", "wtmp", "auditd", "passwdshadow", "wpndb"]
  },
  network: {
    name: "Network",
    artifacts: ["rdp", "srum", "networkprofiles", "networkshares", "knownnetworks", "cloudstorage"]
  },
  externalDevices: {
    name: "External Devices",
    artifacts: ["usb", "iosbackup"]
  },
  browserEmail: {
    name: "Browser & Email",
    artifacts: ["browser", "outlook", "quarantine"]
  },
  fileSystem: {
    name: "File System",
    artifacts: ["mft", "logfile", "recyclebin", "ads", "vss", "fsevents", "spotlight", "tmpshm", "etchosts", "procfs", "hibernation", "wsl"]
  },
  logs: {
    name: "System Logs",
    artifacts: ["syslog", "journal", "kernellogs", "webserverlogs", "packages", "wer", "coredumps", "defender"]
  },
  security: {
    name: "Security",
    artifacts: ["tccdb", "keychain", "sshkeys", "suidsgid", "capabilities", "unifiedlogs"]
  },
  timeline: {
    name: "Timeline",
    artifacts: ["timeline", "printspooler"]
  }
};

// Build reverse lookup: artifact ID -> category ID
const artifactToCategory = {};
Object.entries(artifactCategories).forEach(([catId, cat]) => {
  cat.artifacts.forEach((artifactId) => {
    artifactToCategory[artifactId] = catId;
  });
});

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
    takeaway: "Authoritative event timeline for authentication, process execution, service changes, and security events.",
    what: "Structured Windows event records stored in EVTX format across multiple log channels. The three primary logs (Security, System, Application) are supplemented by hundreds of operational logs for specific features and services.",
    why: "Authoritative timeline for authentication, process, and service activity. Many attack techniques leave traces only in event logs. Critical for establishing user activity, lateral movement, and persistence.",
    question: "When did the user log in, what processes ran, and what changed on the system?",
    corroborate: ["Prefetch for execution confirmation", "Registry for persistence mechanisms", "$MFT for file timeline", "PowerShell logs for script activity"],
    location: [
      "C:\\Windows\\System32\\winevt\\Logs\\ - All EVTX files",
      "Security.evtx - Authentication, audit, privilege use",
      "System.evtx - Services, drivers, system events",
      "Application.evtx - Application crashes, errors",
      "Microsoft-Windows-PowerShell%4Operational.evtx - PowerShell activity",
      "Microsoft-Windows-Sysmon%4Operational.evtx - Sysmon (if installed)",
      "Microsoft-Windows-TaskScheduler%4Operational.evtx - Scheduled tasks",
      "Microsoft-Windows-TerminalServices-*.evtx - RDP activity"
    ],
    databases: {
      "Authentication": [
        { file: "4624", tables: "Successful logon", timestamps: "Logon Type: 2=Interactive, 3=Network, 10=RDP" },
        { file: "4625", tables: "Failed logon", timestamps: "Includes source IP, failure reason" },
        { file: "4648", tables: "Explicit credential use (runas)", timestamps: "Target server, username" },
        { file: "4672", tables: "Special privileges assigned", timestamps: "Admin logon indicator" },
        { file: "4776", tables: "NTLM authentication", timestamps: "Domain controller validation" }
      ],
      "Process Execution": [
        { file: "4688", tables: "Process creation", timestamps: "Requires audit policy; shows command line if enabled" },
        { file: "4689", tables: "Process termination", timestamps: "Process exit" },
        { file: "1", tables: "Sysmon: Process create", timestamps: "Full command line, hashes, parent process" }
      ],
      "Persistence & Services": [
        { file: "7045", tables: "Service installed", timestamps: "New service name, path, account" },
        { file: "7040", tables: "Service start type changed", timestamps: "Service state modification" },
        { file: "4698", tables: "Scheduled task created", timestamps: "Task name, XML content" },
        { file: "4699", tables: "Scheduled task deleted", timestamps: "Task removal" }
      ],
      "Lateral Movement": [
        { file: "4648", tables: "Explicit credentials", timestamps: "Pass-the-hash indicator" },
        { file: "4624 Type 3", tables: "Network logon", timestamps: "SMB, WMI, PSRemoting access" },
        { file: "5140", tables: "Network share accessed", timestamps: "Share name, source IP" },
        { file: "5145", tables: "Share object access", timestamps: "File-level share access" }
      ],
      "Log Management": [
        { file: "1102", tables: "Audit log cleared", timestamps: "Security log cleared (tampering indicator)" },
        { file: "104", tables: "Log cleared (System)", timestamps: "Any log cleared" }
      ]
    },
    keyFields: [
      "Security 4624: LogonType, TargetUserName, IpAddress, WorkstationName",
      "Security 4688: NewProcessName, CommandLine, ParentProcessName (if enabled)",
      "System 7045: ServiceName, ImagePath, ServiceType, StartType",
      "Use wevtutil or Get-WinEvent for extraction",
      "EvtxECmd for timeline-friendly parsing"
    ]
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
    name: "Browser Artifacts",
    os: ["windows", "macos", "linux"],
    takeaway: "Shows user intent, downloads, searches, and browsing context across all platforms.",
    what: "Per-profile SQLite databases tracking URLs, downloads, searches, cookies, cached credentials, and visit timestamps. Each browser stores data differently but all provide rich forensic evidence.",
    why: "Reveals user intent, initial access vectors, download sources, and browsing patterns tied to suspected activity. Critical for phishing investigations and tracking lateral movement via web interfaces.",
    question: "What did the user search for, download, or visit?",
    corroborate: ["Downloads folder timestamps", "Zone.Identifier / Quarantine events for download sources", "Prefetch for downloaded executable runs", "LNK files for opened downloads"],
    location: [
      "Chrome (Windows): %LocalAppData%\\Google\\Chrome\\User Data\\Default\\",
      "Chrome (macOS): ~/Library/Application Support/Google/Chrome/Default/",
      "Chrome (Linux): ~/.config/google-chrome/Default/",
      "Firefox (Windows): %AppData%\\Mozilla\\Firefox\\Profiles\\<profile>/",
      "Firefox (macOS): ~/Library/Application Support/Firefox/Profiles/<profile>/",
      "Firefox (Linux): ~/.mozilla/firefox/<profile>/",
      "Edge (Windows): %LocalAppData%\\Microsoft\\Edge\\User Data\\Default/",
      "Safari (macOS): ~/Library/Safari/"
    ],
    databases: {
      chrome: [
        { file: "History", tables: "urls, visits, downloads, keyword_search_terms", timestamps: "visit_time, last_visit_time (WebKit: microseconds since 1601-01-01)" },
        { file: "Login Data", tables: "logins", timestamps: "date_created, date_last_used" },
        { file: "Cookies", tables: "cookies", timestamps: "creation_utc, last_access_utc, expires_utc" },
        { file: "Web Data", tables: "autofill, credit_cards", timestamps: "date_created, date_last_used" },
        { file: "Favicons", tables: "favicons, icon_mapping", timestamps: "last_updated" },
        { file: "Top Sites", tables: "top_sites", timestamps: "last_updated" }
      ],
      firefox: [
        { file: "places.sqlite", tables: "moz_places, moz_historyvisits, moz_bookmarks", timestamps: "visit_date, last_visit_date (PRTime: microseconds since Unix epoch)" },
        { file: "downloads.sqlite", tables: "moz_downloads (older versions)", timestamps: "startTime, endTime" },
        { file: "cookies.sqlite", tables: "moz_cookies", timestamps: "creationTime, lastAccessed, expiry" },
        { file: "formhistory.sqlite", tables: "moz_formhistory", timestamps: "firstUsed, lastUsed" },
        { file: "logins.json", tables: "N/A (JSON)", timestamps: "timeCreated, timeLastUsed, timePasswordChanged" }
      ],
      edge: [
        { file: "History", tables: "urls, visits, downloads (Chromium-based, same as Chrome)", timestamps: "WebKit format" }
      ],
      safari: [
        { file: "History.db", tables: "history_items, history_visits", timestamps: "visit_time (Mac absolute time: seconds since 2001-01-01)" },
        { file: "Downloads.plist", tables: "N/A (plist)", timestamps: "DownloadEntryDateAddedKey" },
        { file: "Bookmarks.plist", tables: "N/A (plist)", timestamps: "Various date fields" }
      ]
    },
    keyFields: [
      "urls.url / moz_places.url - Full URL visited",
      "urls.title / moz_places.title - Page title",
      "urls.visit_count / moz_places.visit_count - Number of visits",
      "downloads.target_path - Where file was saved",
      "downloads.tab_url / referrer - Source page for download",
      "keyword_search_terms.term - Search queries",
      "cookies.host_key - Domain for session analysis"
    ]
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
    takeaway: "Identifies removable devices with first/last connection times and user attribution.",
    what: "Multiple registry keys and log files recording USB device installs, vendor/product IDs, serial numbers, volume serial numbers, drive letters, and connection timestamps. Cross-referencing these sources enables full device timeline reconstruction.",
    why: "Critical for data exfiltration investigations. Correlating device serial numbers with user SIDs proves which user connected which device and when.",
    question: "Which USB storage devices were connected, when, and by whom?",
    corroborate: ["Shellbags for volume/folder browsing on the device", "$MFT/USN for file operations on removable drives", "LNK files pointing to removable drive paths", "Event Logs (Event IDs 20001, 20003 in DeviceSetupManager)"],
    location: [
      "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR - Device identification",
      "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB - VID/PID lookup",
      "HKLM\\SYSTEM\\MountedDevices - Volume GUID to drive letter mapping",
      "HKLM\\SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices - Friendly names",
      "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2 - Per-user device connections",
      "C:\\Windows\\inf\\setupapi.dev.log - First install timestamps",
      "C:\\Windows\\inf\\setupapi.upgrade.log - Additional install records"
    ],
    keyFields: [
      "USBSTOR\\Disk&Ven_X&Prod_Y&Rev_Z\\SerialNumber - Unique device identifier",
      "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064 - First install time",
      "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066 - Last connected time",
      "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067 - Last removal time",
      "MountPoints2\\{GUID} - Links user SID to volume GUID",
      "MountedDevices\\\\DosDevices\\D: - Maps drive letter to device signature"
    ]
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
    takeaway: "Tracks remote desktop connections both inbound (to this system) and outbound (from this system).",
    what: "Registry keys storing outbound connection history, event logs recording both inbound and outbound sessions with usernames, source IPs, and timestamps. Bitmap cache files may contain screenshots of remote sessions.",
    why: "Essential for tracking lateral movement. Inbound connections show who accessed this system; outbound connections show what systems this user accessed. Bitmap cache can reveal what the attacker saw.",
    question: "Who connected via RDP, from where, to where, and when?",
    corroborate: ["Security Event Logs for authentication", "Prefetch for mstsc.exe/rdpclip.exe execution", "Network connections for RDP port 3389", "Corresponding logs on remote systems"],
    location: [
      "NTUSER.DAT\\Software\\Microsoft\\Terminal Server Client\\Servers - Outbound: servers this user connected TO",
      "NTUSER.DAT\\Software\\Microsoft\\Terminal Server Client\\Default - Outbound: MRU of recent connections",
      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp - Inbound: RDP configuration",
      "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\*.bmc - Bitmap cache tiles",
      "C:\\Users\\<user>\\Documents\\Default.rdp - Saved connection defaults"
    ],
    eventLogs: {
      inbound: [
        { id: "4624", log: "Security", meaning: "Successful logon (Type 10 = RemoteInteractive)" },
        { id: "4625", log: "Security", meaning: "Failed logon attempt" },
        { id: "4778", log: "Security", meaning: "Session reconnected" },
        { id: "4779", log: "Security", meaning: "Session disconnected" },
        { id: "21", log: "TerminalServices-LocalSessionManager/Operational", meaning: "Successful logon (includes source IP)" },
        { id: "22", log: "TerminalServices-LocalSessionManager/Operational", meaning: "Shell start (session ready)" },
        { id: "24", log: "TerminalServices-LocalSessionManager/Operational", meaning: "Session disconnected" },
        { id: "25", log: "TerminalServices-LocalSessionManager/Operational", meaning: "Session reconnected" },
        { id: "1149", log: "TerminalServices-RemoteConnectionManager/Operational", meaning: "Authentication succeeded (pre-logon, shows source IP)" }
      ],
      outbound: [
        { id: "1024", log: "TerminalServices-RDPClient/Operational", meaning: "Outbound connection attempt" },
        { id: "1102", log: "TerminalServices-RDPClient/Operational", meaning: "Outbound connection established" }
      ]
    },
    keyFields: [
      "Terminal Server Client\\Servers\\<hostname> - UsernameHint shows username used",
      "Logon Type 10 (RemoteInteractive) in Event 4624 confirms RDP",
      "Source Network Address in Event 4624/21 shows originating IP",
      "Bitmap cache: use bmc-tools to extract cached screen tiles"
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
    takeaway: "History of wired and wireless networks with first/last connection timestamps for location analysis.",
    what: "Registry records of every network the system has connected to, including network names (SSIDs), network types (public/private/domain), MAC addresses of gateways, and precise first/last connection timestamps. Each network gets a unique Profile GUID.",
    why: "Shows where the system has been physically located based on network connections. First connection time proves when a system first appeared on a network; last connection time shows most recent presence. Gateway MAC addresses can identify specific network infrastructure.",
    question: "What networks has this system connected to, and when?",
    corroborate: ["Event Logs for connection/disconnection events", "SRUM for network data usage", "WLAN AutoConfig logs for WiFi details", "Browser history for location context"],
    location: [
      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{GUID} - Network metadata",
      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\{GUID} - Wired networks",
      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed\\{GUID} - Domain networks",
      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Cache - Network location awareness cache"
    ],
    keyFields: [
      "ProfileName - Human-readable network name (SSID for WiFi)",
      "Description - Network description",
      "DateCreated (REG_BINARY) - First connection timestamp (SYSTEMTIME format)",
      "DateLastConnected (REG_BINARY) - Last connection timestamp (SYSTEMTIME format)",
      "Category - Network type: 0=Public, 1=Private, 2=Domain",
      "NameType - 6=Wired, 23=VPN, 71=Wireless",
      "Signatures\\*\\DefaultGatewayMac - Gateway MAC address (network fingerprint)",
      "Signatures\\*\\DnsSuffix - DNS suffix for the network"
    ],
    eventLogs: {
      "WiFi Events": [
        { id: "8001", log: "WLAN-AutoConfig/Operational", meaning: "Successfully connected to wireless network" },
        { id: "8002", log: "WLAN-AutoConfig/Operational", meaning: "Failed to connect to wireless network" },
        { id: "8003", log: "WLAN-AutoConfig/Operational", meaning: "Disconnected from wireless network" },
        { id: "11000", log: "WLAN-AutoConfig/Operational", meaning: "Wireless association started" },
        { id: "11001", log: "WLAN-AutoConfig/Operational", meaning: "Wireless association succeeded" }
      ],
      "Network Profile": [
        { id: "10000", log: "NetworkProfile/Operational", meaning: "Network connected" },
        { id: "10001", log: "NetworkProfile/Operational", meaning: "Network disconnected" }
      ]
    }
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
    takeaway: "Centralized logging for all system and application events with rich filtering capabilities.",
    what: "macOS unified logging system (introduced in 10.12) consolidating kernel, system, and application logs into a compressed binary format with structured fields, subsystems, categories, and multiple log levels. Supports predicate-based filtering for precise queries.",
    why: "Primary and often only source for system activity on modern macOS. Contains authentication events, process execution, network activity, and application behavior. Traditional log files are largely deprecated.",
    question: "What system and application events occurred?",
    corroborate: ["FSEvents for file activity", "Launch agents/daemons for persistence", "TCC.db for permission grants", "Quarantine events for downloads"],
    location: [
      "/var/db/diagnostics/ - Persisted log archives (tracev3 files)",
      "/var/db/uuidtext/ - UUID to string mappings for log messages",
      "/private/var/db/diagnostics/Persist/ - Historical logs",
      "Live logs in memory (not persisted unless collected)"
    ],
    keyFields: [
      "log show --predicate 'processImagePath CONTAINS \"ssh\"' - Filter by process",
      "log show --predicate 'subsystem == \"com.apple.securityd\"' - Security subsystem",
      "log show --predicate 'eventMessage CONTAINS \"authentication\"' - Search messages",
      "log show --predicate 'category == \"connection\"' - Filter by category",
      "log show --start 'YYYY-MM-DD HH:MM:SS' --end 'YYYY-MM-DD HH:MM:SS' - Time range",
      "log collect --device --output ~/Desktop/logs.logarchive - Export for analysis"
    ],
    databases: {
      "Key Subsystems": [
        { file: "com.apple.securityd", tables: "Authentication, keychain, code signing", timestamps: "Per-event timestamp" },
        { file: "com.apple.authd", tables: "Authorization and privilege escalation", timestamps: "Per-event timestamp" },
        { file: "com.apple.loginwindow", tables: "User login/logout events", timestamps: "Per-event timestamp" },
        { file: "com.apple.xpc", tables: "Inter-process communication", timestamps: "Per-event timestamp" },
        { file: "com.apple.network", tables: "Network connections and changes", timestamps: "Per-event timestamp" },
        { file: "com.apple.launchd", tables: "Service/daemon lifecycle", timestamps: "Per-event timestamp" }
      ]
    }
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
  },
  sysmon: {
    name: "Sysmon Logs",
    os: ["windows"],
    takeaway: "Enhanced process, network, and file monitoring when deployed.",
    what: "Microsoft Sysinternals tool that logs detailed process creation, network connections, file creation, registry changes, and process access events to the Windows Event Log.",
    why: "Provides visibility into LSASS access (Event ID 10), process injection, and command-line arguments not captured by default Windows logging.",
    question: "What detailed process and network activity occurred on this system?",
    corroborate: ["Standard Event Logs for correlation", "Prefetch for execution confirmation"],
    location: [
      "Event Log: Microsoft-Windows-Sysmon/Operational",
      "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
      "Requires Sysmon to be installed and configured"
    ]
  },
  outlook: {
    name: "Outlook Artifacts",
    os: ["windows"],
    takeaway: "Email storage and attachment cache for phishing investigations.",
    what: "Microsoft Outlook data files (OST/PST), attachment cache, and temporary files storing emails, attachments, and metadata.",
    why: "Critical for tracing phishing attacks; attachment cache may contain malicious payloads even after email deletion.",
    question: "What emails were received and what attachments were opened?",
    corroborate: ["Browser history for webmail access", "Prefetch for attachment execution"],
    location: [
      "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Outlook\\ (OST files)",
      "C:\\Users\\<user>\\Documents\\Outlook Files\\ (PST files)",
      "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\",
      "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.Outlook\\"
    ]
  },
  printspooler: {
    name: "Print Spooler",
    os: ["windows"],
    takeaway: "Print job history for hardcopy exfiltration detection.",
    what: "Windows Print Spooler service logs and spool files (.SPL, .SHD) recording print job metadata including document names, timestamps, and printer destinations.",
    why: "Useful for insider threat investigations where documents may have been printed for physical exfiltration.",
    question: "What documents were printed, and when?",
    corroborate: ["RecentDocs for file access", "Event Logs for print events (Event ID 307)"],
    location: [
      "C:\\Windows\\System32\\spool\\PRINTERS\\",
      "Event Log: Microsoft-Windows-PrintService/Operational",
      "Spool files may be deleted after job completion"
    ]
  },
  activitiescache: {
    name: "Windows Activity Timeline",
    os: ["windows"],
    takeaway: "Rich user activity history including app usage, file access, and cross-device sync.",
    what: "SQLite database tracking user activities including application usage, file opens, clipboard history, and browser activity. Introduced in Windows 10 1803 as part of Timeline feature. Can sync across devices via Microsoft account.",
    why: "Provides detailed user activity timeline with timestamps, even for activities that don't leave traditional artifacts. Shows what users were doing and when, including activities synced from other devices.",
    question: "What applications did the user interact with and what files did they access?",
    corroborate: ["Recent Documents for file access", "Prefetch for application execution", "Browser history for web activity", "Jump Lists for app-specific file access"],
    location: [
      "C:\\Users\\<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<account>\\ActivitiesCache.db",
      "C:\\Users\\<user>\\AppData\\Local\\ConnectedDevicesPlatform\\L.<account>\\ActivitiesCache.db"
    ],
    databases: {
      "Key Tables": [
        { file: "Activity", tables: "Core activity records with timestamps and payload", timestamps: "StartTime, EndTime, LastModifiedTime (Unix epoch)" },
        { file: "ActivityOperation", tables: "Pending sync operations", timestamps: "OperationTime" },
        { file: "Activity_PackageId", tables: "Application package associations", timestamps: "N/A" }
      ]
    },
    keyFields: [
      "AppId - JSON blob with application identifiers (exe path, AUMID)",
      "ActivityType - 5=Open app, 6=Open file/URI, 10=Clipboard, 16=Copy/Paste",
      "Payload - Base64/JSON with activity details (file paths, URLs)",
      "StartTime/EndTime - Activity duration timestamps",
      "PlatformDeviceId - Identifies source device for synced activities",
      "ClipboardPayload - Clipboard content for Type 10 activities"
    ]
  },
  officedocs: {
    name: "Office Document Metadata",
    os: ["windows", "macos", "cross"],
    takeaway: "Document metadata reveals authorship, edit history, and potential macro threats.",
    what: "Microsoft Office documents (DOCX, XLSX, PPTX, legacy DOC/XLS/PPT) contain rich metadata including author names, creation/modification times, revision counts, company names, and embedded objects. Legacy OLE formats may contain macro code.",
    why: "Metadata can reveal true document origin, authorship, and edit history even when file timestamps are modified. Macros and embedded objects are common malware delivery vectors. Useful for attribution and phishing investigations.",
    question: "Who created this document, when was it actually authored, and does it contain malicious content?",
    corroborate: ["Email artifacts for delivery vector", "Browser downloads for source", "Prefetch for application execution after opening", "Recent Documents for access history"],
    location: [
      "Document itself (embedded metadata)",
      "~$<filename> - Temporary owner files while document is open",
      "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Office\\Recent\\ - Office MRU",
      "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Office\\<version>\\OfficeFileCache\\ - Cached files"
    ],
    keyFields: [
      "Core Properties: dc:creator, dc:title, dcterms:created, dcterms:modified",
      "Extended Properties: Application, AppVersion, Company, TotalTime (edit minutes)",
      "Custom Properties: User-defined metadata fields",
      "Revision Number: Indicates how many times document was saved",
      "Last Modified By: Last person to save the document",
      "Template: Source template may indicate origin"
    ],
    databases: {
      "OOXML (Modern)": [
        { file: "docProps/core.xml", tables: "Dublin Core metadata (author, dates)", timestamps: "dcterms:created, dcterms:modified (ISO 8601)" },
        { file: "docProps/app.xml", tables: "Application metadata (version, company, edit time)", timestamps: "N/A" },
        { file: "word/vbaProject.bin", tables: "VBA macro code (if present)", timestamps: "N/A" }
      ],
      "OLE (Legacy)": [
        { file: "SummaryInformation", tables: "Title, author, timestamps", timestamps: "FILETIME format" },
        { file: "DocumentSummaryInformation", tables: "Company, version, byte count", timestamps: "N/A" },
        { file: "Macros/VBA", tables: "Embedded macro streams", timestamps: "N/A" }
      ]
    }
  },
  cloudstorage: {
    name: "Cloud Storage Clients",
    os: ["windows", "macos"],
    takeaway: "Local sync databases reveal cloud file access and sync history.",
    what: "Desktop sync clients for OneDrive, Dropbox, Google Drive, and similar services maintain local SQLite databases tracking synced files, sync status, deleted items, and sharing metadata. These persist even when files are removed from the cloud.",
    why: "Reveals files that existed in cloud storage, sharing activity, and data exfiltration via cloud sync. Local databases may contain evidence of files deleted from the cloud. Critical for insider threat and data theft investigations.",
    question: "What files were synced to/from cloud storage, and what was shared externally?",
    corroborate: ["File system for synced file content", "Browser history for web interface access", "Network logs for sync traffic", "Recent Documents for local access"],
    location: [
      "OneDrive (Win): %LocalAppData%\\Microsoft\\OneDrive\\settings\\Personal\\<cid>.dat",
      "OneDrive (Win): %LocalAppData%\\Microsoft\\OneDrive\\logs\\",
      "Dropbox (Win): %LocalAppData%\\Dropbox\\instance1\\filecache.dbx",
      "Dropbox (Win): %AppData%\\Dropbox\\<various>.dbx files",
      "Google Drive (Win): %LocalAppData%\\Google\\DriveFS\\<account>\\metadata_sqlite_db",
      "Dropbox (macOS): ~/.dropbox/<various>.dbx",
      "Google Drive (macOS): ~/Library/Application Support/Google/DriveFS/<account>/"
    ],
    databases: {
      "OneDrive": [
        { file: "SyncEngineDatabase.db", tables: "Synced files, folders, status", timestamps: "Various timestamp fields" },
        { file: "<cid>.dat", tables: "Account configuration, sync roots", timestamps: "N/A" },
        { file: "logs/SyncDiagnostics.log", tables: "Sync operations, errors", timestamps: "Log timestamps" }
      ],
      "Dropbox": [
        { file: "filecache.dbx", tables: "File cache metadata (encrypted SQLite)", timestamps: "modified_time, sync_time" },
        { file: "deleted.dbx", tables: "Deleted file records", timestamps: "deletion timestamps" },
        { file: "config.dbx", tables: "Account configuration", timestamps: "N/A" }
      ],
      "Google Drive": [
        { file: "metadata_sqlite_db", tables: "File metadata, sync state", timestamps: "modified_date, viewed_by_me_date" },
        { file: "mirror_sqlite_db", tables: "Mirrored files", timestamps: "local_mtime" }
      ]
    },
    keyFields: [
      "File paths and names (even for deleted cloud files)",
      "Sharing status and shared link recipients",
      "Sync timestamps (local vs cloud)",
      "File size and hash values",
      "Account email addresses"
    ]
  },
  wpndb: {
    name: "Windows Push Notifications",
    os: ["windows"],
    takeaway: "Toast notification history reveals app activity and message content.",
    what: "SQLite database storing Windows push notification history including toast notifications, badges, and tiles. Contains notification content, timestamps, and source applications. Introduced in Windows 10.",
    why: "Notifications may contain message previews from chat apps, email subjects, calendar reminders, and other sensitive content. Shows application activity even when the app itself leaves minimal artifacts.",
    question: "What notifications did the user receive, and from which applications?",
    corroborate: ["Application-specific artifacts for full content", "Timeline/ActivitiesCache for app usage", "Event Logs for application activity"],
    location: [
      "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\Notifications\\wpndatabase.db",
      "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\Notifications\\appdb.dat"
    ],
    databases: {
      "Key Tables": [
        { file: "Notification", tables: "Individual notification records with content", timestamps: "ArrivalTime, ExpiryTime (Windows FILETIME)" },
        { file: "NotificationHandler", tables: "Registered notification sources", timestamps: "CreatedTime, ModifiedTime" },
        { file: "HandlerAssets", tables: "App icons and images for notifications", timestamps: "N/A" }
      ]
    },
    keyFields: [
      "Payload - XML content of the notification (may include message text)",
      "Type - Notification type (toast, badge, tile)",
      "HandlerId - Links to source application",
      "ArrivalTime - When notification was received",
      "ExpiryTime - When notification expires",
      "PayloadType - toast, badge, tileLarge, etc."
    ]
  },
  iconcache: {
    name: "IconCache Database",
    os: ["windows"],
    takeaway: "Cached program icons prove applications existed even after deletion.",
    what: "Windows maintains a cache of application icons in thumbcache-style database files. Contains icon images extracted from executables, providing evidence of programs that existed on the system.",
    why: "Icon cache entries persist after programs are uninstalled or deleted. Can prove a specific application was present on the system even when all other traces have been removed.",
    question: "What applications existed on this system, including deleted ones?",
    corroborate: ["Prefetch for execution", "Amcache for program metadata", "UserAssist for GUI execution", "Shimcache for file presence"],
    location: [
      "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\Explorer\\iconcache_*.db",
      "C:\\Users\\<user>\\AppData\\Local\\IconCache.db (legacy)",
      "%LocalAppData%\\Microsoft\\Windows\\Explorer\\iconcache_16.db through iconcache_1024.db"
    ],
    keyFields: [
      "Icon images at various resolutions (16x16 through 1024x1024)",
      "Indexed by executable path hash",
      "May contain icons for deleted programs",
      "Use thumbcache_viewer or similar tools to extract",
      "Compare extracted icons to known malware icons"
    ]
  },
  knowledgec: {
    name: "KnowledgeC.db",
    os: ["macos"],
    takeaway: "Comprehensive user activity database tracking app usage, device interactions, and screen time.",
    what: "SQLite database maintained by the Knowledge framework (knowledged daemon) that tracks extensive user activity including application usage, Safari browsing, media playback, device sleep/wake cycles, bluetooth connections, and screen time. One of the richest forensic artifacts on macOS.",
    why: "Provides detailed timeline of user activity with precise timestamps. Shows what apps were in focus, how long they were used, and user interaction patterns. Critical for establishing user presence and activity during an incident.",
    question: "What was the user doing on this system and when?",
    corroborate: ["Unified Logs for system events", "FSEvents for file activity", "Browser history for web context", "Launch Agents for app configurations"],
    location: [
      "~/Library/Application Support/Knowledge/knowledgeC.db",
      "/private/var/db/CoreDuet/Knowledge/knowledgeC.db (system-wide)"
    ],
    databases: {
      "Key Tables": [
        { file: "ZOBJECT", tables: "Core activity records", timestamps: "ZSTARTDATE, ZENDDATE (Mac absolute time)" },
        { file: "ZSOURCE", tables: "Data source definitions", timestamps: "N/A" },
        { file: "ZSTRUCTUREDMETADATA", tables: "Extended activity metadata", timestamps: "Per-record timestamps" }
      ]
    },
    keyFields: [
      "ZSTREAMNAME - Activity type: /app/usage, /safari/history, /device/isLocked, /audio/outputRoute",
      "ZVALUESTRING - Application bundle ID or activity identifier",
      "ZSTARTDATE/ZENDDATE - Activity duration (Mac absolute: seconds since 2001-01-01)",
      "ZSECONDSFROMGMT - Timezone offset for the activity",
      "ZSTRUCTUREDMETADATA.Z_DKAPPLICATIONACTIVITYMETADATAKEY__ACTIVITYTYPE - Detailed app activity",
      "Use mac_apt or KAPE for parsing"
    ]
  },
  hibernation: {
    name: "Hiberfil.sys / Pagefile.sys",
    os: ["windows"],
    takeaway: "Disk-based memory artifacts that can reveal passwords, encryption keys, and process data.",
    what: "Hiberfil.sys contains a compressed copy of RAM written during hibernation. Pagefile.sys (and swapfile.sys on Win10+) contain memory pages swapped to disk during normal operation. Both can contain sensitive data from memory including passwords, encryption keys, and process memory.",
    why: "Enables partial memory forensics without live acquisition. May contain decryption keys for BitLocker/VeraCrypt, plaintext passwords, chat messages, and evidence of running processes. Persists across reboots.",
    question: "What sensitive data or process memory can be recovered from disk?",
    corroborate: ["Full memory image if available", "Prefetch for process execution", "Event Logs for hibernation/shutdown events", "Registry for recent activity"],
    location: [
      "C:\\hiberfil.sys - Hibernation file (hidden, system)",
      "C:\\pagefile.sys - Page file (hidden, system)",
      "C:\\swapfile.sys - Modern apps swap file (Win10+)"
    ],
    keyFields: [
      "Hiberfil.sys: Compressed RAM image, decompress with Volatility or hibernation-recon",
      "Pagefile.sys: Unstructured, use strings/bulk_extractor for keyword searching",
      "Look for: passwords, URLs, chat fragments, encryption keys, process memory",
      "Compression: XPRESS (Win8+) or LZ (older)",
      "Size: Typically 40-100% of RAM for hiberfil, configurable for pagefile"
    ]
  },
  logfile: {
    name: "$LogFile (NTFS Transaction Log)",
    os: ["windows"],
    takeaway: "NTFS transaction log that can recover very recent file operations even when MFT is overwritten.",
    what: "NTFS journaling log that records all metadata changes to the file system before they're committed. Contains a circular buffer of recent operations including file creation, deletion, rename, and attribute changes. Separate from and more granular than $UsnJrnl.",
    why: "Can recover evidence of very recent file operations (typically last few hours) with high precision. May reveal file operations that occurred between $MFT updates or when $UsnJrnl has rolled over.",
    question: "What file operations occurred in the last few hours that might not appear elsewhere?",
    corroborate: ["$MFT for file records", "$UsnJrnl for change journal", "Prefetch for execution context", "Event Logs for system timeline"],
    location: [
      "$LogFile in root of NTFS volume",
      "Typically 64MB default size",
      "Circular buffer - older entries overwritten"
    ],
    keyFields: [
      "Redo/Undo operations for each transaction",
      "File reference numbers linking to $MFT entries",
      "Operation types: CreateFile, DeleteFile, SetAttributes, RenameFile",
      "LSN (Log Sequence Number) for ordering operations",
      "Parse with LogFileParser, NTFS Log Tracker, or Autopsy"
    ]
  },
  wsl: {
    name: "WSL Artifacts",
    os: ["windows"],
    takeaway: "Linux filesystem and artifacts running inside Windows - increasingly used for tools and evasion.",
    what: "Windows Subsystem for Linux creates a Linux environment with its own filesystem, bash history, logs, and artifacts. WSL1 stores files in a Windows-accessible location; WSL2 uses a virtual disk (ext4.vhdx). Attackers may use WSL to run Linux tools or evade Windows-focused detection.",
    why: "Malware and attackers increasingly leverage WSL to execute Linux tools on Windows, access Linux-native exploits, or hide activity from Windows security tools. Full Linux artifact analysis applies within the WSL environment.",
    question: "Was WSL used on this system, and what Linux activity occurred within it?",
    corroborate: ["Prefetch for wsl.exe execution", "PowerShell logs for WSL commands", "Windows Event Logs for WSL service", "Standard Linux artifacts within WSL filesystem"],
    location: [
      "WSL1: %LocalAppData%\\Packages\\<distro>\\LocalState\\rootfs\\",
      "WSL2: %LocalAppData%\\Packages\\<distro>\\LocalState\\ext4.vhdx",
      "Common distro paths: CanonicalGroupLimited.Ubuntu*, TheDebianProject.DebianGNULinux*",
      "WSL config: %UserProfile%\\.wslconfig, /etc/wsl.conf inside distro"
    ],
    keyFields: [
      "rootfs/home/<user>/.bash_history - Command history",
      "rootfs/var/log/ - Linux system logs",
      "rootfs/etc/passwd, /etc/shadow - User accounts",
      "rootfs/tmp/ - Temporary files and staged tools",
      "ext4.vhdx can be mounted on Linux for analysis",
      "Check for wsl.exe in Prefetch as indicator of use"
    ]
  },
  iosbackup: {
    name: "iOS/iTunes Backups",
    os: ["windows", "macos"],
    takeaway: "Mobile device evidence preserved on desktop - messages, photos, app data, and more.",
    what: "iTunes and Finder create backups of iOS devices containing databases, preferences, and files from the mobile device. Includes messages (SMS/iMessage), call history, contacts, photos, Safari history, and third-party app data. May be encrypted with user-chosen password.",
    why: "Mobile devices often contain critical evidence but may be locked or unavailable. Desktop backups provide access to substantial mobile data including messages and app data. Unencrypted backups are immediately accessible; encrypted backups require the backup password.",
    question: "What mobile device data is preserved in desktop backups?",
    corroborate: ["Mobile device itself if available", "iCloud data if accessible", "Desktop browser history for iCloud web access", "File system timestamps for backup timing"],
    location: [
      "Windows: %AppData%\\Apple Computer\\MobileSync\\Backup\\",
      "macOS: ~/Library/Application Support/MobileSync/Backup/",
      "Each device has a UDID-named folder containing backup files"
    ],
    databases: {
      "Key Files": [
        { file: "Manifest.db", tables: "File inventory with domains and paths", timestamps: "N/A" },
        { file: "Info.plist", tables: "Device info, backup date, iOS version", timestamps: "Last Backup Date" },
        { file: "Status.plist", tables: "Backup completion status", timestamps: "Date" },
        { file: "Manifest.plist", tables: "Encryption status, app list", timestamps: "N/A" }
      ],
      "Key Databases (hashed filenames)": [
        { file: "sms.db", tables: "Messages (SMS, iMessage, attachments)", timestamps: "date (Mac absolute time)" },
        { file: "call_history.db", tables: "Call log with numbers and duration", timestamps: "date" },
        { file: "AddressBook.sqlitedb", tables: "Contacts", timestamps: "ModificationDate" },
        { file: "History.db", tables: "Safari browsing history", timestamps: "visit_time" }
      ]
    },
    keyFields: [
      "Manifest.db maps hashed filenames to original paths",
      "Domain field indicates source app (HomeDomain, AppDomain, etc.)",
      "Encrypted backups require password - check Keychain for stored password",
      "Use iphone-backup-analyzer, iExplorer, or commercial mobile forensic tools",
      "Third-party app data in AppDomain-* files"
    ]
  },
  wbemrepository: {
    name: "WBEM Repository",
    os: ["windows"],
    takeaway: "Raw WMI database files for offline analysis of WMI persistence and configuration.",
    what: "The WBEM (Web-Based Enterprise Management) repository stores all WMI classes, instances, and subscriptions in a proprietary database format. Contains the same data queryable via live WMI but accessible for offline forensic analysis.",
    why: "WMI persistence (event subscriptions) is a common attack technique. The repository allows analysis of WMI artifacts from disk images without live system access. Can reveal persistence mechanisms, custom classes, and historical WMI activity.",
    question: "What WMI persistence mechanisms or custom configurations exist on this system?",
    corroborate: ["WMI event logs (WMI-Activity)", "PowerShell logs for WMI commands", "Scheduled Tasks for alternative persistence", "Registry WMI configuration"],
    location: [
      "C:\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA - Main data file",
      "C:\\Windows\\System32\\wbem\\Repository\\INDEX.BTR - Index file",
      "C:\\Windows\\System32\\wbem\\Repository\\MAPPING*.MAP - Mapping files"
    ],
    keyFields: [
      "__EventFilter - Trigger conditions for subscriptions",
      "__EventConsumer - Actions executed (CommandLineEventConsumer, ActiveScriptEventConsumer)",
      "__FilterToConsumerBinding - Links filters to consumers (persistence indicator)",
      "Parse with PyWMIPersistenceFinder, WMI-Forensics, or Velociraptor",
      "Look for non-standard namespaces beyond root\\subscription"
    ]
  },
  dockfinder: {
    name: "Dock & Finder Preferences",
    os: ["macos"],
    takeaway: "Application usage patterns and folder access from Dock and Finder settings.",
    what: "macOS stores Dock configuration (pinned apps, recent apps) and Finder preferences (sidebar items, recent folders, window positions) in plist files. These reveal commonly used applications and folder navigation patterns.",
    why: "Shows user's frequently accessed applications and folders. Dock persistent apps indicate intentional placement; recent items show actual usage. Finder sidebar and recent folders reveal navigation patterns.",
    question: "What applications and folders did the user frequently access?",
    corroborate: ["KnowledgeC.db for detailed app usage", "FSEvents for folder access", "Launch Services for app associations", "Recent Items folder"],
    location: [
      "~/Library/Preferences/com.apple.dock.plist - Dock configuration",
      "~/Library/Preferences/com.apple.finder.plist - Finder preferences",
      "~/Library/Application Support/com.apple.sharedfilelist/ - Recent items",
      "~/Library/Preferences/com.apple.LSSharedFileList.*.plist - Recent documents/servers"
    ],
    keyFields: [
      "persistent-apps - Apps pinned to Dock by user",
      "recent-apps - Recently used applications (if enabled)",
      "persistent-others - Folders/files pinned to Dock",
      "FXRecentFolders - Recently accessed folders in Finder",
      "FXDesktopVolumePositions - Mounted volume positions",
      "FK* keys in finder.plist - Various Finder state data"
    ]
  }
};

// Registry reference data - curated high-value forensic keys
const registryData = {
  // User Activity
  useractivity: {
    category: "User Activity",
    items: [
      {
        key: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        purpose: "Recently opened files by extension",
        lookFor: "MRU order, file names, timestamps"
      },
      {
        key: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
        purpose: "Files opened/saved via common dialogs",
        lookFor: "Full paths from Open/Save dialogs"
      },
      {
        key: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
        purpose: "Apps used in Open/Save dialogs",
        lookFor: "Application-to-folder relationships"
      },
      {
        key: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
        purpose: "Paths typed in Explorer address bar",
        lookFor: "User-initiated navigation to specific paths"
      },
      {
        key: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery",
        purpose: "Explorer search terms",
        lookFor: "What the user searched for"
      },
      {
        key: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
        purpose: "Commands typed in Run dialog",
        lookFor: "Programs/commands user executed"
      }
    ]
  },
  // Execution Evidence
  execution: {
    category: "Execution Evidence",
    items: [
      {
        key: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count",
        purpose: "GUI program execution (ROT13 encoded)",
        lookFor: "Run count, last run time, focus time"
      },
      {
        key: "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
        purpose: "Application compatibility cache (Shimcache)",
        lookFor: "File path, size, last modified time"
      },
      {
        key: "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\{SID}",
        purpose: "Background Activity Moderator (Win10 1709+)",
        lookFor: "Full path, last execution time"
      },
      {
        key: "NTUSER.DAT\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
        purpose: "Executable display names",
        lookFor: "Path-to-friendly-name mappings"
      }
    ]
  },
  // Persistence Mechanisms
  persistence: {
    category: "Persistence (Registry)",
    items: [
      {
        key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        purpose: "System-wide auto-start programs",
        lookFor: "Unexpected entries, suspicious paths"
      },
      {
        key: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        purpose: "User-specific auto-start programs",
        lookFor: "Per-user persistence mechanisms"
      },
      {
        key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        purpose: "One-time execution at next boot",
        lookFor: "Entries deleted after execution"
      },
      {
        key: "HKLM\\SYSTEM\\CurrentControlSet\\Services",
        purpose: "Windows services configuration",
        lookFor: "ImagePath, Start type, ServiceDll"
      },
      {
        key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
        purpose: "Scheduled task definitions",
        lookFor: "Actions, triggers, last run time"
      },
      {
        key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        purpose: "Winlogon process hooks",
        lookFor: "Shell, Userinit, Notify values"
      },
      {
        key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        purpose: "Debugger hijacking (IFEO)",
        lookFor: "Debugger value pointing to malware"
      }
    ]
  },
  // Network Activity
  network: {
    category: "Network Activity",
    items: [
      {
        key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
        purpose: "Network connection history",
        lookFor: "Profile names, first/last connect times"
      },
      {
        key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
        purpose: "Network signatures (MAC, SSID)",
        lookFor: "Gateway MAC, DNS suffix"
      },
      {
        key: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2",
        purpose: "Mounted volumes and network shares",
        lookFor: "Drive letters, UNC paths"
      },
      {
        key: "NTUSER.DAT\\Network",
        purpose: "Mapped network drives",
        lookFor: "Drive letter to UNC path mappings"
      }
    ]
  },
  // USB/External Devices
  devices: {
    category: "External Devices",
    items: [
      {
        key: "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
        purpose: "USB storage device history",
        lookFor: "Vendor, product, serial number, timestamps"
      },
      {
        key: "SYSTEM\\CurrentControlSet\\Enum\\USB",
        purpose: "All USB device connections",
        lookFor: "VID/PID, device class, serial"
      },
      {
        key: "SYSTEM\\MountedDevices",
        purpose: "Volume-to-device mappings",
        lookFor: "Drive letter assignments, device signatures"
      },
      {
        key: "SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices",
        purpose: "Portable device friendly names",
        lookFor: "Device name, serial number"
      }
    ]
  },
  // Shell/Explorer
  shell: {
    category: "Shell & Explorer",
    items: [
      {
        key: "NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
        purpose: "Folder browsing history (Shellbags)",
        lookFor: "Folder paths, view settings, timestamps"
      },
      {
        key: "USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
        purpose: "Additional shellbags (removable/network)",
        lookFor: "Paths to deleted or external folders"
      },
      {
        key: "NTUSER.DAT\\Software\\Microsoft\\Internet Explorer\\TypedURLs",
        purpose: "URLs typed in IE/Explorer",
        lookFor: "Direct URL navigation history"
      }
    ]
  }
};

// Persistence locations - file and registry paths for autoruns
const persistenceData = {
  registry: {
    category: "Registry Autoruns",
    items: [
      {
        path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        scope: "System",
        trigger: "User logon",
        notes: "Most common persistence location"
      },
      {
        path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        scope: "User",
        trigger: "User logon",
        notes: "Per-user startup programs"
      },
      {
        path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        scope: "System",
        trigger: "Next boot (once)",
        notes: "Entry deleted after execution"
      },
      {
        path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        scope: "System",
        trigger: "User logon",
        notes: "Policy-based autorun"
      },
      {
        path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
        scope: "System",
        trigger: "User logon",
        notes: "Default: explorer.exe"
      },
      {
        path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
        scope: "System",
        trigger: "User logon",
        notes: "Default: userinit.exe"
      },
      {
        path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>",
        scope: "System",
        trigger: "Boot/demand",
        notes: "Service Start type: 0=Boot, 2=Auto, 3=Manual"
      },
      {
        path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<exe>\\Debugger",
        scope: "System",
        trigger: "Process launch",
        notes: "IFEO hijacking - runs debugger instead"
      },
      {
        path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\<exe>",
        scope: "System",
        trigger: "Process exit",
        notes: "Monitor process termination"
      },
      {
        path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
        scope: "User",
        trigger: "User logon",
        notes: "Points to Startup folder path"
      }
    ]
  },
  filesystem: {
    category: "File System Autoruns",
    items: [
      {
        path: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        scope: "User",
        trigger: "User logon",
        notes: "User startup folder - shortcuts/executables"
      },
      {
        path: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        scope: "System",
        trigger: "Any user logon",
        notes: "All-users startup folder"
      },
      {
        path: "C:\\Windows\\System32\\Tasks\\",
        scope: "System",
        trigger: "Scheduled",
        notes: "Task Scheduler XML definitions"
      },
      {
        path: "C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Startup",
        scope: "System",
        trigger: "Boot",
        notes: "Group Policy startup scripts"
      },
      {
        path: "C:\\Windows\\System32\\GroupPolicy\\User\\Scripts\\Logon",
        scope: "User",
        trigger: "User logon",
        notes: "Group Policy logon scripts"
      }
    ]
  },
  wmi: {
    category: "WMI Persistence",
    items: [
      {
        path: "root\\subscription - __EventFilter",
        scope: "System",
        trigger: "WMI event",
        notes: "Defines trigger condition (e.g., process start)"
      },
      {
        path: "root\\subscription - __EventConsumer",
        scope: "System",
        trigger: "Filter match",
        notes: "CommandLineEventConsumer or ActiveScriptEventConsumer"
      },
      {
        path: "root\\subscription - __FilterToConsumerBinding",
        scope: "System",
        trigger: "Links filter to consumer",
        notes: "Binding completes the persistence chain"
      }
    ]
  },
  scheduled: {
    category: "Scheduled Tasks (Common)",
    items: [
      {
        path: "schtasks /query /fo LIST /v",
        scope: "System",
        trigger: "Various",
        notes: "Command to enumerate all tasks"
      },
      {
        path: "C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\",
        scope: "System",
        trigger: "Various",
        notes: "Built-in Windows tasks location"
      },
      {
        path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree",
        scope: "System",
        trigger: "Registry view",
        notes: "Task tree structure in registry"
      }
    ]
  },
  linux: {
    category: "Linux Persistence",
    items: [
      {
        path: "/etc/crontab",
        scope: "System",
        trigger: "Cron schedule",
        notes: "System-wide cron jobs"
      },
      {
        path: "/etc/cron.d/",
        scope: "System",
        trigger: "Cron schedule",
        notes: "Additional system cron jobs"
      },
      {
        path: "/var/spool/cron/crontabs/<user>",
        scope: "User",
        trigger: "Cron schedule",
        notes: "Per-user crontabs"
      },
      {
        path: "/etc/rc.local",
        scope: "System",
        trigger: "Boot",
        notes: "Legacy boot script (if enabled)"
      },
      {
        path: "/etc/systemd/system/",
        scope: "System",
        trigger: "Boot/socket/timer",
        notes: "Custom systemd unit files"
      },
      {
        path: "~/.config/systemd/user/",
        scope: "User",
        trigger: "User session",
        notes: "User-level systemd units"
      },
      {
        path: "~/.bashrc, ~/.bash_profile, ~/.profile",
        scope: "User",
        trigger: "Shell start",
        notes: "Shell initialization scripts"
      },
      {
        path: "/etc/profile.d/",
        scope: "System",
        trigger: "Any login shell",
        notes: "System-wide shell scripts"
      },
      {
        path: "/etc/ld.so.preload",
        scope: "System",
        trigger: "Any process",
        notes: "Library preloading (rootkit technique)"
      }
    ]
  },
  macos: {
    category: "macOS Persistence",
    items: [
      {
        path: "~/Library/LaunchAgents/",
        scope: "User",
        trigger: "User login",
        notes: "Per-user launch agents (plist)"
      },
      {
        path: "/Library/LaunchAgents/",
        scope: "System",
        trigger: "Any user login",
        notes: "System-wide launch agents"
      },
      {
        path: "/Library/LaunchDaemons/",
        scope: "System",
        trigger: "Boot",
        notes: "System daemons (root context)"
      },
      {
        path: "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
        scope: "User",
        trigger: "User login",
        notes: "Login Items database"
      },
      {
        path: "/etc/periodic/daily, weekly, monthly",
        scope: "System",
        trigger: "Periodic schedule",
        notes: "Scheduled maintenance scripts"
      }
    ]
  }
};

// Event log reference - curated high-value security events
const eventData = {
  authentication: {
    category: "Authentication",
    items: [
      { id: "4624", log: "Security", name: "Successful Logon", lookFor: "Logon Type, Account Name, Source IP, Logon ID" },
      { id: "4625", log: "Security", name: "Failed Logon", lookFor: "Failure Reason, Account Name, Source IP" },
      { id: "4634", log: "Security", name: "Logoff", lookFor: "Logon ID correlation with 4624" },
      { id: "4647", log: "Security", name: "User-Initiated Logoff", lookFor: "Interactive session end" },
      { id: "4648", log: "Security", name: "Explicit Credential Logon", lookFor: "runas, credential theft indicators" },
      { id: "4672", log: "Security", name: "Special Privileges Assigned", lookFor: "Admin logon, sensitive privileges" },
      { id: "4776", log: "Security", name: "NTLM Authentication", lookFor: "Domain controller validation" },
      { id: "4768", log: "Security", name: "Kerberos TGT Request", lookFor: "Initial authentication to DC" },
      { id: "4769", log: "Security", name: "Kerberos Service Ticket", lookFor: "Service access, Kerberoasting" },
      { id: "4771", log: "Security", name: "Kerberos Pre-Auth Failed", lookFor: "AS-REP Roasting attempts" }
    ]
  },
  logonTypes: {
    category: "Logon Types (4624/4625)",
    items: [
      { id: "2", log: "Type", name: "Interactive", lookFor: "Console logon at keyboard" },
      { id: "3", log: "Type", name: "Network", lookFor: "SMB, network share access" },
      { id: "4", log: "Type", name: "Batch", lookFor: "Scheduled task execution" },
      { id: "5", log: "Type", name: "Service", lookFor: "Service account logon" },
      { id: "7", log: "Type", name: "Unlock", lookFor: "Workstation unlock" },
      { id: "8", log: "Type", name: "NetworkCleartext", lookFor: "IIS basic auth, cleartext creds" },
      { id: "9", log: "Type", name: "NewCredentials", lookFor: "runas /netonly" },
      { id: "10", log: "Type", name: "RemoteInteractive", lookFor: "RDP, Terminal Services" },
      { id: "11", log: "Type", name: "CachedInteractive", lookFor: "Cached domain credentials" }
    ]
  },
  process: {
    category: "Process Events",
    items: [
      { id: "4688", log: "Security", name: "Process Created", lookFor: "New Process Name, Command Line, Parent Process" },
      { id: "4689", log: "Security", name: "Process Exited", lookFor: "Process termination correlation" },
      { id: "1", log: "Sysmon", name: "Process Create", lookFor: "Full command line, hashes, parent details" },
      { id: "5", log: "Sysmon", name: "Process Terminated", lookFor: "Process exit tracking" },
      { id: "10", log: "Sysmon", name: "Process Access", lookFor: "LSASS access, credential dumping" }
    ]
  },
  persistence: {
    category: "Persistence Events",
    items: [
      { id: "7045", log: "System", name: "Service Installed", lookFor: "New service name, path, account" },
      { id: "7040", log: "System", name: "Service Start Type Changed", lookFor: "Auto-start modifications" },
      { id: "4698", log: "Security", name: "Scheduled Task Created", lookFor: "Task name, command, trigger" },
      { id: "4699", log: "Security", name: "Scheduled Task Deleted", lookFor: "Anti-forensics, cleanup" },
      { id: "4700", log: "Security", name: "Scheduled Task Enabled", lookFor: "Task activation" },
      { id: "4701", log: "Security", name: "Scheduled Task Disabled", lookFor: "Task deactivation" },
      { id: "13", log: "Sysmon", name: "Registry Value Set", lookFor: "Run key modifications" },
      { id: "12", log: "Sysmon", name: "Registry Object Created/Deleted", lookFor: "New keys, deleted keys" }
    ]
  },
  network: {
    category: "Network Events",
    items: [
      { id: "5156", log: "Security", name: "Windows Filtering Platform Connection", lookFor: "Outbound connections, destination IP/port" },
      { id: "5158", log: "Security", name: "WFP Bind", lookFor: "Listening ports" },
      { id: "3", log: "Sysmon", name: "Network Connection", lookFor: "Process network activity, C2 detection" },
      { id: "22", log: "Sysmon", name: "DNS Query", lookFor: "Domain lookups, C2 domains" }
    ]
  },
  rdp: {
    category: "Remote Desktop",
    items: [
      { id: "1149", log: "TerminalServices-RemoteConnectionManager", name: "RDP User Authentication Succeeded", lookFor: "Source IP, username" },
      { id: "21", log: "TerminalServices-LocalSessionManager", name: "Session Logon Succeeded", lookFor: "Session ID, Source IP" },
      { id: "22", log: "TerminalServices-LocalSessionManager", name: "Shell Start", lookFor: "Desktop session started" },
      { id: "24", log: "TerminalServices-LocalSessionManager", name: "Session Disconnect", lookFor: "Session ended by disconnect" },
      { id: "25", log: "TerminalServices-LocalSessionManager", name: "Session Reconnect", lookFor: "Reconnection to existing session" },
      { id: "4778", log: "Security", name: "Session Reconnected", lookFor: "RDP session reconnection" },
      { id: "4779", log: "Security", name: "Session Disconnected", lookFor: "RDP session disconnect" }
    ]
  },
  powershell: {
    category: "PowerShell",
    items: [
      { id: "4103", log: "PowerShell", name: "Module Logging", lookFor: "Cmdlet execution details" },
      { id: "4104", log: "PowerShell", name: "Script Block Logging", lookFor: "Full script content, decoded" },
      { id: "4105", log: "PowerShell", name: "Script Block Start", lookFor: "Script execution begin" },
      { id: "4106", log: "PowerShell", name: "Script Block Stop", lookFor: "Script execution end" },
      { id: "400", log: "Windows PowerShell", name: "Engine Start", lookFor: "PowerShell session started" },
      { id: "403", log: "Windows PowerShell", name: "Engine Stop", lookFor: "PowerShell session ended" },
      { id: "800", log: "Windows PowerShell", name: "Pipeline Execution", lookFor: "Command pipeline details" }
    ]
  },
  defender: {
    category: "Windows Defender",
    items: [
      { id: "1006", log: "Windows Defender", name: "Malware Detected", lookFor: "Threat name, file path, action" },
      { id: "1007", log: "Windows Defender", name: "Action Taken", lookFor: "Quarantine, remove, allow" },
      { id: "1116", log: "Windows Defender", name: "Real-time Protection Detection", lookFor: "Live threat detection" },
      { id: "1117", log: "Windows Defender", name: "Real-time Protection Action", lookFor: "Automated response" },
      { id: "5001", log: "Windows Defender", name: "Real-time Protection Disabled", lookFor: "Security control bypass" }
    ]
  },
  objectAccess: {
    category: "Object Access",
    items: [
      { id: "4663", log: "Security", name: "Object Access Attempt", lookFor: "File/folder access with auditing" },
      { id: "4656", log: "Security", name: "Handle Requested", lookFor: "Object handle request" },
      { id: "4658", log: "Security", name: "Handle Closed", lookFor: "Object handle closed" },
      { id: "4660", log: "Security", name: "Object Deleted", lookFor: "File/object deletion" },
      { id: "11", log: "Sysmon", name: "File Created", lookFor: "New file creation with hash" },
      { id: "23", log: "Sysmon", name: "File Delete", lookFor: "File deletion tracking" }
    ]
  },
  accountMgmt: {
    category: "Account Management",
    items: [
      { id: "4720", log: "Security", name: "User Account Created", lookFor: "New local account creation" },
      { id: "4722", log: "Security", name: "User Account Enabled", lookFor: "Account activation" },
      { id: "4724", log: "Security", name: "Password Reset Attempt", lookFor: "Admin password reset" },
      { id: "4728", log: "Security", name: "Member Added to Security Group", lookFor: "Privilege escalation" },
      { id: "4732", log: "Security", name: "Member Added to Local Group", lookFor: "Local admin group changes" },
      { id: "4756", log: "Security", name: "Member Added to Universal Group", lookFor: "Domain group changes" }
    ]
  }
};

const escapeHtml = (value) => String(value)
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#39;");

const buildDetailMarkup = (data) => {
  let html = `
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
  </div>`;

  // Add databases section if present (for browser artifacts, etc.)
  if (data.databases) {
    html += `<div class="detail-section">
      <div class="detail-label">Key databases &amp; tables</div>
      <div class="detail-databases">`;

    Object.entries(data.databases).forEach(([browser, files]) => {
      html += `<div class="detail-db-group">
        <div class="detail-db-browser">${escapeHtml(browser.charAt(0).toUpperCase() + browser.slice(1))}</div>
        <div class="detail-db-files">`;

      files.forEach((db) => {
        html += `<div class="detail-db-file">
          <code class="detail-db-name">${escapeHtml(db.file)}</code>
          <span class="detail-db-tables">${escapeHtml(db.tables)}</span>
          <span class="detail-db-ts">${escapeHtml(db.timestamps)}</span>
        </div>`;
      });

      html += `</div></div>`;
    });

    html += `</div></div>`;
  }

  // Add event logs section if present (for RDP, etc.)
  if (data.eventLogs) {
    html += `<div class="detail-section">
      <div class="detail-label">Related Event IDs</div>
      <div class="detail-events">`;

    Object.entries(data.eventLogs).forEach(([direction, events]) => {
      html += `<div class="detail-event-group">
        <div class="detail-event-direction">${escapeHtml(direction.charAt(0).toUpperCase() + direction.slice(1))}</div>
        <div class="detail-event-list">`;

      events.forEach((evt) => {
        html += `<div class="detail-event-row">
          <code class="detail-event-id">${escapeHtml(evt.id)}</code>
          <span class="detail-event-log">${escapeHtml(evt.log)}</span>
          <span class="detail-event-meaning">${escapeHtml(evt.meaning)}</span>
        </div>`;
      });

      html += `</div></div>`;
    });

    html += `</div></div>`;
  }

  // Add key fields section if present
  if (data.keyFields && data.keyFields.length > 0) {
    html += `<div class="detail-section">
      <div class="detail-label">Key fields to query</div>
      <ul class="detail-list detail-fields">
        ${data.keyFields.map((field) => `<li><code>${escapeHtml(field)}</code></li>`).join("")}
      </ul>
    </div>`;
  }

  return html;
};

// Cache for icon labels to avoid repeated string operations
const iconLabelCache = new Map();

const getGlossaryIconLabel = (name, artifactId) => {
  const cacheKey = artifactId || name || "";
  if (iconLabelCache.has(cacheKey)) {
    return iconLabelCache.get(cacheKey);
  }

  let label = "??";
  if (name) {
    const cleaned = name.replace(/\([^)]*\)/g, " ");
    const words = cleaned.split(/[^a-zA-Z0-9]+/).filter(Boolean);
    if (words.length === 1) {
      const word = words[0];
      label = (word.slice(0, 2) || word).toUpperCase();
    } else if (words.length > 1) {
      const initials = words.map((word) => word[0]).join("");
      label = (initials.slice(0, 2) || initials).toUpperCase();
    }
  } else if (artifactId) {
    label = artifactId.replace(/[^a-zA-Z0-9]+/g, "").slice(0, 2).toUpperCase();
  }

  iconLabelCache.set(cacheKey, label);
  return label;
};

const applyGlossaryIconLabels = () => {
  const icons = Array.from(document.querySelectorAll(".glossary-tile-icon"));
  icons.forEach((icon) => {
    const tile = icon.closest("[data-glossary-tile]");
    const artifactId = tile?.dataset.artifact || icon.dataset.artifact;
    const name = artifactId ? artifactData[artifactId]?.name : "";
    const label = getGlossaryIconLabel(name, artifactId);
    icon.textContent = label;
    icon.classList.add("glossary-tile-icon--label");
  });
};

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

applyGlossaryIconLabels();

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

// Sidebar section handling
const initSidebarSections = () => {
  if (!sidebar) return;

  const tabContainer = sidebar.querySelector("[data-sidebar-tabs]");
  const tabs = Array.from(sidebar.querySelectorAll("[data-sidebar-tab]"));
  const sidebarContent = sidebar.querySelector("[data-sidebar-content]");
  const glossaryGrid = sidebar.querySelector("[data-glossary-grid]");
  const refContent = sidebar.querySelector("[data-sidebar-ref-content]");
  const searchInput = sidebar.querySelector("[data-glossary-search]");
  const detailPane = sidebar.querySelector("[data-glossary-detail]");
  const detailContent = sidebar.querySelector("[data-glossary-detail-content]");
  const backButton = sidebar.querySelector("[data-glossary-back]");
  const viewToggle = sidebar.querySelector("[data-sidebar-view-toggle]");
  const viewModeButtons = viewToggle ? Array.from(viewToggle.querySelectorAll("[data-view-mode]")) : [];

  if (!tabContainer || !tabs.length) return;

  let activeSidebarSection = "artifacts";
  let sidebarViewMode = localStorage.getItem("sifted.sidebar.viewMode") || "categorized";

  // Get counts for sidebar tabs
  const getSidebarCounts = () => {
    return {
      artifacts: Object.keys(artifactData).length,
      registry: Object.values(registryData).reduce((sum, g) => sum + g.items.length, 0),
      persistence: Object.values(persistenceData).reduce((sum, g) => sum + g.items.length, 0),
      events: Object.values(eventData).reduce((sum, g) => sum + g.items.length, 0)
    };
  };

  // Update sidebar tab counts
  const updateSidebarCounts = () => {
    const counts = getSidebarCounts();
    tabs.forEach((tab) => {
      const section = tab.dataset.sidebarTab;
      const countEl = tab.querySelector("[data-sidebar-count]");
      if (countEl && counts[section] !== undefined) {
        countEl.textContent = counts[section];
      }
    });
  };

  // Build sidebar artifact list
  const buildSidebarArtifacts = (query = "") => {
    const lowerQuery = query.toLowerCase();
    let html = "";

    Object.entries(artifactCategories).forEach(([catId, category]) => {
      const filtered = category.artifacts.filter((id) => {
        const data = artifactData[id];
        if (!data) return false;
        if (!query) return true;
        const text = `${data.name} ${data.what} ${data.takeaway} ${id}`.toLowerCase();
        return text.includes(lowerQuery);
      });

      if (filtered.length === 0) return;

      const isExpanded = query ? true : false;
      const previewBadges = filtered.slice(0, 5).map((id) => {
        const icon = getGlossaryIconLabel(artifactData[id]?.name, id);
        return `<span class="category-preview-badge">${icon}</span>`;
      }).join("");
      const hasMore = filtered.length > 5;
      html += `
        <div class="ref-category ${isExpanded ? "expanded" : ""}" data-category="${catId}">
          <button class="ref-category-header" type="button">
            <span class="ref-category-title">${escapeHtml(category.name)}</span>
            <span class="ref-category-count">${filtered.length}</span>
          </button>
          <div class="category-preview">
            ${previewBadges}${hasMore ? '<span class="category-preview-more">...</span>' : ''}
          </div>
          <div class="ref-list artifact-list">
            ${filtered.map((id) => {
              const data = artifactData[id];
              const icon = getGlossaryIconLabel(data.name, id);
              return `
              <button class="artifact-row" type="button" data-artifact="${id}">
                <span class="artifact-row-icon">${icon}</span>
                <span class="artifact-row-name">${escapeHtml(data.name)}</span>
                <span class="artifact-row-hint">${escapeHtml(data.takeaway)}</span>
              </button>`;
            }).join("")}
          </div>
        </div>`;
    });

    return html || '<p class="ref-empty">No matching artifacts.</p>';
  };

  // Build sidebar registry list
  const buildSidebarRegistry = (query = "") => {
    const lowerQuery = query.toLowerCase();
    let html = "";

    Object.entries(registryData).forEach(([groupId, group]) => {
      const filtered = group.items.filter((item) => {
        if (!query) return true;
        return item.key.toLowerCase().includes(lowerQuery) ||
               item.purpose.toLowerCase().includes(lowerQuery);
      });

      if (filtered.length === 0) return;

      const isExpanded = query ? true : false;
      const previewDots = Math.min(filtered.length, 6);
      const hasMore = filtered.length > 6;
      html += `
        <div class="ref-category ${isExpanded ? "expanded" : ""}" data-category="${groupId}">
          <button class="ref-category-header" type="button">
            <span class="ref-category-title">${escapeHtml(group.category)}</span>
            <span class="ref-category-count">${filtered.length}</span>
          </button>
          <div class="category-preview">
            ${Array(previewDots).fill('<span class="category-preview-dot category-preview-dot--registry"></span>').join("")}${hasMore ? '<span class="category-preview-more">...</span>' : ''}
          </div>
          <div class="ref-list">
            ${filtered.map((item) => `
              <div class="ref-row">
                <code class="ref-key">${escapeHtml(item.key)}</code>
                <span class="ref-desc">${escapeHtml(item.purpose)}</span>
              </div>
            `).join("")}
          </div>
        </div>`;
    });

    return html || '<p class="ref-empty">No matching registry keys.</p>';
  };

  // Build sidebar persistence list
  const buildSidebarPersistence = (query = "") => {
    const lowerQuery = query.toLowerCase();
    let html = "";

    Object.entries(persistenceData).forEach(([groupId, group]) => {
      const filtered = group.items.filter((item) => {
        if (!query) return true;
        return item.path.toLowerCase().includes(lowerQuery) ||
               item.notes.toLowerCase().includes(lowerQuery);
      });

      if (filtered.length === 0) return;

      const isExpanded = query ? true : false;
      const previewDots = Math.min(filtered.length, 6);
      const hasMore = filtered.length > 6;
      html += `
        <div class="ref-category ${isExpanded ? "expanded" : ""}" data-category="${groupId}">
          <button class="ref-category-header" type="button">
            <span class="ref-category-title">${escapeHtml(group.category)}</span>
            <span class="ref-category-count">${filtered.length}</span>
          </button>
          <div class="category-preview">
            ${Array(previewDots).fill('<span class="category-preview-dot category-preview-dot--persistence"></span>').join("")}${hasMore ? '<span class="category-preview-more">...</span>' : ''}
          </div>
          <div class="ref-list">
            ${filtered.map((item) => `
              <div class="ref-row">
                <code class="ref-key">${escapeHtml(item.path)}</code>
                <span class="ref-desc">${escapeHtml(item.notes)}</span>
              </div>
            `).join("")}
          </div>
        </div>`;
    });

    return html || '<p class="ref-empty">No matching persistence locations.</p>';
  };

  // Build sidebar events list
  const buildSidebarEvents = (query = "") => {
    const lowerQuery = query.toLowerCase();
    let html = "";

    Object.entries(eventData).forEach(([groupId, group]) => {
      const filtered = group.items.filter((item) => {
        if (!query) return true;
        return item.id.toLowerCase().includes(lowerQuery) ||
               item.name.toLowerCase().includes(lowerQuery) ||
               item.log.toLowerCase().includes(lowerQuery);
      });

      if (filtered.length === 0) return;

      const isExpanded = query ? true : false;
      const previewBadges = filtered.slice(0, 4).map((item) =>
        `<span class="category-preview-badge category-preview-badge--event">${escapeHtml(item.id)}</span>`
      ).join("");
      const hasMore = filtered.length > 4;
      html += `
        <div class="ref-category ${isExpanded ? "expanded" : ""}" data-category="${groupId}">
          <button class="ref-category-header" type="button">
            <span class="ref-category-title">${escapeHtml(group.category)}</span>
            <span class="ref-category-count">${filtered.length}</span>
          </button>
          <div class="category-preview">
            ${previewBadges}${hasMore ? '<span class="category-preview-more">...</span>' : ''}
          </div>
          <div class="ref-list event-grid">
            ${filtered.map((item) => `
              <div class="event-row">
                <code class="event-id">${escapeHtml(item.id)}</code>
                <span class="event-name">${escapeHtml(item.name)}</span>
                <span class="event-desc">${escapeHtml(item.lookFor)}</span>
              </div>
            `).join("")}
          </div>
        </div>`;
    });

    return html || '<p class="ref-empty">No matching events.</p>';
  };

  // Build alphabetical artifact list for sidebar
  const buildSidebarArtifactsAlphabetical = (query = "") => {
    const lowerQuery = query.toLowerCase();

    const matchingArtifacts = Object.entries(artifactData)
      .filter(([id, data]) => {
        if (!data) return false;
        if (!query) return true;
        const text = `${data.name} ${data.what} ${data.takeaway} ${id}`.toLowerCase();
        return text.includes(lowerQuery);
      })
      .sort((a, b) => a[1].name.localeCompare(b[1].name));

    if (matchingArtifacts.length === 0) {
      return '<p class="ref-empty">No matching artifacts.</p>';
    }

    return `
      <div class="ref-list ref-list-alphabetical artifact-list">
        ${matchingArtifacts.map(([id, data]) => {
          const icon = getGlossaryIconLabel(data.name, id);
          return `
          <button class="artifact-row" type="button" data-artifact="${id}">
            <span class="artifact-row-icon">${icon}</span>
            <span class="artifact-row-name">${escapeHtml(data.name)}</span>
            <span class="artifact-row-hint">${escapeHtml(data.takeaway)}</span>
          </button>`;
        }).join("")}
      </div>
    `;
  };

  // Build alphabetical registry list for sidebar
  const buildSidebarRegistryAlphabetical = (query = "") => {
    const lowerQuery = query.toLowerCase();
    const allItems = [];

    Object.values(registryData).forEach((group) => {
      group.items.forEach((item) => {
        if (!query) {
          allItems.push(item);
          return;
        }
        if (item.key.toLowerCase().includes(lowerQuery) ||
            item.purpose.toLowerCase().includes(lowerQuery)) {
          allItems.push(item);
        }
      });
    });

    allItems.sort((a, b) => a.key.localeCompare(b.key));

    if (allItems.length === 0) {
      return '<p class="ref-empty">No matching registry keys.</p>';
    }

    return `
      <div class="ref-list ref-list-alphabetical">
        ${allItems.map((item) => `
          <div class="ref-row">
            <code class="ref-key">${escapeHtml(item.key)}</code>
            <span class="ref-desc">${escapeHtml(item.purpose)}</span>
          </div>
        `).join("")}
      </div>
    `;
  };

  // Build alphabetical persistence list for sidebar
  const buildSidebarPersistenceAlphabetical = (query = "") => {
    const lowerQuery = query.toLowerCase();
    const allItems = [];

    Object.values(persistenceData).forEach((group) => {
      group.items.forEach((item) => {
        if (!query) {
          allItems.push(item);
          return;
        }
        if (item.path.toLowerCase().includes(lowerQuery) ||
            item.notes.toLowerCase().includes(lowerQuery)) {
          allItems.push(item);
        }
      });
    });

    allItems.sort((a, b) => a.path.localeCompare(b.path));

    if (allItems.length === 0) {
      return '<p class="ref-empty">No matching persistence locations.</p>';
    }

    return `
      <div class="ref-list ref-list-alphabetical">
        ${allItems.map((item) => `
          <div class="ref-row">
            <code class="ref-key">${escapeHtml(item.path)}</code>
            <span class="ref-desc">${escapeHtml(item.notes)}</span>
          </div>
        `).join("")}
      </div>
    `;
  };

  // Build alphabetical events list for sidebar
  const buildSidebarEventsAlphabetical = (query = "") => {
    const lowerQuery = query.toLowerCase();
    const allItems = [];

    Object.values(eventData).forEach((group) => {
      group.items.forEach((item) => {
        if (!query) {
          allItems.push(item);
          return;
        }
        if (item.id.toLowerCase().includes(lowerQuery) ||
            item.name.toLowerCase().includes(lowerQuery) ||
            item.log.toLowerCase().includes(lowerQuery)) {
          allItems.push(item);
        }
      });
    });

    // Sort by event ID numerically
    allItems.sort((a, b) => {
      const aNum = parseInt(a.id, 10);
      const bNum = parseInt(b.id, 10);
      if (!isNaN(aNum) && !isNaN(bNum)) return aNum - bNum;
      return a.id.localeCompare(b.id);
    });

    if (allItems.length === 0) {
      return '<p class="ref-empty">No matching events.</p>';
    }

    return `
      <div class="ref-list ref-list-alphabetical event-grid">
        ${allItems.map((item) => `
          <div class="event-row">
            <code class="event-id">${escapeHtml(item.id)}</code>
            <span class="event-name">${escapeHtml(item.name)}</span>
            <span class="event-desc">${escapeHtml(item.lookFor)}</span>
          </div>
        `).join("")}
      </div>
    `;
  };

  // Show artifact detail in sidebar
  const showSidebarDetail = (artifactId) => {
    const data = artifactData[artifactId];
    if (!data || !detailPane || !detailContent) return;

    detailContent.innerHTML = buildDetailMarkup(data);
    detailContent.scrollTop = 0;
    detailPane.hidden = false;
    if (sidebarContent) sidebarContent.style.display = "none";
  };

  // Hide artifact detail in sidebar
  const hideSidebarDetail = () => {
    if (detailPane) detailPane.hidden = true;
    if (sidebarContent) sidebarContent.style.display = "";
    renderSidebarSection(activeSidebarSection, searchInput?.value || "");
  };

  // Render the active sidebar section
  const renderSidebarSection = (section, query = "") => {
    if (glossaryGrid) glossaryGrid.style.display = "none";
    if (refContent) {
      refContent.style.display = "flex";
      refContent.classList.add("active");
    }

    let html = "";
    if (section === "artifacts") {
      html = sidebarViewMode === "alphabetical"
        ? buildSidebarArtifactsAlphabetical(query)
        : buildSidebarArtifacts(query);
    } else if (section === "registry") {
      html = sidebarViewMode === "alphabetical"
        ? buildSidebarRegistryAlphabetical(query)
        : buildSidebarRegistry(query);
    } else if (section === "persistence") {
      html = sidebarViewMode === "alphabetical"
        ? buildSidebarPersistenceAlphabetical(query)
        : buildSidebarPersistence(query);
    } else if (section === "events") {
      html = sidebarViewMode === "alphabetical"
        ? buildSidebarEventsAlphabetical(query)
        : buildSidebarEvents(query);
    }

    if (refContent) {
      refContent.innerHTML = html;

      // Attach category expand/collapse handlers
      refContent.querySelectorAll(".ref-category-header").forEach((header) => {
        header.addEventListener("click", () => {
          header.closest(".ref-category").classList.toggle("expanded");
        });
      });

      // Attach artifact click handlers for artifact section
      if (section === "artifacts") {
        refContent.querySelectorAll(".artifact-row").forEach((row) => {
          row.addEventListener("click", () => {
            const artifactId = row.dataset.artifact;
            if (artifactId) showSidebarDetail(artifactId);
          });
        });
      }
    }
  };

  // Tab click handlers
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const section = tab.dataset.sidebarTab;
      if (section === activeSidebarSection) return;

      tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      activeSidebarSection = section;

      // Hide detail pane when switching sections
      if (detailPane) detailPane.hidden = true;

      renderSidebarSection(section, searchInput?.value || "");
    });
  });

  // Search input handler
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      if (detailPane && !detailPane.hidden) {
        hideSidebarDetail();
      }
      renderSidebarSection(activeSidebarSection, searchInput.value);
    });
  }

  // Back button handler
  if (backButton) {
    backButton.addEventListener("click", hideSidebarDetail);
  }

  // View mode toggle handler
  if (viewModeButtons.length) {
    viewModeButtons.forEach((btn) => {
      btn.addEventListener("click", () => {
        const newMode = btn.dataset.viewMode;
        if (newMode === sidebarViewMode) return;

        sidebarViewMode = newMode;
        localStorage.setItem("sifted.sidebar.viewMode", newMode);

        // Update button active states
        viewModeButtons.forEach((b) => b.classList.toggle("active", b.dataset.viewMode === newMode));

        // Re-render section
        renderSidebarSection(activeSidebarSection, searchInput?.value || "");
      });
    });

    // Restore view mode button state on init
    viewModeButtons.forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.viewMode === sidebarViewMode);
    });
  }

  // Initialize
  updateSidebarCounts();
  renderSidebarSection("artifacts", "");
};

initSidebarSections();

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

// Cache for tooltip HTML content to avoid regenerating on every hover
const tooltipCache = new Map();

const getTooltipHtml = (artifactId) => {
  if (tooltipCache.has(artifactId)) {
    return tooltipCache.get(artifactId);
  }
  const data = artifactData[artifactId];
  if (!data) return null;

  const html = `
    <h4>${escapeHtml(data.name)}</h4>
    <p><span class="tooltip-label">What:</span> ${escapeHtml(data.what)}</p>
    <p><span class="tooltip-label">Why:</span> ${escapeHtml(data.why)}</p>
  `;
  tooltipCache.set(artifactId, html);
  return html;
};

const showTooltip = (element, artifactId) => {
  const html = getTooltipHtml(artifactId);
  if (!html || !tooltip || !tooltipContent) {
    return;
  }

  tooltipContent.innerHTML = html;

  // Single layout read - batch all measurements together
  const rect = element.getBoundingClientRect();
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;

  // Calculate position (tooltip is 320px wide, ~150px tall)
  let left = rect.left + (rect.width / 2) - 160;
  let top = rect.bottom + 8;

  // Keep tooltip in viewport - use cached viewport dimensions
  if (left < 10) left = 10;
  if (left + 320 > viewportWidth - 10) {
    left = viewportWidth - 330;
  }
  if (top + 150 > viewportHeight) {
    top = rect.top - 150;
  }

  // Batch all style writes together
  tooltip.style.cssText = `left:${left}px;top:${top}px`;
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

// Event delegation for artifact link tooltips - uses single document listener
// instead of per-element listeners for better performance
let tooltipDelegationInitialized = false;
let currentHoveredLink = null;

const initTooltipDelegation = () => {
  if (tooltipDelegationInitialized) return;
  tooltipDelegationInitialized = true;

  // Single mouseenter handler using event delegation
  document.addEventListener("mouseover", (event) => {
    const link = event.target.closest(".artifact-link");
    if (!link || link === currentHoveredLink) return;

    currentHoveredLink = link;
    clearTimeout(tooltipTimeout);
    tooltipTimeout = setTimeout(() => {
      showTooltip(link, link.dataset.artifact);
    }, 200);
  });

  // Single mouseleave handler using event delegation
  document.addEventListener("mouseout", (event) => {
    const link = event.target.closest(".artifact-link");
    if (!link) return;

    // Check if we're moving to another element within the same link
    const relatedTarget = event.relatedTarget;
    if (relatedTarget && link.contains(relatedTarget)) return;

    currentHoveredLink = null;
    clearTimeout(tooltipTimeout);
    tooltipTimeout = setTimeout(hideTooltip, 100);
  });

  // Single click handler using event delegation
  document.addEventListener("click", (event) => {
    const link = event.target.closest(".artifact-link");
    if (!link) return;

    event.preventDefault();
    hideTooltip();
    openSidebar();
    sidebarApi?.showDetail(link.dataset.artifact);
  });
};

// Initialize event delegation immediately
initTooltipDelegation();

// Legacy function kept for compatibility - now a no-op since delegation handles everything
const initArtifactTooltips = (container = document) => {
  // Event delegation handles all artifact links automatically
  // This function is kept for backward compatibility with code that calls it
  // (e.g., guide modal initialization)
};

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

// ==============================================
// REFERENCE SECTIONS - Artifacts, Registry, Persistence, Events
// ==============================================

// Build artifact list HTML with category grouping
const buildArtifactList = (query = "", osFilter = "all") => {
  const lowerQuery = query.toLowerCase();
  let html = "";
  let totalVisible = 0;

  Object.entries(artifactCategories).forEach(([catId, category]) => {
    const filteredArtifacts = category.artifacts.filter((artifactId) => {
      const data = artifactData[artifactId];
      if (!data) return false;

      // OS filter
      if (osFilter && osFilter !== "all") {
        if (!(data.os || []).includes(osFilter)) return false;
      }

      // Search filter
      if (!query) return true;
      const searchText = `${data.name} ${data.what} ${data.why} ${data.question} ${data.takeaway || ""} ${artifactId}`.toLowerCase();
      return searchText.includes(lowerQuery);
    });

    if (filteredArtifacts.length === 0) return;

    totalVisible += filteredArtifacts.length;
    const isExpanded = query ? true : false;

    html += `
      <div class="ref-category ${isExpanded ? "expanded" : ""}" data-category="${catId}">
        <button class="ref-category-header" type="button">
          <span class="ref-category-title">${escapeHtml(category.name)}</span>
          <span class="ref-category-count">${filteredArtifacts.length}</span>
        </button>
        <div class="ref-list artifact-list">
          ${filteredArtifacts
            .map((artifactId) => {
              const data = artifactData[artifactId];
              const iconLabel = getGlossaryIconLabel(data.name, artifactId);
              return `
              <button class="artifact-row" type="button" data-artifact="${artifactId}">
                <span class="artifact-row-icon">${iconLabel}</span>
                <span class="artifact-row-name">${escapeHtml(data.name)}</span>
                <span class="artifact-row-hint">${escapeHtml(data.takeaway)}</span>
              </button>
            `;
            })
            .join("")}
        </div>
      </div>
    `;
  });

  return { html, count: totalVisible };
};

// Build registry reference list HTML
const buildRegistryList = (query = "") => {
  const lowerQuery = query.toLowerCase();
  let html = "";
  let totalVisible = 0;

  Object.entries(registryData).forEach(([groupId, group]) => {
    const filteredItems = group.items.filter((item) => {
      if (!query) return true;
      return (
        item.key.toLowerCase().includes(lowerQuery) ||
        item.purpose.toLowerCase().includes(lowerQuery) ||
        (item.lookFor && item.lookFor.toLowerCase().includes(lowerQuery))
      );
    });

    if (filteredItems.length === 0) return;

    totalVisible += filteredItems.length;
    const isExpanded = query ? true : false; // Auto-expand when searching

    html += `
      <div class="ref-category ${isExpanded ? "expanded" : ""}" data-category="${groupId}">
        <button class="ref-category-header" type="button">
          <span class="ref-category-title">${escapeHtml(group.category)}</span>
          <span class="ref-category-count">${filteredItems.length}</span>
        </button>
        <div class="ref-list">
          ${filteredItems
            .map(
              (item) => `
            <div class="ref-row">
              <code class="ref-key">${escapeHtml(item.key)}</code>
              <span class="ref-desc">${escapeHtml(item.purpose)}</span>
            </div>
          `
            )
            .join("")}
        </div>
      </div>
    `;
  });

  return { html, count: totalVisible };
};

// Build persistence reference list HTML
const buildPersistenceList = (query = "", osFilter = null) => {
  const lowerQuery = query.toLowerCase();
  let html = "";
  let totalVisible = 0;

  // Define OS mapping for categories
  const categoryOs = {
    registry: "windows",
    filesystem: "windows",
    wmi: "windows",
    scheduled: "windows",
    linux: "linux",
    macos: "macos"
  };

  Object.entries(persistenceData).forEach(([groupId, group]) => {
    // Filter by OS if specified
    const groupOs = categoryOs[groupId];
    if (osFilter && osFilter !== "all" && groupOs !== osFilter) return;

    const filteredItems = group.items.filter((item) => {
      if (!query) return true;
      return (
        item.path.toLowerCase().includes(lowerQuery) ||
        item.notes.toLowerCase().includes(lowerQuery) ||
        item.trigger.toLowerCase().includes(lowerQuery)
      );
    });

    if (filteredItems.length === 0) return;

    totalVisible += filteredItems.length;
    const isExpanded = query ? true : false;

    html += `
      <div class="ref-category ${isExpanded ? "expanded" : ""}" data-category="${groupId}">
        <button class="ref-category-header" type="button">
          <span class="ref-category-title">${escapeHtml(group.category)}</span>
          <span class="ref-category-count">${filteredItems.length}</span>
        </button>
        <div class="ref-list">
          ${filteredItems
            .map(
              (item) => `
            <div class="ref-row">
              <code class="ref-key">${escapeHtml(item.path)}</code>
              <span class="ref-desc">${escapeHtml(item.notes)}</span>
            </div>
          `
            )
            .join("")}
        </div>
      </div>
    `;
  });

  return { html, count: totalVisible };
};

// Build alphabetical artifact list (flat, no categories)
const buildArtifactListAlphabetical = (query = "", osFilter = "all") => {
  const lowerQuery = query.toLowerCase();

  // Collect all matching artifacts
  const matchingArtifacts = Object.entries(artifactData)
    .filter(([artifactId, data]) => {
      if (!data) return false;
      if (osFilter && osFilter !== "all") {
        if (!(data.os || []).includes(osFilter)) return false;
      }
      if (!query) return true;
      const searchText = `${data.name} ${data.what} ${data.why} ${data.question} ${data.takeaway || ""} ${artifactId}`.toLowerCase();
      return searchText.includes(lowerQuery);
    })
    .sort((a, b) => a[1].name.localeCompare(b[1].name));

  if (matchingArtifacts.length === 0) {
    return { html: '<p class="ref-empty">No matching artifacts found.</p>', count: 0 };
  }

  const html = `
    <div class="ref-list ref-list-alphabetical artifact-list">
      ${matchingArtifacts
        .map(([artifactId, data]) => {
          const iconLabel = getGlossaryIconLabel(data.name, artifactId);
          return `
          <button class="artifact-row" type="button" data-artifact="${artifactId}">
            <span class="artifact-row-icon">${iconLabel}</span>
            <span class="artifact-row-name">${escapeHtml(data.name)}</span>
            <span class="artifact-row-hint">${escapeHtml(data.takeaway)}</span>
          </button>
        `;
        })
        .join("")}
    </div>
  `;

  return { html, count: matchingArtifacts.length };
};

// Build alphabetical registry list (flat, no categories)
const buildRegistryListAlphabetical = (query = "") => {
  const lowerQuery = query.toLowerCase();

  const allItems = [];
  Object.values(registryData).forEach((group) => {
    group.items.forEach((item) => {
      if (!query) {
        allItems.push(item);
        return;
      }
      const searchText = `${item.key} ${item.purpose} ${item.lookFor || ""}`.toLowerCase();
      if (searchText.includes(lowerQuery)) allItems.push(item);
    });
  });

  allItems.sort((a, b) => a.key.localeCompare(b.key));

  if (allItems.length === 0) {
    return { html: '<p class="ref-empty">No matching registry keys found.</p>', count: 0 };
  }

  const html = `
    <div class="ref-list ref-list-alphabetical">
      ${allItems
        .map((item) => `
          <div class="ref-row">
            <code class="ref-key">${escapeHtml(item.key)}</code>
            <span class="ref-desc">${escapeHtml(item.purpose)}</span>
          </div>
        `)
        .join("")}
    </div>
  `;

  return { html, count: allItems.length };
};

// Build alphabetical persistence list (flat, no categories)
const buildPersistenceListAlphabetical = (query = "", osFilter = null) => {
  const lowerQuery = query.toLowerCase();

  const categoryOs = {
    registry: "windows",
    filesystem: "windows",
    wmi: "windows",
    scheduled: "windows",
    linux: "linux",
    macos: "macos"
  };

  const allItems = [];
  Object.entries(persistenceData).forEach(([groupId, group]) => {
    const groupOs = categoryOs[groupId];
    if (osFilter && osFilter !== "all" && groupOs !== osFilter) return;

    group.items.forEach((item) => {
      if (!query) {
        allItems.push(item);
        return;
      }
      const searchText = `${item.path} ${item.notes} ${item.trigger}`.toLowerCase();
      if (searchText.includes(lowerQuery)) allItems.push(item);
    });
  });

  allItems.sort((a, b) => a.path.localeCompare(b.path));

  if (allItems.length === 0) {
    return { html: '<p class="ref-empty">No matching persistence locations found.</p>', count: 0 };
  }

  const html = `
    <div class="ref-list ref-list-alphabetical">
      ${allItems
        .map((item) => `
          <div class="ref-row">
            <code class="ref-key">${escapeHtml(item.path)}</code>
            <span class="ref-desc">${escapeHtml(item.notes)}</span>
          </div>
        `)
        .join("")}
    </div>
  `;

  return { html, count: allItems.length };
};

// Build alphabetical event list (flat, no categories)
const buildEventListAlphabetical = (query = "") => {
  const lowerQuery = query.toLowerCase();

  const allItems = [];
  Object.values(eventData).forEach((group) => {
    group.items.forEach((item) => {
      if (!query) {
        allItems.push(item);
        return;
      }
      const searchText = `${item.id} ${item.name} ${item.log} ${item.lookFor}`.toLowerCase();
      if (searchText.includes(lowerQuery)) allItems.push(item);
    });
  });

  // Sort by event ID numerically where possible
  allItems.sort((a, b) => {
    const aNum = parseInt(a.id, 10);
    const bNum = parseInt(b.id, 10);
    if (!isNaN(aNum) && !isNaN(bNum)) return aNum - bNum;
    return a.id.localeCompare(b.id);
  });

  if (allItems.length === 0) {
    return { html: '<p class="ref-empty">No matching events found.</p>', count: 0 };
  }

  const html = `
    <div class="ref-list ref-list-alphabetical">
      ${allItems
        .map((item) => `
          <div class="ref-row ref-row-event">
            <span class="ref-id">${escapeHtml(item.id)}</span>
            <span class="ref-name">${escapeHtml(item.name)}</span>
            <span class="ref-log">${escapeHtml(item.log)}</span>
          </div>
        `)
        .join("")}
    </div>
  `;

  return { html, count: allItems.length };
};

// Build event reference list HTML
const buildEventList = (query = "") => {
  const lowerQuery = query.toLowerCase();
  let html = "";
  let totalVisible = 0;

  Object.entries(eventData).forEach(([groupId, group]) => {
    const filteredItems = group.items.filter((item) => {
      if (!query) return true;
      return (
        item.id.toLowerCase().includes(lowerQuery) ||
        item.name.toLowerCase().includes(lowerQuery) ||
        item.log.toLowerCase().includes(lowerQuery) ||
        item.lookFor.toLowerCase().includes(lowerQuery)
      );
    });

    if (filteredItems.length === 0) return;

    totalVisible += filteredItems.length;
    const isExpanded = query ? true : false;

    html += `
      <div class="ref-category ${isExpanded ? "expanded" : ""}" data-category="${groupId}">
        <button class="ref-category-header" type="button">
          <span class="ref-category-title">${escapeHtml(group.category)}</span>
          <span class="ref-category-count">${filteredItems.length}</span>
        </button>
        <div class="ref-list">
          ${filteredItems
            .map(
              (item) => `
            <div class="ref-row ref-row-event">
              <span class="ref-id">${escapeHtml(item.id)}</span>
              <span class="ref-name">${escapeHtml(item.name)}</span>
              <span class="ref-log">${escapeHtml(item.log)}</span>
            </div>
          `
            )
            .join("")}
        </div>
      </div>
    `;
  });

  return { html, count: totalVisible };
};

// Initialize reference section tabs (page glossary only)
const initReferenceSections = () => {
  const pagePanel = document.querySelector('[data-glossary-surface="page"]');
  if (!pagePanel) return;

  const tabContainer = pagePanel.querySelector("[data-section-tabs]");
  const contentContainer = pagePanel.querySelector("[data-section-content]");
  const searchInput = pagePanel.querySelector("[data-glossary-search]");
  const countDisplay = pagePanel.querySelector("[data-glossary-count]");
  const osFilterGroup = pagePanel.querySelector('[data-glossary-filter-group="os"]');
  const detailContent = pagePanel.querySelector("[data-glossary-detail-content]");

  if (!tabContainer || !contentContainer) return;

  const tabs = Array.from(tabContainer.querySelectorAll("[data-section-tab]"));

  // Restore persisted state from localStorage
  const savedSection = localStorage.getItem("sifted.glossary.section");
  const savedOsFilter = localStorage.getItem("sifted.glossary.osFilter");
  const savedViewMode = localStorage.getItem("sifted.glossary.viewMode");

  let activeSection = savedSection || "artifacts";
  let currentOsFilter = savedOsFilter || "all";
  let currentViewMode = savedViewMode || "categorized";

  // View toggle elements
  const viewToggle = pagePanel.querySelector("[data-view-toggle]");
  const viewModeButtons = viewToggle ? Array.from(viewToggle.querySelectorAll("[data-view-mode]")) : [];

  // Count items for each section
  const getCounts = (query = "") => {
    const lowerQuery = query.toLowerCase();

    // Artifacts count - iterate over artifactData directly for accurate counts
    let artifactCount = 0;
    Object.entries(artifactData).forEach(([artifactId, data]) => {
      if (!data) return;

      const osMatches = currentOsFilter === "all" || (data.os || []).includes(currentOsFilter);
      if (!osMatches) return;

      if (!query) {
        artifactCount++;
        return;
      }

      const name = data.name?.toLowerCase() || "";
      const searchText = `${name} ${data.what} ${data.why} ${data.question} ${data.takeaway || ""} ${artifactId}`.toLowerCase();
      if (searchText.includes(lowerQuery)) {
        artifactCount++;
      }
    });

    // Registry count
    let registryCount = 0;
    Object.values(registryData).forEach((group) => {
      group.items.forEach((item) => {
        if (!query) {
          registryCount++;
          return;
        }
        const searchText = `${item.key} ${item.purpose} ${item.lookFor || ""}`.toLowerCase();
        if (searchText.includes(lowerQuery)) registryCount++;
      });
    });

    // Persistence count
    let persistenceCount = 0;
    const persistenceOsMap = {
      registry: "windows",
      filesystem: "windows",
      wmi: "windows",
      scheduled: "windows",
      linux: "linux",
      macos: "macos"
    };
    Object.entries(persistenceData).forEach(([groupId, group]) => {
      const groupOs = persistenceOsMap[groupId];
      if (currentOsFilter !== "all" && groupOs !== currentOsFilter) return;

      group.items.forEach((item) => {
        if (!query) {
          persistenceCount++;
          return;
        }
        const searchText = `${item.path} ${item.notes} ${item.trigger}`.toLowerCase();
        if (searchText.includes(lowerQuery)) persistenceCount++;
      });
    });

    // Events count
    let eventCount = 0;
    Object.values(eventData).forEach((group) => {
      group.items.forEach((item) => {
        if (!query) {
          eventCount++;
          return;
        }
        const searchText = `${item.id} ${item.name} ${item.log} ${item.lookFor}`.toLowerCase();
        if (searchText.includes(lowerQuery)) eventCount++;
      });
    });

    return { artifacts: artifactCount, registry: registryCount, persistence: persistenceCount, events: eventCount };
  };

  // Update tab badges with counts
  const updateTabCounts = (query = "") => {
    const counts = getCounts(query);
    tabs.forEach((tab) => {
      const section = tab.dataset.sectionTab;
      const badge = tab.querySelector(".section-tab-count");
      if (badge && counts[section] !== undefined) {
        badge.textContent = counts[section];
      }
    });
  };

  // Render the active section content
  const renderSection = (section, query = "") => {
    const artifactGrid = pagePanel.querySelector("[data-glossary-grid]");
    const artifactDetail = pagePanel.querySelector("[data-glossary-detail]");
    const refContent = contentContainer.querySelector(".ref-content");

    // Hide the old static artifact grid (we render dynamically now)
    if (artifactGrid) artifactGrid.style.display = "none";

    if (section === "artifacts") {
      // Show artifact detail pane and reference content side by side
      if (artifactDetail) artifactDetail.style.display = "";
      if (refContent) {
        refContent.style.display = "";
        refContent.classList.remove("full-width");
      }
      if (osFilterGroup) osFilterGroup.style.display = "";

      // Build and render artifacts (categorized or alphabetical)
      const result = currentViewMode === "alphabetical"
        ? buildArtifactListAlphabetical(query, currentOsFilter)
        : buildArtifactList(query, currentOsFilter);
      refContent.innerHTML = result.html || '<p class="ref-empty">No matching artifacts found.</p>';

      // Attach category expand/collapse handlers
      refContent.querySelectorAll(".ref-category-header").forEach((header) => {
        header.addEventListener("click", () => {
          header.closest(".ref-category").classList.toggle("expanded");
        });
      });

      // Attach artifact click handlers to show detail
      refContent.querySelectorAll(".artifact-row").forEach((row) => {
        row.addEventListener("click", () => {
          const artifactId = row.dataset.artifact;
          if (artifactId) {
            // Remove active state from all rows
            refContent.querySelectorAll(".artifact-row").forEach((r) => r.classList.remove("active"));
            row.classList.add("active");
            // Show detail
            const data = artifactData[artifactId];
            if (data && detailContent) {
              detailContent.innerHTML = buildDetailMarkup(data);
            }
          }
        });
      });

      // Set default detail placeholder if no artifact is selected
      if (detailContent && !refContent.querySelector(".artifact-row.active")) {
        detailContent.innerHTML = `
          <div class="detail-placeholder">
            <p class="helper">Select an artifact to view details</p>
          </div>
        `;
      }

      // Update count display
      if (countDisplay) {
        const total = Object.keys(artifactData).length;
        if (query || currentOsFilter !== "all") {
          countDisplay.textContent = `${result.count} of ${total} artifacts`;
        } else {
          countDisplay.textContent = `${total} artifacts`;
        }
      }
    } else {
      // Hide artifact detail, show reference content full width
      if (artifactDetail) artifactDetail.style.display = "none";
      if (refContent) {
        refContent.style.display = "";
        refContent.classList.add("full-width");
      }

      // Show/hide OS filter based on section
      if (osFilterGroup) {
        osFilterGroup.style.display = section === "persistence" ? "" : "none";
      }

      let result;
      if (section === "registry") {
        result = currentViewMode === "alphabetical"
          ? buildRegistryListAlphabetical(query)
          : buildRegistryList(query);
      } else if (section === "persistence") {
        result = currentViewMode === "alphabetical"
          ? buildPersistenceListAlphabetical(query, currentOsFilter)
          : buildPersistenceList(query, currentOsFilter);
      } else if (section === "events") {
        result = currentViewMode === "alphabetical"
          ? buildEventListAlphabetical(query)
          : buildEventList(query);
      }

      if (result) {
        refContent.innerHTML = result.html || '<p class="ref-empty">No matching entries found.</p>';

        // Attach collapse/expand handlers to category headers
        refContent.querySelectorAll(".ref-category-header").forEach((header) => {
          header.addEventListener("click", () => {
            const category = header.closest(".ref-category");
            category.classList.toggle("expanded");
          });
        });

        // Update count display
        if (countDisplay) {
          const sectionNames = { registry: "registry keys", persistence: "locations", events: "Windows events" };
          countDisplay.textContent = `${result.count} ${sectionNames[section]}`;
        }
      }
    }

    updateTabCounts(query);
  };

  // Handle tab clicks
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const section = tab.dataset.sectionTab;
      if (section === activeSection) return;

      // Update active state
      tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      activeSection = section;

      // Persist to localStorage
      localStorage.setItem("sifted.glossary.section", section);

      // Render section
      renderSection(section, searchInput?.value || "");
    });
  });

  // Handle search input
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      renderSection(activeSection, searchInput.value);
    });
  }

  // Handle OS filter changes for persistence and artifacts
  if (osFilterGroup) {
    const filterButtons = osFilterGroup.querySelectorAll("[data-glossary-filter-value]");
    filterButtons.forEach((btn) => {
      btn.addEventListener("click", () => {
        currentOsFilter = btn.dataset.glossaryFilterValue || "all";

        // Persist to localStorage
        localStorage.setItem("sifted.glossary.osFilter", currentOsFilter);

        // Update tab counts when filter changes
        updateTabCounts(searchInput?.value || "");
        if (activeSection === "persistence" || activeSection === "artifacts") {
          renderSection(activeSection, searchInput?.value || "");
        }
      });
    });
  }

  // Handle view mode toggle (Categorized / A-Z)
  if (viewModeButtons.length) {
    viewModeButtons.forEach((btn) => {
      btn.addEventListener("click", () => {
        const newMode = btn.dataset.viewMode;
        if (newMode === currentViewMode) return;

        currentViewMode = newMode;
        localStorage.setItem("sifted.glossary.viewMode", newMode);

        // Update button active states
        viewModeButtons.forEach((b) => b.classList.toggle("active", b.dataset.viewMode === newMode));

        // Re-render section
        renderSection(activeSection, searchInput?.value || "");
      });
    });
  }

  // Keyboard shortcuts for section switching (1-4 keys)
  document.addEventListener("keydown", (event) => {
    // Only trigger if not typing in an input
    if (event.target.tagName === "INPUT" || event.target.tagName === "TEXTAREA") return;

    const sectionMap = { "1": "artifacts", "2": "registry", "3": "persistence", "4": "events" };
    const section = sectionMap[event.key];

    if (section && section !== activeSection) {
      const tab = tabContainer.querySelector(`[data-section-tab="${section}"]`);
      if (tab) {
        tabs.forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        activeSection = section;
        renderSection(section, searchInput?.value || "");
      }
    }
  });

  // Initial render - restore persisted state
  setTimeout(() => {
    // Restore active tab visually
    const savedTab = tabContainer.querySelector(`[data-section-tab="${activeSection}"]`);
    if (savedTab) {
      tabs.forEach((t) => t.classList.remove("active"));
      savedTab.classList.add("active");
    }

    // Restore OS filter button state
    if (osFilterGroup && currentOsFilter) {
      const filterButtons = osFilterGroup.querySelectorAll("[data-glossary-filter-value]");
      filterButtons.forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.glossaryFilterValue === currentOsFilter);
      });
    }

    // Restore view mode button state
    if (viewModeButtons.length) {
      viewModeButtons.forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.viewMode === currentViewMode);
      });
    }

    // Render the active section
    renderSection(activeSection, "");
    updateTabCounts();
  }, 0);
};

// Initialize reference sections on page load
initReferenceSections();
