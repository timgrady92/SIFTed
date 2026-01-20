// ==============================================
// GUIDES SIDEBAR - Standalone sidebar for all pages
// ==============================================

// Guide data for sidebar - full content from main guides page
const sidebarGuidesData = {
  hypothesis: [
    {
      title: "I think a phishing email led to compromise",
      description: "Trace the chain from email delivery to payload execution.",
      category: "execution",
      keywords: "phishing email attachment macro office document initial access outlook spam malicious link",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Framing</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">The hypothesis</div>
            <p class="guide-detail-text">A user may have received a phishing email and interacted with a malicious attachment or link, leading to code execution. Your goal is to establish the chain from email delivery through user interaction to payload execution.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Key questions</div>
            <ul class="guide-detail-list">
              <li>Did the user open a suspicious attachment or click a link near the suspected timeframe?</li>
              <li>Was code execution triggered by the interaction (macro, script, executable)?</li>
              <li>What is the timeline from email arrival to first signs of compromise?</li>
              <li>Could this be a legitimate document or a false positive from security tooling?</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Evidence</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Email and delivery artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="browser">Browser history</span> may show webmail access or clicked links from the email.</li>
              <li><span class="artifact-link" data-artifact="recentdocs">RecentDocs</span> and <span class="artifact-link" data-artifact="lnk">LNK files</span> may reveal recently opened suspicious documents.</li>
              <li><span class="artifact-link" data-artifact="outlook">Outlook attachment cache</span> or temp files in the user profile may contain the payload.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Execution artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="prefetch">Prefetch</span> may show Office apps, wscript.exe, powershell.exe, or cmd.exe execution times.</li>
              <li><span class="artifact-link" data-artifact="powershell">PowerShell logs</span> may contain encoded commands or suspicious script blocks.</li>
              <li><span class="artifact-link" data-artifact="eventlogs">Event logs</span> (4688) may reveal child processes spawned by Office applications.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">File artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="ads">Zone.Identifier</span> may prove the file was downloaded from the internet.</li>
              <li><span class="artifact-link" data-artifact="mft">$MFT</span> may show document creation time and location.</li>
              <li><span class="artifact-link" data-artifact="jumplists">Jump Lists</span> for Office apps may show the opened document.</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Analysis</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Corroboration</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="defender">Windows Defender</span> detections around the same timeframe.</li>
              <li>Parent-child process relationships linking Office to script interpreters.</li>
              <li>Network connections initiated shortly after document open.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Pitfalls</div>
            <ul class="guide-detail-list">
              <li>The email itself may be deleted—focus on artifacts of interaction, not the email.</li>
              <li>Macro-enabled documents are not inherently malicious; many are legitimate.</li>
              <li>Timestamp gaps between email tools can create misleading timelines.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Limitations</div>
            <ul class="guide-detail-list">
              <li>Email content and headers may not be available without mail server access.</li>
              <li>Opening a document does not prove a payload executed successfully.</li>
              <li>Webmail-based phishing may leave fewer local artifacts than desktop clients.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">When to stop</div>
            <p class="guide-detail-text">If the chain from email to execution is established, pivot to post-exploitation analysis. If the user opened the document but no execution occurred, the attack may have failed. If no interaction artifacts exist, reconsider the delivery vector.</p>
          </div>
        </div>
      `
    },
    {
      title: "I think data was exfiltrated",
      description: "Investigate staging, archiving, and data transfer activity.",
      category: "exfil",
      keywords: "data exfiltration staging theft usb cloud upload archive zip rar compression transfer leak",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Framing</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">The hypothesis</div>
            <p class="guide-detail-text">Sensitive data may have been collected, staged, and transferred out of the environment. Your goal is to identify evidence of data collection, staging or archiving activity, and the transfer mechanism used.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Key questions</div>
            <ul class="guide-detail-list">
              <li>Was data collected or staged in unusual locations or archive files?</li>
              <li>What transfer mechanism was used—USB, cloud storage, network, or email?</li>
              <li>Does the volume or type of data suggest targeted collection or bulk theft?</li>
              <li>Could this be legitimate backup, file sharing, or work-from-home activity?</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Evidence</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Staging and archiving artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="prefetch">Prefetch</span> may show execution of archiving tools (7z.exe, rar.exe, zip utilities).</li>
              <li><span class="artifact-link" data-artifact="mft">$MFT</span> may reveal recently created archives in temp or user folders.</li>
              <li><span class="artifact-link" data-artifact="shellbags">Shellbags</span> may indicate browsing of sensitive directories.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Transfer artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="usb">USB device history</span> may show removable media connections near the timeframe.</li>
              <li><span class="artifact-link" data-artifact="browser">Browser history</span> may reveal cloud storage uploads (Drive, Dropbox, WeTransfer).</li>
              <li><span class="artifact-link" data-artifact="srum">SRUM</span> may show network usage spikes by specific applications.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">File and access artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="lnk">LNK files</span> may point to archive files or staging folders.</li>
              <li><span class="artifact-link" data-artifact="recyclebin">Recycle Bin</span> may contain deleted archives or staging evidence.</li>
              <li><span class="artifact-link" data-artifact="recentdocs">RecentDocs</span> may show access to sensitive files before staging.</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Analysis</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Corroboration</div>
            <ul class="guide-detail-list">
              <li>Timeline alignment between file access, archive creation, and transfer activity.</li>
              <li>Network or proxy logs showing large outbound transfers.</li>
              <li>DLP alerts or email gateway logs for the same timeframe.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Pitfalls</div>
            <ul class="guide-detail-list">
              <li>Archive creation is routine—focus on what was archived and where it went.</li>
              <li>Cloud sync tools create continuous uploads that may mask exfiltration.</li>
              <li>USB insertion does not prove data was copied to it.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Limitations</div>
            <ul class="guide-detail-list">
              <li>Deleted staging artifacts may only be recoverable from Volume Shadow Copies.</li>
              <li>Encrypted archives hide their contents from forensic review.</li>
              <li>Network-based exfiltration may leave no endpoint artifacts.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">When to stop</div>
            <p class="guide-detail-text">If staging and transfer are confirmed, document the timeline and data involved. If staging exists but no transfer is found, the exfiltration may have been interrupted or used a channel not examined. If no staging evidence exists, reconsider whether data loss occurred through a different method.</p>
          </div>
        </div>
      `
    },
    {
      title: "I think there was lateral movement",
      description: "Investigate remote access between systems.",
      category: "lateral",
      keywords: "lateral movement rdp psexec wmi remote access pivot network smb admin share",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Framing</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">The hypothesis</div>
            <p class="guide-detail-text">An attacker may have moved from one system to another within the environment using remote access techniques. Your goal is to identify evidence of inbound or outbound remote connections and determine whether they were authorized.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Key questions</div>
            <ul class="guide-detail-list">
              <li>Was this host accessed remotely from another internal system?</li>
              <li>Did this host initiate connections to other internal systems?</li>
              <li>What technique was used—RDP, PsExec, WMI, SMB, or other?</li>
              <li>Could this be legitimate administrative activity or IT operations?</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Evidence</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Inbound access (this host was targeted)</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="eventlogs">Event logs</span> 4624 Type 3 (network) and Type 10 (RDP) may show source IPs and accounts.</li>
              <li><span class="artifact-link" data-artifact="eventlogs">Event logs</span> 7045 (service install) or 4698 (task creation) may indicate remote execution.</li>
              <li><span class="artifact-link" data-artifact="prefetch">Prefetch</span> may show PsExec, WMIC, or remote admin tool execution.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Outbound access (this host was the source)</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="rdp">RDP artifacts</span> in the registry may show outbound connection history.</li>
              <li><span class="artifact-link" data-artifact="shellbags">Shellbags</span> may reveal network share browsing via UNC paths.</li>
              <li><span class="artifact-link" data-artifact="lnk">LNK files</span> may point to files on remote systems.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Execution artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="bam">BAM/DAM</span> may show remote tool execution times.</li>
              <li><span class="artifact-link" data-artifact="wmi">WMI subscriptions</span> may indicate remote execution persistence.</li>
              <li><span class="artifact-link" data-artifact="powershell">PowerShell logs</span> may contain remote execution commands (Invoke-Command, Enter-PSSession).</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Analysis</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Corroboration</div>
            <ul class="guide-detail-list">
              <li>Matching timestamps on source and destination systems for the same connection.</li>
              <li>Firewall or network logs showing connections between internal hosts.</li>
              <li>Credential theft artifacts preceding the lateral movement activity.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Pitfalls</div>
            <ul class="guide-detail-list">
              <li>Type 3 logons are extremely common—filter by source IP and account context.</li>
              <li>IT tools like SCCM and monitoring agents generate legitimate remote connections.</li>
              <li>Single-host analysis misses half the story—correlate across source and destination.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Limitations</div>
            <ul class="guide-detail-list">
              <li>Network logons may not identify the technique used (RDP vs SMB vs WMI).</li>
              <li>Outbound connection artifacts require the source host to be analyzed.</li>
              <li>Pass-the-hash and token manipulation leave fewer artifacts than password-based access.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">When to stop</div>
            <p class="guide-detail-text">If lateral movement is confirmed, map the full path across systems and identify the technique. If only one direction is visible, obtain artifacts from the other host. If no remote access evidence exists, reconsider whether movement occurred via a different method or time window.</p>
          </div>
        </div>
      `
    },
    {
      title: "I think the user downloaded something malicious",
      description: "Trace from download source to disk to execution.",
      category: "execution",
      keywords: "malicious download drive-by browser exploit kit dropper initial access download zone identifier motw",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Framing</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">The hypothesis</div>
            <p class="guide-detail-text">A user may have downloaded a malicious file from the internet and executed it. Your goal is to establish the chain from download source through file creation to execution and any subsequent activity.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Key questions</div>
            <ul class="guide-detail-list">
              <li>What was the source URL and how did the user reach it?</li>
              <li>Was the downloaded file executed, and by what method (user action or automatic)?</li>
              <li>Did security controls (Defender, SmartScreen) intervene or alert?</li>
              <li>Could this be a legitimate download that triggered a false positive?</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Evidence</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Download artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="browser">Browser history</span> may show the URL and referring page.</li>
              <li><span class="artifact-link" data-artifact="browser">Browser downloads</span> database contains file name, URL, and timestamp.</li>
              <li><span class="artifact-link" data-artifact="ads">Zone.Identifier ADS</span> proves internet origin and may contain the source URL.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">File system artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="mft">$MFT</span> shows file creation time in Downloads or temp folders.</li>
              <li><span class="artifact-link" data-artifact="lnk">LNK files</span> may be created when the file is opened.</li>
              <li><span class="artifact-link" data-artifact="recentdocs">RecentDocs</span> may show the file was accessed.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Execution artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="prefetch">Prefetch</span> confirms execution with timestamp and run count.</li>
              <li><span class="artifact-link" data-artifact="userassist">UserAssist</span> shows GUI-based execution by the user.</li>
              <li><span class="artifact-link" data-artifact="amcache">Amcache</span> records execution with file hash and path.</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Analysis</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Corroboration</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="defender">Windows Defender</span> or AV logs for detection events.</li>
              <li>SmartScreen events in Application event log.</li>
              <li>Network connections initiated by the downloaded file after execution.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Pitfalls</div>
            <ul class="guide-detail-list">
              <li>Zone.Identifier may be stripped if the file was extracted from an archive.</li>
              <li>Browser history can be cleared; check multiple browsers.</li>
              <li>File may have been renamed or moved after download.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">When to stop</div>
            <p class="guide-detail-text">If download and execution are confirmed, pivot to analyzing what the malware did post-execution. If downloaded but not executed, the threat may have been blocked. If no download evidence exists, consider other delivery mechanisms.</p>
          </div>
        </div>
      `
    },
    {
      title: "I think credentials were stolen",
      description: "Investigate credential theft techniques and artifacts.",
      category: "credential",
      keywords: "credential theft mimikatz lsass dump password hash ntlm kerberos ticket golden silver",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Framing</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">The hypothesis</div>
            <p class="guide-detail-text">An attacker may have harvested credentials from this system using tools like Mimikatz, credential dumping, or keylogging. Your goal is to identify evidence of credential access and determine what accounts may be compromised.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Key questions</div>
            <ul class="guide-detail-list">
              <li>Were credential dumping tools executed on this system?</li>
              <li>Was LSASS accessed or dumped?</li>
              <li>Were any suspicious authentications observed after the suspected theft?</li>
              <li>What accounts were logged in and potentially exposed?</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Evidence</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Tool execution artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="prefetch">Prefetch</span> may show mimikatz.exe, procdump.exe, or similar tools.</li>
              <li><span class="artifact-link" data-artifact="amcache">Amcache</span> may contain hashes of credential theft tools.</li>
              <li><span class="artifact-link" data-artifact="eventlogs">Event logs</span> 4688 may show suspicious process command lines.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">LSASS access artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="eventlogs">Event logs</span> 4656/4663 may show LSASS handle requests (if object access auditing enabled).</li>
              <li>Sysmon Event 10 (ProcessAccess) targeting lsass.exe.</li>
              <li>Windows Defender alerts for credential theft behavior.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Post-theft indicators</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="eventlogs">Event logs</span> 4624 Type 9 (NewCredentials) may indicate pass-the-hash.</li>
              <li>Unusual Kerberos ticket requests (4768, 4769) for sensitive accounts.</li>
              <li>Authentication from unexpected sources for privileged accounts.</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Analysis</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Corroboration</div>
            <ul class="guide-detail-list">
              <li>Memory dumps or suspicious .dmp files in temp directories.</li>
              <li>PowerShell logs showing credential-related modules or commands.</li>
              <li>Subsequent lateral movement using the stolen credentials.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Pitfalls</div>
            <ul class="guide-detail-list">
              <li>Credential theft tools are often renamed or packed to avoid detection.</li>
              <li>LSASS access is legitimate for some system processes—context matters.</li>
              <li>In-memory credential theft may leave minimal disk artifacts.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">When to stop</div>
            <p class="guide-detail-text">If credential theft is confirmed, identify all potentially compromised accounts and recommend password resets. Pivot to tracking lateral movement using those credentials. If no theft evidence exists but suspicious auth is observed, investigate the authentication source.</p>
          </div>
        </div>
      `
    },
    {
      title: "I think malware established persistence",
      description: "Identify mechanisms used to survive reboots.",
      category: "persistence",
      keywords: "persistence autorun startup registry scheduled task service wmi subscription run key",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Framing</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">The hypothesis</div>
            <p class="guide-detail-text">Malware may have established persistence mechanisms to survive reboots and maintain access. Your goal is to identify all persistence locations and understand how they were created.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Key questions</div>
            <ul class="guide-detail-list">
              <li>What persistence mechanisms are present and when were they created?</li>
              <li>What binary or script does each persistence mechanism execute?</li>
              <li>Are there multiple layers of persistence for redundancy?</li>
              <li>Could any of these be legitimate software installations?</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Evidence</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Registry persistence</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="runkeys">Run/RunOnce keys</span> in HKLM and HKCU for auto-start programs.</li>
              <li>Winlogon Shell, Userinit, and Notify registry values.</li>
              <li>AppInit_DLLs and other DLL injection points.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Scheduled tasks and services</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="scheduledtasks">Scheduled Tasks</span> XML files and registry entries.</li>
              <li><span class="artifact-link" data-artifact="services">Services</span> registry entries for new or modified services.</li>
              <li><span class="artifact-link" data-artifact="eventlogs">Event logs</span> 7045 (service install) and 4698 (task created).</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Other persistence locations</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="startupfolder">Startup folder</span> contents for user and system.</li>
              <li><span class="artifact-link" data-artifact="wmi">WMI subscriptions</span> for event-based persistence.</li>
              <li><span class="artifact-link" data-artifact="bits">BITS jobs</span> for download-based persistence.</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Analysis</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Corroboration</div>
            <ul class="guide-detail-list">
              <li>File creation timestamps for referenced binaries.</li>
              <li>Process execution evidence from Prefetch or Amcache.</li>
              <li>Network connections from persistent processes.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Pitfalls</div>
            <ul class="guide-detail-list">
              <li>Many legitimate programs use Run keys and scheduled tasks.</li>
              <li>Persistence may reference legitimate system binaries (LOLBins).</li>
              <li>Some persistence is only visible with elevated privileges.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">When to stop</div>
            <p class="guide-detail-text">Document all persistence mechanisms found and the binaries they execute. If persistence is confirmed, analyze the payload and its capabilities. If no persistence is found but execution occurred, the attack may be non-persistent or using an overlooked mechanism.</p>
          </div>
        </div>
      `
    },
    {
      title: "I think PowerShell was used maliciously",
      description: "Investigate script execution and encoded commands.",
      category: "execution",
      keywords: "powershell script encoded base64 bypass execution policy iex downloadstring",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Framing</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">The hypothesis</div>
            <p class="guide-detail-text">PowerShell may have been used to execute malicious scripts, download payloads, or perform post-exploitation activities. Your goal is to reconstruct what PowerShell commands were executed and their impact.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Key questions</div>
            <ul class="guide-detail-list">
              <li>What PowerShell commands or scripts were executed?</li>
              <li>Were encoded commands used to obfuscate activity?</li>
              <li>Did PowerShell download or execute remote content?</li>
              <li>What was the parent process that launched PowerShell?</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Evidence</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">PowerShell logs</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="powershell">PowerShell Operational log</span> (4103, 4104) contains script block logging.</li>
              <li>PowerShell transcript files if transcription was enabled.</li>
              <li>Console history file: ConsoleHost_history.txt in user profile.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Execution artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="prefetch">Prefetch</span> for powershell.exe, pwsh.exe, or PowerShell ISE.</li>
              <li><span class="artifact-link" data-artifact="eventlogs">Event logs</span> 4688 may show PowerShell command line arguments.</li>
              <li>Sysmon Event 1 with full command line if installed.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Indicators to look for</div>
            <ul class="guide-detail-list">
              <li>-EncodedCommand or -enc parameter (Base64 encoded commands).</li>
              <li>-ExecutionPolicy Bypass or -ep bypass flags.</li>
              <li>IEX, Invoke-Expression, DownloadString, DownloadFile patterns.</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Analysis</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Corroboration</div>
            <ul class="guide-detail-list">
              <li>Network connections from PowerShell processes.</li>
              <li>Files created or modified during script execution.</li>
              <li>Parent process context (Office, WMI, Scheduled Task).</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Pitfalls</div>
            <ul class="guide-detail-list">
              <li>Script block logging must be enabled to capture full scripts.</li>
              <li>Encoded commands require Base64 decoding for analysis.</li>
              <li>PowerShell Constrained Language Mode may limit attacker capabilities.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">When to stop</div>
            <p class="guide-detail-text">If malicious PowerShell activity is confirmed, decode and document all commands executed. Identify what the script downloaded, created, or modified. Pivot to analyzing downloaded payloads or established persistence.</p>
          </div>
        </div>
      `
    },
    {
      title: "I think a USB device was used for data theft",
      description: "Investigate removable media activity and file transfers.",
      category: "exfil",
      keywords: "usb removable media data theft copy transfer external drive thumb flash",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Framing</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">The hypothesis</div>
            <p class="guide-detail-text">A USB storage device may have been used to copy sensitive data from this system. Your goal is to identify what devices were connected, when, and what evidence suggests data was transferred.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Key questions</div>
            <ul class="guide-detail-list">
              <li>What USB storage devices were connected and when?</li>
              <li>What drive letter was assigned to the device?</li>
              <li>Is there evidence of files being copied to the device?</li>
              <li>Was this an authorized device or unknown to the organization?</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Evidence</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">USB device identification</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="usb">USB device registry keys</span> (USBSTOR, USB) contain device serial numbers.</li>
              <li>SYSTEM\\MountedDevices shows volume GUIDs and drive letters.</li>
              <li>setupapi.dev.log contains device installation timestamps.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">User interaction artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="shellbags">Shellbags</span> may show folder browsing on the USB drive.</li>
              <li><span class="artifact-link" data-artifact="lnk">LNK files</span> may reference files on the removable volume.</li>
              <li><span class="artifact-link" data-artifact="jumplists">Jump Lists</span> may show files opened from the USB.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">File transfer indicators</div>
            <ul class="guide-detail-list">
              <li>Volume serial numbers in LNK files matching the USB device.</li>
              <li><span class="artifact-link" data-artifact="recentdocs">RecentDocs</span> showing file access patterns.</li>
              <li>File copy utilities in <span class="artifact-link" data-artifact="prefetch">Prefetch</span> (robocopy, xcopy).</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Analysis</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Corroboration</div>
            <ul class="guide-detail-list">
              <li>Correlation between USB insertion time and file access activity.</li>
              <li>Physical security logs or camera footage for device insertion.</li>
              <li>DLP alerts for removable media transfers.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Pitfalls</div>
            <ul class="guide-detail-list">
              <li>USB insertion proves connection, not data transfer.</li>
              <li>Multiple devices may share the same vendor/product ID.</li>
              <li>Some users routinely use USB devices for legitimate purposes.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">When to stop</div>
            <p class="guide-detail-text">If USB connection and data transfer are confirmed, document the device details, timeline, and files involved. If the device itself can be obtained, image it for evidence. If connection exists but transfer is unconfirmed, the evidence may be circumstantial.</p>
          </div>
        </div>
      `
    },
    {
      title: "I think ransomware executed on this system",
      description: "Investigate encryption activity and ransom artifacts.",
      category: "malware",
      keywords: "ransomware encryption ransom note bitcoin crypto locker files encrypted extension",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Framing</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">The hypothesis</div>
            <p class="guide-detail-text">Ransomware may have executed on this system, encrypting files and leaving ransom demands. Your goal is to confirm the ransomware family, identify the initial access vector, and determine the scope of impact.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Key questions</div>
            <ul class="guide-detail-list">
              <li>What ransomware family is involved (based on extension, ransom note)?</li>
              <li>How did the ransomware arrive on the system?</li>
              <li>What is the extent of encrypted files?</li>
              <li>Did the ransomware spread to other systems?</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Evidence</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Ransomware indicators</div>
            <ul class="guide-detail-list">
              <li>Ransom notes (README.txt, DECRYPT_INSTRUCTIONS, etc.) in affected folders.</li>
              <li>Files with unusual extensions (.encrypted, .locked, family-specific).</li>
              <li><span class="artifact-link" data-artifact="mft">$MFT</span> showing mass file modification times.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Execution artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="prefetch">Prefetch</span> for the ransomware executable.</li>
              <li><span class="artifact-link" data-artifact="amcache">Amcache</span> with file hash for malware identification.</li>
              <li><span class="artifact-link" data-artifact="eventlogs">Event logs</span> showing process execution and service changes.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Anti-recovery activity</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="vss">Volume Shadow Copy</span> deletion (vssadmin, wmic shadowcopy).</li>
              <li>Backup service termination commands.</li>
              <li>Security tool disabling attempts.</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Analysis</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Corroboration</div>
            <ul class="guide-detail-list">
              <li>Hash lookup on VirusTotal or malware databases.</li>
              <li>Ransom note text search for known ransomware families.</li>
              <li>Network connections to C2 infrastructure or payment sites.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Pitfalls</div>
            <ul class="guide-detail-list">
              <li>Some ransomware self-deletes after encryption.</li>
              <li>Ransomware may have arrived days before executing.</li>
              <li>Multiple systems may be affected—scope the incident.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">When to stop</div>
            <p class="guide-detail-text">Once the ransomware family and initial access vector are identified, focus on containment and recovery. Document the timeline and affected systems. Check for data exfiltration before encryption (double extortion).</p>
          </div>
        </div>
      `
    },
    {
      title: "I think this account was compromised",
      description: "Investigate account activity and authentication anomalies.",
      category: "credential",
      keywords: "account compromise authentication logon brute force password spray mfa bypass",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Framing</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">The hypothesis</div>
            <p class="guide-detail-text">A user account may have been compromised and used by an attacker. Your goal is to identify unauthorized access patterns and determine how the account was compromised.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Key questions</div>
            <ul class="guide-detail-list">
              <li>What unusual authentication activity is associated with this account?</li>
              <li>Were logins from unexpected locations, times, or devices?</li>
              <li>How were the credentials obtained (phishing, spray, theft)?</li>
              <li>What did the attacker do while using the account?</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Evidence</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Authentication artifacts</div>
            <ul class="guide-detail-list">
              <li><span class="artifact-link" data-artifact="eventlogs">Event logs</span> 4624/4625 for successful and failed logons.</li>
              <li>Logon type analysis (interactive, network, RDP, service).</li>
              <li>Source IP addresses and workstation names.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Anomaly indicators</div>
            <ul class="guide-detail-list">
              <li>Logins outside normal working hours or from unusual locations.</li>
              <li>Simultaneous sessions from geographically distant locations.</li>
              <li>Failed login attempts followed by success (credential guessing).</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Post-compromise activity</div>
            <ul class="guide-detail-list">
              <li>Email forwarding rules or mailbox access (if email account).</li>
              <li>File access or data download patterns.</li>
              <li>Privilege escalation attempts or group membership changes.</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Analysis</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Corroboration</div>
            <ul class="guide-detail-list">
              <li>VPN logs showing source IPs and connection times.</li>
              <li>Cloud service (O365, Azure AD) sign-in logs.</li>
              <li>User interview to confirm or deny activity.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Pitfalls</div>
            <ul class="guide-detail-list">
              <li>VPNs and proxies can mask attacker origin.</li>
              <li>Legitimate travel or remote work may appear suspicious.</li>
              <li>Shared accounts complicate attribution.</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">When to stop</div>
            <p class="guide-detail-text">If compromise is confirmed, reset credentials and review all account activity. Identify the compromise method to prevent recurrence. If activity appears legitimate, document the investigation and close.</p>
          </div>
        </div>
      `
    }
  ],
  artifact: [
    {
      title: "What can Prefetch tell me?",
      description: "Understand execution evidence from Prefetch files.",
      category: "execution",
      keywords: "prefetch pf execution run count timestamp program launch",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Overview</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What it is</div>
            <p class="guide-detail-text">Windows Prefetch files (.pf) are created when executables run, storing metadata to speed up subsequent launches. They provide strong evidence of program execution with timestamps and run counts.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Location</div>
            <p class="guide-detail-text">C:\\Windows\\Prefetch\\</p>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Key Information</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What you can determine</div>
            <ul class="guide-detail-list">
              <li>Name of executable that ran</li>
              <li>Last run time (up to 8 timestamps on Win8+)</li>
              <li>Run count (number of executions)</li>
              <li>Files and directories referenced during execution</li>
              <li>Volume information where the executable resided</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Investigative value</div>
            <ul class="guide-detail-list">
              <li>Proves a program executed, even if later deleted</li>
              <li>Establishes timeline with execution timestamps</li>
              <li>Referenced files can reveal malware behavior</li>
              <li>Run count indicates frequency of use</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Limitations</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Things to know</div>
            <ul class="guide-detail-list">
              <li>May be disabled on SSDs or by Group Policy</li>
              <li>Limited to 1024 files; old entries get overwritten</li>
              <li>Does not prove WHO ran the program</li>
              <li>Timestamps are last run, not first run</li>
              <li>Server editions have Prefetch disabled by default</li>
            </ul>
          </div>
        </div>
      `
    },
    {
      title: "What can Event Logs reveal?",
      description: "Key Windows event IDs for forensic investigations.",
      category: "timeline",
      keywords: "event log evtx security system application logon process service",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Overview</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What they are</div>
            <p class="guide-detail-text">Windows Event Logs are structured records of system, security, and application events. They provide the authoritative timeline for authentication, process execution, and system changes.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Location</div>
            <p class="guide-detail-text">C:\\Windows\\System32\\winevt\\Logs\\</p>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Critical Event IDs</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Authentication (Security.evtx)</div>
            <ul class="guide-detail-list">
              <li>4624 - Successful logon (check LogonType)</li>
              <li>4625 - Failed logon attempt</li>
              <li>4648 - Explicit credential logon (runas)</li>
              <li>4672 - Special privileges assigned (admin logon)</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Process and Services (Security/System)</div>
            <ul class="guide-detail-list">
              <li>4688 - Process creation (requires audit policy)</li>
              <li>7045 - Service installed</li>
              <li>4698 - Scheduled task created</li>
              <li>1102 - Audit log cleared (tampering indicator)</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Limitations</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Things to know</div>
            <ul class="guide-detail-list">
              <li>Many events require audit policies to be enabled</li>
              <li>Log retention is limited; old events get overwritten</li>
              <li>Attackers may clear logs (watch for 1102)</li>
              <li>Command line logging requires explicit configuration</li>
            </ul>
          </div>
        </div>
      `
    },
    {
      title: "What can the MFT show me?",
      description: "File system timeline and metadata from $MFT.",
      category: "filesystem",
      keywords: "mft ntfs file creation modification access timestamp metadata",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Overview</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What it is</div>
            <p class="guide-detail-text">The Master File Table ($MFT) is the NTFS file system database containing metadata for every file and directory on a volume, including timestamps, sizes, and attributes.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Location</div>
            <p class="guide-detail-text">Root of NTFS volume (requires raw disk access or forensic tools)</p>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Key Information</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Timestamps (MACB)</div>
            <ul class="guide-detail-list">
              <li>Modified - Content last changed</li>
              <li>Accessed - Last read (often disabled)</li>
              <li>Changed ($MFT) - Metadata last modified</li>
              <li>Born - File creation time</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Investigative value</div>
            <ul class="guide-detail-list">
              <li>Timeline of file system activity</li>
              <li>Evidence of deleted files (if not overwritten)</li>
              <li>File sizes and directory structure</li>
              <li>Detection of timestamp manipulation (SI vs FN)</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Limitations</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Things to know</div>
            <ul class="guide-detail-list">
              <li>Access time updates often disabled for performance</li>
              <li>Timestamps can be manipulated by attackers</li>
              <li>Deleted file entries get reused over time</li>
              <li>Requires forensic tools to parse properly</li>
            </ul>
          </div>
        </div>
      `
    },
    {
      title: "What can Registry keys reveal?",
      description: "User activity, system config, and persistence in the Registry.",
      category: "persistence",
      keywords: "registry hive ntuser system software sam persistence run key mru",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Overview</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What it is</div>
            <p class="guide-detail-text">The Windows Registry is a hierarchical database storing system configuration, user preferences, and application settings. It's a goldmine for forensic artifacts.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Key hive files</div>
            <ul class="guide-detail-list">
              <li>NTUSER.DAT - Per-user settings and activity</li>
              <li>SYSTEM - System configuration, services, USB devices</li>
              <li>SOFTWARE - Installed programs, Run keys</li>
              <li>SAM - Local user account information</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Forensic Value</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">User activity</div>
            <ul class="guide-detail-list">
              <li>RecentDocs - Recently opened files by extension</li>
              <li>TypedPaths - Explorer address bar entries</li>
              <li>UserAssist - GUI program execution</li>
              <li>Shellbags - Folder browsing history</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">System artifacts</div>
            <ul class="guide-detail-list">
              <li>Run/RunOnce keys - Auto-start programs</li>
              <li>Services - Installed services and drivers</li>
              <li>USBSTOR - USB device history</li>
              <li>AppCompatCache - Program execution evidence</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Limitations</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Things to know</div>
            <ul class="guide-detail-list">
              <li>Timestamps are key last-modified, not value-modified</li>
              <li>Some artifacts have limited retention</li>
              <li>Values can be deleted or modified by attackers</li>
              <li>Requires offline analysis for locked hives</li>
            </ul>
          </div>
        </div>
      `
    },
    {
      title: "What can Browser History show?",
      description: "Web activity, downloads, and user behavior from browsers.",
      category: "browser",
      keywords: "browser history chrome firefox edge safari downloads search cache cookies",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Overview</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What it contains</div>
            <p class="guide-detail-text">Browser artifacts include visited URLs, search queries, downloads, cached files, cookies, and form data. Each browser stores this in SQLite databases.</p>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Key Artifacts</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">History and activity</div>
            <ul class="guide-detail-list">
              <li>URLs visited with timestamps and visit counts</li>
              <li>Search queries entered in search engines</li>
              <li>Download history with source URLs and file paths</li>
              <li>Form autofill data</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Investigative value</div>
            <ul class="guide-detail-list">
              <li>Trace malware download sources</li>
              <li>Identify phishing or watering hole visits</li>
              <li>Establish user activity timeline</li>
              <li>Find cloud storage and webmail access</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Limitations</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Things to know</div>
            <ul class="guide-detail-list">
              <li>Private/incognito mode leaves minimal artifacts</li>
              <li>History can be easily cleared by users</li>
              <li>Multiple browser profiles may exist</li>
              <li>HTTPS URLs visible but not content</li>
            </ul>
          </div>
        </div>
      `
    },
    {
      title: "What can LNK files tell me?",
      description: "File and folder access evidence from shortcut files.",
      category: "fileaccess",
      keywords: "lnk shortcut recent file access path volume serial target",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Overview</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What they are</div>
            <p class="guide-detail-text">LNK files (Windows shortcuts) are created when users open files or folders. They contain rich metadata about the target, even if the original file no longer exists.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Location</div>
            <p class="guide-detail-text">C:\\Users\\&lt;user&gt;\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\</p>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Key Information</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Embedded metadata</div>
            <ul class="guide-detail-list">
              <li>Target file path (original location)</li>
              <li>Target file timestamps (MAC times at access)</li>
              <li>Volume serial number and type</li>
              <li>Network share paths (if applicable)</li>
              <li>Machine ID where file was accessed</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Investigative value</div>
            <ul class="guide-detail-list">
              <li>Proves user opened specific files</li>
              <li>Links files to removable media via volume serial</li>
              <li>Shows access to network shares</li>
              <li>Evidence persists after file deletion</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Limitations</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Things to know</div>
            <ul class="guide-detail-list">
              <li>LNK creation depends on how file was opened</li>
              <li>May not be created for all file access methods</li>
              <li>Timestamps are from time of access, not current</li>
            </ul>
          </div>
        </div>
      `
    },
    {
      title: "What can Jump Lists reveal?",
      description: "Application-specific file access and recent documents.",
      category: "fileaccess",
      keywords: "jump list automatic custom destination recent files application",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Overview</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What they are</div>
            <p class="guide-detail-text">Jump Lists provide quick access to recently used files for specific applications. They contain embedded LNK data showing what files were opened by which programs.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Location</div>
            <ul class="guide-detail-list">
              <li>AutomaticDestinations - System-created lists</li>
              <li>CustomDestinations - Application-created lists</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Key Information</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What you can determine</div>
            <ul class="guide-detail-list">
              <li>Files opened by specific applications</li>
              <li>Application usage timeline</li>
              <li>Full file paths and metadata (like LNK files)</li>
              <li>Evidence linking applications to documents</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Limitations</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Things to know</div>
            <ul class="guide-detail-list">
              <li>Not all applications create Jump Lists</li>
              <li>Lists have limited entry counts</li>
              <li>AppID mapping needed to identify applications</li>
            </ul>
          </div>
        </div>
      `
    },
    {
      title: "What can Shellbags show?",
      description: "Folder browsing history and deleted folder evidence.",
      category: "fileaccess",
      keywords: "shellbags folder browsing explorer deleted directory path",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Overview</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What they are</div>
            <p class="guide-detail-text">Shellbags store Explorer folder view settings (size, position, view mode) and persist evidence of folder access even after folders are deleted.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Location</div>
            <p class="guide-detail-text">NTUSER.DAT and UsrClass.dat registry hives</p>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Key Information</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What you can determine</div>
            <ul class="guide-detail-list">
              <li>Folders browsed by the user</li>
              <li>Deleted folder paths that were once accessed</li>
              <li>Removable media and network share access</li>
              <li>Timestamps of folder access</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Investigative value</div>
            <ul class="guide-detail-list">
              <li>Proves user knowledge of folder locations</li>
              <li>Evidence of USB drive folder browsing</li>
              <li>Shows network share reconnaissance</li>
              <li>Persists after folder deletion</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Limitations</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Things to know</div>
            <ul class="guide-detail-list">
              <li>Only records Explorer GUI browsing</li>
              <li>Command-line access not captured</li>
              <li>Timestamps may reflect last settings change, not access</li>
            </ul>
          </div>
        </div>
      `
    },
    {
      title: "What can SRUM data provide?",
      description: "Application resource usage and network activity over time.",
      category: "network",
      keywords: "srum resource usage network bytes application execution time",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Overview</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What it is</div>
            <p class="guide-detail-text">System Resource Usage Monitor (SRUM) tracks application resource consumption including network bytes, CPU time, and energy usage over 30-60 days.</p>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Location</div>
            <p class="guide-detail-text">C:\\Windows\\System32\\sru\\SRUDB.dat</p>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Key Information</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What you can determine</div>
            <ul class="guide-detail-list">
              <li>Applications that ran and when</li>
              <li>Network bytes sent and received per application</li>
              <li>CPU and memory usage over time</li>
              <li>User account associated with activity</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Investigative value</div>
            <ul class="guide-detail-list">
              <li>Identify data exfiltration by network volume</li>
              <li>Prove application execution over time</li>
              <li>Correlate network activity with specific programs</li>
              <li>30-60 day historical data</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Limitations</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Things to know</div>
            <ul class="guide-detail-list">
              <li>Only available on Windows 8+</li>
              <li>Network data is aggregate, not connection-specific</li>
              <li>Requires ESE database parsing tools</li>
            </ul>
          </div>
        </div>
      `
    },
    {
      title: "What can USB artifacts reveal?",
      description: "Device connections, serial numbers, and mount history.",
      category: "external",
      keywords: "usb device serial vendor product mount volume removable media",
      body: `
        <div class="guide-group">
          <div class="guide-group-header">Overview</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">What they track</div>
            <p class="guide-detail-text">Windows records extensive information about USB device connections in multiple registry locations and log files, including device identification and mount history.</p>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Key Information</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Device identification</div>
            <ul class="guide-detail-list">
              <li>Vendor and Product IDs</li>
              <li>Device serial number (unique identifier)</li>
              <li>Device friendly name</li>
              <li>First and last connection times</li>
            </ul>
          </div>
          <div class="guide-detail-section">
            <div class="guide-detail-label">Registry locations</div>
            <ul class="guide-detail-list">
              <li>SYSTEM\\CurrentControlSet\\Enum\\USBSTOR</li>
              <li>SYSTEM\\CurrentControlSet\\Enum\\USB</li>
              <li>SYSTEM\\MountedDevices</li>
              <li>SOFTWARE\\Microsoft\\Windows Portable Devices</li>
            </ul>
          </div>
        </div>
        <div class="guide-group">
          <div class="guide-group-header">Limitations</div>
          <div class="guide-detail-section">
            <div class="guide-detail-label warning">Things to know</div>
            <ul class="guide-detail-list">
              <li>Connection proves device was plugged in, not data transfer</li>
              <li>Some devices don't have unique serial numbers</li>
              <li>Registry entries persist after device removal</li>
              <li>Setupapi.dev.log provides additional timestamps</li>
            </ul>
          </div>
        </div>
      `
    }
  ]
};

// Format category label
const formatSidebarCategoryLabel = (value) => {
  if (!value) return "Guide";
  return value
    .split("-")
    .map((chunk) => chunk.charAt(0).toUpperCase() + chunk.slice(1))
    .join(" ");
};

// Escape HTML
const escapeSidebarHtml = (text) => {
  if (!text) return "";
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
};

// Initialize guides sidebar
const initGuidesSidebar = () => {
  const sidebar = document.querySelector('[data-guides-surface="sidebar"]');
  const toggleButtons = Array.from(document.querySelectorAll('[data-guides-toggle="sidebar"]'));
  const closeButton = sidebar?.querySelector("[data-guides-close]");

  if (!sidebar) return;

  const tabContainer = sidebar.querySelector("[data-guides-tabs]");
  const tabs = Array.from(sidebar.querySelectorAll("[data-guides-tab]"));
  const guidesList = sidebar.querySelector("[data-guides-list]");
  const searchInput = sidebar.querySelector("[data-guides-search]");
  const detailPane = sidebar.querySelector("[data-guides-detail]");
  const detailContent = sidebar.querySelector("[data-guides-detail-content]");
  const backButton = sidebar.querySelector("[data-guides-back]");
  const sidebarContent = sidebar.querySelector("[data-guides-content]");

  let activeTab = "hypothesis";

  // Open sidebar
  const openSidebar = () => {
    sidebar.classList.add("open");
    sidebar.setAttribute("aria-hidden", "false");
    document.body.classList.add("guides-open");
    if (searchInput) {
      setTimeout(() => searchInput.focus(), 100);
    }
  };

  // Close sidebar
  const closeSidebar = () => {
    sidebar.classList.remove("open");
    sidebar.setAttribute("aria-hidden", "true");
    document.body.classList.remove("guides-open");
  };

  // Get counts
  const getCounts = () => ({
    hypothesis: sidebarGuidesData.hypothesis.length,
    artifact: sidebarGuidesData.artifact.length
  });

  // Update tab counts
  const updateCounts = () => {
    const counts = getCounts();
    tabs.forEach((tab) => {
      const section = tab.dataset.guidesTab;
      const countEl = tab.querySelector("[data-guides-count]");
      if (countEl && counts[section] !== undefined) {
        countEl.textContent = counts[section];
      }
    });
  };

  // Build guide list
  const buildGuideList = (tabId, query = "") => {
    const lowerQuery = query.toLowerCase();
    const guides = sidebarGuidesData[tabId] || [];

    const filtered = guides.filter((guide) => {
      if (!query) return true;
      const searchText = `${guide.title} ${guide.description} ${guide.keywords} ${guide.category}`.toLowerCase();
      return searchText.includes(lowerQuery);
    });

    if (filtered.length === 0) {
      return '<p class="guides-sidebar-empty">No guides match your search.</p>';
    }

    return filtered.map((guide, index) => {
      const categoryLabel = formatSidebarCategoryLabel(guide.category);
      return `
        <button class="guides-sidebar-item" type="button" data-guide-index="${index}" data-guide-tab="${tabId}">
          <span class="guides-sidebar-icon" data-category="${guide.category}">${categoryLabel.charAt(0)}</span>
          <div class="guides-sidebar-item-content">
            <h4 class="guides-sidebar-item-title">${escapeSidebarHtml(guide.title)}</h4>
            <p class="guides-sidebar-item-desc">${escapeSidebarHtml(guide.description)}</p>
            <span class="guides-sidebar-item-category">${escapeSidebarHtml(categoryLabel)}</span>
          </div>
        </button>
      `;
    }).join("");
  };

  // Show guide detail within sidebar
  const showGuideDetail = (tabId, index) => {
    const guides = sidebarGuidesData[tabId] || [];
    const guide = guides[index];
    if (!guide || !detailPane || !detailContent) return;

    const categoryLabel = formatSidebarCategoryLabel(guide.category);

    detailContent.innerHTML = `
      <h3>${escapeSidebarHtml(guide.title)}</h3>
      <p class="guide-detail-helper">${escapeSidebarHtml(guide.description)}</p>
      <span class="guide-pill" data-category="${guide.category}">${escapeSidebarHtml(categoryLabel)}</span>
      <div class="guide-body-content">
        ${guide.body}
      </div>
    `;

    // Initialize artifact tooltips for the detail content
    if (typeof window.initArtifactTooltips === "function") {
      window.initArtifactTooltips(detailContent);
    }

    detailPane.hidden = false;
    detailPane.dataset.category = guide.category;
    if (sidebarContent) sidebarContent.style.display = "none";
  };

  // Hide guide detail and return to list
  const hideGuideDetail = () => {
    if (detailPane) detailPane.hidden = true;
    if (sidebarContent) sidebarContent.style.display = "";
  };

  // Render section
  const renderSection = (tabId, query = "") => {
    if (!guidesList) return;

    // Hide detail pane when rendering list
    hideGuideDetail();

    const html = buildGuideList(tabId, query);
    guidesList.innerHTML = html;

    // Attach click handlers
    guidesList.querySelectorAll(".guides-sidebar-item").forEach((item) => {
      item.addEventListener("click", () => {
        const guideTab = item.dataset.guideTab;
        const guideIndex = parseInt(item.dataset.guideIndex, 10);
        showGuideDetail(guideTab, guideIndex);
      });
    });
  };

  // Tab click handlers
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const tabId = tab.dataset.guidesTab;
      if (tabId === activeTab) return;

      tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      activeTab = tabId;

      renderSection(tabId, searchInput?.value || "");
    });
  });

  // Search handler
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      renderSection(activeTab, searchInput.value);
    });
  }

  // Back button handler
  if (backButton) {
    backButton.addEventListener("click", hideGuideDetail);
  }

  // Toggle button handlers
  toggleButtons.forEach((btn) => {
    btn.addEventListener("click", openSidebar);
  });

  // Close button handler
  if (closeButton) {
    closeButton.addEventListener("click", closeSidebar);
  }

  // Escape key handler
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && sidebar.classList.contains("open")) {
      closeSidebar();
    }
  });

  // Initialize
  updateCounts();
  renderSection("hypothesis", "");
};

// Initialize when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initGuidesSidebar);
} else {
  initGuidesSidebar();
}
