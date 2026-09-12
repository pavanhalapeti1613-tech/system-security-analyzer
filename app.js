/**
 * ============================================================================
 * SECURECHECK – WINDOWS SECURITY HEALTH ANALYZER
 * ============================================================================
 * 
 * ARCHITECTURE OVERVIEW:
 * SecureCheck is a client-side Windows cybersecurity audit engine designed
 * to assess system hardening without requiring invasive software agents,
 * remote server communication, or elevated automated scripts.
 * 
 * CORE DESIGN PRINCIPLES:
 * 1. Zero-Agent / Non-Intrusive:
 *    The user runs standard, read-only Windows PowerShell cmdlets in their own
 *    terminal and pastes the resulting text here. SecureCheck NEVER executes
 *    commands on the user's computer or opens remote management ports.
 * 
 * 2. 100% Client-Side Privacy:
 *    All parsing, regex evaluation, CVSS severity categorization, score computation,
 *    and PDF generation happen purely inside the browser's JavaScript runtime.
 *    No telemetry, logs, or system data are sent to any remote servers.
 * 
 * 3. Deterministic Security Parsing:
 *    The `SecurityAnalyzer` class extracts key configuration values from PowerShell
 *    output, cross-references baseline standards (CIS Benchmarks, Microsoft Baselines),
 *    and produces clear, educational diagnoses with CVSS scores and copyable fixes.
 * ============================================================================
 */

// ============================================================================
// SECTION 1: CHECKS CONFIGURATION & REALISTIC SAMPLES
// ============================================================================
/**
 * Array containing the definitions for all 6 core security dimensions evaluated.
 * 
 * Each check object defines:
 * - `id`: Unique programmatic identifier used across state, UI elements, and routers.
 * - `step`: Numerical step index in the guided audit workflow (1 to 6).
 * - `title`: Human-readable display name of the security component.
 * - `weight`: Maximum points allocated to this check towards the 100-point score.
 * - `command`: The exact, safe PowerShell cmdlet recommended for the audit.
 * - `shortDesc`: Brief subtitle explaining the check's functional domain.
 * - `why`: Educational explanation explaining the threat model and risk of misconfiguration.
 * - `powershellInstructions`: Clear guidance on how to run the command in PowerShell.
 * - `sampleSecure`: Example PowerShell output representing a hardened, secure configuration.
 * - `sampleVulnerable`: Example PowerShell output representing a misconfigured or exposed system.
 * - `remediationCommand`: Ready-to-copy PowerShell command that applies the security fix.
 */
const SECURITY_CHECKS = [
  {
    id: "firewall",
    step: 1,
    title: "Windows Firewall",
    themeClass: "theme-firewall",
    categoryTag: "NETWORK SHIELD",
    icon: "🛡️",
    accentColor: "var(--accent-cyan)",
    weight: 20,
    command: "Get-NetFirewallProfile",
    shortDesc: "Network Perimeter Defense",
    why: "Windows Firewall acts as your device's first line of defense against network intrusion. It filters inbound and outbound internet traffic across Domain, Private (home/work), and Public (cafes/airports) network profiles. If disabled, malicious computers on your network or the internet can probe open ports and attempt unauthorized connections.",
    powershellInstructions: "Press Win + X, select 'Terminal (Admin)' or 'Windows PowerShell (Admin)', run the command below, and copy the terminal output.",
    sampleSecure: `Name                            : Domain
DisplayName                     : Domain
Description                     : Domain
DisplayGroup                    : 
Group                           : 
Enabled                         : True
DefaultInboundAction            : Block
DefaultOutboundAction           : Allow
AllowInboundRules               : True
AllowLocalFirewallRules         : True

Name                            : Private
DisplayName                     : Private
Description                     : Private
DisplayGroup                    : 
Group                           : 
Enabled                         : True
DefaultInboundAction            : Block
DefaultOutboundAction           : Allow
AllowInboundRules               : True
AllowLocalFirewallRules         : True

Name                            : Public
DisplayName                     : Public
Description                     : Public
DisplayGroup                    : 
Group                           : 
Enabled                         : True
DefaultInboundAction            : Block
DefaultOutboundAction           : Allow
AllowInboundRules               : True
AllowLocalFirewallRules         : True`,
    sampleVulnerable: `Name                            : Domain
DisplayName                     : Domain
Description                     : Domain
Enabled                         : True
DefaultInboundAction            : Block
DefaultOutboundAction           : Allow

Name                            : Private
DisplayName                     : Private
Description                     : Private
Enabled                         : False
DefaultInboundAction            : Allow
DefaultOutboundAction           : Allow

Name                            : Public
DisplayName                     : Public
Description                     : Public
Enabled                         : False
DefaultInboundAction            : Allow
DefaultOutboundAction           : Allow`,
    remediationCommand: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
  },
  {
    id: "bitlocker",
    step: 2,
    title: "BitLocker / Disk Encryption",
    themeClass: "theme-bitlocker",
    categoryTag: "CRYPTOGRAPHY",
    icon: "🔒",
    accentColor: "var(--accent-purple)",
    weight: 20,
    command: "Get-BitLockerVolume",
    shortDesc: "Data-at-Rest Protection",
    why: "Disk encryption scrambles all personal files, passwords, documents, and system files stored on your hard drive. Without encryption, if your laptop is stolen or physically accessed, an attacker can remove the SSD/hard drive or boot from a USB drive to access your private files directly, completely bypassing Windows login passwords.",
    powershellInstructions: "Run the command in PowerShell as Administrator to inspect all volume encryption and protection states.",
    sampleSecure: `VolumeType      Mount CapacityGB VolumeStatus        Encryption KeyProtector  AutoUnlock Protection
                Point                                Method                 Status     Status    
----------      ----- ---------- ------------        ---------- ------------ ---------- ----------
OperatingSystem C:        475.69 FullyEncrypted      XtsAes128  Tpm, Recovery.. Disabled   On        
Data            D:        931.51 FullyEncrypted      XtsAes128  Password, Rec.. Disabled   On`,
    sampleVulnerable: `VolumeType      Mount CapacityGB VolumeStatus        Encryption KeyProtector  AutoUnlock Protection
                Point                                Method                 Status     Status    
----------      ----- ---------- ------------        ---------- ------------ ---------- ----------
OperatingSystem C:        475.69 FullyDecrypted      None       None         Disabled   Off       
Data            D:        931.51 FullyDecrypted      None       None         Disabled   Off`,
    remediationCommand: "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector"
  },
  {
    id: "admin",
    step: 3,
    title: "Administrator Accounts",
    themeClass: "theme-admins",
    categoryTag: "LEAST PRIVILEGE",
    icon: "👥",
    accentColor: "var(--accent-amber)",
    weight: 15,
    command: "Get-LocalGroupMember -Group \"Administrators\"",
    shortDesc: "Privilege Separation & Least Privilege",
    why: "Administrator privileges allow complete, unrestricted control over the computer—including installing kernel drivers, disabling antivirus, and modifying system files. The Principle of Least Privilege advises using a standard non-admin account for everyday web browsing and office work, reserving administrator rights only when system maintenance is specifically needed.",
    powershellInstructions: "Run this command to enumerate accounts and groups that currently possess local administrator rights.",
    sampleSecure: `ObjectClass Name                     PrincipalSource
----------- ----                     ---------------
User        DESKTOP-PC\\SecOpsAdmin   Local`,
    sampleVulnerable: `ObjectClass Name                     PrincipalSource
----------- ----                     ---------------
User        DESKTOP-PC\\Administrator Local          
User        DESKTOP-PC\\GuestUser     Local          
User        DESKTOP-PC\\FamilyPC      Local          
User        DESKTOP-PC\\TempInstaller Local`,
    remediationCommand: "Remove-LocalGroupMember -Group 'Administrators' -Member 'DESKTOP-PC\\AccountNameToDemote'"
  },
  {
    id: "guest",
    step: 4,
    title: "Guest Account",
    themeClass: "theme-guest",
    categoryTag: "PERIMETER DEFENSE",
    icon: "👤",
    accentColor: "var(--accent-rose)",
    weight: 15,
    command: "Get-LocalUser -Name \"Guest\"",
    shortDesc: "Anonymous Logon Surface",
    why: "The built-in Windows Guest account allows anyone to log on to the workstation without entering a password. If enabled, anyone with physical or local network access could start an interactive session, probe the local network, and explore files or unpatched local privilege escalation exploits.",
    powershellInstructions: "Run this command to check whether the built-in Guest account is enabled or disabled.",
    sampleSecure: `Name  Enabled Description
----  ------- -----------
Guest False   Built-in account for guest access to the computer/domain`,
    sampleVulnerable: `Name  Enabled Description
----  ------- -----------
Guest True    Built-in account for guest access to the computer/domain`,
    remediationCommand: "Disable-LocalUser -Name 'Guest'"
  },
  {
    id: "updates",
    step: 5,
    title: "Windows Updates & Patch Hygiene",
    themeClass: "theme-updates",
    categoryTag: "PATCH CURRENCY",
    icon: "🔄",
    accentColor: "var(--accent-emerald)",
    weight: 15,
    command: "Get-WindowsUpdate",
    shortDesc: "Vulnerability Patching",
    why: "Operating system updates deliver security patches for zero-day vulnerabilities, buffer overflows, and privilege escalation bugs actively exploited by ransomware operators. Running an unpatched system leaves open known backdoors that malware can exploit automatically without needing your permission.",
    powershellInstructions: "If Get-WindowsUpdate (PSWindowsUpdate) is not installed, you may also run:\nGet-CimInstance Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending | Select-Object -First 5\nor copy status text from Windows Settings > Windows Update.",
    sampleSecure: `ComputerName Status     KB          Size Title
------------ ------     --          ---- -----
DESKTOP-SEC  Installed  KB5034441   12MB 2026-08 Cumulative Security Update for Windows 11
DESKTOP-SEC  Installed  KB5034123   45MB Windows Malicious Software Removal Tool
(0 pending updates. Device is up to date as of today.)`,
    sampleVulnerable: `ComputerName Status     KB          Size Title
------------ ------     --          ---- -----
DESKTOP-VULN Pending    KB5034441  650MB 2026-08 Cumulative Security Update for Windows 11
DESKTOP-VULN Pending    KB5033375  210MB Security Update for Windows Defender Antivirus
DESKTOP-VULN Pending    KB5029244  420MB Windows Kernel Vulnerability Hotfix (Critical Remote Code Execution)`,
    remediationCommand: "Install-WindowsUpdate -AcceptAll -AutoReboot"
  },
  {
    id: "apps",
    step: 6,
    title: "Installed Applications / Shadow IT",
    themeClass: "theme-apps",
    categoryTag: "APP HYGIENE",
    icon: "📦",
    accentColor: "var(--accent-indigo)",
    weight: 15,
    command: "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | Where-Object {$_.DisplayName}",
    shortDesc: "Software Inventory & Attack Surface",
    why: "Third-party software introduces vulnerabilities, unauthorized remote access utilities (shadow IT), and unnecessary background services. Outdated runtimes (like legacy Java or Flash) or questionable utility software (registry cleaners, untrusted remote access clients) significantly expand your attack surface.",
    powershellInstructions: "Run this command to list installed software packages registered on the machine.",
    sampleSecure: `DisplayName                               DisplayVersion
-----------                               --------------
Google Chrome                             128.0.6613.120
Microsoft Visual Studio Code              1.92.2
7-Zip 24.07 (x64)                         24.07
Git                                       2.46.0
Microsoft Edge                            128.0.2739.54`,
    sampleVulnerable: `DisplayName                               DisplayVersion
-----------                               --------------
Google Chrome                             128.0.6613.120
TeamViewer Remote Administration          15.42.3
AnyDesk Remote Desktop Access             7.1.8
Java 7 Update 67 (32-bit)                 7.0.670
Ask Toolbar Search Assistant              3.1.0
CCleaner Registry Utility                 5.88.9346
uTorrent Bundleware Client                3.5.5`,
    remediationCommand: "winget uninstall --name \"TeamViewer Remote Administration\""
  }
];

// ============================================================================
// SECTION 2: PARSING & SECURITY ANALYSIS ENGINE
// ============================================================================
/**
 * SecurityAnalyzer
 * 
 * Static utility class responsible for:
 * 1. Sanitizing user-submitted terminal text.
 * 2. Scanning for accidental credential leakage (private keys, tokens, passwords).
 * 3. Detecting PowerShell runtime execution errors (e.g. Access Denied, missing cmdlets).
 * 4. Parsing configuration blocks from output for each of the 6 security domains.
 * 5. Calculating severity, CVSS scores, remediation commands, and formatted evidence.
 */
class SecurityAnalyzer {
  /**
   * Cleans up raw input by stripping leading/trailing whitespace.
   * @param {string} text - Raw input from textarea.
   * @returns {string} Sanitized string.
   */
  static sanitize(text) {
    return text ? text.trim() : "";
  }

  /**
   * Privacy Protection Guard:
   * Scans user input for accidental leakage of highly sensitive tokens or secrets
   * before analysis. If detected, SecureCheck warns the user to sanitize their text.
   * 
   * @param {string} text - Raw text to inspect.
   * @returns {string|null} Name of detected secret pattern, or null if clean.
   */
  static checkSensitiveInfo(text) {
    const patterns = [
      { name: "Private Key", regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/i },
      { name: "AWS / API Secret Key", regex: /(AKIA[0-9A-Z]{16}|secret[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_\-\/]{20,}['"]?)/i },
      { name: "Plaintext Password", regex: /(password|passwd|pwd)\s*[:=]\s*['"]?[^ \r\n\t]{6,}['"]?/i },
      { name: "Bearer Token / JWT", regex: /Bearer\s+eyJ[a-zA-Z0-9_\-\.]+/i }
    ];

    for (const p of patterns) {
      if (p.regex.test(text)) {
        return p.name;
      }
    }
    return null;
  }

  /**
   * Diagnostic Helper for PowerShell Execution Errors:
   * Detects whether the pasted output is actually an error stream from PowerShell
   * rather than command output. Common causes include:
   * - Running commands without Administrator elevation (Access Denied / HRESULT 0x80041003).
   * - Missing PowerShell modules (e.g. PSWindowsUpdate not installed).
   * 
   * @param {string} raw - Raw text from the user.
   * @returns {object|null} Diagnostic error details with troubleshooting steps, or null.
   */
  static detectPowerShellError(raw) {
    if (!raw) return null;
    const text = String(raw).trim();

    // Check for elevation / permission denied errors
    if (/PermissionDenied|Access denied|Access is denied|HRESULT 0x80041003|UnauthorizedAccessException/i.test(text)) {
      return {
        type: "access_denied",
        title: "Administrator Elevation Required (Access Denied)",
        message: "PowerShell returned <code>Access denied / PermissionDenied (HRESULT 0x80041003)</code>. This check inspects core operating system security components which require an elevated Administrator session.",
        fix: "Press <strong>Win + X</strong> on your keyboard &rarr; Click <strong>Terminal (Admin)</strong> or <strong>Windows PowerShell (Admin)</strong> &rarr; Run the command again and paste the output."
      };
    }

    // Check for missing cmdlet or module errors
    if (/not recognized as the name of a cmdlet|is not recognized as an internal or external command/i.test(text)) {
      return {
        type: "cmdlet_missing",
        title: "Command or Module Not Available",
        message: "PowerShell reported that the cmdlet is not recognized on this system.",
        fix: "Check that you copied the complete command line accurately, or check if the command is supported on your Windows edition."
      };
    }
    return null;
  }

  // --------------------------------------------------------------------------
  // 1. WINDOWS FIREWALL ANALYSIS
  // --------------------------------------------------------------------------
  /**
   * Evaluates PowerShell output from `Get-NetFirewallProfile`.
   * 
   * Windows maintains three active network firewall profiles:
   * - Domain: Used when connected to an Active Directory domain network.
   * - Private: Used on trusted home or private business networks.
   * - Public: Used on untrusted networks (public Wi-Fi, coffee shops, airports).
   * 
   * Scoring Logic:
   * - Secure (20/20 pts): All profiles are active (Enabled: True) with default inbound block.
   * - Warning (8/20 pts): Only Domain profile is disabled, or non-admin access error occurred.
   * - Danger (0/20 pts): Public or Private profile is disabled (critical network exposure).
   * 
   * @param {string} raw - Raw text from Get-NetFirewallProfile.
   * @returns {object|null} Evaluation result object or null if text unrecognized.
   */
  static analyzeFirewall(raw) {
    const text = this.sanitize(raw);
    if (!text || text.length < 10) return null;

    // Check if contains profile keywords or Enabled status
    const hasProfileKeywords = /firewall|profile|domain|private|public/i.test(text);
    const hasEnabledKeyword = /enabled\s*[:=]/i.test(text);
    const isAccessDenied = /PermissionDenied|Access denied|Access is denied|HRESULT 0x80041003/i.test(text);

    if (!hasProfileKeywords && !hasEnabledKeyword && !isAccessDenied) {
      return null;
    }

    // Handle non-admin elevation restrictions
    if (isAccessDenied) {
      return {
        checkId: "firewall",
        status: "warning",
        score: 0,
        maxScore: 20,
        severity: "Medium",
        cvss: "5.0 (Medium)",
        finding: "Windows Firewall status could not be determined — Administrator privileges required",
        whatWeFound: "PowerShell returned an Access Denied error when inspecting Windows Firewall profiles.",
        whyItMatters: "Firewall rules inspect and protect incoming network traffic. Administrator permissions are needed to read firewall status.",
        recommendedAction: "Open PowerShell as Administrator (Win + X > Terminal (Admin)) and re-run: Get-NetFirewallProfile",
        remediationCmd: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        evidence: text.slice(0, 150)
      };
    }

    // Split profiles or examine lines
    const profiles = {
      Domain: null,
      Private: null,
      Public: null
    };

    // Regex for block style: Name: X ... Enabled: True/False
    const profileBlocks = text.split(/(?=Name\s*:\s*(?:Domain|Private|Public))/i);
    for (const block of profileBlocks) {
      const nameMatch = block.match(/Name\s*:\s*(Domain|Private|Public)/i);
      const enabledMatch = block.match(/Enabled\s*:\s*(True|False|1|0)/i);
      if (nameMatch && enabledMatch) {
        const name = nameMatch[1].charAt(0).toUpperCase() + nameMatch[1].slice(1).toLowerCase();
        const isEnabled = enabledMatch[1].toLowerCase() === "true" || enabledMatch[1] === "1";
        profiles[name] = isEnabled;
      }
    }

    // Fallback: If formatted as a table or single lines
    if (profiles.Domain === null && profiles.Private === null && profiles.Public === null) {
      const lines = text.split(/\r?\n/);
      let currentProf = null;
      for (const line of lines) {
        if (/domain/i.test(line)) currentProf = "Domain";
        else if (/private/i.test(line)) currentProf = "Private";
        else if (/public/i.test(line)) currentProf = "Public";

        const enMatch = line.match(/Enabled\s*[:=]\s*(True|False|1|0)/i);
        if (enMatch && currentProf) {
          profiles[currentProf] = enMatch[1].toLowerCase() === "true" || enMatch[1] === "1";
        }
      }
    }

    // Direct general scan if only "Enabled : True" or "Enabled : False" exists
    const falseMatches = [...text.matchAll(/([A-Za-z0-9_\-]+)\s*(?:profile)?[\s\S]{0,40}?Enabled\s*:\s*(False|0)/gi)];
    const trueMatches = [...text.matchAll(/([A-Za-z0-9_\-]+)\s*(?:profile)?[\s\S]{0,40}?Enabled\s*:\s*(True|1)/gi)];

    const disabledProfiles = [];
    if (profiles.Domain === false) disabledProfiles.push("Domain");
    if (profiles.Private === false) disabledProfiles.push("Private");
    if (profiles.Public === false) disabledProfiles.push("Public");

    const enabledProfiles = [];
    if (profiles.Domain === true) enabledProfiles.push("Domain");
    if (profiles.Private === true) enabledProfiles.push("Private");
    if (profiles.Public === true) enabledProfiles.push("Public");

    // Gather short quote evidence
    const evidenceLines = text.split(/\r?\n/)
      .filter(line => /enabled\s*:/i.test(line) || /name\s*:/i.test(line))
      .slice(0, 4)
      .join("\n");

    const evidence = evidenceLines || (text.slice(0, 150) + "...");

    if (disabledProfiles.length > 0 || (falseMatches.length > 0 && trueMatches.length === 0)) {
      const isPublicDisabled = disabledProfiles.includes("Public") || /public[\s\S]{0,30}false/i.test(text);
      const isPrivateDisabled = disabledProfiles.includes("Private") || /private[\s\S]{0,30}false/i.test(text);

      const isHigh = isPublicDisabled || isPrivateDisabled;
      const status = isHigh ? "danger" : "warning";
      const severity = isHigh ? "High" : "Medium";
      const cvss = isHigh ? "7.5 (High)" : "5.3 (Medium)";
      const points = isHigh ? 0 : 8;

      return {
        checkId: "firewall",
        status,
        score: points,
        maxScore: 20,
        severity,
        cvss,
        finding: disabledProfiles.length > 0 
          ? `Windows Firewall is DISABLED on profile(s): ${disabledProfiles.join(", ")}` 
          : "One or more Windows Firewall profiles are disabled",
        whatWeFound: `We detected that the Windows Firewall is currently switched off for ${disabledProfiles.length ? disabledProfiles.join(" and ") : "crucial network"} connection profiles.`,
        whyItMatters: "When the firewall is turned off, all incoming network ports remain unshielded. Anyone connected to the same Wi-Fi network (such as at home, an office, or public coffee shop) or malicious worms can probe your system, send exploit payloads, and attempt remote code execution.",
        recommendedAction: "Immediately re-enable the Windows Firewall across all profiles (Domain, Private, and Public). You can run this command in Administrator PowerShell:\nSet-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        remediationCmd: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        evidence: evidence
      };
    }

    if (enabledProfiles.length > 0 || (trueMatches.length > 0 && falseMatches.length === 0)) {
      return {
        checkId: "firewall",
        status: "secure",
        score: 20,
        maxScore: 20,
        severity: "Informational",
        cvss: "0.0 (Secure)",
        finding: "Windows Firewall is fully active and filtering incoming traffic",
        whatWeFound: `Firewall protection is active on ${enabledProfiles.length ? enabledProfiles.join(", ") : "all"} profiles with default inbound connection blocking.`,
        whyItMatters: "Active firewalls automatically drop unsolicited inbound connection attempts, shielding your computer from network port scanners and automated worm attacks.",
        recommendedAction: "Maintain the current firewall configuration. Avoid creating broad inbound firewall allowances for untrusted applications.",
        remediationCmd: null,
        evidence: evidence
      };
    }

    return null;
  }

  // --------------------------------------------------------------------------
  // 2. BITLOCKER / FULL DISK ENCRYPTION ANALYSIS
  // --------------------------------------------------------------------------
  /**
   * Evaluates PowerShell output from `Get-BitLockerVolume`.
   * 
   * Protects the primary operating system volume (C:) against offline theft.
   * Handles:
   * - FullyEncrypted with ProtectionStatus On (Secure - 20 pts).
   * - EncryptionInProgress (Warning - 12 pts).
   * - FullyDecrypted or ProtectionStatus Off (Danger - 0 pts).
   * - WMI permission denied / Windows Home Device Encryption differences.
   * 
   * @param {string} raw - Raw text from Get-BitLockerVolume.
   * @returns {object|null} Evaluation result object or null if text unrecognized.
   */
  static analyzeBitLocker(raw) {
    const text = this.sanitize(raw);
    if (!text || text.length < 10) return null;

    const hasBitLockerKeywords = /bitlocker|volume|mountpoint|protection|encrypted|encryption|keyprotector|ciminstance|0x80041003|win32encryptablevolume/i.test(text);
    if (!hasBitLockerKeywords) {
      return null;
    }

    const lines = text.split(/\r?\n/);
    const evidenceLines = lines.filter(l => 
      /C:|Protection|VolumeStatus|FullyEncrypted|FullyDecrypted|EncryptionMethod|On|Off|Access denied|PermissionDenied|0x80041003|associated BitLocker volume/i.test(l)
    ).slice(0, 4).join("\n");

    const evidence = evidenceLines || (text.slice(0, 160) + "...");

    // 1. Detect Permission Denied / Access Denied / Windows Home Edition
    const isAccessDenied = /PermissionDenied|Access denied|Access is denied|HRESULT 0x80041003|UnauthorizedAccess/i.test(text);
    const isNoAssociatedVolume = /does not have an associated BitLocker volume|not available on this edition|Win32EncryptableVolumeInternal/i.test(text);

    if (isAccessDenied || isNoAssociatedVolume) {
      const errEvidence = lines.filter(l => /Access denied|PermissionDenied|0x80041003|does not have an associated|Error/i.test(l)).slice(0, 3).join("\n") || lines.slice(0, 3).join("\n");
      return {
        checkId: "bitlocker",
        status: "warning",
        score: 0,
        maxScore: 20,
        severity: "High",
        cvss: "7.0 (High)",
        finding: isAccessDenied
          ? "BitLocker status blocked — Administrator privileges required or Windows Home edition"
          : "BitLocker volume not associated — Windows Home edition or drive unencrypted",
        whatWeFound: isAccessDenied
          ? "PowerShell reported 'Access Denied' (PermissionDenied / HRESULT 0x80041003) when querying BitLocker WMI encryption providers. Querying volume encryption status requires an elevated Administrator PowerShell session. Note: If your PC runs Windows Home edition, standard BitLocker cmdlets are restricted because Windows Home uses basic Device Encryption instead."
          : "PowerShell reported that no BitLocker volume was associated with this system. This typically occurs on Windows Home edition (which uses Device Encryption instead of BitLocker) or when drive encryption is inactive.",
        whyItMatters: "Without active disk encryption, files stored on your hard drive are unprotected at rest and can be extracted if your laptop or PC is lost, stolen, or physically inspected without needing your Windows login credentials.",
        recommendedAction: "1. Run PowerShell as Administrator: Press Win + X, select 'Terminal (Admin)' or 'Windows PowerShell (Admin)', and re-run: Get-BitLockerVolume\n2. Windows Home Users: Open Windows Settings > Privacy & Security > Device Encryption to enable Device Encryption.\n3. Alternative Check: In an Administrator prompt, run 'manage-bde -status C:' to inspect volume encryption.",
        remediationCmd: "manage-bde -status C:",
        evidence: errEvidence || evidence
      };
    }

    // Check for explicit ProtectionStatus Off / FullyDecrypted
    const isDecrypted = /FullyDecrypted/i.test(text);
    const isProtectionOff = /ProtectionStatus\s*:\s*(Off|0|ProtectionOff)/i.test(text) || 
      /C:[\s\S]{0,100}FullyDecrypted[\s\S]{0,100}Off/i.test(text) ||
      /C:[\s\S]{0,40}Off\b/i.test(text);

    const isEncrypted = /FullyEncrypted/i.test(text);
    const isProtectionOn = /ProtectionStatus\s*:\s*(On|1|ProtectionOn)/i.test(text) || 
      /C:[\s\S]{0,100}FullyEncrypted[\s\S]{0,100}On/i.test(text) ||
      /C:[\s\S]{0,40}On\b/i.test(text);

    if (isProtectionOff || (isDecrypted && !isProtectionOn)) {
      return {
        checkId: "bitlocker",
        status: "danger",
        score: 0,
        maxScore: 20,
        severity: "High",
        cvss: "7.8 (High)",
        finding: "BitLocker / Full Volume Disk Encryption is NOT active on system drive (C:)",
        whatWeFound: "Your primary operating system storage drive (C:) is stored in cleartext without active hardware or software cryptographic protection.",
        whyItMatters: "If your computer is stolen, lost, or temporarily unattended, anyone can remove the hard drive or boot into a portable Linux USB stick to read every document, saved browser password, cached email, and secret file without needing your Windows login credentials.",
        recommendedAction: "Turn on BitLocker Device Encryption via Windows Settings (Settings > Privacy & Security > Device Encryption or BitLocker) or enable it via PowerShell as Administrator:\nEnable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector",
        remediationCmd: "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector",
        evidence: evidence
      };
    }

    if (isProtectionOn || isEncrypted) {
      return {
        checkId: "bitlocker",
        status: "secure",
        score: 20,
        maxScore: 20,
        severity: "Informational",
        cvss: "0.0 (Secure)",
        finding: "BitLocker disk encryption is ENABLED and actively protecting system storage",
        whatWeFound: "Volume C: is protected by full disk encryption with an active key protector (e.g., TPM / Recovery Key).",
        whyItMatters: "Your sensitive files are cryptographically protected at rest. Even if the computer is physically stolen or the drive is removed, unauthorized parties cannot read the underlying raw data.",
        recommendedAction: "Ensure your BitLocker recovery key is safely backed up to your personal Microsoft Account or printed in a secure offline location.",
        remediationCmd: null,
        evidence: evidence
      };
    }

    if (/EncryptionInProgress/i.test(text)) {
      return {
        checkId: "bitlocker",
        status: "warning",
        score: 12,
        maxScore: 20,
        severity: "Medium",
        cvss: "4.0 (Medium)",
        finding: "BitLocker encryption is currently in progress",
        whatWeFound: "The storage drive is actively encrypting in the background.",
        whyItMatters: "Protection will be fully established once the encryption operation completes 100%.",
        recommendedAction: "Keep your laptop plugged into power and allow encryption to finish.",
        remediationCmd: null,
        evidence: evidence
      };
    }

    return null;
  }

  // --------------------------------------------------------------------------
  // 3. ADMINISTRATOR ACCOUNTS ANALYSIS
  // --------------------------------------------------------------------------
  /**
   * Evaluates PowerShell output from `Get-LocalGroupMember -Group "Administrators"`.
   * 
   * Audits local group membership against the Principle of Least Privilege:
   * - Secure (15 pts): 1-2 recognized administrative accounts.
   * - Warning (8 pts): >= 3 privileged accounts, or built-in Administrator active with other accounts,
   *   or elevation required to query group members.
   * 
   * @param {string} raw - Raw text from Get-LocalGroupMember.
   * @returns {object|null} Evaluation result object or null if text unrecognized.
   */
  static analyzeAdmins(raw) {
    const text = this.sanitize(raw);
    if (!text || text.length < 10) return null;

    const isAccessDenied = /PermissionDenied|Access denied|Access is denied|HRESULT 0x80041003/i.test(text);

    if (!/localgroupmember|administrators|objectclass|principalsource|user|group/i.test(text) && !isAccessDenied) {
      return null;
    }

    if (isAccessDenied) {
      return {
        checkId: "admin",
        status: "warning",
        score: 8,
        maxScore: 15,
        severity: "Medium",
        cvss: "5.0 (Medium)",
        finding: "Administrator group query restricted — Administrator rights required",
        whatWeFound: "PowerShell returned an Access Denied error when querying local Administrator group members.",
        whyItMatters: "Auditing user accounts with administrator privileges requires administrative access.",
        recommendedAction: "Open PowerShell as Administrator (Win + X > Terminal (Admin)) and re-run: Get-LocalGroupMember -Group 'Administrators'",
        remediationCmd: null,
        evidence: text.slice(0, 150)
      };
    }

    const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
    const memberLines = lines.filter(l => 
      /User\s+|DESKTOP|LAPTOP|Administrator|Admin|Local|AzureAD|MicrosoftAccount/i.test(l) &&
      !/ObjectClass|-----------/i.test(l)
    );

    const accounts = [];
    for (const line of memberLines) {
      const match = line.match(/(?:[A-Za-z0-9_\-]+\\)?([A-Za-z0-9_\-\.\@]+)/i);
      if (match && !/^(user|objectclass|principalsource|local)$/i.test(match[1])) {
        accounts.push(match[0].trim());
      }
    }

    const evidence = memberLines.slice(0, 5).join("\n") || lines.slice(0, 4).join("\n");

    const hasBuiltInAdmin = /\\Administrator\b/i.test(text) || memberLines.some(m => /\bAdministrator\b/i.test(m));
    const memberCount = accounts.length > 0 ? accounts.length : memberLines.length;

    if (memberCount >= 3 || (hasBuiltInAdmin && memberCount > 1)) {
      return {
        checkId: "admin",
        status: "warning",
        score: 8,
        maxScore: 15,
        severity: "Medium",
        cvss: "5.5 (Medium)",
        finding: `Excessive Administrator accounts detected (${memberCount} privileged users)`,
        whatWeFound: `We identified ${memberCount} accounts configured with local Administrator rights (${accounts.slice(0, 3).join(", ")}${accounts.length > 3 ? '...' : ''}), including potential shared or built-in accounts.`,
        whyItMatters: "Every account with administrator rights can alter security settings, install root-level malware, and access all users' files. If a daily-use web browsing account runs as an Administrator, any malicious download or phishing payload instantly executes with full system authority.",
        recommendedAction: "Review each administrator account. Do NOT remove your own primary account automatically. Demote accounts used for routine everyday browsing to Standard User status, and ensure that shared, guest, or contractor accounts do not retain administrator privileges.",
        remediationCmd: "# Review accounts first before modifying:\n# Remove-LocalGroupMember -Group 'Administrators' -Member 'PC_NAME\\AccountToDemote'",
        evidence: evidence
      };
    }

    if (memberCount >= 1) {
      return {
        checkId: "admin",
        status: "secure",
        score: 15,
        maxScore: 15,
        severity: "Informational",
        cvss: "0.0 (Secure)",
        finding: "Administrator group is appropriately restricted",
        whatWeFound: `Only ${memberCount} designated account(s) have local administrator rights (${accounts.join(", ")}).`,
        whyItMatters: "Minimizing local administrators aligns with the Principle of Least Privilege, reducing the attack surface for credential theft and lateral movement.",
        recommendedAction: "Continue using a standard non-admin account for daily tasks and keep administrator credentials guarded with a strong passphrase.",
        remediationCmd: null,
        evidence: evidence
      };
    }

    return null;
  }

  // --------------------------------------------------------------------------
  // 4. GUEST ACCOUNT STATUS ANALYSIS
  // --------------------------------------------------------------------------
  /**
   * Evaluates PowerShell output from `Get-LocalUser -Name "Guest"` or `net user guest`.
   * 
   * Windows baseline standards dictate that the built-in Guest account must be
   * permanently disabled to prevent passwordless, anonymous local access:
   * - Secure (15 pts): Guest account status is False / No / Disabled.
   * - Danger (0 pts): Guest account is True / Yes / Active.
   * - Warning (8 pts): Permission restriction occurred when reading user account.
   * 
   * @param {string} raw - Raw text from Get-LocalUser.
   * @returns {object|null} Evaluation result object or null if text unrecognized.
   */
  static analyzeGuest(raw) {
    const text = this.sanitize(raw);
    if (!text || text.length < 5) return null;

    const isAccessDenied = /PermissionDenied|Access denied|Access is denied|HRESULT 0x80041003/i.test(text);

    if (!/guest|localuser|user account/i.test(text) && !isAccessDenied) {
      return null;
    }

    if (isAccessDenied) {
      return {
        checkId: "guest",
        status: "warning",
        score: 8,
        maxScore: 15,
        severity: "Medium",
        cvss: "5.0 (Medium)",
        finding: "Guest account query restricted — Administrator rights required",
        whatWeFound: "PowerShell returned an Access Denied error when querying the local Guest user account status.",
        whyItMatters: "Checking that the built-in Guest account is disabled requires administrative permissions.",
        recommendedAction: "Open PowerShell as Administrator (Win + X > Terminal (Admin)) and re-run: Get-LocalUser -Name 'Guest'",
        remediationCmd: "Disable-LocalUser -Name 'Guest'",
        evidence: text.slice(0, 150)
      };
    }

    const lines = text.split(/\r?\n/);
    const guestLine = lines.find(l => /guest/i.test(l)) || text;
    const evidence = guestLine.trim().slice(0, 150);

    // Support both Get-LocalUser (Enabled: True/False) and 'net user guest' (Account active: Yes/No)
    const isEnabled = /Enabled\s*:\s*(True|1)/i.test(text) || 
      /Guest\s+True/i.test(text) ||
      /Account active\s+Yes/i.test(text);

    const isDisabled = /Enabled\s*:\s*(False|0)/i.test(text) || 
      /Guest\s+False/i.test(text) ||
      /Account active\s+No/i.test(text);

    if (isEnabled) {
      return {
        checkId: "guest",
        status: "danger",
        score: 0,
        maxScore: 15,
        severity: "High",
        cvss: "7.3 (High)",
        finding: "Built-in Guest account is ACTIVE and ENABLED",
        whatWeFound: "The Windows Guest user account is enabled, allowing passwordless access.",
        whyItMatters: "An active Guest account allows unauthorized visitors or local network participants to log into your machine interactively without providing a password. It serves as a classic beachhead for unauthenticated exploration.",
        recommendedAction: "Disable the Guest account immediately. In Administrator PowerShell, run:\nDisable-LocalUser -Name 'Guest'",
        remediationCmd: "Disable-LocalUser -Name 'Guest'",
        evidence: evidence
      };
    }

    if (isDisabled) {
      return {
        checkId: "guest",
        status: "secure",
        score: 15,
        maxScore: 15,
        severity: "Informational",
        cvss: "0.0 (Secure)",
        finding: "Built-in Guest account is properly DISABLED",
        whatWeFound: "The Guest account status is marked as Disabled (False / No).",
        whyItMatters: "With the Guest account disabled, no unauthorized or anonymous user can sign in to the workstation without valid credentials.",
        recommendedAction: "Keep the Guest account permanently disabled as part of Windows security baselines.",
        remediationCmd: null,
        evidence: evidence
      };
    }

    return null;
  }

  // --------------------------------------------------------------------------
  // 5. WINDOWS UPDATES ANALYSIS
  // --------------------------------------------------------------------------
  /**
   * Evaluates PowerShell output from `Get-WindowsUpdate` or `Get-HotFix`.
   * 
   * Evaluates operating system patching currency:
   * - Secure (15 pts): Patches up to date, 0 pending security hotfixes.
   * - Warning (5-10 pts): Pending critical updates, or missing PSWindowsUpdate module.
   * 
   * @param {string} raw - Raw text from Get-WindowsUpdate or Get-HotFix.
   * @returns {object|null} Evaluation result object or null if text unrecognized.
   */
  static analyzeUpdates(raw) {
    const text = this.sanitize(raw);
    if (!text || text.length < 5) return null;

    const hasUpdateKeywords = /update|kb\d+|quickfixengineering|hotfix|installedon|pending|computername/i.test(text);
    const isNotRecognized = /not recognized as the name of a cmdlet|is not recognized as an internal or external command/i.test(text);
    const isAccessDenied = /PermissionDenied|Access denied|Access is denied/i.test(text);

    if (!hasUpdateKeywords && !isNotRecognized && !isAccessDenied) {
      return null;
    }

    const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
    const evidence = lines.slice(0, 4).join("\n");

    if (isNotRecognized) {
      return {
        checkId: "updates",
        status: "warning",
        score: 10,
        maxScore: 15,
        severity: "Low",
        cvss: "3.0 (Low)",
        finding: "PSWindowsUpdate module not pre-installed — Check Settings or Get-HotFix",
        whatWeFound: "PowerShell reported that 'Get-WindowsUpdate' is not recognized. This command relies on the optional PSWindowsUpdate module which is not bundled with standard Windows by default.",
        whyItMatters: "Without the module or checking Settings, recent update patch levels cannot be directly queried through this specific cmdlet.",
        recommendedAction: "1. Check Windows Updates directly in Windows Settings > Windows Update > 'Check for updates'.\n2. Or install the module in Administrator PowerShell: Install-Module -Name PSWindowsUpdate -Force\n3. Or run the built-in Windows hotfix command: Get-HotFix",
        remediationCmd: "Get-HotFix",
        evidence: evidence
      };
    }

    if (isAccessDenied) {
      return {
        checkId: "updates",
        status: "warning",
        score: 8,
        maxScore: 15,
        severity: "Medium",
        cvss: "5.0 (Medium)",
        finding: "Windows Update query restricted — Administrator rights required",
        whatWeFound: "PowerShell returned an Access Denied error when querying update status.",
        whyItMatters: "Checking system update status requires administrative permissions.",
        recommendedAction: "Open PowerShell as Administrator (Win + X > Terminal (Admin)) and re-run update checks.",
        remediationCmd: "Get-HotFix",
        evidence: evidence
      };
    }

    const hasPendingUpdates = /pending|available|not installed|downloading|restart required/i.test(text);
    const isUpToDate = /0 (pending|updates found)|up to date|installed|no updates/i.test(text);

    // If QuickFixEngineering is pasted, check dates
    const dateMatches = text.match(/\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/g);

    if (hasPendingUpdates && !isUpToDate) {
      const kbMatches = [...text.matchAll(/KB\d+/gi)].map(m => m[0]);
      const uniqueKBs = [...new Set(kbMatches)];

      return {
        checkId: "updates",
        status: "warning",
        score: 5,
        maxScore: 15,
        severity: "Medium",
        cvss: "6.8 (Medium)",
        finding: `Security Updates are PENDING installation ${uniqueKBs.length ? `(${uniqueKBs.slice(0, 3).join(", ")})` : ""}`,
        whatWeFound: "Uninstalled cumulative security hotfixes or defender definitions were detected pending on your system.",
        whyItMatters: "Unpatched vulnerabilities allow exploit kits, phishing droppers, and malware to exploit known Common Vulnerabilities and Exposures (CVEs) for which public fixes already exist.",
        recommendedAction: "Go to Windows Settings > Windows Update > 'Check for updates' and apply all pending patches and restart your machine promptly. Or run:\nInstall-WindowsUpdate -AcceptAll -AutoReboot",
        remediationCmd: "Install-WindowsUpdate -AcceptAll -AutoReboot",
        evidence: evidence
      };
    }

    if (isUpToDate || /KB\d+/i.test(text)) {
      return {
        checkId: "updates",
        status: "secure",
        score: 15,
        maxScore: 15,
        severity: "Informational",
        cvss: "0.0 (Secure)",
        finding: "Windows Update patch level appears current",
        whatWeFound: "Recent security patches and hotfixes have been installed and no urgent pending updates were flagged.",
        whyItMatters: "Keeping Windows up to date mitigates known zero-day vulnerabilities and memory corruption flaws.",
        recommendedAction: "Leave Automatic Windows Updates enabled to receive timely monthly 'Patch Tuesday' releases.",
        remediationCmd: null,
        evidence: evidence
      };
    }

    return null;
  }

  // --------------------------------------------------------------------------
  // 6. INSTALLED APPLICATIONS / SHADOW IT ANALYSIS
  // --------------------------------------------------------------------------
  /**
   * Evaluates PowerShell output from the registry uninstall key scan.
   * 
   * Identifies potentially risky applications:
   * - Shadow IT & Remote Administration utilities (TeamViewer, AnyDesk, VNC, etc.).
   * - Obsolete or dangerous runtimes (Java 6/7, Flash, Silverlight).
   * - Questionable bundled utilities (toolbars, torrent clients, aggressive cleaners).
   * 
   * @param {string} raw - Raw text from registry uninstall query.
   * @returns {object|null} Evaluation result object or null if text unrecognized.
   */
  static analyzeApps(raw) {
    const text = this.sanitize(raw);
    if (!text || text.length < 10) return null;

    const hasAppSignals = /displayname|displayversion|uninstall|software|chrome|edge|code|office|version/i.test(text);
    if (!hasAppSignals) {
      return null;
    }

    const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
    const evidence = lines.slice(0, 5).join("\n");

    // Classification lists
    const shadowITReview = [
      { name: "TeamViewer", reason: "Remote desktop control utility. If unmanaged, can allow persistent external access." },
      { name: "AnyDesk", reason: "Remote access tool frequently targeted by social engineering tech support scams." },
      { name: "uTorrent", reason: "BitTorrent client frequently bundled with adware and untrusted third-party installers." },
      { name: "BitTorrent", reason: "P2P torrent software prone to downloading copyrighted or Trojan-infected files." },
      { name: "LogMeIn", reason: "Remote administration software." },
      { name: "VNC", reason: "Virtual Network Computing server/viewer." },
      { name: "CCleaner", reason: "Aggressive registry modification tool with historical supply-chain compromise incidents." }
    ];

    const potentiallyUnnecessary = [
      { name: "Java 7", reason: "Severely obsolete Java runtime containing multiple critical remote code execution vulnerabilities." },
      { name: "Java 6", reason: "Discontinued runtime vulnerable to known privilege escalation exploits." },
      { name: "Flash", reason: "End-of-life Adobe Flash player plugin; highly dangerous to keep installed." },
      { name: "Silverlight", reason: "Deprecated browser plugin." },
      { name: "Ask Toolbar", reason: "Potentially Unwanted Program (PUP) / browser hijacker." },
      { name: "Yahoo! Toolbar", reason: "Legacy browser toolbar." }
    ];

    const flaggedReview = [];
    const flaggedUnnecessary = [];

    for (const item of shadowITReview) {
      if (new RegExp(item.name, "i").test(text)) {
        flaggedReview.push(item);
      }
    }

    for (const item of potentiallyUnnecessary) {
      if (new RegExp(item.name, "i").test(text)) {
        flaggedUnnecessary.push(item);
      }
    }

    if (flaggedReview.length > 0 || flaggedUnnecessary.length > 0) {
      const allFlagged = [...flaggedReview, ...flaggedUnnecessary];
      const names = allFlagged.map(f => f.name).join(", ");
      const isDangerous = flaggedUnnecessary.length > 0;
      const status = isDangerous ? "warning" : "warning";
      const severity = isDangerous ? "Medium" : "Low";
      const score = isDangerous ? 6 : 9;

      return {
        checkId: "apps",
        status,
        score,
        maxScore: 15,
        severity,
        cvss: isDangerous ? "5.8 (Medium)" : "3.5 (Low)",
        finding: `Software inventory contains items that require user review (${names})`,
        whatWeFound: `We identified ${allFlagged.length} software package(s) classified as 'Needs review' or 'Potentially unnecessary' (${names}). Note: SecureCheck does not automatically claim software is malicious, but users should inspect unfamiliar software.`,
        whyItMatters: "Unused remote management utilities and obsolete runtimes expand your attack surface. Remote access tools can be abused if configured without two-factor authentication, and legacy runtimes lack modern memory protection.",
        recommendedAction: "Review installed software in Windows Settings > Apps > Installed apps. If you did not intentionally install these utilities or no longer need them, uninstall them safely.",
        remediationCmd: `winget uninstall --name "${allFlagged[0].name}"`,
        evidence: evidence,
        appCategories: {
          needsReview: flaggedReview.map(f => `${f.name} - ${f.reason}`),
          potentiallyUnnecessary: flaggedUnnecessary.map(f => `${f.name} - ${f.reason}`)
        }
      };
    }

    // Default clean application list
    return {
      checkId: "apps",
      status: "secure",
      score: 15,
      maxScore: 15,
      severity: "Informational",
      cvss: "0.0 (Secure)",
      finding: "Installed applications appear standard with no suspicious shadow IT detected",
      whatWeFound: "Recognized standard applications (web browsers, developer tools, office software) were found with no obsolete plugins or high-risk remote utilities.",
      whyItMatters: "Keeping a minimal, trusted software footprint significantly lowers your vulnerability surface.",
      recommendedAction: "Regularly audit installed applications and remove software you no longer use.",
      remediationCmd: null,
      evidence: evidence
    };
  }

  // --------------------------------------------------------------------------
  // CENTRAL DISPATCHER ROUTER
  // --------------------------------------------------------------------------
  /**
   * Routes the checkId and text to the corresponding analyzer method.
   * @param {string} checkId - One of: firewall, bitlocker, admin, guest, updates, apps.
   * @param {string} text - Raw terminal output to analyze.
   * @returns {object|null} Parsed security result, or null if text could not be parsed.
   */
  static analyze(checkId, text) {
    switch (checkId) {
      case "firewall": return this.analyzeFirewall(text);
      case "bitlocker": return this.analyzeBitLocker(text);
      case "admin": return this.analyzeAdmins(text);
      case "guest": return this.analyzeGuest(text);
      case "updates": return this.analyzeUpdates(text);
      case "apps": return this.analyzeApps(text);
      default: return null;
    }
  }
}

// ============================================================================
// SECTION 3: APPLICATION STATE & SPA NAVIGATION CONTROLLER
// ============================================================================
/**
 * Global AppState:
 * Centralized, ephemeral in-memory state store for the single-page application.
 * 
 * Properties:
 * - `currentView`: The active view identifier ('home', 'audit', 'dashboard', 'report', 'about').
 * - `activeStepIndex`: Currently visible audit step index (0 through 5).
 * - `results`: Dictionary mapping checkId -> analysis result object or { skipped: true }.
 */
const AppState = {
  currentView: "home",
  activeStepIndex: 0,
  results: {}
};

/**
 * Single-Page Application (SPA) View Switcher:
 * Toggles visibility of view sections without triggering page reloads.
 * Synchronizes top navigation active button styling and smooth-scrolls to top.
 * 
 * @param {string} viewName - The target view key ('home', 'audit', 'dashboard', 'report', 'about').
 */
function switchView(viewName) {
  AppState.currentView = viewName;

  // Hide all view sections and deactivate all navigation buttons
  document.querySelectorAll(".view-section").forEach(el => el.style.display = "none");
  document.querySelectorAll(".nav-btn").forEach(btn => btn.classList.remove("active"));

  // Show target view container
  const targetView = document.getElementById(`view-${viewName}`);
  if (targetView) targetView.style.display = "block";

  // Mark corresponding navigation button as active
  const targetNav = document.getElementById(`nav-${viewName}`);
  if (targetNav) targetNav.classList.add("active");

  // Smooth scroll to top of viewport
  window.scrollTo({ top: 0, behavior: "smooth" });

  // Trigger view-specific render routines
  if (viewName === "audit") {
    renderAuditStep(AppState.activeStepIndex);
  } else if (viewName === "dashboard") {
    renderDashboard();
  } else if (viewName === "report") {
    renderReport();
  }
}

// ============================================================================
// SECTION 4: GUIDED AUDIT WORKFLOW RENDERING & INTERACTION HANDLERS
// ============================================================================
/**
 * Scrolls the viewport and audit container to the top so next/previous steps start from the top.
 */
function scrollAuditToTop() {
  const doScroll = () => {
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
    if (document.documentElement) document.documentElement.scrollTop = 0;
    if (document.body) document.body.scrollTop = 0;
    const auditView = document.getElementById("view-audit") || document.getElementById("audit-progress-header") || document.getElementById("main-content");
    if (auditView) {
      auditView.scrollIntoView({ behavior: "instant", block: "start" });
    }
  };

  // Immediate scroll
  doScroll();

  // Ensure scroll completes after browser reflow and layout
  requestAnimationFrame(doScroll);
  setTimeout(doScroll, 30);
  setTimeout(doScroll, 100);
}

/**
 * Renders the guided audit card for a specific check index (0 through 5).
 * Generates step-by-step instructions, command copy boxes, sample output tabs,
 * textarea input area, sensitive token alerts, and previous result cards if present.
 * 
 * @param {number} index - Index in SECURITY_CHECKS array.
 */
function renderAuditStep(index) {
  AppState.activeStepIndex = index;
  const check = SECURITY_CHECKS[index];
  const container = document.getElementById("auditCardContainer");
  if (!container) return;

  // Update Stepper Progress Indicators
  renderStepper();

  const existingResult = AppState.results[check.id];

  container.innerHTML = `
    <div class="audit-card ${check.themeClass}" id="audit-step-card-${check.id}">
      <div class="audit-card-header">
        <div style="display: flex; align-items: flex-start; gap: 14px;">
          <div class="feature-icon" style="width: 44px; height: 44px; font-size: 1.35rem; flex-shrink: 0; margin-top: 2px;">
            ${check.icon}
          </div>
          <div>
            <div class="step-number-tag" style="color: ${check.accentColor}; display: flex; align-items: center; gap: 8px;">
              <span>STEP ${index + 1} OF ${SECURITY_CHECKS.length}</span>
              <span style="opacity: 0.5;">•</span>
              <span>${check.categoryTag}</span>
            </div>
            <h2 class="check-title">${check.title}</h2>
            <div style="color: var(--text-secondary); font-size: 0.92rem;">${check.shortDesc}</div>
          </div>
        </div>
        <div class="check-weight-badge" style="border-color: ${check.accentColor}; color: ${check.accentColor};">Weight: ${check.weight} Points</div>
      </div>

      <div class="audit-card-body">
        <!-- Why checking box: Explains threat model in accessible terms -->
        <div class="why-box">
          <div class="why-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="16" x2="12" y2="12"></line>
              <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>
          </div>
          <div>
            <div class="why-title">Why are we checking this?</div>
            <div class="why-text">${check.why}</div>
          </div>
        </div>

        <!-- Step Instructions: Safe execution workflow -->
        <div class="execution-steps">
          <div class="instruction-step">
            <div class="step-num-bubble">1</div>
            <div class="instruction-content">
              <div class="instruction-label">Open Command Prompt as Administrator</div>
              <div class="admin-open-steps" style="margin-top: 8px; display: flex; flex-direction: column; gap: 8px; font-size: 0.88rem; color: var(--text-secondary); line-height: 1.5;">
                <div style="display: flex; align-items: flex-start; gap: 8px;">
                  <span style="color: var(--accent-cyan); font-weight: 700; flex-shrink: 0;">•</span>
                  <span>Click the Windows Start button or press the Windows key.</span>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 8px;">
                  <span style="color: var(--accent-cyan); font-weight: 700; flex-shrink: 0;">•</span>
                  <span>Type cmd into the search bar.</span>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 8px;">
                  <span style="color: var(--accent-cyan); font-weight: 700; flex-shrink: 0;">•</span>
                  <span>Right-click the Command Prompt result and select Run as administrator.</span>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 8px;">
                  <span style="color: var(--accent-cyan); font-weight: 700; flex-shrink: 0;">•</span>
                  <span>Click Yes on the User Account Control (UAC) prompt to allow elevated permissions.</span>
                </div>
              </div>
            </div>
          </div>

          <div class="instruction-step">
            <div class="step-num-bubble">2</div>
            <div class="instruction-content">
              <div class="instruction-label">Copy this command:</div>
              <div class="command-box">
                <code class="command-code" id="cmd-text-${check.id}">${check.command}</code>
                <button class="btn-copy" id="btn-copy-${check.id}" onclick="copyCheckCommand('${check.id}')">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                  </svg>
                  <span>Copy Command</span>
                </button>
              </div>
            </div>
          </div>

          <div class="instruction-step">
            <div class="step-num-bubble">3</div>
            <div class="instruction-content">
              <div class="instruction-label">Run the command in PowerShell</div>
              <div class="instruction-hint">Paste into the Administrator PowerShell window and press <strong>Enter</strong>.</div>
            </div>
          </div>

          <div class="instruction-step">
            <div class="step-num-bubble">4</div>
            <div class="instruction-content">
              <div class="instruction-label">Copy the complete output</div>
              <div class="instruction-hint">Highlight all the text returned by PowerShell and copy it (Ctrl + C).</div>
            </div>
          </div>

          <div class="instruction-step">
            <div class="step-num-bubble">5</div>
            <div class="instruction-content output-input-section">
              <div class="output-helper-bar">
                <div class="output-helper-title">Paste it below:</div>
                <div class="output-action-pills">
                  <button class="btn-sample-pill" onclick="clearOutputText('${check.id}')">
                    🗑️ Clear
                  </button>
                </div>
              </div>

              <textarea 
                class="output-textarea" 
                id="output-textarea-${check.id}" 
                placeholder="Paste PowerShell output here... (e.g., Name : Domain, Enabled : True...)"
                rows="6"
                oninput="onOutputChanged('${check.id}')"
              ></textarea>

              <div id="sensitive-alert-${check.id}" class="sensitive-alert" style="display: none;"></div>
              <div id="parse-error-${check.id}" class="parse-error-alert" style="display: none;"></div>
            </div>
          </div>
        </div>

        <!-- Action Buttons -->
        <div class="audit-actions-bar">
          <div class="action-left">
            ${index > 0 ? `
              <button class="btn btn-secondary btn-sm" onclick="goToStep(${index - 1})">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
                Previous Check
              </button>
            ` : ""}
            <button class="btn btn-secondary btn-sm" onclick="skipCheck('${check.id}')">
              ⏭️ Skip This Check
            </button>
          </div>
          <div class="action-right">
            <button class="btn btn-primary" id="btn-analyze-${check.id}" onclick="analyzeCurrentCheck('${check.id}')">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
              Analyze Result
            </button>
          </div>
        </div>

        <!-- Result Container: Shows card upon successful analysis -->
        <div id="result-container-${check.id}">
          ${existingResult && !existingResult.skipped ? renderResultCardHtml(existingResult) : ""}
        </div>
      </div>
    </div>
  `;

  // Ensure next/previous page starts from the very top
  scrollAuditToTop();
}

/**
 * Updates the horizontal progress stepper bar showing:
 * - Current active step with neon cyan glow.
 * - Completed steps with green checkmarks.
 * - Skipped steps with a dash indicator.
 */
function renderStepper() {
  const stepper = document.getElementById("stepperContainer");
  const bar = document.getElementById("progressBarFill");
  if (!stepper) return;

  const total = SECURITY_CHECKS.length;
  const current = AppState.activeStepIndex;
  const percent = Math.round(((current) / (total - 1)) * 100);
  if (bar) bar.style.width = `${percent}%`;

  let html = "";
  SECURITY_CHECKS.forEach((c, idx) => {
    const isDone = AppState.results[c.id] && !AppState.results[c.id].skipped;
    const isSkipped = AppState.results[c.id]?.skipped;
    const isActive = idx === current;

    let badgeContent = `${idx + 1}`;
    if (isDone) badgeContent = "✓";
    if (isSkipped) badgeContent = "—";

    let stateClass = "";
    if (isActive) stateClass = "active";
    else if (isDone) stateClass = "completed";

    html += `
      <div class="step-indicator-item ${stateClass}" onclick="goToStep(${idx})" title="${c.title}">
        <div class="step-badge-circle">${badgeContent}</div>
        <span>${c.title}</span>
      </div>
    `;
  });

  stepper.innerHTML = html;
}

/**
 * Navigates directly to a specific step index in the audit flow.
 * @param {number} idx - Check index (0 to 5).
 */
function goToStep(idx) {
  if (idx >= 0 && idx < SECURITY_CHECKS.length) {
    renderAuditStep(idx);
    scrollAuditToTop();
  }
}

// --------------------------------------------------------------------------
// HTML & ATTRIBUTE ESCAPING UTILITIES
// --------------------------------------------------------------------------
/**
 * Escapes unsafe characters for HTML rendering to prevent XSS.
 * @param {string} str - Raw string.
 * @returns {string} Sanitized string safe for HTML text.
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Escapes unsafe characters for HTML attribute values.
 * @param {string} str - Raw string.
 * @returns {string} Sanitized string.
 */
function escapeAttr(str) {
  return escapeHtml(str);
}

// --------------------------------------------------------------------------
// CLIPBOARD COPY UTILITIES
// --------------------------------------------------------------------------
/**
 * Copies text to the system clipboard with visual button state feedback.
 * Includes fallback textarea copy method for sandboxed iframes or older browsers.
 * 
 * @param {string} text - Command or snippet to copy.
 * @param {string} btnId - ID of button triggering copy.
 */
function copyCommand(text, btnId) {
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(btnId);
    if (btn) {
      btn.classList.add("copied");
      const span = btn.querySelector("span");
      if (span) span.textContent = "Copied!";
      setTimeout(() => {
        btn.classList.remove("copied");
        if (span) span.textContent = "Copy Command";
      }, 2000);
    }
  }).catch(() => {
    // Fallback if clipboard API permission is blocked in iframe
    const input = document.createElement("textarea");
    input.value = text;
    document.body.appendChild(input);
    input.select();
    document.execCommand("copy");
    document.body.removeChild(input);
    const btn = document.getElementById(btnId);
    if (btn) {
      btn.classList.add("copied");
      const span = btn.querySelector("span");
      if (span) span.textContent = "Copied!";
      setTimeout(() => {
        btn.classList.remove("copied");
        if (span) span.textContent = "Copy Command";
      }, 2000);
    }
  });
}

/**
 * Safely copies the audit command for a specific check by lookup.
 * @param {string} checkId - Check identifier.
 */
function copyCheckCommand(checkId) {
  const chk = SECURITY_CHECKS.find(c => c.id === checkId);
  if (chk && chk.command) {
    copyCommand(chk.command, `btn-copy-${checkId}`);
  }
}

/**
 * Safely copies the diagnosed remediation command for an audit result.
 * @param {string} checkId - Check identifier.
 */
function copyRemediation(checkId) {
  const res = AppState.results[checkId];
  if (res && res.remediationCmd) {
    copyCommand(res.remediationCmd, `btn-copy-rem-${checkId}`);
  }
}

/**
 * Safely copies remediation command from the final report view.
 * @param {string} checkId - Check identifier.
 * @param {string} btnId - Button DOM ID.
 */
function copyReportRemediation(checkId, btnId) {
  const res = AppState.results[checkId];
  if (res && res.remediationCmd) {
    copyCommand(res.remediationCmd, btnId);
  }
}

/**
 * Clears the textarea and deletes any stored evaluation result for this check.
 * @param {string} checkId - Check identifier.
 */
function clearOutputText(checkId) {
  const textarea = document.getElementById(`output-textarea-${checkId}`);
  if (textarea) {
    textarea.value = "";
    onOutputChanged(checkId);
  }
  const resultContainer = document.getElementById(`result-container-${checkId}`);
  if (resultContainer) resultContainer.innerHTML = "";
  delete AppState.results[checkId];
  renderStepper();
}

/**
 * Input event listener for textarea:
 * Real-time scan for accidental credentials or private keys.
 * @param {string} checkId - Check identifier.
 */
function onOutputChanged(checkId) {
  const textarea = document.getElementById(`output-textarea-${checkId}`);
  const sensitiveAlert = document.getElementById(`sensitive-alert-${checkId}`);
  const parseError = document.getElementById(`parse-error-${checkId}`);
  if (!textarea) return;

  if (parseError) parseError.style.display = "none";

  const sensitive = SecurityAnalyzer.checkSensitiveInfo(textarea.value);
  if (sensitiveAlert) {
    if (sensitive) {
      sensitiveAlert.style.display = "flex";
      sensitiveAlert.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
        <span><strong>Sensitive Token Detected:</strong> Found potential <em>${sensitive}</em> in pasted text. Please remove any secrets or passwords before analyzing.</span>
      `;
    } else {
      sensitiveAlert.style.display = "none";
    }
  }
}

/**
 * Marks a check as skipped by the user and advances to the next step.
 * @param {string} checkId - Check identifier.
 */
function skipCheck(checkId) {
  AppState.results[checkId] = {
    checkId,
    skipped: true
  };
  renderStepper();
  proceedToNextStep();
}

/**
 * Main Controller for analyzing pasted terminal output for current check:
 * 1. Checks that input is not empty.
 * 2. Passes text to `SecurityAnalyzer.analyze(checkId, text)`.
 * 3. If parsing fails, detects PowerShell elevation/cmdlet errors and renders troubleshooting cards.
 * 4. On success, persists result in AppState and renders the finding card.
 * 
 * @param {string} checkId - Check identifier.
 */
function analyzeCurrentCheck(checkId) {
  const textarea = document.getElementById(`output-textarea-${checkId}`);
  const parseError = document.getElementById(`parse-error-${checkId}`);
  const resultContainer = document.getElementById(`result-container-${checkId}`);

  if (!textarea) return;
  const rawText = textarea.value;

  if (!rawText || rawText.trim().length < 5) {
    if (parseError) {
      parseError.style.display = "flex";
      parseError.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
        <div>Please paste the output from PowerShell before analyzing.</div>
      `;
    }
    return;
  }

  const analysis = SecurityAnalyzer.analyze(checkId, rawText);

  if (!analysis) {
    if (parseError) {
      const errDetails = SecurityAnalyzer.detectPowerShellError(rawText);
      parseError.style.display = "flex";
      if (errDetails) {
        parseError.innerHTML = `
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
          <div>
            <strong style="color: #ef4444; font-size: 1rem;">${errDetails.title}</strong><br>
            <span style="font-size: 0.9rem; line-height: 1.5;">${errDetails.message}</span>
            <div style="margin-top: 8px; font-size: 0.85rem; background: rgba(0,0,0,0.3); padding: 8px 12px; border-radius: 6px; border: 1px solid var(--border-color);">
              <strong>How to fix:</strong> ${errDetails.fix}
            </div>
          </div>
        `;
      } else {
        parseError.innerHTML = `
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
          <div>
            <strong>Unable to confidently analyze this output.</strong><br>
            Please make sure you copied the complete PowerShell result. Check that you ran the exact command as Administrator and that the command produced text.
          </div>
        `;
      }
    }
    return;
  }

  // Success! Store result
  if (parseError) parseError.style.display = "none";
  AppState.results[checkId] = analysis;
  renderStepper();

  if (resultContainer) {
    resultContainer.innerHTML = renderResultCardHtml(analysis);
    resultContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

/**
 * Generates the HTML card markup for displaying an analysis result.
 * Colors and badges depend on the status ('secure', 'warning', or 'danger').
 * Displays:
 * - Status badge (Secure, Needs Attention, High Risk)
 * - Severity and CVSS score
 * - Primary finding headline
 * - 4-part breakdown: What we found, Why it matters, Recommended action (with 1-click copy fix), Evidence snippet
 * 
 * @param {object} result - Analysis result object from SecurityAnalyzer.
 * @returns {string} HTML string.
 */
function renderResultCardHtml(result) {
  let statusBadge = "";
  let cardClass = "";

  if (result.status === "secure") {
    cardClass = "secure";
    statusBadge = `🟢 SECURE`;
  } else if (result.status === "warning") {
    cardClass = "warning";
    statusBadge = `🟡 NEEDS ATTENTION`;
  } else {
    cardClass = "danger";
    statusBadge = `🔴 HIGH RISK`;
  }

  const isLastCheck = AppState.activeStepIndex === SECURITY_CHECKS.length - 1;

  return `
    <div class="result-card ${cardClass}">
      <div class="result-header">
        <div class="result-status-pill">${statusBadge}</div>
        <div class="severity-tag">Severity: <strong>${result.severity}</strong> (CVSS: ${result.cvss})</div>
      </div>

      <div class="result-finding-title">${result.finding}</div>

      <div class="result-grid">
        <div class="result-section-box">
          <div class="result-section-label">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
            What we found
          </div>
          <div class="result-section-content">${result.whatWeFound}</div>
        </div>

        <div class="result-section-box">
          <div class="result-section-label">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path></svg>
            Why it matters
          </div>
          <div class="result-section-content">${result.whyItMatters}</div>
        </div>

        <div class="result-section-box">
          <div class="result-section-label">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"></polyline><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>
            Recommended action
          </div>
          <div class="result-section-content">
            ${result.recommendedAction}
            ${result.remediationCmd ? `
              <div class="remediation-code-box">
                <code>${escapeHtml(result.remediationCmd)}</code>
                <button class="btn-copy" onclick="copyRemediation('${result.checkId}')" id="btn-copy-rem-${result.checkId}">
                  Copy Fix
                </button>
              </div>
            ` : ""}
          </div>
        </div>

        <div class="result-section-box">
          <div class="result-section-label">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
            Evidence detected from your PowerShell output
          </div>
          <div class="evidence-quote-box">${escapeHtml(result.evidence)}</div>
        </div>
      </div>

      <div style="display: flex; justify-content: flex-end; gap: 12px; margin-top: 18px;">
        <button class="btn btn-primary" onclick="proceedToNextStep()">
          ${isLastCheck ? "View Final Security Dashboard 🏁" : "Continue to Next Check ➡️"}
        </button>
      </div>
    </div>
  `;
}

/**
 * Advances the user to the next audit check step, or switches
 * to the final Dashboard if all 6 checks have been reached.
 */
function proceedToNextStep() {
  if (AppState.activeStepIndex < SECURITY_CHECKS.length - 1) {
    goToStep(AppState.activeStepIndex + 1);
  } else {
    switchView("dashboard");
  }
}

// ============================================================================
// SECTION 5: SECURITY SCORING ALGORITHM & DASHBOARD RENDERING
// ============================================================================
/**
 * Computes the overall security score and risk classification.
 * - Aggregates points earned across completed checks.
 * - Normalizes score on a 0-100 scale based on assessed check weights.
 * - Classifies posture into LOW, MODERATE, CRITICAL risk or NOT ASSESSED (if all skipped).
 * 
 * @returns {object} Calculated metrics, final score, risk tier, and summary text.
 */
function computeSecurityScore() {
  let earnedScore = 0;
  let totalAssessedWeight = 0;
  let secureCount = 0;
  let warningCount = 0;
  let dangerCount = 0;
  let skippedCount = 0;

  SECURITY_CHECKS.forEach(check => {
    const res = AppState.results[check.id];
    if (!res || res.skipped) {
      skippedCount++;
    } else {
      totalAssessedWeight += check.weight;
      earnedScore += res.score;
      if (res.status === "secure") secureCount++;
      else if (res.status === "warning") warningCount++;
      else if (res.status === "danger") dangerCount++;
    }
  });

  const isUnavailable = totalAssessedWeight === 0 || skippedCount === SECURITY_CHECKS.length;

  // Calculate normalized 0-100 score based on checks completed
  let finalScore = 0;
  if (!isUnavailable) {
    finalScore = Math.round((earnedScore / totalAssessedWeight) * 100);
  }

  let overallRisk = "LOW";
  let riskClass = "risk-secure";
  let riskLabel = "🟢 LOW RISK – SYSTEM HARDENED";
  let riskSummary = "Your Windows workstation demonstrates strong cybersecurity hygiene across the assessed parameters.";

  if (isUnavailable) {
    overallRisk = "NOT ASSESSED";
    riskClass = "risk-unassessed";
    riskLabel = "⚪ SCORE UNAVAILABLE – CHECKS SKIPPED";
    riskSummary = "All security audit checks were skipped. A security score cannot be calculated until at least one test has been analyzed.";
  } else if (dangerCount >= 2 || finalScore < 60) {
    overallRisk = "CRITICAL";
    riskClass = "risk-danger";
    riskLabel = "🔴 HIGH RISK – CRITICAL WEAKNESSES DETECTED";
    riskSummary = "Urgent vulnerabilities were detected that could expose your machine to unauthorized network access, data theft, or malware propagation.";
  } else if (dangerCount === 1 || warningCount >= 2 || finalScore < 85) {
    overallRisk = "MODERATE";
    riskClass = "risk-warning";
    riskLabel = "🟡 MODERATE RISK – REMEDIATION REQUIRED";
    riskSummary = "Notable security gaps or misconfigurations require attention to harden your operating system against common attack vectors.";
  }

  return {
    score: isUnavailable ? null : finalScore,
    isUnavailable,
    scoreDisplay: isUnavailable ? "Score Unavailable" : `${finalScore} / 100`,
    earnedScore,
    totalAssessedWeight,
    secureCount,
    warningCount,
    dangerCount,
    skippedCount,
    overallRisk,
    riskClass,
    riskLabel,
    riskSummary
  };
}

/**
 * Renders the interactive Security Posture Dashboard:
 * - Circular HUD score gauge with color dynamics (Green / Amber / Red)
 * - Overall risk rating and summary diagnosis
 * - Metric pills (Secure, Attention, High Risk, Skipped)
 * - 6-card grid for individual security dimensions with re-test navigation
 * - Quick action buttons (Generate Report, Reset Audit)
 */
function renderDashboard() {
  const container = document.getElementById("dashboardContent");
  if (!container) return;

  const scoreData = computeSecurityScore();

  let scoreColor = "var(--secure-green)";
  if (!scoreData.isUnavailable) {
    if (scoreData.score < 60) scoreColor = "var(--danger-red)";
    else if (scoreData.score < 85) scoreColor = "var(--warning-yellow)";
  }

  let checksGridHtml = "";
  SECURITY_CHECKS.forEach(c => {
    const res = AppState.results[c.id];
    let statusPill = `<span class="stat-pill" style="color: var(--text-muted);">⚪ Not Assessed</span>`;
    let findingText = "This check was not performed or was skipped.";
    let scoreBadge = `0 / ${c.weight} pts`;

    if (res && !res.skipped) {
      scoreBadge = `${res.score} / ${c.weight} pts`;
      if (res.status === "secure") {
        statusPill = `<span class="stat-pill" style="color: var(--secure-green); border-color: var(--secure-green-border); background: var(--secure-green-bg);">🟢 Secure</span>`;
      } else if (res.status === "warning") {
        statusPill = `<span class="stat-pill" style="color: var(--warning-yellow); border-color: var(--warning-yellow-border); background: var(--warning-yellow-bg);">🟡 Needs Attention</span>`;
      } else {
        statusPill = `<span class="stat-pill" style="color: var(--danger-red); border-color: var(--danger-red-border); background: var(--danger-red-bg);">🔴 High Risk</span>`;
      }
      findingText = res.finding;
    }

    checksGridHtml += `
      <div class="check-status-card ${c.themeClass}">
        <div class="check-status-top">
          <div style="display: flex; align-items: center; gap: 10px;">
            <div class="check-status-icon" style="width: 36px; height: 36px; border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: center; font-size: 1.15rem; background: rgba(255, 255, 255, 0.05); border: 1px solid var(--border-cyber); flex-shrink: 0;">
              ${c.icon}
            </div>
            <div>
              <div class="check-status-title">${c.title}</div>
              <div style="font-size: 0.74rem; color: var(--text-muted); font-family: var(--font-mono); letter-spacing: 0.03em;">${c.categoryTag} • ${c.shortDesc}</div>
            </div>
          </div>
          ${statusPill}
        </div>
        <div class="check-status-desc">${findingText}</div>
        <div class="check-status-footer">
          <span style="color: var(--text-muted);">Score Contribution: <strong style="color: ${c.accentColor};">${scoreBadge}</strong></span>
          <button class="btn btn-secondary btn-sm" onclick="goToStep(${c.step - 1}); switchView('audit');">
            Inspect / Re-test ➔
          </button>
        </div>
      </div>
    `;
  });

  container.innerHTML = `
    <div class="dashboard-hero-card">
      <div class="score-display-column">
        ${scoreData.isUnavailable ? `
          <div class="score-circle-wrapper unassessed">
            <div class="score-number" style="color: var(--text-secondary); font-size: 1.35rem; line-height: 1.25; text-align: center; font-family: var(--font-mono); padding: 0 6px;">
              Score<br>Unavailable
            </div>
            <div class="score-max" style="margin-top: 6px;">0 of 6 assessed</div>
          </div>
          <div class="score-label" style="color: var(--text-muted);">Score Unavailable</div>
        ` : `
          <div class="score-circle-wrapper" style="border-color: ${scoreColor};">
            <div class="score-number" style="color: ${scoreColor};">${scoreData.score}</div>
            <div class="score-max">/ 100</div>
          </div>
          <div class="score-label">Your Security Score</div>
        `}
      </div>

      <div class="dashboard-summary-column">
        <div class="overall-risk-badge ${scoreData.riskClass}">${scoreData.riskLabel}</div>
        <div class="risk-summary-text">${scoreData.riskSummary}</div>

        <div class="stats-pill-row">
          <div class="stat-pill stat-pill-secure">🟢 Secure Checks: <strong>${scoreData.secureCount}</strong></div>
          <div class="stat-pill stat-pill-warning">🟡 Needs Attention: <strong>${scoreData.warningCount}</strong></div>
          <div class="stat-pill stat-pill-danger">🔴 High-Risk Findings: <strong>${scoreData.dangerCount}</strong></div>
          <div class="stat-pill stat-pill-skipped">⚪ Skipped (Not Assessed): <strong>${scoreData.skippedCount}</strong></div>
        </div>

        <div class="dashboard-actions-row">
          <button class="btn btn-primary" onclick="switchView('report')">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
            Generate Security Report
          </button>


          <button class="btn btn-outline-danger" onclick="resetAllData()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"></path><path d="M21 3v5h-5"></path><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"></path><path d="M8 16H3v5"></path></svg>
            Reset Audit
          </button>
        </div>
      </div>
    </div>

    <h3 style="font-size: 1.3rem; font-weight: 700; margin-bottom: 18px;">Audit Dimension Breakdown</h3>
    <div class="checks-status-grid">
      ${checksGridHtml}
    </div>
  `;
}

// ============================================================================
// SECTION 6: COMPREHENSIVE FINAL SECURITY REPORT
// ============================================================================
/**
 * Renders the full interactive Audit Report in the web UI:
 * - Official header banner with brand logo and PDF download action
 * - Executive metadata cards (Report Date, Score, Risk Level, Audit Scope)
 * - Section 1: Flaws Found / Vulnerability Diagnosis (CVSS, evidence quotes)
 * - Section 2: Remediation Actions / Hardening Steps (1-click PowerShell copy)
 */
function renderReport() {
  const container = document.getElementById("reportContent");
  if (!container) return;

  const scoreData = computeSecurityScore();
  const dateStr = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric", hour: "2-digit", minute: "2-digit" });

  // Gather flaws / vulnerabilities
  const flaws = [];
  const remediations = [];

  SECURITY_CHECKS.forEach(c => {
    const res = AppState.results[c.id];
    if (res && !res.skipped && res.status !== "secure") {
      flaws.push({
        check: c,
        result: res
      });
      remediations.push({
        check: c,
        result: res
      });
    }
  });

  let flawsHtml = "";
  if (flaws.length === 0) {
    flawsHtml = `
      <div style="background-color: var(--secure-green-bg); border: 1px solid var(--secure-green-border); border-radius: var(--radius-md); padding: 20px; color: var(--secure-green);">
        <strong>No High-Risk Flaws or Warnings Identified:</strong> All completed checks passed baseline hardening requirements.
      </div>
    `;
  } else {
    flaws.forEach((item, idx) => {
      const { check, result } = item;
      const severityColor = result.severity === "High" ? "var(--danger-red)" : "var(--warning-yellow)";

      flawsHtml += `
        <div class="flaw-item-card ${check.themeClass}">
          <div class="flaw-header">
            <div class="flaw-title" style="display: flex; align-items: center; gap: 8px;">
              <span>${check.icon}</span>
              <span>${idx + 1}. ${result.finding}</span>
            </div>
            <span class="severity-tag" style="border-color: ${severityColor}; color: ${severityColor};">
              ${result.severity} (CVSS: ${result.cvss})
            </span>
          </div>
          <div class="flaw-body-grid">
            <div><strong>Audit Scope:</strong> <span style="color: ${check.accentColor}; font-weight: 700;">${check.title}</span> (${check.command})</div>
            <div><strong>Diagnosis / Explanation:</strong> ${result.whatWeFound}</div>
            <div><strong>Vulnerability Risk:</strong> ${result.whyItMatters}</div>
            <div>
              <strong>Evidence Detected from PowerShell Output:</strong>
              <div class="evidence-quote-box">${result.evidence}</div>
            </div>
          </div>
        </div>
      `;
    });
  }

  let remediationHtml = "";
  if (remediations.length === 0) {
    remediationHtml = `
      <div style="background-color: var(--bg-surface-elevated); border-radius: var(--radius-md); padding: 20px; color: var(--text-secondary);">
        No remediation actions required. Your baseline configuration conforms to standard Windows cybersecurity best practices.
      </div>
    `;
  } else {
    remediations.forEach((item, idx) => {
      const { check, result } = item;
      remediationHtml += `
        <div class="remediation-item-card ${check.themeClass}">
          <div class="remediation-title" style="display: flex; align-items: center; gap: 8px; color: ${check.accentColor};">
            <span>${check.icon}</span>
            <span>Action #${idx + 1}: ${check.title} Remediation</span>
          </div>
          <p style="font-size: 0.92rem; color: var(--text-secondary); margin-bottom: 10px;">
            <strong>Recommended Fix:</strong> ${result.recommendedAction}
          </p>
          ${result.remediationCmd ? `
            <div class="remediation-code-box">
              <code>${escapeHtml(result.remediationCmd)}</code>
              <button class="btn-copy" onclick="copyReportRemediation('${check.id}', 'btn-copy-rep-${idx}')" id="btn-copy-rep-${idx}">
                Copy Remediation
              </button>
            </div>
          ` : ""}
          <p style="font-size: 0.86rem; color: var(--text-muted); margin-top: 10px;">
            <strong>Why this improves security:</strong> Reduces unauthorized remote interaction, protects data at rest, and applies the Principle of Least Privilege.
          </p>
        </div>
      `;
    });
  }

  container.innerHTML = `
    <div class="report-document-container">
      <div class="report-header-banner">
        <div>
          <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 8px;">
            <div class="brand-icon-wrapper" style="width: 44px; height: 44px; background: #ffffff; border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: center; overflow: hidden; padding: 2px; flex-shrink: 0; box-shadow: 0 0 14px rgba(0, 240, 255, 0.4); border: 1px solid var(--border-cyber);">
              <img src="/web-logo.jpg" alt="SecureCheck Shield Logo" class="brand-logo-img" style="width: 100%; height: 100%; object-fit: contain; display: block;" />
            </div>
            <div>
              <h1 style="font-size: 1.75rem; font-weight: 800; line-height: 1.2;">SecureCheck Security Assessment Report</h1>
              <span style="font-size: 0.76rem; color: var(--accent-cyan); display: block; font-weight: 600; font-family: var(--font-mono); letter-spacing: 0.05em; text-transform: uppercase;">secure your windows</span>
            </div>
          </div>
          <div style="color: var(--text-secondary); font-size: 0.95rem; margin-top: 4px;">Windows Security Health & Vulnerability Diagnosis</div>
        </div>

        <button class="btn btn-primary" onclick="generatePdfReport(event)">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
          Download Security Report as PDF
        </button>
      </div>

      <div class="report-meta-grid">
        <div class="report-meta-item">
          <label>Report Date</label>
          <strong>${dateStr}</strong>
        </div>
        <div class="report-meta-item">
          <label>Security Score</label>
          <strong style="font-size: 1.15rem; color: ${scoreData.isUnavailable ? 'var(--text-secondary)' : 'var(--accent-cyan)'};">
            ${scoreData.isUnavailable ? 'Score Unavailable' : `${scoreData.score} / 100`}
          </strong>
        </div>
        <div class="report-meta-item">
          <label>Overall Risk Level</label>
          <span class="stat-pill ${scoreData.riskClass}" style="padding: 2px 8px; font-size: 0.78rem;">${scoreData.overallRisk}</span>
        </div>
        <div class="report-meta-item">
          <label>Audit Scope</label>
          <strong>${6 - scoreData.skippedCount} of 6 Checks Completed</strong>
        </div>
      </div>

      <!-- SECTION 1: FLAWS FOUND -->
      <div class="report-section-title">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
        1. Flaws Found / Diagnosis
      </div>
      ${flawsHtml}

      <!-- SECTION 2: REMEDIATION ACTIONS -->
      <div class="report-section-title">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"></polyline><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>
        2. Remediation Actions / Treatment
      </div>
      ${remediationHtml}

      <!-- DEVELOPER SIGNATURE BLOCK -->
      <div class="report-signoff-row" style="display: flex; justify-content: flex-end; margin: 32px 0 16px 0;">
        <div class="signature-block-placeholder" id="reportSignatureBlock" style="margin: 0 0 0 auto;">
          <img src="/digital-sign-2-cropped.png" alt="digital sign 2 img" class="signature-block-img" id="digitalSign2Img" onerror="this.src='/digital-sign-2.png'" />
          <div class="signature-block-role">devloper</div>
          <div class="signature-block-org">SecureCheck</div>
        </div>
      </div>
    </div>
  `;
}

// ============================================================================
// SECTION 7: CLIENT-SIDE CRYPTOGRAPHICALLY CERTIFIED PDF REPORT EXPORT (JSPDF)
// ============================================================================
/**
 * Safely loads an image asset from a URL and converts it to an optimized base64 Data URL via canvas.
 * Preserves transparency for PNGs and avoids browser CORS/tainting issues.
 * 
 * @param {string} url - Image path or relative URL.
 * @param {number} maxWidth - Maximum target canvas width.
 * @param {number} maxHeight - Maximum target canvas height.
 * @returns {Promise<object|null>} { dataUrl, width, height, aspect, format }
 */
function loadImageAsBase64(url, maxWidth = 800, maxHeight = 800) {
  return new Promise((resolve) => {
    const img = new Image();
    img.crossOrigin = "Anonymous";
    img.onload = () => {
      try {
        let width = img.naturalWidth || img.width;
        let height = img.naturalHeight || img.height;
        if (width > maxWidth || height > maxHeight) {
          const ratio = Math.min(maxWidth / width, maxHeight / height);
          width = Math.round(width * ratio);
          height = Math.round(height * ratio);
        }
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext("2d");
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(0, 0, width, height);
        ctx.drawImage(img, 0, 0, width, height);
        const mimeType = url.toLowerCase().includes(".png") ? "image/png" : "image/jpeg";
        const dataUrl = canvas.toDataURL(mimeType, 0.95);
        resolve({
          dataUrl,
          width,
          height,
          aspect: width / height,
          format: mimeType === "image/png" ? "PNG" : "JPEG"
        });
      } catch (err) {
        console.warn("Canvas export failed for image:", url, err);
        resolve(null);
      }
    };
    img.onerror = () => {
      console.warn("Could not load image at:", url);
      resolve(null);
    };
    img.src = url;
  });
}

/**
 * Client-Side PDF Report Generator:
 * Uses jsPDF and autoTable plugin to render an executive cybersecurity assessment document:
 * 1. Branded Header: Navy header bar with brand logo, report title, date, and slogan.
 * 2. Executive Score Card: Overall health score (0-100), risk tier badge, breakdown metrics.
 * 3. Scope & Findings Summary Table: Dimension name, evaluation status, score points, finding.
 * 4. Section 1: Flaws Found & Diagnosis with CVSS risk classification and PowerShell evidence quotes.
 * 5. Section 2: Remediation Actions & Hardening Steps with actionable PowerShell scripts.
 * 6. Bottom Signature Block: developer title, SecureCheck brand, and digital certification image.
 * 7. Running Headers, Page Numbers, and Legal Disclaimers across multi-page layouts.
 * 
 * @param {Event} e - Button click event.
 */
async function generatePdfReport(e) {
  if (typeof window.jspdf === "undefined" && typeof window.jsPDF === "undefined") {
    alert("PDF library is loading from CDN. Please check your internet connection and try again.");
    return;
  }

  // Visual button state: show loading spinner while generating
  const targetBtn = e && e.target ? e.target.closest("button") : null;
  const originalBtnHtml = targetBtn ? targetBtn.innerHTML : "";
  if (targetBtn) {
    targetBtn.disabled = true;
    targetBtn.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation: spin 1s linear infinite;"><circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle><path d="M12 2a10 10 0 0 1 10 10" stroke-opacity="0.75"></path></svg>
      Generating PDF...
    `;
  }

  try {
    // Pre-load application logo and digital sign
    let [logoImgData, signImgData] = await Promise.all([
      loadImageAsBase64("/web-logo.jpg", 300, 300),
      loadImageAsBase64("/digital-sign-2-cropped.png", 600, 300)
    ]);
    if (!signImgData) {
      signImgData = await loadImageAsBase64("/digital-sign-2.png", 600, 300);
    }

    const { jsPDF } = window.jspdf || window;
    const doc = new jsPDF({
      orientation: "portrait",
      unit: "pt",
      format: "a4"
    });

    const scoreData = computeSecurityScore();
    const dateStr = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric", hour: "2-digit", minute: "2-digit" });

    const primaryColor = [15, 23, 42]; // #0f172a
    const accentColor = [14, 165, 233]; // #0ea5e9
    const textDark = [30, 41, 59]; // #1e293b
    const textMuted = [100, 116, 139]; // #64748b

    // Page 1: Header & Executive Summary
    doc.setFillColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    doc.rect(0, 0, 595.28, 84, "F");

    // Cyan accent bottom border on header
    doc.setFillColor(accentColor[0], accentColor[1], accentColor[2]);
    doc.rect(0, 82, 595.28, 2, "F");

    // Add Logo in Header at the top
    let titleStartX = 40;
    if (logoImgData) {
      doc.setFillColor(255, 255, 255);
      doc.roundedRect(40, 14, 52, 52, 4, 4, "F");
      doc.addImage(logoImgData.dataUrl, "JPEG", 42, 16, 48, 48);
      titleStartX = 104;
    }

    // Title in Header
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.text("SecureCheck", titleStartX, 36);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.2);
    doc.setTextColor(203, 213, 225);
    doc.text("Windows Security Health & Vulnerability Assessment Report", titleStartX, 51);

    doc.setFontSize(7.5);
    doc.setTextColor(56, 189, 248);
    doc.text("SECURE YOUR WINDOWS  •  OFFICIAL ASSESSMENT", titleStartX, 64);

    // Date in Header right
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.setTextColor(203, 213, 225);
    doc.text(dateStr, 555, 46, { align: "right" });

    let y = 96;

    // Executive Score Box
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.8);
    doc.roundedRect(40, y, 515, 86, 6, 6, "FD");

    if (scoreData.isUnavailable) {
      doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(20);
      doc.text("Unavailable", 65, y + 46);

      doc.setFontSize(8);
      doc.text("ALL CHECKS SKIPPED", 65, y + 64);

      doc.setDrawColor(226, 232, 240);
      doc.line(165, y + 10, 165, y + 76);

      doc.setFont("helvetica", "bold");
      doc.setFontSize(13);
      doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
      doc.text("Overall Risk Level: NOT ASSESSED", 180, y + 28);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(textDark[0], textDark[1], textDark[2]);
      const splitSummary = doc.splitTextToSize(scoreData.riskSummary, 350);
      doc.text(splitSummary, 180, y + 44);

      doc.setFontSize(8.5);
      doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
      doc.text(`Secure: 0   |   Needs Attention: 0   |   High-Risk: 0   |   Skipped: 6`, 180, y + 70);
    } else {
      // Score Number
      let scoreRgb = [16, 185, 129];
      if (scoreData.score < 60) scoreRgb = [239, 68, 68];
      else if (scoreData.score < 85) scoreRgb = [245, 158, 11];

      doc.setTextColor(scoreRgb[0], scoreRgb[1], scoreRgb[2]);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(34);
      doc.text(`${scoreData.score}`, 68, y + 50);

      doc.setFontSize(12);
      doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
      doc.text("/ 100", 118, y + 46);

      doc.setFontSize(8);
      doc.text("SECURITY HEALTH SCORE", 58, y + 68);

      // Subtle vertical divider between score and breakdown
      doc.setDrawColor(226, 232, 240);
      doc.line(165, y + 10, 165, y + 76);

      // Overall Risk Text
      doc.setFont("helvetica", "bold");
      doc.setFontSize(13);
      doc.setTextColor(scoreRgb[0], scoreRgb[1], scoreRgb[2]);
      doc.text(`Overall Risk Level: ${scoreData.overallRisk}`, 180, y + 26);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(textDark[0], textDark[1], textDark[2]);
      const splitSummary = doc.splitTextToSize(scoreData.riskSummary, 350);
      doc.text(splitSummary, 180, y + 42);

      // Metrics summary
      doc.setFontSize(8.5);
      doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
      doc.text(`Secure: ${scoreData.secureCount}   |   Needs Attention: ${scoreData.warningCount}   |   High-Risk: ${scoreData.dangerCount}   |   Skipped: ${scoreData.skippedCount}`, 180, y + 70);
    }

    y += 86 + 18;

    // Checks Overview Table
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    doc.text("Audit Scope & Completed Dimensions", 40, y);

    y += 10;

    const tableBody = SECURITY_CHECKS.map(c => {
      const res = AppState.results[c.id];
      let statusText = "Not Assessed";
      let scoreText = `0 / ${c.weight}`;
      let findingText = "Skipped";

      if (res && !res.skipped) {
        statusText = res.status === "secure" ? "SECURE" : (res.status === "warning" ? "WARNING" : "HIGH RISK");
        scoreText = `${res.score} / ${c.weight}`;
        findingText = res.finding;
      }

      return [c.title, statusText, scoreText, findingText];
    });

    if (typeof doc.autoTable === "function") {
      doc.autoTable({
        startY: y,
        head: [["Security Dimension", "Status", "Score", "Evaluated Finding"]],
        body: tableBody,
        theme: "grid",
        margin: { left: 40, right: 40 },
        headStyles: {
          fillColor: primaryColor,
          textColor: 255,
          fontSize: 8.5,
          fontStyle: "bold",
          cellPadding: 5
        },
        styles: {
          fontSize: 8,
          cellPadding: 4.5,
          overflow: "linebreak",
          lineColor: [226, 232, 240],
          lineWidth: 0.5
        },
        columnStyles: {
          0: { cellWidth: 120, fontStyle: "bold" },
          1: { cellWidth: 70, halign: "center", fontStyle: "bold" },
          2: { cellWidth: 50, halign: "center" },
          3: { cellWidth: 275 }
        },
        didParseCell: function(data) {
          if (data.section === "body" && data.column.index === 1) {
            if (data.cell.raw === "SECURE") {
              data.cell.styles.textColor = [5, 150, 105];
            } else if (data.cell.raw === "WARNING") {
              data.cell.styles.textColor = [217, 119, 6];
            } else if (data.cell.raw === "HIGH RISK") {
              data.cell.styles.textColor = [220, 38, 38];
            }
          }
        }
      });

      y = doc.lastAutoTable.finalY + 22;
    } else {
      tableBody.forEach(row => {
        doc.setFont("helvetica", "bold");
        doc.setFontSize(8.5);
        doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
        doc.text(`${row[0]} [${row[1]}] (${row[2]})`, 40, y);
        doc.setFont("helvetica", "normal");
        doc.setTextColor(textDark[0], textDark[1], textDark[2]);
        const splitFinding = doc.splitTextToSize(row[3], 500);
        doc.text(splitFinding, 40, y + 12);
        y += 20 + (splitFinding.length * 8);
      });
      y += 14;
    }

    // SECTION 1: Flaws Found / Diagnosis
    const flaws = SECURITY_CHECKS
      .map(c => AppState.results[c.id])
      .filter(r => r && !r.skipped && r.status !== "secure");

    if (y + 80 > 750) {
      doc.addPage();
      y = 50;
    }

    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    doc.text("1. Flaws Found / Vulnerability Diagnosis", 40, y);

    y += 14;

    if (flaws.length === 0) {
      doc.setFillColor(240, 253, 244);
      doc.setDrawColor(187, 247, 208);
      doc.setLineWidth(0.8);
      doc.roundedRect(40, y, 515, 30, 4, 4, "FD");

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(5, 150, 105);
      doc.text("No high-risk flaws or warnings were detected during this assessment. Baseline is secure.", 52, y + 19);
      y += 40;
    } else {
      flaws.forEach((flaw, idx) => {
        const innerW = 480;
        doc.setFont("helvetica", "bold");
        doc.setFontSize(9.5);
        const titleLines = doc.splitTextToSize(`${idx + 1}. ${flaw.finding}  [${(flaw.severity || "Warning").toUpperCase()} • CVSS ${flaw.cvss || "4.5"}]`, innerW);

        doc.setFont("helvetica", "normal");
        doc.setFontSize(8.5);
        const diagLines = doc.splitTextToSize(`Diagnosis: ${flaw.whatWeFound}`, innerW);
        const riskLines = doc.splitTextToSize(`Risk Impact: ${flaw.whyItMatters}`, innerW);

        const cleanEv = (flaw.evidence || "").replace(/\r?\n+/g, " ").trim();
        const evSnippet = cleanEv.length > 170 ? cleanEv.slice(0, 167) + "..." : cleanEv;
        doc.setFont("courier", "normal");
        doc.setFontSize(7.5);
        const evLines = doc.splitTextToSize(`Evidence: ${evSnippet}`, innerW);

        const titleH = titleLines.length * 12;
        const diagH = diagLines.length * 11;
        const riskH = riskLines.length * 11;
        const evH = evLines.length * 10;
        const cardH = 10 + titleH + 4 + diagH + 4 + riskH + 4 + evH + 10;

        if (y + cardH > 750) {
          doc.addPage();
          y = 50;
        }

        doc.setFillColor(254, 242, 242);
        doc.setDrawColor(254, 202, 202);
        doc.setLineWidth(0.8);
        doc.roundedRect(40, y, 515, cardH, 4, 4, "FD");

        // Red left accent indicator
        doc.setFillColor(239, 68, 68);
        doc.roundedRect(40, y, 3.5, cardH, 2, 2, "F");

        let textY = y + 10;
        doc.setFont("helvetica", "bold");
        doc.setFontSize(9.5);
        doc.setTextColor(185, 28, 28);
        doc.text(titleLines, 52, textY + 9);
        textY += titleH + 4;

        doc.setFont("helvetica", "normal");
        doc.setFontSize(8.5);
        doc.setTextColor(30, 41, 59);
        doc.text(diagLines, 52, textY + 8);
        textY += diagH + 4;

        doc.text(riskLines, 52, textY + 8);
        textY += riskH + 4;

        doc.setFont("courier", "normal");
        doc.setFontSize(7.5);
        doc.setTextColor(100, 116, 139);
        doc.text(evLines, 52, textY + 7);

        y += cardH + 12;
      });
    }

    // SECTION 2: Remediation Actions
    if (y + 80 > 750) {
      doc.addPage();
      y = 50;
    }

    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    doc.text("2. Remediation Actions / Hardening Steps", 40, y);

    y += 14;

    if (flaws.length === 0) {
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.8);
      doc.roundedRect(40, y, 515, 30, 4, 4, "FD");

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
      doc.text("No remediation required. System conforms to baseline security expectations.", 52, y + 19);
      y += 40;
    } else {
      flaws.forEach((flaw, idx) => {
        const innerW = 480;
        doc.setFont("helvetica", "bold");
        doc.setFontSize(9.5);
        const titleLines = doc.splitTextToSize(`Treatment Step #${idx + 1}: ${flaw.finding}`, innerW);

        doc.setFont("helvetica", "normal");
        doc.setFontSize(8.5);
        const recLines = doc.splitTextToSize(`Action: ${flaw.recommendedAction}`, innerW);

        let cmdLines = [];
        let cmdBoxH = 0;
        if (flaw.remediationCmd) {
          doc.setFont("courier", "bold");
          doc.setFontSize(8);
          cmdLines = doc.splitTextToSize(`PowerShell: ${flaw.remediationCmd.trim()}`, 470);
          cmdBoxH = cmdLines.length * 10 + 10;
        }

        const titleH = titleLines.length * 12;
        const recH = recLines.length * 11;
        const cardH = 10 + titleH + 4 + recH + (cmdBoxH > 0 ? 6 + cmdBoxH : 0) + 10;

        if (y + cardH > 750) {
          doc.addPage();
          y = 50;
        }

        doc.setFillColor(248, 250, 252);
        doc.setDrawColor(226, 232, 240);
        doc.setLineWidth(0.8);
        doc.roundedRect(40, y, 515, cardH, 4, 4, "FD");

        // Cyan left accent indicator
        doc.setFillColor(14, 165, 233);
        doc.roundedRect(40, y, 3.5, cardH, 2, 2, "F");

        let textY = y + 10;
        doc.setFont("helvetica", "bold");
        doc.setFontSize(9.5);
        doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
        doc.text(titleLines, 52, textY + 9);
        textY += titleH + 4;

        doc.setFont("helvetica", "normal");
        doc.setFontSize(8.5);
        doc.setTextColor(textDark[0], textDark[1], textDark[2]);
        doc.text(recLines, 52, textY + 8);
        textY += recH;

        if (cmdBoxH > 0) {
          textY += 6;
          doc.setFillColor(241, 245, 249);
          doc.setDrawColor(203, 213, 225);
          doc.setLineWidth(0.6);
          doc.roundedRect(50, textY, 495, cmdBoxH, 3, 3, "FD");

          doc.setFont("courier", "bold");
          doc.setFontSize(8);
          doc.setTextColor(2, 132, 199);
          doc.text(cmdLines, 56, textY + 11);
        }

        y += cardH + 12;
      });
    }

    // DEVELOPER SIGNATURE BLOCK
    const signBoxW = 180;
    const signBoxH = 80;
    const signBoxX = 595.28 - 40 - signBoxW; // 375.28

    if (y + signBoxH + 20 > 790) {
      doc.addPage();
      y = 50;
    } else {
      y += 16;
    }

    doc.setFillColor(255, 255, 255);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.8);
    doc.roundedRect(signBoxX, y, signBoxW, signBoxH, 4, 4, "FD");

    if (signImgData) {
      const maxW = 145;
      const maxH = 38;
      let sW = maxW;
      let sH = (signImgData.height / signImgData.width) * sW;
      if (sH > maxH) {
        sH = maxH;
        sW = (signImgData.width / signImgData.height) * sH;
      }
      const signFormat = signImgData.format || "PNG";
      doc.addImage(signImgData.dataUrl, signFormat, signBoxX + 14, y + 6, sW, sH);
    } else {
      doc.setFont("helvetica", "italic");
      doc.setFontSize(8.5);
      doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
      doc.text("[digital sign 2 img]", signBoxX + 14, y + 22);
    }

    doc.setFont("helvetica", "bold");
    doc.setFontSize(10.5);
    doc.setTextColor(17, 24, 39);
    doc.text("devloper", signBoxX + 14, y + 54);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.setTextColor(55, 65, 81);
    doc.text("SecureCheck", signBoxX + 14, y + 68);

    // Add running headers on page 2+ and footer page numbers
    const pageCount = doc.internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      if (i > 1) {
        doc.setFillColor(15, 23, 42);
        doc.rect(0, 0, 595.28, 28, "F");
        doc.setFillColor(14, 165, 233);
        doc.rect(0, 27, 595.28, 1, "F");

        if (logoImgData) {
          doc.addImage(logoImgData.dataUrl, "JPEG", 40, 4, 20, 20);
        }
        doc.setFont("helvetica", "bold");
        doc.setFontSize(8.5);
        doc.setTextColor(255, 255, 255);
        doc.text("SecureCheck  •  Windows Security Assessment Report", 68, 18);

        doc.setFont("helvetica", "normal");
        doc.setFontSize(7.5);
        doc.setTextColor(203, 213, 225);
        doc.text(dateStr, 555, 18, { align: "right" });
      }

      // Running footer on all pages
      doc.setDrawColor(226, 232, 240);
      doc.line(40, 810, 555, 810);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(7.5);
      doc.setTextColor(148, 163, 184);
      doc.text("SecureCheck Official Assessment  •  Confidential Security Report", 40, 822);
      doc.text(`Page ${i} of ${pageCount}`, 555, 822, { align: "right" });
    }

  // Save File
  doc.save(`SecureCheck-Windows-Assessment-${Date.now()}.pdf`);
} catch (err) {
  console.error("Error generating PDF:", err);
  alert("An error occurred while generating the PDF. Please try again.");
} finally {
  if (targetBtn) {
    targetBtn.disabled = false;
    targetBtn.innerHTML = originalBtnHtml;
  }
}
}

/**
 * Resets all session data and evaluated checks after confirmation.
 * Returns the user to the initial welcome screen.
 */
function resetAllData() {
  if (confirm("Are you sure you want to reset all audit checks and start fresh?")) {
    AppState.results = {};
    AppState.activeStepIndex = 0;
    switchView("home");
  }
}

// ============================================================================
// SECTION 8: WEBSITE OPENING ANIMATION & LIFECYCLE INITIALIZATION
// ============================================================================
let openingAnimationTimer = null;
let isOpeningAnimationActive = false;

/**
 * Initializes and plays the cyber website opening animation.
 * Features progress bar loading, terminal status lines, and sound/visual transitions.
 */
function initOpeningAnimation(isReplay = false) {
  const overlay = document.getElementById("site-opening-overlay");
  if (!overlay) return;

  if (openingAnimationTimer) {
    cancelAnimationFrame(openingAnimationTimer);
    openingAnimationTimer = null;
  }

  isOpeningAnimationActive = true;
  document.body.classList.add("site-animating");
  document.body.classList.remove("site-entered");

  overlay.classList.remove("closing", "hidden");
  overlay.setAttribute("aria-hidden", "false");

  const pBar = document.getElementById("openingProgressBar");
  const pPct = document.getElementById("openingProgressPct");
  const pLabel = document.getElementById("openingProgressLabel");
  const line1 = document.getElementById("openingTermLine1");
  const line2 = document.getElementById("openingTermLine2");
  const line3 = document.getElementById("openingTermLine3");

  if (pBar) pBar.style.width = "0%";
  if (pPct) pPct.textContent = "0%";
  if (pLabel) pLabel.textContent = "INITIALIZING SECURE AUDIT ENGINE...";
  if (line1) line1.classList.remove("revealed");
  if (line2) line2.classList.remove("revealed");
  if (line3) line3.classList.remove("revealed");

  const startTime = performance.now();
  const duration = 1500; // 1.5 seconds smooth intro

  function frame(now) {
    if (!isOpeningAnimationActive) return;
    const elapsed = now - startTime;
    const progress = Math.min(1, elapsed / duration);
    const pct = Math.floor(progress * 100);

    if (pBar) pBar.style.width = `${pct}%`;
    if (pPct) pPct.textContent = `${pct}%`;

    // Progressive terminal diagnostics logs
    if (progress >= 0.15 && line1) line1.classList.add("revealed");
    if (progress >= 0.45 && line2) line2.classList.add("revealed");
    if (progress >= 0.75 && line3) line3.classList.add("revealed");

    if (progress >= 0.45 && progress < 0.85 && pLabel) {
      pLabel.textContent = "VERIFYING POWERSHELL HEURISTICS...";
    } else if (progress >= 0.85 && pLabel) {
      pLabel.textContent = "ALL DEFENSE MODULES OPERATIONAL";
    }

    if (progress < 1) {
      openingAnimationTimer = requestAnimationFrame(frame);
    } else {
      setTimeout(() => {
        dismissOpeningAnimation();
      }, 160);
    }
  }

  openingAnimationTimer = requestAnimationFrame(frame);

  // Safety fallback after 3.2s to guarantee the user is never locked out
  setTimeout(() => {
    if (isOpeningAnimationActive) {
      dismissOpeningAnimation();
    }
  }, 3200);
}

/**
 * Dismisses the opening animation and transitions smoothly into the main website.
 */
function dismissOpeningAnimation() {
  if (!isOpeningAnimationActive) return;
  isOpeningAnimationActive = false;

  if (openingAnimationTimer) {
    cancelAnimationFrame(openingAnimationTimer);
    openingAnimationTimer = null;
  }

  const overlay = document.getElementById("site-opening-overlay");
  const pBar = document.getElementById("openingProgressBar");
  const pPct = document.getElementById("openingProgressPct");
  const pLabel = document.getElementById("openingProgressLabel");
  const line1 = document.getElementById("openingTermLine1");
  const line2 = document.getElementById("openingTermLine2");
  const line3 = document.getElementById("openingTermLine3");

  if (pBar) pBar.style.width = "100%";
  if (pPct) pPct.textContent = "100%";
  if (pLabel) pLabel.textContent = "SYSTEM READY • ENTERING WORKSPACE";
  if (line1) line1.classList.add("revealed");
  if (line2) line2.classList.add("revealed");
  if (line3) line3.classList.add("revealed");

  document.body.classList.remove("site-animating");
  document.body.classList.add("site-entered");

  if (overlay) {
    overlay.classList.add("closing");
    overlay.setAttribute("aria-hidden", "true");
    setTimeout(() => {
      overlay.classList.add("hidden");
    }, 450);
  }
}

/**
 * Global trigger to replay the opening animation from UI button or debug console.
 */
function triggerOpeningAnimation() {
  initOpeningAnimation(true);
}

/**
 * DOMContentLoaded Event Listener:
 * Fires when document structure is ready, boots up the default home view and opening animation.
 */
document.addEventListener("DOMContentLoaded", () => {
  // Render initial homepage
  switchView("home");

  // Launch website opening animation
  initOpeningAnimation();

  // Handle keyboard shortcut (Esc / Space / Enter) to skip opening animation
  window.addEventListener("keydown", (e) => {
    if (isOpeningAnimationActive) {
      if (e.key === "Escape" || e.key === " " || e.key === "Enter") {
        dismissOpeningAnimation();
      }
    }
  });
});

// Expose functions globally to window so inline HTML onclick and oninput handlers can invoke them
window.switchView = switchView;
window.goToStep = goToStep;
window.copyCommand = copyCommand;
window.clearOutputText = clearOutputText;
window.onOutputChanged = onOutputChanged;
window.skipCheck = skipCheck;
window.analyzeCurrentCheck = analyzeCurrentCheck;
window.proceedToNextStep = proceedToNextStep;
window.generatePdfReport = generatePdfReport;
window.resetAllData = resetAllData;
window.copyCheckCommand = copyCheckCommand;
window.copyRemediation = copyRemediation;
window.copyReportRemediation = copyReportRemediation;
window.scrollAuditToTop = scrollAuditToTop;
window.initOpeningAnimation = initOpeningAnimation;
window.dismissOpeningAnimation = dismissOpeningAnimation;
window.triggerOpeningAnimation = triggerOpeningAnimation;
