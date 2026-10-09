export interface ForensicTool {
  id: string;
  name: string;
  category: ToolCategory;
  tagline: string;
  description: string;
  downloadUrl: string;
  features: string[];
  targetArtifact: string;
  iconName: string;
  badge?: "Featured" | "Core" | "New" | "Updated";
  version: string;
  highlights: string[];
}

export type ToolCategory =
  | "All"
  | "Startup & Persistence"
  | "Execution History"
  | "File System & NTFS"
  | "Memory & RAM"
  | "Hardware & DMA"
  | "Web & Network"
  | "Scripting & Logs"
  | "Anti-Cheat & Gaming";

export const CATEGORIES: { label: ToolCategory; count?: number; icon: string }[] = [
  { label: "All", icon: "LayoutGrid" },
  { label: "Execution History", icon: "History" },
  { label: "File System & NTFS", icon: "HardDrive" },
  { label: "Memory & RAM", icon: "Cpu" },
  { label: "Startup & Persistence", icon: "Zap" },
  { label: "Hardware & DMA", icon: "Usb" },
  { label: "Web & Network", icon: "Globe" },
  { label: "Scripting & Logs", icon: "Terminal" },
  { label: "Anti-Cheat & Gaming", icon: "ShieldCheck" },
];

export const TOOLS_DATA: ForensicTool[] = [
  {
    id: "autoruns-plus-plus",
    name: "Autoruns++",
    category: "Startup & Persistence",
    tagline: "Next-generation Sysinternals Autoruns alternative with USN tracking",
    description:
      "A completely rebuilt and enhanced alternative to Microsoft Sysinternals Autoruns. It monitors USN journal modifications for startup entries, features flawless digital signature verification, and includes intuitive checkboxes to quickly filter out anomalies and pinpoint suspicious files.",
    downloadUrl: "https://detect.ac/tool/Autoruns++",
    features: [
      "USN Journal modification monitoring",
      "Flawless digital signature verification",
      "Intuitive anomaly filtering checkboxes",
      "Persistent malware & rootkit discovery",
    ],
    targetArtifact: "Startup Registry & Services",
    iconName: "Zap",
    badge: "Core",
    version: "v2.4",
    highlights: ["USN Journal Tracker", "Digital Sig Verification", "Anomaly Filter"],
  },
  {
    id: "string-explorer-plus-plus",
    name: "StringExplorer++",
    category: "Memory & RAM",
    tagline: "Deep binary string navigation, entropy analysis & VirusTotal scoring",
    description:
      "String Explorer enables seamless navigation of an executable's complete string data, allowing users to verify compilation dates, analyze entropy, and detect anomalous indicators. Equipped with intuitive filtering checkboxes and direct VirusTotal integration, it streamlines the identification of potentially malicious files.",
    downloadUrl: "https://detect.ac/tool/StringExplorer++",
    features: [
      "Complete binary string decomposition",
      "Mathematical entropy scoring",
      "PE compilation date verification",
      "1-Click VirusTotal reputation check",
    ],
    targetArtifact: "PE Executables & Memory Dumps",
    iconName: "Binary",
    badge: "Featured",
    version: "v3.1",
    highlights: ["Entropy Scoring", "PE Date Verification", "VirusTotal Link"],
  },
  {
    id: "moss-2-0",
    name: "MOSS 2.0",
    category: "Anti-Cheat & Gaming",
    tagline: "Real-time match observation & competitive anti-cheat integrity monitor",
    description:
      "MOSS 2.0 is a complete rewrite of MOSS (Match Observation & Statistical System) built specifically for Rainbow Six Siege. Developed by detect.ac, it provides real-time integrity monitoring during competitive matches to ensure a fair playing environment.",
    downloadUrl: "https://detect.ac/tool/MOSS-2.0",
    features: [
      "Rainbow Six Siege dedicated integrity engine",
      "Real-time screen & memory monitoring",
      "Tamper-proof encrypted log package",
      "Instant referee verification protocol",
    ],
    targetArtifact: "R6S Process & Memory Integrity",
    iconName: "ShieldCheck",
    badge: "Featured",
    version: "v2.0",
    highlights: ["R6 Siege Engine", "Live Match Integrity", "Encrypted Hash Report"],
  },
  {
    id: "win-prefetch-view-plus-plus",
    name: "WinPrefetchView++",
    category: "Execution History",
    tagline: "Elite signature checks, pink USN highlights & custom YARA rules",
    description:
      "This enhanced version of WinPrefetchView introduces built-in bypass detections and highlights modified files in pink for easy analysis. It combines elite signature checks and YARA rules for every file, while giving you the flexibility to import and run your own custom YARA rules.",
    downloadUrl: "https://detect.ac/tool/WinPrefetchView++",
    features: [
      "Built-in cleaner bypass detections",
      "Visual pink highlight for modified prefetch files",
      "Elite code signature verification",
      "Custom & built-in YARA rule engine",
    ],
    targetArtifact: "C:\\Windows\\Prefetch (*.pf)",
    iconName: "FileClock",
    badge: "Updated",
    version: "v2.8",
    highlights: ["Pink USN Highlight", "Custom YARA", "Cleaner Bypass Flag"],
  },
  {
    id: "usb-deview-plus-plus",
    name: "USBDeview++",
    category: "Hardware & DMA",
    tagline: "Neutralize DMA hardware cheats & uncover wiped USB device traces",
    description:
      "The ultimate tool for neutralizing DMA threats and USB bypasses. It pulls device logs from multiple sources and cross-references them into a single view. By comparing IDs against DeviceHunt and live APIs, it flags unverified firmware and uncovers hidden traces of cleaned USB devices with high-level forensic depth.",
    downloadUrl: "https://detect.ac/tool/USBDeview++",
    features: [
      "DMA card & PCIe bypass neutralization",
      "Multi-source USB registry & log cross-referencing",
      "DeviceHunt live API hardware database matching",
      "Unverified firmware & ghost device detection",
    ],
    targetArtifact: "USB Registry & Hardware Descriptors",
    iconName: "Usb",
    badge: "Featured",
    version: "v2.6",
    highlights: ["DMA Neutralizer", "DeviceHunt Live API", "Ghost Device Recovery"],
  },
  {
    id: "saved-files-viewer-plus-plus",
    name: "SavedFilesViewer++",
    category: "File System & NTFS",
    tagline: "Completely local timestamp cross-referencing with cleaner detection",
    description:
      "View every file saved to disk by cross-referencing multiple artifacts to establish precise timestamps for downloads. This tool is completely local and operates without touching the browser, featuring built-in detections for automated cleaners.",
    downloadUrl: "https://detect.ac/tool/SavedFilesViewer++",
    features: [
      "100% local operation without browser locks",
      "Multi-artifact forensic timestamp resolution",
      "Automated trace cleaner detection",
      "Deep download origin auditing",
    ],
    targetArtifact: "NTFS Artifacts & ShellBags",
    iconName: "FolderSearch",
    badge: "Core",
    version: "v2.2",
    highlights: ["100% Local Processing", "Multi-Artifact Match", "Anti-Cleaner Detection"],
  },
  {
    id: "power-shell-parser-plus-plus",
    name: "PowerShellParser++",
    category: "Scripting & Logs",
    tagline: "Hayabusa replacement with deep PowerShell history & bypass scraping",
    description:
      "A comprehensive replacement for Hayabusa, offering deep scraping of all PowerShell history artifacts. It utilizes advanced filters and flags to streamline the discovery of PowerShell-related bypasses while maintaining robust, integrated protections.",
    downloadUrl: "https://detect.ac/tool/PowerShellParser++",
    features: [
      "ConsoleHost_history.txt deep parsing",
      "PowerShell event log scraping (4104/4103)",
      "Automated execution bypass flagging",
      "Obfuscation & base64 decoder",
    ],
    targetArtifact: "PSReadLine & Event Logs",
    iconName: "Terminal",
    badge: "Updated",
    version: "v2.5",
    highlights: ["Hayabusa Replacement", "PSReadLine Scraping", "Obfuscation Decoder"],
  },
  {
    id: "paths-parser-plus-plus",
    name: "PathsParser++",
    category: "File System & NTFS",
    tagline: "Streamlined GUI paths analysis, YARA scanning & pink USN viewer",
    description:
      "An enhanced paths parser featuring a streamlined GUI that supports multiple input methods. It includes integrated YARA rule support with custom rule imports and a visual USN journal viewer that highlights modifications in pink for rapid analysis.",
    downloadUrl: "https://detect.ac/tool/PathsParser++",
    features: [
      "Flexible multi-input GUI engine",
      "Visual USN journal modification viewer (pink highlights)",
      "Integrated & custom YARA rule scanner",
      "Deep filesystem path normalization",
    ],
    targetArtifact: "System Path Registry & USN",
    iconName: "FolderGit2",
    badge: "Core",
    version: "v2.1",
    highlights: ["Multi-Input GUI", "Pink USN Highlighting", "Custom YARA Support"],
  },
  {
    id: "mft-explorer-plus-plus",
    name: "MFTExplorer++",
    category: "File System & NTFS",
    tagline: "Defined $MFT view, Alternate Data Streams (ADS) & historical trace verification",
    description:
      "Provides a defined view of the $MFT to identify suspicious Alternate Data Streams. With accurate filtering for historical file traces, it is an essential tool for verifying whether a specific file has ever been present on a system.",
    downloadUrl: "https://detect.ac/tool/MFTExplorer++",
    features: [
      "Direct raw $MFT filesystem parser",
      "Alternate Data Stream (ADS) hidden payload detection",
      "Historical file footprint verification",
      "Deleted record recovery & timestamp audit",
    ],
    targetArtifact: "NTFS $MFT & $LogFile",
    iconName: "HardDrive",
    badge: "Featured",
    version: "v3.0",
    highlights: ["Raw $MFT Parsing", "ADS Stream Finder", "Historical File Verification"],
  },
  {
    id: "kernel-live-dump-plus-plus",
    name: "KernelLiveDump++",
    category: "Memory & RAM",
    tagline: "Simultaneous Kernel & User-mode RAM capture with suspicious string toggles",
    description:
      "Dumps both Kernel and User-mode RAM simultaneously and supports loading external dumps. Users can toggle between flagged suspicious strings and the full dump via a simple switch box, with full support for custom search strings.",
    downloadUrl: "https://detect.ac/tool/KernelLiveDump++",
    features: [
      "Dual Kernel & User RAM simultaneous acquisition",
      "Suspicious string AI flag switcher",
      "External memory dump file loader (.dmp / .raw)",
      "Custom regex & signature string matching",
    ],
    targetArtifact: "Kernel & User Physical RAM",
    iconName: "Cpu",
    badge: "Featured",
    version: "v2.9",
    highlights: ["Kernel+User RAM Dump", "Flagged String Switch", "Custom Search String"],
  },
  {
    id: "journal-trace-plus-plus",
    name: "JournalTrace++",
    category: "File System & NTFS",
    tagline: "Evolved USN Journal investigation with reason codes & bypass detectors",
    description:
      "An evolved version of Journaltrace specifically for USN Journal analysis. It introduces integrated bypass detections and sophisticated filtering by reason codes and keywords to provide a more reliable and feature-rich environment for investigators.",
    downloadUrl: "https://detect.ac/tool/JournalTrace++",
    features: [
      "Complete $UsnJrnl:$J record decomposition",
      "Advanced reason code filtering (0x80000000+)",
      "Journal wipe & shrink bypass detection",
      "Keyword & file hash correlation",
    ],
    targetArtifact: "$Extend\\$UsnJrnl",
    iconName: "Activity",
    badge: "Updated",
    version: "v2.3",
    highlights: ["Reason Code Filter", "Wipe Bypass Detector", "USN Stream Forensics"],
  },
  {
    id: "crashed-file-viewer-plus-plus",
    name: "CrashedFileViewer++",
    category: "Execution History",
    tagline: "Windows crash artifact aggregation, log clearing detection & YARA import",
    description:
      "Compiles all Windows crash-related artifacts into a single, unified view. It features USN entry highlighting to identify modified crash files and integrated bypass detection to uncover attempts at log clearing.",
    downloadUrl: "https://detect.ac/tool/CrashedFileViewer++",
    features: [
      "Windows Error Reporting (WER) & Dump compilation",
      "Log clearing & purge attempt detection",
      "USN entry highlighting for altered dumps",
      "Importable custom YARA rule sets",
    ],
    targetArtifact: "WER Dumps & Minidumps",
    iconName: "AlertTriangle",
    badge: "Core",
    version: "v2.0",
    highlights: ["WER Aggregator", "Log Clear Detector", "Pink USN Highlighting"],
  },
  {
    id: "browsing-history-view-plus-plus",
    name: "BrowsingHistoryView++",
    category: "Web & Network",
    tagline: "Cross-browser unified timeline, suspicious domain flags & VirusTotal links",
    description:
      "Consolidates browsing history from across multiple browsers into one interface. It features a universal filter box, automated flagging for suspicious domains, and direct VirusTotal links to analyze user behavior and engagement timing.",
    downloadUrl: "https://detect.ac/tool/BrowsingHistoryView++",
    features: [
      "Chrome, Edge, Firefox, Brave & Opera unified history",
      "Automated suspicious / malicious domain flagging",
      "Direct VirusTotal domain reputation links",
      "Microsecond engagement timing analysis",
    ],
    targetArtifact: "Multi-Browser SQLite Databases",
    iconName: "Globe",
    badge: "Core",
    version: "v2.7",
    highlights: ["Universal Browser Sync", "Suspicious Domain AI", "VirusTotal Integration"],
  },
  {
    id: "browser-downloads-view-plus-plus",
    name: "BrowserDownloadsView++",
    category: "Web & Network",
    tagline: "Multi-browser download tracker with pink USN change flags & YARA scanning",
    description:
      "Aggregates download history from multiple browsers and identifies USN Journal modifications associated with those files. Modifications are highlighted in pink, and the tool supports YARA scanning with both built-in and custom rule sets.",
    downloadUrl: "https://detect.ac/tool/BrowserDownloadsView++",
    features: [
      "Multi-browser download history aggregation",
      "USN Journal modification pink highlighting",
      "Built-in & custom YARA malware rule scanner",
      "Referrer URL & download origin reconstruction",
    ],
    targetArtifact: "Browser Download Catalogs",
    iconName: "DownloadCloud",
    badge: "Updated",
    version: "v2.5",
    highlights: ["Pink USN Tracking", "Built-in & Custom YARA", "Origin URL Trace"],
  },
  {
    id: "bam-parser-plus-plus",
    name: "BamParser++",
    category: "Execution History",
    tagline: "Background Activity Monitor extraction, anti-tampering & pink USN tags",
    description:
      "Extracts execution history and timestamps from the Background Activity Monitor (BAM). It features an upgraded YARA engine, visual USN modification flags in pink, and integrated detections for BAM artifact tampering.",
    downloadUrl: "https://detect.ac/tool/BamParser++",
    features: [
      "SYSTEM BAM registry hive deep extraction",
      "Artifact tampering & registry deletion detection",
      "Pink USN modification flags",
      "Upgraded high-speed YARA engine",
    ],
    targetArtifact: "SYSTEM\\ControlSet\\Services\\bam",
    iconName: "Clock",
    badge: "Core",
    version: "v2.4",
    highlights: ["BAM Hive Extraction", "Tampering Detection", "Pink USN Highlights"],
  },
  {
    id: "amcache-parser-plus-plus",
    name: "AmcacheParser++",
    category: "Execution History",
    tagline: "High-performance Amcache parser with SHA1 filtering & 1-click VirusTotal",
    description:
      "A high-performance Amcache parser with integrated YARA scanning for suspicious file detection. It offers advanced filtering by SHA1 hash and other metadata, alongside one-click VirusTotal integration for instant reputation checks.",
    downloadUrl: "https://detect.ac/tool/AmcacheParser++",
    features: [
      "Amcache.hve raw registry hive parsing",
      "Instant SHA1 hash filtering & search",
      "1-Click VirusTotal hash lookup",
      "Custom YARA rule matching",
    ],
    targetArtifact: "C:\\Windows\\AppCompat\\Programs\\Amcache.hve",
    iconName: "ShieldAlert",
    badge: "Core",
    version: "v2.8",
    highlights: ["Amcache.hve Engine", "SHA1 Instant Lookup", "VirusTotal Integration"],
  },
  {
    id: "srum-explorer-plus-plus",
    name: "SRUMExplorer++",
    category: "Execution History",
    tagline: "System Resource Usage Monitor mapper with network byte telemetry & USN tracking",
    description:
      "This tool comprehensively maps every file path and active service from SRUM (System Resource Usage Monitor), reflecting their network usage (in bytes) and connection timestamps. For deeper analysis, it features automated forensic checks, generic YARA rule matching on all executables, and integrated USN journal modification tracking.",
    downloadUrl: "https://detect.ac/tool/SRUMExplorer++",
    features: [
      "SRUM ESE database (SRUDB.dat) parsing",
      "Precise network byte transmission forensics",
      "Active service & file path mapping",
      "Integrated USN modification tracking & YARA",
    ],
    targetArtifact: "C:\\Windows\\System32\\sru\\SRUDB.dat",
    iconName: "Network",
    badge: "Featured",
    version: "v3.0",
    highlights: ["Network Byte Telemetry", "Active Service Map", "SRUDB.dat Deep Parsing"],
  },
];
