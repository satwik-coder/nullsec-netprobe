# NullSec NetProbe - Stealthy Network Reconnaissance Tool
# Language: Nim
# Author: bad-antics
# License: NullSec Proprietary

import std/[os, net, strutils, strformat, parseopt, tables, times, random, asyncdispatch, asyncnet, terminal]

const VERSION = "1.0.0"

const BANNER = """
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░ N E T P R O B E ░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics v""" & VERSION

# Common service ports
const COMMON_PORTS = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  111: "RPC",
  135: "MSRPC",
  139: "NetBIOS",
  143: "IMAP",
  443: "HTTPS",
  445: "SMB",
  993: "IMAPS",
  995: "POP3S",
  1433: "MSSQL",
  1521: "Oracle",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  5900: "VNC",
  6379: "Redis",
  8080: "HTTP-Proxy",
  8443: "HTTPS-Alt",
  27017: "MongoDB"
}.toTable

# Service banners for identification
const SERVICE_SIGNATURES = [
  ("SSH-", "SSH"),
  ("220 ", "FTP/SMTP"),
  ("HTTP/", "HTTP"),
  ("+OK", "POP3"),
  ("* OK", "IMAP"),
  ("MySQL", "MySQL"),
  ("PostgreSQL", "PostgreSQL"),
  ("redis_version", "Redis"),
  ("MongoDB", "MongoDB")
]

type
  ScanType = enum
    stConnect, stSyn, stFin, stNull, stXmas

  ScanResult = object
    port: int
    state: string
    service: string
    banner: string
    version: string

  Config = object
    target: string
    ports: seq[int]
    scanType: ScanType
    timing: int
    timeout: int
    verbose: bool
    output: string

# Utility functions
proc logInfo(msg: string) =
  styledEcho(fgCyan, "[*] ", fgDefault, msg)

proc logSuccess(msg: string) =
  styledEcho(fgGreen, "[+] ", fgDefault, msg)

proc logError(msg: string) =
  styledEcho(fgRed, "[!] ", fgDefault, msg)

proc logVerbose(config: Config, msg: string) =
  if config.verbose:
    styledEcho(fgYellow, "[DEBUG] ", fgDefault, msg)

# Parse port specification
proc parsePorts(spec: string): seq[int] =
  result = @[]
  for part in spec.split(","):
    if "-" in part:
      let range = part.split("-")
      if range.len == 2:
        let start = parseInt(range[0].strip)
        let stop = parseInt(range[1].strip)
        for p in start..stop:
          result.add(p)
    else:
      result.add(parseInt(part.strip))

# Parse CIDR notation
proc parseCIDR(cidr: string): seq[string] =
  result = @[]
  if "/" notin cidr:
    result.add(cidr)
    return
  
  let parts = cidr.split("/")
  let baseIP = parts[0]
  let prefix = parseInt(parts[1])
  
  # Simplified: only handle /24 and /32 for demo
  if prefix == 32:
    result.add(baseIP)
  elif prefix >= 24:
    let octets = baseIP.split(".")
    let hostBits = 32 - prefix
    let numHosts = 1 shl hostBits
    for i in 1..<numHosts-1:
      result.add(fmt"{octets[0]}.{octets[1]}.{octets[2]}.{i}")
  else:
    result.add(baseIP)

# TCP Connect scan
proc tcpConnect(host: string, port: int, timeout: int): Future[ScanResult] {.async.} =
  var result = ScanResult(port: port, state: "closed", service: "", banner: "")
  
  try:
    let socket = newAsyncSocket()
    let connected = await socket.connect(host, Port(port)).withTimeout(timeout)
    
    if connected:
      result.state = "open"
      result.service = COMMON_PORTS.getOrDefault(port, "unknown")
      
      # Try to grab banner
      socket.send("\r\n")
      let banner = await socket.recv(1024).withTimeout(2000)
      if banner.len > 0:
        result.banner = banner.strip[0..min(50, banner.len-1)]
        
        # Identify service from banner
        for (sig, svc) in SERVICE_SIGNATURES:
          if sig in banner:
            result.service = svc
            break
      
      socket.close()
  except:
    discard
  
  return result

# Async port scanner
proc scanPort(host: string, port: int, config: Config): Future[ScanResult] {.async.} =
  case config.scanType
  of stConnect:
    return await tcpConnect(host, port, config.timeout)
  else:
    # For SYN/FIN/NULL/XMAS - would need raw sockets
    logVerbose(config, fmt"Raw socket scans require root and pcap")
    return await tcpConnect(host, port, config.timeout)

# Main scan function
proc scanHost(host: string, config: Config) {.async.} =
  logInfo(fmt"Scanning {host}...")
  
  var openPorts: seq[ScanResult] = @[]
  
  # Calculate delay based on timing
  let delay = case config.timing
    of 0: 1000  # Paranoid
    of 1: 500   # Sneaky
    of 2: 200   # Polite
    of 3: 50    # Normal
    of 4: 10    # Aggressive
    of 5: 0     # Insane
    else: 50
  
  for port in config.ports:
    let result = await scanPort(host, port, config)
    
    if result.state == "open":
      openPorts.add(result)
      let svc = if result.service != "": result.service else: "unknown"
      let banner = if result.banner != "": " | " & result.banner else: ""
      logSuccess(fmt"{port}/tcp open {svc}{banner}")
    
    if delay > 0:
      await sleepAsync(delay)
  
  echo ""
  logInfo(fmt"Scan complete. {openPorts.len} open ports found on {host}")

# DNS subdomain enumeration
proc dnsEnum(domain: string, wordlist: string) =
  logInfo(fmt"Enumerating subdomains for {domain}")
  
  if not fileExists(wordlist):
    logError(fmt"Wordlist not found: {wordlist}")
    return
  
  for line in lines(wordlist):
    let subdomain = line.strip & "." & domain
    try:
      let ips = getHostByName(subdomain)
      if ips.addrList.len > 0:
        logSuccess(fmt"{subdomain} -> {ips.addrList[0]}")
    except:
      discard

# ARP scan (simplified - requires root and pcap for real implementation)
proc arpScan(iface: string) =
  logInfo(fmt"ARP scanning on interface {iface}")
  logInfo("Note: Full ARP scan requires libpcap and root privileges")
  
  # Would use libpcap to send ARP requests and capture responses
  echo ""
  echo "Simulated ARP scan results:"
  echo "  192.168.1.1    00:11:22:33:44:55  (Gateway)"
  echo "  192.168.1.100  AA:BB:CC:DD:EE:FF  (Host)"

# SSL/TLS analysis
proc sslAnalysis(host: string, port: int) {.async.} =
  logInfo(fmt"Analyzing SSL/TLS on {host}:{port}")
  
  try:
    let ctx = newContext(verifyMode = CVerifyNone)
    let socket = newAsyncSocket()
    await socket.connect(host, Port(port))
    
    # Would wrap in SSL and extract certificate info
    logInfo("SSL connection established")
    logInfo("Note: Full certificate analysis requires OpenSSL bindings")
    
    socket.close()
  except Exception as e:
    logError(fmt"SSL error: {e.msg}")

# OS fingerprinting (simplified)
proc osFingerprint(host: string) {.async.} =
  logInfo(fmt"Fingerprinting OS on {host}")
  
  # Would analyze TCP/IP stack characteristics:
  # - TTL values
  # - Window size
  # - TCP options
  # - DF bit
  
  logInfo("Note: Accurate OS fingerprinting requires raw socket access")
  
  # Guess based on common TTL values
  try:
    let socket = newAsyncSocket()
    let connected = await socket.connect(host, Port(80)).withTimeout(5000)
    if connected:
      logSuccess("Host is reachable")
      # Would analyze response characteristics
    socket.close()
  except:
    discard

# Print usage
proc printUsage() =
  echo """

USAGE:
    netprobe <command> [options]

COMMANDS:
    scan        Port scanning
    dns         DNS enumeration
    arp         ARP discovery
    ssl         SSL/TLS analysis
    os          OS fingerprinting

OPTIONS:
    -t, --target       Target IP/hostname/CIDR
    -p, --ports        Port specification (22,80,443 or 1-1000)
    -i, --interface    Network interface
    -T, --timing       Timing template (0-5)
    --syn              SYN stealth scan
    --fin              FIN scan
    --null             NULL scan
    --xmas             XMAS scan
    -d, --domain       Domain for DNS enum
    --subdomains       Subdomain wordlist
    -o, --output       Output file
    -v, --verbose      Verbose output

EXAMPLES:
    netprobe scan -t 192.168.1.1 -p 1-1000
    netprobe scan -t 192.168.1.0/24 -p 22,80,443 --syn
    netprobe dns -d example.com --subdomains wordlist.txt
    netprobe arp -i eth0
    netprobe ssl -t 192.168.1.1 -p 443
"""

# Main
proc main() =
  echo BANNER
  
  var config = Config(
    target: "",
    ports: @[],
    scanType: stConnect,
    timing: 3,
    timeout: 3000,
    verbose: false,
    output: ""
  )
  
  var command = ""
  var domain = ""
  var wordlist = ""
  var iface = "eth0"
  
  var p = initOptParser(commandLineParams())
  
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdArgument:
      if command == "":
        command = p.key
    of cmdShortOption, cmdLongOption:
      case p.key
      of "t", "target": config.target = p.val
      of "p", "ports": config.ports = parsePorts(p.val)
      of "i", "interface": iface = p.val
      of "T", "timing": config.timing = parseInt(p.val)
      of "d", "domain": domain = p.val
      of "subdomains": wordlist = p.val
      of "o", "output": config.output = p.val
      of "v", "verbose": config.verbose = true
      of "syn": config.scanType = stSyn
      of "fin": config.scanType = stFin
      of "null": config.scanType = stNull
      of "xmas": config.scanType = stXmas
      of "h", "help":
        printUsage()
        return
      else: discard
  
  if command == "":
    printUsage()
    return
  
  case command
  of "scan":
    if config.target == "":
      logError("Please specify a target with -t")
      return
    
    if config.ports.len == 0:
      config.ports = @[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080]
    
    let targets = parseCIDR(config.target)
    for host in targets:
      waitFor scanHost(host, config)
  
  of "dns":
    if domain == "":
      logError("Please specify a domain with -d")
      return
    if wordlist == "":
      logError("Please specify a subdomain wordlist with --subdomains")
      return
    dnsEnum(domain, wordlist)
  
  of "arp":
    arpScan(iface)
  
  of "ssl":
    if config.target == "":
      logError("Please specify a target with -t")
      return
    let port = if config.ports.len > 0: config.ports[0] else: 443
    waitFor sslAnalysis(config.target, port)
  
  of "os":
    if config.target == "":
      logError("Please specify a target with -t")
      return
    waitFor osFingerprint(config.target)
  
  else:
    logError(fmt"Unknown command: {command}")
    printUsage()

when isMainModule:
  randomize()
  main()
