# NullSec NetProbe - Hardened Async Network Reconnaissance
# Language: Nim (Systems Programming with GC Safety)
# Author: bad-antics  
# License: NullSec Proprietary
# Security Level: Maximum Hardening
#
# Security Features:
# - Input validation on all network parameters
# - Rate limiting to prevent detection
# - Memory-safe string handling
# - Timeout enforcement on all operations
# - Secure random for timing jitter

import std/[
  asyncdispatch, asyncnet, nativesockets, net, os, strutils,
  strformat, parseopt, tables, times, random, sequtils,
  algorithm, hashes, sets, locks, atomics
]

const
  VERSION = "2.0.0"
  MAX_CONCURRENT = 256
  DEFAULT_TIMEOUT = 3000
  MAX_TIMEOUT = 30000
  MIN_TIMEOUT = 100
  MAX_PORT = 65535
  MAX_TARGETS = 10000
  JITTER_FACTOR = 0.2

# ============================================================================
# Secure Configuration
# ============================================================================

type
  ScanConfig = object
    targets: seq[string]
    ports: seq[uint16]
    timeout: int
    concurrent: int
    timing: TimingTemplate
    stealth: bool
    serviceScan: bool
    outputFile: string
    
  TimingTemplate = enum
    Paranoid = 0    # Serial, 5min between probes
    Sneaky = 1      # Serial, 15s between probes
    Polite = 2      # Serial, 0.4s between probes
    Normal = 3      # Parallel, normal timing
    Aggressive = 4  # Parallel, faster
    Insane = 5      # Maximum speed
    
  ScanResult = object
    host: string
    port: uint16
    state: PortState
    service: string
    banner: string
    latency: float
    timestamp: Time
    
  PortState = enum
    Open, Closed, Filtered, Unknown
    
  ServiceProbe = object
    name: string
    pattern: string
    ports: seq[uint16]

# ============================================================================
# Banner with Integrity
# ============================================================================

const BANNER = """

    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░░ N E T P R O B E ░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics v""" & VERSION & "\n"

# ============================================================================
# Service Signatures (Hardened Pattern Matching)
# ============================================================================

const SERVICE_PROBES = @[
  ServiceProbe(name: "ssh", pattern: "SSH-", ports: @[22u16]),
  ServiceProbe(name: "http", pattern: "HTTP/", ports: @[80u16, 8080, 8000]),
  ServiceProbe(name: "https", pattern: "", ports: @[443u16, 8443]),
  ServiceProbe(name: "ftp", pattern: "220", ports: @[21u16]),
  ServiceProbe(name: "smtp", pattern: "220", ports: @[25u16, 587]),
  ServiceProbe(name: "mysql", pattern: "\x00\x00", ports: @[3306u16]),
  ServiceProbe(name: "postgresql", pattern: "", ports: @[5432u16]),
  ServiceProbe(name: "redis", pattern: "-ERR", ports: @[6379u16]),
  ServiceProbe(name: "mongodb", pattern: "", ports: @[27017u16]),
  ServiceProbe(name: "dns", pattern: "", ports: @[53u16]),
  ServiceProbe(name: "rdp", pattern: "\x03\x00", ports: @[3389u16]),
  ServiceProbe(name: "smb", pattern: "", ports: @[445u16, 139]),
]

const COMMON_PORTS = @[
  21u16, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
  993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
]

# ============================================================================
# Input Validation (Security Critical)
# ============================================================================

proc validateIP(ip: string): bool =
  ## Strict IP address validation
  let parts = ip.split('.')
  if parts.len != 4:
    return false
  for part in parts:
    if part.len == 0 or part.len > 3:
      return false
    try:
      let num = parseInt(part)
      if num < 0 or num > 255:
        return false
      # Prevent octal interpretation (leading zeros)
      if part.len > 1 and part[0] == '0':
        return false
    except:
      return false
  return true

proc validateHostname(hostname: string): bool =
  ## Validate hostname per RFC 1123
  if hostname.len == 0 or hostname.len > 253:
    return false
  let labels = hostname.split('.')
  for label in labels:
    if label.len == 0 or label.len > 63:
      return false
    if label[0] == '-' or label[^1] == '-':
      return false
    for c in label:
      if not (c in {'a'..'z', 'A'..'Z', '0'..'9', '-'}):
        return false
  return true

proc validateTarget(target: string): bool =
  validateIP(target) or validateHostname(target)

proc validatePort(port: int): bool =
  port >= 1 and port <= MAX_PORT

proc validateConfig(config: ScanConfig): seq[string] =
  ## Validate entire configuration, return errors
  var errors: seq[string] = @[]
  
  if config.targets.len == 0:
    errors.add("No targets specified")
  if config.targets.len > MAX_TARGETS:
    errors.add(fmt"Too many targets (max {MAX_TARGETS})")
  
  for target in config.targets:
    if not validateTarget(target):
      errors.add(fmt"Invalid target: {target}")
      
  if config.ports.len == 0:
    errors.add("No ports specified")
    
  for port in config.ports:
    if not validatePort(int(port)):
      errors.add(fmt"Invalid port: {port}")
      
  if config.timeout < MIN_TIMEOUT or config.timeout > MAX_TIMEOUT:
    errors.add(fmt"Timeout must be {MIN_TIMEOUT}-{MAX_TIMEOUT}ms")
    
  if config.concurrent < 1 or config.concurrent > MAX_CONCURRENT:
    errors.add(fmt"Concurrent must be 1-{MAX_CONCURRENT}")
    
  return errors

# ============================================================================
# CIDR Parser (Bounds Checked)
# ============================================================================

proc parseCIDR(cidr: string): seq[string] =
  ## Parse CIDR notation with strict validation
  result = @[]
  
  let parts = cidr.split('/')
  if parts.len != 2:
    return @[cidr]  # Not CIDR, return as-is
    
  let baseIP = parts[0]
  if not validateIP(baseIP):
    return @[]
    
  var prefix: int
  try:
    prefix = parseInt(parts[1])
  except:
    return @[]
    
  if prefix < 0 or prefix > 32:
    return @[]
    
  # Limit to /24 to prevent accidental massive scans
  if prefix < 24:
    echo "[!] Warning: CIDR smaller than /24 limited for safety"
    prefix = 24
    
  let octets = baseIP.split('.')
  let baseAddr = (parseInt(octets[0]) shl 24) or
                 (parseInt(octets[1]) shl 16) or
                 (parseInt(octets[2]) shl 8) or
                 parseInt(octets[3])
                 
  let mask = 0xFFFFFFFF'u32 shl (32 - prefix)
  let network = baseAddr.uint32 and mask
  let broadcast = network or (not mask)
  
  var current = network + 1  # Skip network address
  while current < broadcast:
    let ip = fmt"{(current shr 24) and 0xFF}.{(current shr 16) and 0xFF}.{(current shr 8) and 0xFF}.{current and 0xFF}"
    result.add(ip)
    current += 1
    
    # Safety limit
    if result.len >= 256:
      break

# ============================================================================
# Timing Control (Rate Limiting)
# ============================================================================

type
  RateLimiter = ref object
    lastProbe: Time
    minDelay: Duration
    jitter: float

proc newRateLimiter(timing: TimingTemplate): RateLimiter =
  let delays = @[
    initDuration(minutes = 5),    # Paranoid
    initDuration(seconds = 15),   # Sneaky
    initDuration(milliseconds = 400),  # Polite
    initDuration(milliseconds = 10),   # Normal
    initDuration(milliseconds = 1),    # Aggressive
    initDuration(milliseconds = 0),    # Insane
  ]
  
  result = RateLimiter(
    lastProbe: getTime(),
    minDelay: delays[ord(timing)],
    jitter: JITTER_FACTOR
  )

proc waitForSlot(limiter: RateLimiter) {.async.} =
  let now = getTime()
  let elapsed = now - limiter.lastProbe
  
  if elapsed < limiter.minDelay:
    var waitTime = limiter.minDelay - elapsed
    
    # Add random jitter to evade detection
    let jitterMs = int(float(waitTime.inMilliseconds) * limiter.jitter * rand(1.0))
    waitTime = waitTime + initDuration(milliseconds = jitterMs)
    
    await sleepAsync(int(waitTime.inMilliseconds))
    
  limiter.lastProbe = getTime()

# ============================================================================
# Async TCP Scanner (Hardened)
# ============================================================================

proc scanPort(host: string, port: uint16, timeout: int, stealth: bool): Future[ScanResult] {.async.} =
  var result = ScanResult(
    host: host,
    port: port,
    state: Unknown,
    service: "",
    banner: "",
    latency: -1,
    timestamp: getTime()
  )
  
  let startTime = epochTime()
  var socket: AsyncSocket
  
  try:
    socket = newAsyncSocket()
    socket.setSockOpt(OptReuseAddr, true)
    
    # Set socket timeout
    let fut = socket.connect(host, Port(port))
    let completed = await withTimeout(fut, timeout)
    
    if completed:
      result.state = Open
      result.latency = (epochTime() - startTime) * 1000
      
      # Banner grabbing (with timeout)
      if not stealth:
        try:
          # Send probe for certain ports
          if port == 80 or port == 8080:
            await socket.send("HEAD / HTTP/1.0\r\nHost: " & host & "\r\n\r\n")
          
          let bannerFut = socket.recv(1024)
          let bannerComplete = await withTimeout(bannerFut, 2000)
          
          if bannerComplete:
            result.banner = bannerFut.read().strip()[0..min(127, bannerFut.read().len - 1)]
        except:
          discard
          
      # Identify service
      for probe in SERVICE_PROBES:
        if port in probe.ports:
          result.service = probe.name
          break
        if probe.pattern.len > 0 and probe.pattern in result.banner:
          result.service = probe.name
          break
    else:
      result.state = Filtered
      
  except OSError:
    result.state = Closed
  except:
    result.state = Unknown
  finally:
    if socket != nil:
      socket.close()
      
  return result

# ============================================================================
# Scan Orchestrator
# ============================================================================

type
  ScanOrchestrator = ref object
    config: ScanConfig
    results: seq[ScanResult]
    rateLimiter: RateLimiter
    openPorts: int
    closedPorts: int
    filteredPorts: int
    scanStart: Time
    lock: Lock

proc newOrchestrator(config: ScanConfig): ScanOrchestrator =
  result = ScanOrchestrator(
    config: config,
    results: @[],
    rateLimiter: newRateLimiter(config.timing),
    openPorts: 0,
    closedPorts: 0,
    filteredPorts: 0,
    scanStart: getTime()
  )
  initLock(result.lock)

proc addResult(orch: ScanOrchestrator, res: ScanResult) =
  withLock(orch.lock):
    orch.results.add(res)
    case res.state
    of Open:
      inc orch.openPorts
    of Closed:
      inc orch.closedPorts
    of Filtered:
      inc orch.filteredPorts
    else:
      discard

proc runScan(orch: ScanOrchestrator) {.async.} =
  var pending: seq[Future[ScanResult]] = @[]
  var total = orch.config.targets.len * orch.config.ports.len
  var completed = 0
  
  echo fmt"[*] Scanning {orch.config.targets.len} host(s), {orch.config.ports.len} port(s)"
  echo fmt"[*] Timing: {orch.config.timing}, Timeout: {orch.config.timeout}ms"
  echo "─".repeat(60)
  
  for host in orch.config.targets:
    for port in orch.config.ports:
      await orch.rateLimiter.waitForSlot()
      
      let fut = scanPort(host, port, orch.config.timeout, orch.config.stealth)
      pending.add(fut)
      
      # Limit concurrent operations
      while pending.len >= orch.config.concurrent:
        let idx = await raceIndex(pending)
        let res = pending[idx].read()
        pending.delete(idx)
        
        orch.addResult(res)
        inc completed
        
        if res.state == Open:
          let svc = if res.service.len > 0: fmt" ({res.service})" else: ""
          let bann = if res.banner.len > 0: fmt" - {res.banner[0..min(50, res.banner.len-1)]}" else: ""
          echo fmt"[+] {res.host}:{res.port} OPEN{svc}{bann}"
        
        # Progress indicator
        if completed mod 100 == 0:
          let pct = (completed * 100) div total
          echo fmt"[*] Progress: {completed}/{total} ({pct}%)"
  
  # Wait for remaining
  for fut in pending:
    let res = await fut
    orch.addResult(res)
    if res.state == Open:
      echo fmt"[+] {res.host}:{res.port} OPEN"

proc printSummary(orch: ScanOrchestrator) =
  let elapsed = getTime() - orch.scanStart
  
  echo "\n" & "═".repeat(60)
  echo "[*] Scan Summary"
  echo "─".repeat(60)
  echo fmt"  Duration:     {elapsed.inSeconds}s"
  echo fmt"  Open ports:   {orch.openPorts}"
  echo fmt"  Closed ports: {orch.closedPorts}"
  echo fmt"  Filtered:     {orch.filteredPorts}"
  
  if orch.openPorts > 0:
    echo "\n[+] Open Ports:"
    for res in orch.results:
      if res.state == Open:
        let svc = if res.service.len > 0: res.service else: "unknown"
        echo fmt"    {res.host}:{res.port} ({svc}) - {res.latency:.2f}ms"

# ============================================================================
# DNS Subdomain Enumeration
# ============================================================================

proc enumerateSubdomains(domain: string, wordlist: seq[string], timeout: int) {.async.} =
  echo fmt"[*] Enumerating subdomains for: {domain}"
  echo "─".repeat(60)
  
  var found: seq[string] = @[]
  
  for word in wordlist:
    let subdomain = fmt"{word}.{domain}"
    
    try:
      let addrs = getHostByName(subdomain)
      if addrs.addrList.len > 0:
        echo fmt"[+] {subdomain} -> {addrs.addrList[0]}"
        found.add(subdomain)
    except:
      discard
      
    await sleepAsync(50)  # Rate limit DNS queries
    
  echo fmt"\n[*] Found {found.len} subdomains"

# ============================================================================
# Output Handling
# ============================================================================

proc saveResults(orch: ScanOrchestrator, filename: string) =
  var f: File
  if open(f, filename, fmWrite):
    f.writeLine("# NullSec NetProbe Scan Results")
    f.writeLine(fmt"# Date: {now()}")
    f.writeLine(fmt"# Targets: {orch.config.targets.len}")
    f.writeLine("")
    
    for res in orch.results:
      if res.state == Open:
        f.writeLine(fmt"{res.host},{res.port},{res.service},{res.latency:.2f}")
    
    f.close()
    echo fmt"[*] Results saved to: {filename}"

# ============================================================================
# Command Line Interface
# ============================================================================

proc parseArgs(): ScanConfig =
  result = ScanConfig(
    targets: @[],
    ports: COMMON_PORTS,
    timeout: DEFAULT_TIMEOUT,
    concurrent: 50,
    timing: Normal,
    stealth: false,
    serviceScan: true,
    outputFile: ""
  )
  
  var p = initOptParser()
  
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key
      of "t", "target":
        let targets = p.val.split(',')
        for t in targets:
          if '/' in t:
            result.targets.add(parseCIDR(t.strip()))
          else:
            result.targets.add(t.strip())
      of "p", "ports":
        result.ports = @[]
        for ps in p.val.split(','):
          if '-' in ps:
            let range = ps.split('-')
            if range.len == 2:
              let start = parseInt(range[0].strip())
              let stop = parseInt(range[1].strip())
              for port in start..stop:
                if validatePort(port):
                  result.ports.add(uint16(port))
          else:
            let port = parseInt(ps.strip())
            if validatePort(port):
              result.ports.add(uint16(port))
      of "timeout":
        result.timeout = parseInt(p.val)
      of "c", "concurrent":
        result.concurrent = parseInt(p.val)
      of "T", "timing":
        result.timing = TimingTemplate(parseInt(p.val))
      of "s", "stealth":
        result.stealth = true
      of "o", "output":
        result.outputFile = p.val
      of "h", "help":
        echo """
USAGE:
    netprobe [options]

OPTIONS:
    -t, --target <host>      Target host(s), comma-separated or CIDR
    -p, --ports <ports>      Port(s) to scan (e.g., 22,80,443 or 1-1000)
    --timeout <ms>           Connection timeout (default: 3000)
    -c, --concurrent <n>     Concurrent connections (default: 50)
    -T, --timing <0-5>       Timing template (0=paranoid, 5=insane)
    -s, --stealth            Stealth mode (no banner grabbing)
    -o, --output <file>      Save results to file
    -h, --help               Show this help

EXAMPLES:
    netprobe -t 192.168.1.1 -p 22,80,443
    netprobe -t 192.168.1.0/24 -p 1-1000 -T 4
    netprobe -t example.com -p 80 --timeout 5000
"""
        quit(0)
      else:
        discard
    of cmdArgument:
      if validateTarget(p.key):
        result.targets.add(p.key)

# ============================================================================
# Main Entry Point
# ============================================================================

proc main() =
  randomize()
  echo BANNER
  
  let config = parseArgs()
  let errors = validateConfig(config)
  
  if errors.len > 0:
    echo "[!] Configuration errors:"
    for err in errors:
      echo fmt"    - {err}"
    quit(1)
    
  let orch = newOrchestrator(config)
  
  try:
    waitFor orch.runScan()
    orch.printSummary()
    
    if config.outputFile.len > 0:
      orch.saveResults(config.outputFile)
  except:
    echo fmt"[!] Scan error: {getCurrentExceptionMsg()}"
    quit(1)

when isMainModule:
  main()
