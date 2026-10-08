using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using ProctorAIDetective.Core;
using ProctorAIDetective.Native;

namespace ProctorAIDetective.Scanners
{
    /// <summary>
    /// Network corroboration: PID-attributed live TCP connections, and the Windows DNS
    /// resolver cache.
    ///
    /// SCOPE, AND WHY THE TIERS LOOK TIMID
    /// -----------------------------------
    /// Nothing this scanner observes identifies software. An IP address identifies a server,
    /// and *.parakeet-ai.com is a wildcard DNS record served out of shared Vercel anycast
    /// space with no PTR records, so the same address answers for an arbitrary number of
    /// unrelated sites. A DNS cache entry identifies neither a program nor a user. Both are
    /// therefore emitted as Weak with Attribution = 0: they can corroborate a finding another
    /// scanner made, and they can never, alone, accuse anyone of anything.
    ///
    /// The one exception is the process-attributed signal (<c>E2</c>): when the process that
    /// OWNS a matching socket is itself identifiable as the vendor by Authenticode signer,
    /// certificate thumbprint, VersionInfo or install path, the finding rests on the process
    /// identity and the socket merely proves it is live. That is the only network observation
    /// worth real weight, and the weight comes from the signature evidence, not the packet.
    ///
    /// Deliberately NOT implemented: an IP blocklist. Shipping one would bake today's CDN
    /// lease into a tool that accuses people, and would start producing false positives the
    /// first time a /24 is reassigned. Every address this scanner compares against is resolved
    /// live, at scan time, from the hostnames in signatures.json.
    ///
    /// ORDERING IS LOAD-BEARING: the DNS cache is read BEFORE any hostname is resolved.
    /// Measured on this machine: resolving the vendor hostnames seeds the resolver cache with
    /// every one of them within milliseconds - including ones that FAIL to resolve, which
    /// Windows negative-caches just the same. A scanner that looked the names up first and
    /// read the cache afterwards would find its own footprints and report them as evidence.
    /// </summary>
    public sealed class NetworkScanner : IScanner
    {
        public string Id { get { return "network"; } }

        public string DisplayName { get { return "Network endpoints and DNS cache"; } }

        // ---- scoring constants, kept here so the "corroboration only" intent is auditable ----

        /// <summary>
        /// Raw IP match: scores ZERO. Reported as an observation, never as evidence.
        ///
        /// This was 15, and that was wrong. Observed on a clean development machine: researching
        /// vendor websites put aceround.app, interviewpilot.in, chiku-ai.in and ghostpilotai.com
        /// into the resolver, all of which sit behind Cloudflare. Ordinary unrelated browsing then
        /// held live connections to 104.21.40.247, 172.67.217.19, 172.66.44.253 and 216.24.57.18 -
        /// shared anycast addresses serving millions of unrelated sites. Four such "matches"
        /// stacked to the Weak cap and pushed the class verdict to SUSPICIOUS on a machine running
        /// none of these products.
        ///
        /// The tier cap contained the damage (30, not 55) but containing a false positive is not
        /// the same as not producing one. A remote IP behind a CDN identifies the CDN, not the
        /// program talking to it, so it cannot carry any weight at all. The evidence that counts
        /// is E2 below, where the OWNING PROCESS independently matches a vendor signature - there
        /// the finding rests on the Authenticode identity and the socket is merely corroboration.
        /// </summary>
        private const int EndpointClassScore = 0;

        /// <summary>Process-attributed connection, primary vendor. The evidence is the signature, not the socket.</summary>
        private const int ProcessAttributionScore = 70;
        private const int ProcessClassScore = 65;

        /// <summary>DNS cache hit. Weak, zero attribution, and no state axis at all.</summary>
        private const int DnsClassScore = 12;

        /// <summary>Hard ceilings so a pathological signatures.json or a busy host cannot flood the grid.</summary>
        private const int MaxHostnamesToResolve = 64;
        private const int MaxEndpointSignals = 20;
        private const int MaxDnsSignals = 20;
        private const int MaxParallelResolves = 6;

        /// <summary>
        /// Hostnames THIS PROCESS has asked the resolver about, so a later scan in the same
        /// session does not mistake its own lookups for the subject's browsing history.
        /// Static and process-wide on purpose: scan 2 must remember what scan 1 did.
        /// </summary>
        private static readonly HashSet<string> SelfResolvedNames =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private static readonly object SelfResolvedLock = new object();

        // ================================================================= entry point

        /// <summary>
        /// Never throws. Every stage is independently guarded: a failure in the DNS stage must
        /// not cost us the TCP stage, and neither may take down the scan.
        /// </summary>
        public void Scan(ScanContext context, ScanReport report)
        {
            if (report == null) return;

            try
            {
                if (context == null)
                {
                    report.Limitations.Add("Network scan skipped: no scan context was supplied.");
                    return;
                }

                Stopwatch clock = Stopwatch.StartNew();
                int budgetMs = context.ScannerTimeoutMs > 0 ? context.ScannerTimeoutMs : 8000;

                SignatureSet signatures = context.Signatures ?? new SignatureSet();
                List<VendorSignature> vendors = SelectVendors(signatures, context.ReportClassWide);

                if (vendors.Count == 0)
                {
                    report.Limitations.Add(
                        "Network scan had nothing to look for: the signature database lists no vendor hostnames.");
                    return;
                }

                // STAGE 1 - DNS cache. MUST run before stage 2; see the class comment.
                try
                {
                    ScanDnsCache(context, report, vendors);
                }
                catch (Exception ex)
                {
                    report.Limitations.Add("DNS cache check failed (" + Describe(ex)
                        + "); recently-resolved hostnames are a blind spot for this scan.");
                }

                if (context.Cancel.IsCancellationRequested) return;

                if (clock.ElapsedMilliseconds >= budgetMs)
                {
                    report.Limitations.Add("Network scan ran out of its " + budgetMs
                        + " ms budget after the DNS cache check; live TCP endpoints were not examined.");
                    return;
                }

                // STAGE 2 - live TCP endpoints, attributed to owning processes.
                try
                {
                    ScanTcpEndpoints(context, report, vendors, clock, budgetMs);
                }
                catch (Exception ex)
                {
                    report.Limitations.Add("Live TCP endpoint check failed (" + Describe(ex)
                        + "); network connections are a blind spot for this scan.");
                }
            }
            catch (Exception ex)
            {
                // Belt and braces: the contract is that a scanner never throws, whatever happens.
                try
                {
                    report.Limitations.Add("Network scanner aborted unexpectedly (" + Describe(ex)
                        + "). Network evidence is missing from this report; treat it as unexamined, not clean.");
                }
                catch (Exception) { }
            }
        }

        // ================================================================= stage 1: DNS cache

        private void ScanDnsCache(ScanContext context, ScanReport report, List<VendorSignature> vendors)
        {
            string source;
            List<DnsCacheEntry>? entries = ReadDnsCache(report, out source);
            if (entries == null) return;   // both readers failed; ReadDnsCache already explained why

            if (entries.Count == 0)
            {
                ReportEmptyCache(report);
                return;
            }

            int emitted = 0;
            int selfSuppressed = 0;
            List<string> selfSuppressedNames = new List<string>(4);
            HashSet<string> alreadyReported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (DnsCacheEntry entry in entries)
            {
                if (context.Cancel.IsCancellationRequested) return;
                if (entry == null || string.IsNullOrEmpty(entry.Name)) continue;

                foreach (VendorSignature vendor in vendors)
                {
                    string? matchedHost = FirstMatchingHostname(entry.Name, vendor);
                    if (matchedHost == null) continue;

                    string dedupeKey = vendor.Key + "|" + entry.Name.ToLowerInvariant() + "|" + entry.RecordType;
                    if (!alreadyReported.Add(dedupeKey)) continue;

                    // Did WE put this here? Resolving a vendor hostname seeds the cache with it,
                    // successfully or not, so a repeat scan would otherwise read its own exhaust.
                    if (WasResolvedByThisProcess(entry.Name))
                    {
                        selfSuppressed++;
                        if (selfSuppressedNames.Count < 6) selfSuppressedNames.Add(entry.Name);
                        continue;
                    }

                    if (emitted >= MaxDnsSignals)
                    {
                        report.Limitations.Add("More than " + MaxDnsSignals
                            + " DNS cache entries matched vendor hostnames; the list shown is truncated.");
                        goto doneWithCache;
                    }

                    emitted++;
                    report.Signals.Add(BuildDnsSignal(context, vendor, entry, matchedHost, source, emitted));
                    break;   // one signal per cache entry; the first matching vendor owns it
                }
            }

        doneWithCache:
            if (selfSuppressed > 0)
            {
                report.Limitations.Add(selfSuppressed + " DNS cache "
                    + (selfSuppressed == 1 ? "entry was" : "entries were")
                    + " ignored because Proctor AI Detective resolved " + (selfSuppressed == 1 ? "that name" : "those names")
                    + " itself earlier in this session ("
                    + string.Join(", ", selfSuppressedNames.ToArray())
                    + "). Only the first scan after launch reads the cache before any lookup of its own, "
                    + "so that scan is the authoritative one for DNS-cache evidence.");
            }
        }

        /// <summary>
        /// Read the resolver cache: undocumented native table first, documented-ish WMI class as
        /// a fallback. Returns null only when BOTH failed, having recorded a Limitation.
        /// </summary>
        private static List<DnsCacheEntry>? ReadDnsCache(ScanReport report, out string source)
        {
            source = "";

            // Preferred: DnsGetCacheDataTable, the export `ipconfig /displaydns` uses. It is
            // undocumented and may disappear in a future Windows build, hence the fallback -
            // but it has full recall, where DnsQuery_W + DNS_QUERY_NO_WIRE_QUERY measured 48%
            // and silently returned "does not exist" for names that were genuinely cached.
            string? nativeNote;
            IReadOnlyList<DnsCacheEntry> native = NativeMethods.GetDnsCacheEntries(out nativeNote);

            if (nativeNote == null && native.Count > 0)
            {
                source = "DnsGetCacheDataTable (dnsapi.dll)";
                return new List<DnsCacheEntry>(native);
            }

            // Either the native read failed, or it came back empty. An empty cache is a real
            // state, but it is also what a broken read looks like, so cross-check with WMI
            // before believing it.
            string? wmiNote;
            List<DnsCacheEntry> wmi = ReadDnsCacheViaWmi(out wmiNote);

            if (wmiNote == null)
            {
                if (nativeNote != null)
                {
                    report.Limitations.Add(nativeNote
                        + " Fell back to WMI root\\StandardCimv2 MSFT_DNSClientCache, which returned "
                        + wmi.Count + " entries.");
                }
                source = "WMI root\\StandardCimv2 MSFT_DNSClientCache";
                return wmi;
            }

            if (nativeNote == null)
            {
                // Native read succeeded and genuinely found nothing; WMI could not confirm it.
                source = "DnsGetCacheDataTable (dnsapi.dll)";
                return new List<DnsCacheEntry>(native);
            }

            report.Limitations.Add("The Windows DNS resolver cache could not be read by either method ("
                + nativeNote + " / " + wmiNote
                + "). Recently-resolved hostnames are a blind spot for this scan; this is not a clean result.");
            return null;
        }

        /// <summary>
        /// MSFT_DNSClientCache in root\StandardCimv2 - the class Get-DnsClientCache wraps.
        /// Both Entry (the name that was queried) and Name (the record owner, which differs
        /// down a CNAME chain) are harvested, because either can be the vendor's hostname.
        /// </summary>
        private static List<DnsCacheEntry> ReadDnsCacheViaWmi(out string? failureNote)
        {
            failureNote = null;
            List<DnsCacheEntry> list = new List<DnsCacheEntry>(128);

            try
            {
                EnumerationOptions options = new EnumerationOptions();
                options.ReturnImmediately = true;
                options.Rewindable = false;
                options.Timeout = TimeSpan.FromMilliseconds(2000);

                ManagementScope scope = new ManagementScope(@"\\.\root\StandardCimv2");
                ObjectQuery query = new ObjectQuery("SELECT Entry, Name, Type FROM MSFT_DNSClientCache");

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query, options))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementBaseObject row in results)
                    {
                        using (row)
                        {
                            int type = ReadUInt16(row, "Type");
                            string entry = ReadString(row, "Entry");
                            string name = ReadString(row, "Name");

                            if (entry.Length > 0)
                                list.Add(new DnsCacheEntry { Name = entry, RecordType = type });

                            if (name.Length > 0 && !string.Equals(name, entry, StringComparison.OrdinalIgnoreCase))
                                list.Add(new DnsCacheEntry { Name = name, RecordType = type });
                        }
                    }
                }
            }
            catch (ManagementException ex)
            {
                failureNote = "MSFT_DNSClientCache unavailable (" + ex.ErrorCode + ": " + ex.Message.Trim() + ")";
            }
            catch (UnauthorizedAccessException)
            {
                failureNote = "MSFT_DNSClientCache refused access to this user";
            }
            catch (Exception ex)
            {
                failureNote = "MSFT_DNSClientCache read failed (" + Describe(ex) + ")";
            }

            return list;
        }

        /// <summary>
        /// An empty cache is not evidence of a clean machine. Say why it is empty when we can:
        /// with the DNS Client service stopped the cache is empty by design.
        /// </summary>
        private static void ReportEmptyCache(ScanReport report)
        {
            string state = QueryDnscacheServiceState();

            if (state.Length > 0 && !string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase))
            {
                report.Limitations.Add("The DNS Client service (Dnscache) is '" + state
                    + "', so Windows keeps no resolver cache at all. Hostname history is unavailable on this "
                    + "machine by configuration - that is a blind spot, not a clean result.");
                return;
            }

            report.Limitations.Add("The Windows DNS resolver cache was empty at scan time"
                + (state.Length > 0 ? " (the Dnscache service is " + state + ")" : "")
                + ". Entries expire on their TTL and are cleared by a reboot or `ipconfig /flushdns`, "
                + "so an empty cache shows nothing either way.");
        }

        private static string QueryDnscacheServiceState()
        {
            try
            {
                EnumerationOptions options = new EnumerationOptions();
                options.ReturnImmediately = true;
                options.Rewindable = false;
                options.Timeout = TimeSpan.FromMilliseconds(1500);

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    new ManagementScope(@"\\.\root\cimv2"),
                    new ObjectQuery("SELECT State FROM Win32_Service WHERE Name='Dnscache'"),
                    options))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementBaseObject row in results)
                    {
                        using (row) { return ReadString(row, "State"); }
                    }
                }
            }
            catch (Exception) { /* the service state is a nicety, never a reason to fail */ }

            return "";
        }

        private Signal BuildDnsSignal(ScanContext context, VendorSignature vendor, DnsCacheEntry entry,
                                      string matchedHost, string source, int index)
        {
            bool exact = string.Equals(TrimDot(entry.Name), TrimDot(matchedHost), StringComparison.OrdinalIgnoreCase);

            string detail =
                "The Windows DNS client cache holds '" + entry.Name + "' as a "
                + RecordTypeName(entry.RecordType) + " record"
                + (exact ? "" : ", a subdomain of '" + matchedHost + "'")
                + ", matching " + VendorLabel(vendor) + "'s hostname '" + matchedHost + "'. "
                + "Read via " + source + ". "
                + SpeechmaticsNote(matchedHost)
                + "WHAT THIS DOES NOT SHOW: the DNS cache carries no process attribution whatsoever - it cannot "
                + "say which program looked the name up, or which signed-in user. Entries expire on their TTL "
                + "and vanish on reboot or `ipconfig /flushdns`. Opening a web page, a chat client rendering a "
                + "link preview, a mail client fetching remote images, or a different user on this machine will "
                + "all seed it; Windows also negative-caches lookups that FAILED, so a name can sit here without "
                + "anything ever having connected to it. Scored Weak with zero attribution, and recorded as "
                + "proving neither installation nor execution.";

            Signal signal = new Signal
            {
                Id = "F1.dns.cache." + index.ToString(CultureInfo.InvariantCulture),
                Title = "Vendor hostname in the DNS resolver cache",
                Detail = detail,
                Tier = Tier.Weak,
                Attribution = 0,
                ClassScore = DnsClassScore,
                State = StateAxis.None,
                VendorKey = vendor.Key,
                Subject = entry.Name,
                Source = Id
            };

            ApplyAllowlist(context, signal);
            return signal;
        }

        // ================================================================= stage 2: live TCP

        private void ScanTcpEndpoints(ScanContext context, ScanReport report, List<VendorSignature> vendors,
                                      Stopwatch clock, int budgetMs)
        {
            string? tcpNote;
            IReadOnlyList<TcpConnectionInfo> rows = NativeMethods.GetTcpConnections(out tcpNote);

            if (tcpNote != null)
            {
                report.Limitations.Add(tcpNote
                    + " Part of the TCP connection table is therefore a blind spot for this scan.");
            }

            // Only rows with a real peer are candidates. LISTEN rows carry 0.0.0.0:0 / [::]:0
            // as their "remote" endpoint and describe nothing about where traffic is going.
            List<TcpConnectionInfo> live = new List<TcpConnectionInfo>(rows.Count);
            foreach (TcpConnectionInfo row in rows)
            {
                if (row == null) continue;
                if (row.RemotePort <= 0) continue;
                if (IsUnspecifiedAddress(row.RemoteAddress)) continue;
                live.Add(row);
            }

            if (live.Count == 0)
            {
                // Nothing to compare against, so do not resolve anything: a lookup we do not
                // need is still a lookup that pollutes the resolver cache for the next scan.
                return;
            }

            if (context.Cancel.IsCancellationRequested) return;

            // Resolve vendor hostnames ONCE for the whole scan, in parallel, inside a budget.
            List<string> hostnames = CollectHostnames(vendors, report);
            if (hostnames.Count == 0) return;

            int remaining = budgetMs - (int)clock.ElapsedMilliseconds;
            int dnsBudget = Clamp(remaining - 1000, 500, 3000);

            List<string> resolveProblems = new List<string>(2);
            Dictionary<string, List<string>> resolved =
                ResolveHostnames(hostnames, dnsBudget, context.Cancel, resolveProblems);

            foreach (string problem in resolveProblems) report.Limitations.Add(problem);

            // Stated plainly because it is reproducible and would otherwise look like evidence:
            // asking the resolver about these names puts them in this machine's DNS cache,
            // successfully or not - Windows negative-caches failures just the same. Repeat
            // scans inside one session discount them automatically (see SelfResolvedNames);
            // a fresh launch cannot know what a previous launch asked for.
            report.Limitations.Add("Checking live connections required resolving " + hostnames.Count
                + " vendor hostname" + (hostnames.Count == 1 ? "" : "s")
                + ", which places " + (hostnames.Count == 1 ? "that name" : "those names")
                + " in this machine's DNS cache. If Proctor AI Detective is started again before "
                + (hostnames.Count == 1 ? "it expires" : "they expire")
                + ", its DNS-cache check may see names put there by this scan rather than by the user. "
                + "Repeat scans within one session already discount them.");

            if (resolved.Count == 0) return;
            if (context.Cancel.IsCancellationRequested) return;

            // address -> which vendor hostnames currently answer on it.
            Dictionary<string, List<HostnameHit>> byAddress =
                new Dictionary<string, List<HostnameHit>>(StringComparer.OrdinalIgnoreCase);

            foreach (KeyValuePair<string, List<string>> pair in resolved)
            {
                VendorSignature? owner = OwnerOfHostname(vendors, pair.Key);
                if (owner == null) continue;

                foreach (string address in pair.Value)
                {
                    List<HostnameHit>? hits;
                    if (!byAddress.TryGetValue(address, out hits))
                    {
                        hits = new List<HostnameHit>(2);
                        byAddress[address] = hits;
                    }
                    hits.Add(new HostnameHit(owner, pair.Key));
                }
            }

            // Join live sockets to those addresses, grouped so one busy connection pool does
            // not become thirty near-identical rows in the evidence grid.
            Dictionary<string, MatchGroup> groups = new Dictionary<string, MatchGroup>(StringComparer.OrdinalIgnoreCase);
            int selfOwnedMatches = 0;
            int ownPid = CurrentProcessId();

            foreach (TcpConnectionInfo row in live)
            {
                List<HostnameHit>? hits;
                if (!byAddress.TryGetValue(row.RemoteAddress, out hits)) continue;

                // Proctor AI Detective never dials a vendor host - it only resolves names - so a socket
                // owned by this process cannot be a true positive. Excluded, but counted, so
                // the exclusion is visible rather than silent.
                if (ownPid != 0 && row.Pid == ownPid) { selfOwnedMatches++; continue; }

                foreach (HostnameHit hit in hits)
                {
                    string key = hit.Vendor.Key + "|" + row.RemoteAddress;
                    MatchGroup? group;
                    if (!groups.TryGetValue(key, out group))
                    {
                        group = new MatchGroup(hit.Vendor, row.RemoteAddress);
                        groups[key] = group;
                    }
                    group.Add(hit.Hostname, row);
                }
            }

            if (selfOwnedMatches > 0)
            {
                report.Limitations.Add(selfOwnedMatches + " connection(s) to a vendor address were owned by "
                    + "Proctor AI Detective itself and were excluded from the evidence.");
            }

            if (groups.Count == 0) return;

            // Identify the owning processes once, then reuse for both signal kinds.
            Dictionary<int, ProcessInfo?> owners = IdentifyOwners(groups.Values, context.Cancel);

            int endpointIndex = 0;
            foreach (MatchGroup group in groups.Values)
            {
                if (context.Cancel.IsCancellationRequested) return;

                if (endpointIndex >= MaxEndpointSignals)
                {
                    report.Limitations.Add("More than " + MaxEndpointSignals
                        + " live endpoints matched vendor addresses; the list shown is truncated.");
                    break;
                }

                endpointIndex++;
                report.Signals.Add(BuildEndpointSignal(context, group, owners, endpointIndex));
            }

            // The signal that actually matters: the owning PROCESS is the vendor's binary.
            EmitProcessAttributedSignals(context, report, groups.Values, owners);
        }

        /// <summary>
        /// For every process that owns a matching socket, ask whether the process ITSELF is
        /// identifiable as a vendor by signature evidence. This is where attribution comes
        /// from - the connection only establishes that the identified binary is live.
        /// </summary>
        private void EmitProcessAttributedSignals(ScanContext context, ScanReport report,
                                                  IEnumerable<MatchGroup> groups,
                                                  Dictionary<int, ProcessInfo?> owners)
        {
            SignatureSet signatures = context.Signatures ?? new SignatureSet();
            HashSet<int> done = new HashSet<int>();
            int index = 0;

            foreach (MatchGroup group in groups)
            {
                foreach (int pid in group.Pids)
                {
                    if (context.Cancel.IsCancellationRequested) return;
                    if (pid <= 0) continue;
                    if (!done.Add(pid)) continue;

                    ProcessInfo? owner;
                    if (!owners.TryGetValue(pid, out owner) || owner == null) continue;

                    VendorMatch? match = MatchProcessToVendor(owner, signatures, context.ReportClassWide);
                    if (match == null) continue;

                    index++;
                    report.Signals.Add(BuildProcessSignal(context, match.Value, owner, group, index));
                }
            }
        }

        private Signal BuildEndpointSignal(ScanContext context, MatchGroup group,
                                           Dictionary<int, ProcessInfo?> owners, int index)
        {
            string hostList = string.Join(", ", group.Hostnames.ToArray());
            string portList = string.Join(", ", group.PortDescriptions().ToArray());
            string ownerList = DescribeOwners(group, owners);

            string detail =
                group.ConnectionCount + " live TCP "
                + (group.ConnectionCount == 1 ? "connection" : "connections")
                + " to " + group.RemoteAddress + " (" + portList + "), which "
                + VendorLabel(group.Vendor) + "'s hostname" + (group.Hostnames.Count == 1 ? " " : "s ")
                + hostList + " resolved to at scan time. Owning " + ownerList + ". "
                + SpeechmaticsNote(hostList)
                + "CAVEAT, AND IT IS A LARGE ONE: this is an address match, not an identity match. "
                + "*.parakeet-ai.com is a wildcard DNS record answered from shared Vercel anycast space "
                + "(216.150.x.x) with no PTR records, so one address fronts an unbounded number of unrelated "
                + "sites; the same is true of the Cloudflare ranges the other vendors sit behind. A match here "
                + "is consistent with somebody visiting an ordinary website hosted on the same infrastructure. "
                + "For that reason it is scored Weak with zero attribution and can never, by itself, produce a "
                + "detection. The address was resolved live during this scan - Proctor AI Detective ships no IP blocklist.";

            Signal signal = new Signal
            {
                Id = "E1.net.endpoint." + index.ToString(CultureInfo.InvariantCulture),
                Title = "Live connection to an address a vendor hostname resolves to",
                Detail = detail,
                Tier = Tier.Weak,
                Attribution = 0,
                ClassScore = EndpointClassScore,
                State = StateAxis.Running,
                VendorKey = group.Vendor.Key,
                Subject = group.RemoteAddress,
                Pid = group.Pids.Count == 1 ? group.FirstPid : 0,
                Source = Id
            };

            ApplyAllowlist(context, signal);
            return signal;
        }

        private Signal BuildProcessSignal(ScanContext context, VendorMatch match, ProcessInfo owner,
                                          MatchGroup group, int index)
        {
            bool primary = match.Vendor.PrimaryTarget;
            string hostList = string.Join(", ", group.Hostnames.ToArray());

            string detail =
                "Process '" + DisplayProcessName(owner) + "' (pid "
                + owner.Pid.ToString(CultureInfo.InvariantCulture)
                + ") holds a live TCP connection to " + group.RemoteAddress
                + " (" + string.Join(", ", group.PortDescriptions().ToArray())
                + "), an address " + VendorLabel(group.Vendor) + "'s hostname " + hostList
                + " resolves to - AND the process itself matches " + VendorLabel(match.Vendor)
                + " by " + match.EvidenceKind + ": " + match.Evidence + ". "
                + "Image path: " + (owner.ImagePath.Length > 0 ? owner.ImagePath : "<could not be resolved>") + ". "
                + "Authenticode signer: " + (owner.SignerSubject.Length > 0 ? owner.SignerSubject : "<none readable>") + ". "
                + SpeechmaticsNote(hostList)
                + "The weight here rests on the process identity, not on the address: the connection only "
                + "establishes that this already-identified binary is on the network right now. "
                + (primary
                    ? "Attributed to " + VendorLabel(match.Vendor) + " because it is the primary target of this build."
                    : "Attribution is zero: " + VendorLabel(match.Vendor) + " is not this build's primary target, "
                      + "so this counts only towards the capture-evading assistant class.")
                + (match.PathOnly
                    ? " NOTE: the only match was the install path. A path is user-controllable - anyone may create "
                      + "a folder of that name - so treat this as weaker than the tier suggests unless a signer or "
                      + "certificate match appears elsewhere in this report."
                    : "");

            Signal signal = new Signal
            {
                Id = "E2.net.process." + index.ToString(CultureInfo.InvariantCulture),
                Title = "Identified vendor process holds a live connection to vendor infrastructure",
                Detail = detail,
                Tier = Tier.Strong,
                Attribution = primary ? ProcessAttributionScore : 0,
                ClassScore = ProcessClassScore,
                State = StateAxis.Running,
                VendorKey = match.Vendor.Key,
                Subject = DisplayProcessName(owner),
                SubjectPath = owner.ImagePath,
                Signer = owner.SignerSubject,
                Pid = owner.Pid,
                Source = Id
            };

            ApplyAllowlist(context, signal);
            return signal;
        }

        private static Dictionary<int, ProcessInfo?> IdentifyOwners(IEnumerable<MatchGroup> groups, CancellationToken cancel)
        {
            Dictionary<int, ProcessInfo?> owners = new Dictionary<int, ProcessInfo?>();

            foreach (MatchGroup group in groups)
            {
                foreach (int pid in group.Pids)
                {
                    if (cancel.IsCancellationRequested) return owners;
                    if (pid <= 0 || owners.ContainsKey(pid)) continue;

                    try { owners[pid] = ProcessInfoCollector.ForPid(pid); }
                    catch (Exception) { owners[pid] = null; }
                }
            }

            return owners;
        }

        // ================================================================= hostname resolution

        private static List<string> CollectHostnames(List<VendorSignature> vendors, ScanReport report)
        {
            List<string> hostnames = new List<string>(16);
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool truncated = false;

            foreach (VendorSignature vendor in vendors)
            {
                if (vendor.Hostnames == null) continue;

                foreach (string raw in vendor.Hostnames)
                {
                    if (string.IsNullOrEmpty(raw)) continue;
                    string host = TrimDot(raw.Trim());
                    if (host.Length == 0) continue;
                    if (!seen.Add(host)) continue;

                    if (hostnames.Count >= MaxHostnamesToResolve) { truncated = true; break; }
                    hostnames.Add(host);
                }

                if (truncated) break;
            }

            if (truncated)
            {
                report.Limitations.Add("The signature database lists more than " + MaxHostnamesToResolve
                    + " vendor hostnames; only the first " + MaxHostnamesToResolve
                    + " were resolved, to keep the scan inside its time budget.");
            }

            return hostnames;
        }

        /// <summary>
        /// Resolve hostnames in parallel against a wall-clock budget. Dns.GetHostAddresses has
        /// no timeout of its own and a dead resolver will block for seconds, so the work runs
        /// on pool threads behind a concurrency gate and the caller simply stops waiting. Any
        /// stragglers finish harmlessly into results nobody reads.
        /// </summary>
        private static Dictionary<string, List<string>> ResolveHostnames(List<string> hostnames, int budgetMs,
                                                                         CancellationToken cancel, List<string> problems)
        {
            Dictionary<string, List<string>> resolved = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            if (hostnames.Count == 0) return resolved;

            // Every name we are about to hand the resolver will be cached by Windows, whether
            // it resolves or not. Record that BEFORE asking, so a crash mid-way cannot leave
            // the set out of step with reality.
            RememberSelfResolved(hostnames);

            // Not disposed deliberately: tasks abandoned at the timeout still hold it, and no
            // wait handle is ever materialised, so there is nothing to leak.
            SemaphoreSlim gate = new SemaphoreSlim(MaxParallelResolves);
            List<Task<ResolveResult>> tasks = new List<Task<ResolveResult>>(hostnames.Count);

            foreach (string hostname in hostnames)
            {
                string host = hostname;
                tasks.Add(Task.Run(delegate
                {
                    List<string> addresses = new List<string>(4);
                    string failure = "";
                    try
                    {
                        gate.Wait(cancel);
                        try
                        {
                            IPAddress[] found = Dns.GetHostAddresses(host);
                            foreach (IPAddress address in found) addresses.Add(address.ToString());
                        }
                        finally { gate.Release(); }
                    }
                    catch (System.Net.Sockets.SocketException)
                    {
                        // NXDOMAIN or no answer. Entirely routine - several vendor hostnames in
                        // signatures.json are wildcard parents that never resolve on their own.
                        failure = "";
                    }
                    catch (OperationCanceledException) { failure = ""; }
                    catch (Exception ex) { failure = Describe(ex); }

                    return new ResolveResult(host, addresses, failure);
                }, cancel));
            }

            try { Task.WaitAll(tasks.ToArray(), budgetMs, cancel); }
            catch (OperationCanceledException) { }
            catch (AggregateException) { }
            catch (Exception) { }

            int unfinished = 0;
            List<string> errors = new List<string>(2);

            foreach (Task<ResolveResult> task in tasks)
            {
                if (task.Status != TaskStatus.RanToCompletion) { unfinished++; continue; }

                ResolveResult result = task.Result;
                if (result.Failure.Length > 0 && errors.Count < 3) errors.Add(result.Host + ": " + result.Failure);
                if (result.Addresses.Count > 0) resolved[result.Host] = result.Addresses;
            }

            if (unfinished > 0 && !cancel.IsCancellationRequested)
            {
                problems.Add(unfinished + " vendor hostname lookup(s) did not finish within the "
                    + budgetMs + " ms DNS budget; any live connection to those addresses is a blind spot.");
            }

            if (errors.Count > 0)
            {
                problems.Add("Hostname resolution reported errors (" + string.Join("; ", errors.ToArray()) + ").");
            }

            return resolved;
        }

        private static void RememberSelfResolved(IEnumerable<string> hostnames)
        {
            try
            {
                lock (SelfResolvedLock)
                {
                    foreach (string host in hostnames) SelfResolvedNames.Add(TrimDot(host));
                }
            }
            catch (Exception) { }
        }

        private static bool WasResolvedByThisProcess(string name)
        {
            try
            {
                lock (SelfResolvedLock) { return SelfResolvedNames.Contains(TrimDot(name)); }
            }
            catch (Exception) { return false; }
        }

        // ================================================================= matching helpers

        private static List<VendorSignature> SelectVendors(SignatureSet signatures, bool reportClassWide)
        {
            List<VendorSignature> selected = new List<VendorSignature>();
            if (signatures.Vendors == null) return selected;

            foreach (VendorSignature vendor in signatures.Vendors)
            {
                if (vendor == null) continue;
                if (!reportClassWide && !vendor.PrimaryTarget) continue;
                if (vendor.Hostnames == null || vendor.Hostnames.Count == 0) continue;
                selected.Add(vendor);
            }

            return selected;
        }

        private static VendorSignature? OwnerOfHostname(List<VendorSignature> vendors, string hostname)
        {
            foreach (VendorSignature vendor in vendors)
            {
                if (vendor.Hostnames == null) continue;
                foreach (string candidate in vendor.Hostnames)
                {
                    if (string.IsNullOrEmpty(candidate)) continue;
                    if (string.Equals(TrimDot(candidate.Trim()), hostname, StringComparison.OrdinalIgnoreCase))
                        return vendor;
                }
            }
            return null;
        }

        /// <summary>The vendor hostname that <paramref name="cachedName"/> matches, or null.</summary>
        private static string? FirstMatchingHostname(string cachedName, VendorSignature vendor)
        {
            if (vendor.Hostnames == null) return null;

            foreach (string hostname in vendor.Hostnames)
            {
                if (string.IsNullOrEmpty(hostname)) continue;
                if (IsSameOrSubdomain(cachedName, hostname)) return hostname.Trim();
            }

            return null;
        }

        /// <summary>
        /// True when <paramref name="candidate"/> is the hostname itself or a subdomain of it.
        /// The boundary check on '.' is what stops "notparakeet-ai.com" matching "parakeet-ai.com".
        /// </summary>
        private static bool IsSameOrSubdomain(string candidate, string hostname)
        {
            string a = TrimDot(candidate == null ? "" : candidate.Trim());
            string b = TrimDot(hostname == null ? "" : hostname.Trim());
            if (a.Length == 0 || b.Length == 0) return false;

            if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;

            return a.Length > b.Length + 1
                && a.EndsWith(b, StringComparison.OrdinalIgnoreCase)
                && a[a.Length - b.Length - 1] == '.';
        }

        /// <summary>
        /// Does this process's own identity match a vendor? Evidence is ranked, because a
        /// certificate cannot be forged and a folder name can: thumbprint beats signer beats
        /// VersionInfo beats path, and a path-only match is flagged as such in the signal.
        /// </summary>
        private static VendorMatch? MatchProcessToVendor(ProcessInfo process, SignatureSet signatures, bool reportClassWide)
        {
            if (signatures.Vendors == null) return null;

            VendorMatch? best = null;

            foreach (VendorSignature vendor in signatures.Vendors)
            {
                if (vendor == null) continue;
                if (!reportClassWide && !vendor.PrimaryTarget) continue;

                VendorMatch? candidate = MatchOneVendor(process, vendor);
                if (candidate == null) continue;

                if (best == null
                    || candidate.Value.Rank > best.Value.Rank
                    || (candidate.Value.Rank == best.Value.Rank && candidate.Value.Vendor.PrimaryTarget && !best.Value.Vendor.PrimaryTarget))
                {
                    best = candidate;
                }
            }

            return best;
        }

        private static VendorMatch? MatchOneVendor(ProcessInfo process, VendorSignature vendor)
        {
            // 4 - certificate thumbprint. Unforgeable without the vendor's private key.
            if (process.CertThumbprint.Length > 0 && vendor.CertThumbprints != null)
            {
                foreach (string thumb in vendor.CertThumbprints)
                {
                    if (string.IsNullOrEmpty(thumb)) continue;
                    if (string.Equals(Normalise(thumb), Normalise(process.CertThumbprint), StringComparison.OrdinalIgnoreCase))
                        return new VendorMatch(vendor, 4, "signing-certificate thumbprint",
                            process.CertThumbprint, false);
                }
            }

            // 3 - Authenticode signer subject.
            if (process.SignerSubject.Length > 0 && vendor.SignerContains != null)
            {
                foreach (string fragment in vendor.SignerContains)
                {
                    if (string.IsNullOrEmpty(fragment)) continue;
                    if (process.SignerSubject.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0)
                        return new VendorMatch(vendor, 3, "Authenticode signer",
                            "signer '" + process.SignerSubject + "' contains '" + fragment + "'", false);
                }
            }

            // 2 - VersionInfo. Trivially editable by a rebuild, but not by a rename.
            if (process.CompanyName.Length > 0 && vendor.CompanyNames != null)
            {
                foreach (string company in vendor.CompanyNames)
                {
                    if (string.IsNullOrEmpty(company)) continue;
                    if (string.Equals(process.CompanyName.Trim(), company.Trim(), StringComparison.OrdinalIgnoreCase))
                        return new VendorMatch(vendor, 2, "VersionInfo CompanyName",
                            "CompanyName is '" + process.CompanyName + "'", false);
                }
            }

            if (process.LegalCopyright.Length > 0 && vendor.CopyrightContains != null)
            {
                foreach (string fragment in vendor.CopyrightContains)
                {
                    if (string.IsNullOrEmpty(fragment)) continue;
                    if (process.LegalCopyright.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0)
                        return new VendorMatch(vendor, 2, "VersionInfo LegalCopyright",
                            "LegalCopyright is '" + process.LegalCopyright + "'", false);
                }
            }

            // 1 - install path. Weakest: a user can create any folder they like.
            if (process.ImagePath.Length > 0 && vendor.PathFragments != null)
            {
                foreach (string fragment in vendor.PathFragments)
                {
                    if (string.IsNullOrEmpty(fragment)) continue;
                    if (process.ImagePath.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0)
                        return new VendorMatch(vendor, 1, "install path",
                            "image path contains '" + fragment + "'", true);
                }
            }

            return null;
        }

        // ================================================================= small helpers

        private void ApplyAllowlist(ScanContext context, Signal signal)
        {
            try
            {
                Allowlist? allowlist = context.Allowlist;
                if (allowlist != null) allowlist.Apply(signal);
            }
            catch (Exception)
            {
                // A failed allowlist evaluation must leave the signal at its pass-through
                // multiplier rather than silently zeroing or inflating it.
                signal.Allowlist = AllowlistOutcome.NotListed;
                signal.Multiplier = 1.0;
                signal.AllowlistReason = "";
            }
        }

        /// <summary>
        /// Mentioned when a Speechmatics endpoint is involved: realtime speech-to-text over
        /// wss://*.rt.speechmatics.com is the most distinctive first-party dependency the
        /// primary target has, and is rare on an ordinary desktop. Distinctive is not the same
        /// as attributable, so the tier does not move.
        /// </summary>
        private static string SpeechmaticsNote(string hostnames)
        {
            if (hostnames.IndexOf("speechmatics", StringComparison.OrdinalIgnoreCase) < 0) return "";

            return "WORTH NOTING: wss://*.rt.speechmatics.com is Speechmatics realtime speech-to-text, the most "
                 + "distinctive first-party endpoint the primary target uses and uncommon on an ordinary desktop "
                 + "- though it is a general-purpose commercial STT service with many other customers, so it "
                 + "names a capability, not a product. The tier is unchanged. ";
        }

        private static string DescribeOwners(MatchGroup group, Dictionary<int, ProcessInfo?> owners)
        {
            List<string> parts = new List<string>(group.Pids.Count);

            foreach (int pid in group.Pids)
            {
                ProcessInfo? info;
                owners.TryGetValue(pid, out info);

                if (pid <= 0)
                {
                    parts.Add("an unattributed socket (pid 0 - typically a TIME_WAIT remnant)");
                }
                else if (info == null)
                {
                    parts.Add("pid " + pid.ToString(CultureInfo.InvariantCulture) + " (process could not be identified)");
                }
                else
                {
                    parts.Add("'" + DisplayProcessName(info) + "' (pid " + pid.ToString(CultureInfo.InvariantCulture) + ")");
                }
            }

            string joined = string.Join(", ", parts.ToArray());
            return (parts.Count == 1 ? "process: " : "processes: ") + joined;
        }

        private static string DisplayProcessName(ProcessInfo info)
        {
            if (info.Name.Length > 0) return info.Name;
            if (info.ImagePath.Length > 0)
            {
                int slash = info.ImagePath.LastIndexOf('\\');
                if (slash >= 0 && slash < info.ImagePath.Length - 1) return info.ImagePath.Substring(slash + 1);
                return info.ImagePath;
            }
            return "pid " + info.Pid.ToString(CultureInfo.InvariantCulture);
        }

        private static string VendorLabel(VendorSignature vendor)
        {
            if (vendor.Name.Length > 0) return vendor.Name;
            if (vendor.Key.Length > 0) return vendor.Key;
            return "an unnamed vendor";
        }

        private static bool IsUnspecifiedAddress(string address)
        {
            if (string.IsNullOrEmpty(address)) return true;
            if (address == "0.0.0.0") return true;
            if (address == "::") return true;
            if (address == "::0") return true;
            return false;
        }

        private static string TcpStateName(uint state)
        {
            switch (state)
            {
                case 1: return "CLOSED";
                case 2: return "LISTEN";
                case 3: return "SYN_SENT";
                case 4: return "SYN_RCVD";
                case 5: return "ESTABLISHED";
                case 6: return "FIN_WAIT1";
                case 7: return "FIN_WAIT2";
                case 8: return "CLOSE_WAIT";
                case 9: return "CLOSING";
                case 10: return "LAST_ACK";
                case 11: return "TIME_WAIT";
                case 12: return "DELETE_TCB";
                default: return "state " + state.ToString(CultureInfo.InvariantCulture);
            }
        }

        private static string RecordTypeName(int type)
        {
            switch (type)
            {
                case 1: return "A";
                case 2: return "NS";
                case 5: return "CNAME";
                case 6: return "SOA";
                case 12: return "PTR";
                case 15: return "MX";
                case 16: return "TXT";
                case 28: return "AAAA";
                case 33: return "SRV";
                case 65: return "HTTPS";
                default: return "type " + type.ToString(CultureInfo.InvariantCulture);
            }
        }

        private static string TrimDot(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.TrimEnd('.');
        }

        private static string Normalise(string thumbprint)
        {
            return thumbprint.Replace(" ", "").Replace(":", "").Replace("-", "").Trim();
        }

        private static int Clamp(int value, int low, int high)
        {
            if (value < low) return low;
            if (value > high) return high;
            return value;
        }

        private static int CurrentProcessId()
        {
            try
            {
                using (Process self = Process.GetCurrentProcess()) { return self.Id; }
            }
            catch (Exception) { return 0; }
        }

        private static string ReadString(ManagementBaseObject row, string property)
        {
            try
            {
                object? value = row[property];
                return value as string ?? "";
            }
            catch (Exception) { return ""; }
        }

        private static int ReadUInt16(ManagementBaseObject row, string property)
        {
            try
            {
                object? value = row[property];
                if (value == null) return 0;
                return Convert.ToInt32(value, CultureInfo.InvariantCulture);
            }
            catch (Exception) { return 0; }
        }

        private static string Describe(Exception ex)
        {
            return ex.GetType().Name + ": " + ex.Message;
        }

        // ================================================================= private value types

        /// <summary>One vendor hostname that currently answers on a particular address.</summary>
        private sealed class HostnameHit
        {
            public readonly VendorSignature Vendor;
            public readonly string Hostname;

            public HostnameHit(VendorSignature vendor, string hostname)
            {
                Vendor = vendor;
                Hostname = hostname;
            }
        }

        /// <summary>All the live sockets pointing at one (vendor, remote address) pair.</summary>
        private sealed class MatchGroup
        {
            public readonly VendorSignature Vendor;
            public readonly string RemoteAddress;
            public readonly List<string> Hostnames = new List<string>(2);
            public readonly List<int> Pids = new List<int>(2);

            private readonly List<TcpConnectionInfo> _rows = new List<TcpConnectionInfo>(4);

            public MatchGroup(VendorSignature vendor, string remoteAddress)
            {
                Vendor = vendor;
                RemoteAddress = remoteAddress;
            }

            public int ConnectionCount { get { return _rows.Count; } }

            public int FirstPid { get { return Pids.Count > 0 ? Pids[0] : 0; } }

            public void Add(string hostname, TcpConnectionInfo row)
            {
                if (!Hostnames.Contains(hostname)) Hostnames.Add(hostname);
                if (!Pids.Contains(row.Pid)) Pids.Add(row.Pid);
                _rows.Add(row);
            }

            /// <summary>"port 443 ESTABLISHED" per distinct port+state, so TIME_WAIT is never dressed up as live traffic.</summary>
            public List<string> PortDescriptions()
            {
                List<string> parts = new List<string>(_rows.Count);
                HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);

                foreach (TcpConnectionInfo row in _rows)
                {
                    string text = "port " + row.RemotePort.ToString(CultureInfo.InvariantCulture)
                                + " " + TcpStateName(row.State);
                    if (seen.Add(text)) parts.Add(text);
                }

                if (parts.Count == 0) parts.Add("no port recorded");
                return parts;
            }
        }

        /// <summary>A process identified as a vendor's binary, with the evidence that did it.</summary>
        private struct VendorMatch
        {
            public readonly VendorSignature Vendor;

            /// <summary>4 thumbprint, 3 signer, 2 VersionInfo, 1 path. Higher wins.</summary>
            public readonly int Rank;

            public readonly string EvidenceKind;
            public readonly string Evidence;
            public readonly bool PathOnly;

            public VendorMatch(VendorSignature vendor, int rank, string evidenceKind, string evidence, bool pathOnly)
            {
                Vendor = vendor;
                Rank = rank;
                EvidenceKind = evidenceKind;
                Evidence = evidence;
                PathOnly = pathOnly;
            }
        }

        private struct ResolveResult
        {
            public readonly string Host;
            public readonly List<string> Addresses;
            public readonly string Failure;

            public ResolveResult(string host, List<string> addresses, string failure)
            {
                Host = host;
                Addresses = addresses;
                Failure = failure;
            }
        }
    }
}
