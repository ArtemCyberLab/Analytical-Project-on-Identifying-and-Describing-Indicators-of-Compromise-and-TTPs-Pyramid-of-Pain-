Research Objective

I set myself the goal of thoroughly analyzing a malware sample and its related artifacts (file hashes, IP and domain indicators, host and network artifacts, tools, and TTPs) in order to evaluate their value within the Pyramid of Pain framework and to provide practical insights for threat hunters, incident responders, and SOC analysts.

Research Description and Methodology

During this project, I carried out the following steps:

Hash Identification and Static Analysis

Verified the SHA-256 sample hash: b8ef959a9176aef07fdca8705254a163b50b49a17217a4ff0107487f59d4a35d.

Determined the original file: Sales_Receipt 5606.xls.

Confirmed that relying only on hashes as IOCs is inefficient, as they can be easily changed.

Dynamic Analysis of Network Artifacts

Analyzed sample detonation in the Any.run sandbox.

Recorded the first IP contacted by the malicious process (PID 1632): 50.87.136.52.

Identified the first requested domain: craftingalegacy.com.

Host Artifacts

Observed that the process regidle.exe made POST requests to 96.126.101.6:8080.

Identified the dropped file: G_jugk.exe.

VirusTotal results showed: 9 vendors flagged it as malicious.

Network Artifacts

Extracted User-Agent strings from the PCAP.

Determined the browser used: Internet Explorer.

Counted 6 POST requests in the capture.

Tools and Similarity Methods

Applied fuzzy hashing (SSDeep) to detect related malware samples.

Recorded the alternative term for fuzzy hashing: context triggered piecewise hashes.

TTPs and MITRE ATT&CK

Mapped observed actions to the ATT&CK matrix: the Exfiltration category contains 9 techniques.

Identified the use of Cobalt Strike as a commercial tool for C2 and data exfiltration.

Results (Key Findings)

File hashes are useful for identifying specific samples but can be bypassed easily.

IPs and domains (50.87.136.52, craftingalegacy.com, 96.126.101.6) provide temporary control points but are quickly rotated by attackers.

Host and network artifacts (processes, POST requests, user-agent strings) provide more resilient detection opportunities.

Fuzzy hashing allows detection of related or modified malware samples.

Mapping activity to MITRE ATT&CK helps systematize observations and prioritize defensive measures.

Practical Recommendations

Do not rely solely on hashes — combine different types of indicators.

Automate IOC and TTP correlation in CTI platforms.

Use fuzzy hashing to detect modified or related samples.

Monitor for network anomalies such as rare user-agents or POST requests to non-standard ports.

Prioritize “painful” indicators for attackers (tools and TTPs).

Conclusion

I concluded that the most valuable indicators for detection and defense are behavioral and tactical ones, rather than static IOCs. Leveraging dynamic analysis, fuzzy hashing, and mapping to ATT&CK significantly increases the effectiveness of threat hunting, complicates attacker operations, and reduces response time.
