Building a set of use cases is hard, so below are some links to resources which may help.  Mapped to the excellent [MITRE ATT&CK](https://attack.mitre.org/) where appropriate. Fairly Windows-centric. 

The focus is on information to help people build use cases that generate high quality alerts but clearly there is a massive crossover into the worlds of Incident Response and Threat Hunting so some of that too.

Things not directly to do with use cases but which may be useful to the sort of person interested in use cases are here 

This will always be a work in progress so any queries, comments  or suggestions gratefully received: [website@siemusecases.com](mailto:website@siemusecases.com)

## Use Cases 

Deprecated
{: .label .label-red }

MITRE's Cyber Analytics Repository and D3FEND project <br />
[https://car.mitre.org/analytics/](https://car.mitre.org/analytics/) and [https://d3fend.mitre.org/](https://d3fend.mitre.org/)

Red Canary's report on the most commonly observed ATT&CK techniques and how to detect them. Very very useful <br />
[https://resource.redcanary.com/rs/003-YRU-314/images/2021-Threat-Detection-Report.pdf](https://resource.redcanary.com/rs/003-YRU-314/images/2021-Threat-Detection-Report.pdf)

Bit out of date but still useful <br />
[https://github.com/jhainly/det3ct-the-att-ck/blob/master/use%20case%20library.xlsx](https://github.com/jhainly/det3ct-the-att-ck/blob/master/use%20case%20library.xlsx)

Sigma's detection rules <br />
[https://github.com/SigmaHQ/sigma/tree/master/rules](https://github.com/SigmaHQ/sigma/tree/master/rules)


## SIEM Vendor Detections
Although these are clearly vendor specific, how the logic works is useful in implementing similar detection use cases in other platforms.

Elastic's detection rules <br />
[https://github.com/elastic/detection-rules/tree/main/rules](https://github.com/elastic/detection-rules/tree/main/rules)

Microsoft Sentinel's detection rules <br />
[https://github.com/Azure/Azure-Sentinel/tree/master/Detections](https://github.com/Azure/Azure-Sentinel/tree/master/Detections)

Splunk's Security Essentials detection rules <br />
[https://docs.splunksecurityessentials.com/content-detail/](https://docs.splunksecurityessentials.com/content-detail/) <br />
[https://github.com/splunk/security_content/tree/develop/detections](https://github.com/splunk/security_content/tree/develop/detections)


## Tactics and Techniques
### Kerberoasting [T1158.003](https://attack.mitre.org/techniques/T1558/003/)
[https://www.trimarcsecurity.com/single-post/trimarcresearch-detecting-kerberoasting-activity ](https://www.trimarcsecurity.com/single-post/trimarcresearch-detecting-kerberoasting-activity ) <br />
[https://adsecurity.org/?p=3458](https://adsecurity.org/?p=3458)

### Golden Ticket [T1558.001](https://attack.mitre.org/techniques/T1558/001/) and Silver Ticket [T1558.002](https://attack.mitre.org/techniques/T1558/002/)
[https://adsecurity.org/?p=1515](https://adsecurity.org/?p=1515)

### Password Spraying [T1110.003](https://attack.mitre.org/techniques/T1110/003/)
[https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing](https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing)

### Powershell [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
Potentially suspicious commands <br />
[https://gist.github.com/gfoss/2b39d680badd2cad9d82](https://gist.github.com/gfoss/2b39d680badd2cad9d82)

Mandiant's guide to Powershell logging <br />
[https://www.mandiant.com/resources/greater-visibilityt](https://www.mandiant.com/resources/greater-visibilityt)

### OS Credential Dumping [T1003](https://attack.mitre.org/techniques/T1003/)
**Mimikatz**

[https://redcanary.com/threat-detection-report/threats/mimikatz/](https://redcanary.com/threat-detection-report/threats/mimikatz/) <br />
[https://neil-fox.github.io/Mimikatz-usage-&-detection/](https://neil-fox.github.io/Mimikatz-usage-&-detection/) <br />
[https://medium.com/@levurge/detecting-mimikatz-with-sysmon-f6a96669747e](https://medium.com/@levurge/detecting-mimikatz-with-sysmon-f6a96669747e)

### Lateral Movement [TA0008](https://attack.mitre.org/tactics/TA0008/) 
Japan CERT guide <br />
[https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf](https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf)

CERT-EU guide <br />
[https://media.cert.europa.eu/static/WhitePapers/CERT-EU_SWP_17-002_Lateral_Movements.pdf](https://media.cert.europa.eu/static/WhitePapers/CERT-EU_SWP_17-002_Lateral_Movements.pdf)

Compass Security's guide to GPO settings <br />
[https://www.compass-security.com/fileadmin/Datein/Research/White_Papers/lateral_movement_detection_basic_gpo_settings_v1.0.pdf](https://www.compass-security.com/fileadmin/Datein/Research/White_Papers/lateral_movement_detection_basic_gpo_settings_v1.0.pdf)


## Windows
Windows 10 and Windows Server 2016 security auditing and monitoring reference <br />
[https://www.microsoft.com/en-us/download/details.aspx?id=52630](https://www.microsoft.com/en-us/download/details.aspx?id=52630)

Windows security audit events <br />
[https://www.microsoft.com/en-us/download/details.aspx?id=50034](https://www.microsoft.com/en-us/download/details.aspx?id=50034)

The URL's a Windows endpoint talks to and why <br />
[https://docs.microsoft.com/en-gb/windows/privacy/manage-windows-21h1-endpoints](https://docs.microsoft.com/en-gb/windows/privacy/manage-windows-21h1-endpoints)

All the things in the Windows Security Log <br />
[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/Default.aspx](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/Default.aspx)

Very useful logging cheat sheets <br />
[https://www.malwarearchaeology.com/cheat-sheets](https://www.malwarearchaeology.com/cheat-sheets)

Living Off The Land Binaries and Scripts <br />
[https://lolbas-project.github.io/](https://lolbas-project.github.io/)

RDP <br />
[https://dfironthemountain.wordpress.com/2019/02/15/rdp-event-log-dfir/](https://dfironthemountain.wordpress.com/2019/02/15/rdp-event-log-dfir/)

Windows log samples mapped to MITRE ATT&CK <br />
[https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)

Den Luzvyk's tweet breaking down security log events <br />
[https://twitter.com/duzvik/status/1319215738473820160?s=20](https://twitter.com/duzvik/status/1319215738473820160?s=20)

## Active Directory
adsecurity.org is a very helpful starting point <br />
[https://adsecurity.org/?page_id=4031](https://adsecurity.org/?page_id=4031)

bluteamblog.com <br />
[https://blueteamblog.com/18-ways-to-detect-malcious-actions-in-your-active-directory-logs-using-siem](https://blueteamblog.com/18-ways-to-detect-malcious-actions-in-your-active-directory-logs-using-siem)


## Malware
Florian Roth's AV event cheat sheet <br />
[https://www.nextron-systems.com/2021/08/16/antivirus-event-analysis-cheat-sheet-v1-8-2/](https://www.nextron-systems.com/2021/08/16/antivirus-event-analysis-cheat-sheet-v1-8-2/)

The whole malwarearchaeology site is incredibly useful <br />
[https://www.malwarearchaeology.com/logging/](https://www.malwarearchaeology.com/logging/)

Guide to how AV companies name things <br />
[https://www.gdatasoftware.com/blog/2019/08/35146-taming-the-mess-of-av-detection-names](https://www.gdatasoftware.com/blog/2019/08/35146-taming-the-mess-of-av-detection-names)

Conti Ransomware from Marco Ramilli <br />
[https://marcoramilli.com/2021/11/07/conti-ransomware-cheat-sheet/](https://marcoramilli.com/2021/11/07/conti-ransomware-cheat-sheet/)

## C2 Frameworks
**Cobalt Strike** <br />
Very popular amongst ransomware crews so well worth focus. <br />
[https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/](https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/) <br />
[https://labs.f-secure.com/blog/detecting-cobalt-strike-default-modules-via-named-pipe-analysis/](https://labs.f-secure.com/blog/detecting-cobalt-strike-default-modules-via-named-pipe-analysis/) <br />
[https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-1](https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-1) <br />
[https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-2](https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-2) 

**Nettitude's Posh C2** <br />
[https://labs.nettitude.com/blog/detecting-poshc2-indicators-of-compromise/](https://labs.nettitude.com/blog/detecting-poshc2-indicators-of-compromise/)

**F-Secure's C3** <br />
[https://labs.f-secure.com/blog/hunting-for-c3/](https://labs.f-secure.com/blog/hunting-for-c3/)

## Microsoft 365
[https://medium.com/falconforce/reducing-your-office-365-attack-surface-99830a654d0](https://medium.com/falconforce/reducing-your-office-365-attack-surface-99830a654d0) <br />
[https://us-cert.cisa.gov/ncas/alerts/aa21-008a](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)

## Microsoft Sentinel
[https://github.com/BlueTeamLabs/sentinel-attack](https://github.com/BlueTeamLabs/sentinel-attack)

## Sysmon
This config is a good starting point. Forked from the [SwiftOnSecurity](https://twitter.com/SwiftOnSecurity) [config](https://github.com/SwiftOnSecurity/sysmon-config) <br />
[https://github.com/Neo23x0/sysmon-config](https://github.com/Neo23x0/sysmon-config)

Modular config <br />
[https://github.com/olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)

## Linux
Auditd configuration mapped to ATT&CK <br />
[https://github.com/bfuzzy/auditd-attack](https://github.com/bfuzzy/auditd-attack)

LOLbins for *NIX systems <br />
[https://gtfobins.github.io/](https://gtfobins.github.io/)

Florian Roth's auditd config <br />
[https://gist.github.com/Neo23x0/9fe88c0c5979e017a389b90fd19ddfee](https://gist.github.com/Neo23x0/9fe88c0c5979e017a389b90fd19ddfee)

Detecting ATT&CK techniques & tactics for Linux <br />
[https://github.com/Kirtar22/Litmus_Test/blob/master/README.md](https://github.com/Kirtar22/Litmus_Test/blob/master/README.md)

## Network
Never forget that network devices are endpoints too. <br />
[https://c2defense.medium.com/man-in-the-network-network-devices-are-endpoints-too-d5bd4a279e37](https://c2defense.medium.com/man-in-the-network-network-devices-are-endpoints-too-d5bd4a279e37)

Incredibly useful cheat sheet for detecting maliciousness in proxy logs <br />
[https://www.nextron-systems.com/2020/07/24/web-proxy-event-analysis-cheat-sheet/](https://www.nextron-systems.com/2020/07/24/web-proxy-event-analysis-cheat-sheet/)

Washing your proxy/DNS logs against lists of common lookups can surface the uncommon and potentially malicious. These are a few: <br />
[https://s3-us-west-1.amazonaws.com/umbrella-static/index.html](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html) <br />
[https://tranco-list.eu/](https://tranco-list.eu/) <br />
[https://majestic.com/reports/majestic-million](https://majestic.com/reports/majestic-million) <br />

Detecting Data Staging & Exfil Using the Producer-Consumer Ratio <br />
[http://detect-respond.blogspot.com/2016/09/detecting-data-staging-exfil-using-PCR-shift.html](http://detect-respond.blogspot.com/2016/09/detecting-data-staging-exfil-using-PCR-shift.html)

Monitor the hijacking of your prefixes
[https://github.com/nttgin/BGPalerter](https://github.com/nttgin/BGPalerter)

## Finding C2 
[http://findingbad.blogspot.com/2018/03/c2-hunting.html](http://findingbad.blogspot.com/2018/03/c2-hunting.html)

## Canary Tokens
Thinkst's Canary Tokens are very useful both for UEBA and monitoring access to datasets. Well worth seeding these and building use cases to alert on access. <br />
[https://canarytokens.org/generate](https://canarytokens.org/generate)

## Insider Threat
Interesting approach <br />
[http://findingbad.blogspot.com/2021/02/more-behavioral-hunting-and-insider.html](http://findingbad.blogspot.com/2021/02/more-behavioral-hunting-and-insider.html)

## Use Case Thinking
SpectorOps Detection Spectrum <br />
[https://posts.specterops.io/detection-spectrum-198a0bfb9302](https://posts.specterops.io/detection-spectrum-198a0bfb9302)

Agile Development <br />
[https://opstune.com/2017/10/15/siem-use-cases-development-workflow-agile-all-the-things/](https://opstune.com/2017/10/15/siem-use-cases-development-workflow-agile-all-the-things/)

'Detection is Hard' and 'How to Make Threat Detection Better?' by the great [Anton Chuvakin](https://medium.com/anton-on-security) of Google Cloud Security <br />
[https://medium.com/anton-on-security/why-is-threat-detection-hard-42aa479a197f ](https://medium.com/anton-on-security/why-is-threat-detection-hard-42aa479a197f)<br />
[https://medium.com/anton-on-security/how-to-make-threat-detection-better-c38f1758b842](https://medium.com/anton-on-security/how-to-make-threat-detection-better-c38f1758b842)

Two terrific twitter threads from [Chris Sanders](https://twitter.com/chrissanders88) and [Jon Hencinski](https://twitter.com/jhencinski) <br />
[https://twitter.com/chrissanders88/status/1456982558890250245](https://twitter.com/chrissanders88/status/1456982558890250245) <br />
[https://twitter.com/jhencinski/status/1456974938712121347](https://twitter.com/jhencinski/status/1456974938712121347)

This work by [Desiree Sacher-Boldewin](https://twitter.com/d3sre)'s on use cases is well worth reading <br />
[https://github.com/d3sre/Use_Case_Applicability](https://github.com/d3sre/Use_Case_Applicability) <br />
[https://github.com/d3sre/Use_Case_Applicability/blob/master/UseCaseApplicability-Paper.pdf](https://github.com/d3sre/Use_Case_Applicability/blob/master/UseCaseApplicability-Paper.pdf)

Useful guide with some helpful links <br />
[https://blueteamblog.com/siem-use-case-writing-guide](https://blueteamblog.com/siem-use-case-writing-guide)

Palantir's approach <br />
[https://blog.palantir.com/alerting-and-detection-strategy-framework-52dc33722df2](https://blog.palantir.com/alerting-and-detection-strategy-framework-52dc33722df2)

## Government Advice
**NCSC** <br />
[https://www.ncsc.gov.uk/blog-post/what-exactly-should-we-be-logging](https://www.ncsc.gov.uk/blog-post/what-exactly-should-we-be-logging)

**NSA** <br />
[https://apps.nsa.gov/iaarchive/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm](https://apps.nsa.gov/iaarchive/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm)

**CISA** <br />
[https://us-cert.cisa.gov/ncas/alerts/aa20-245a](https://us-cert.cisa.gov/ncas/alerts/aa20-245a)

## SIEM Vendor Docs
IBM <br />
[https://www.ibm.com/docs/en/dsm?topic=management-threat-use-cases-by-log-source-type](https://www.ibm.com/docs/en/dsm?topic=management-threat-use-cases-by-log-source-type)

Splunk <br />
[https://docs.splunk.com/Documentation/ES/latest/Usecases/Overview](https://docs.splunk.com/Documentation/ES/latest/Usecases/Overview)

## Projects
**SIGMA** <br />
"Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner." Extremely useful <br />
[https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) <br />
[https://medium.com/malware-buddy/security-infographics-9c4d3bd891ef#5920](https://medium.com/malware-buddy/security-infographics-9c4d3bd891ef#5920)

SOC Prime provide a convertor for sigma rules into different formats <br />
[https://uncoder.io/](https://uncoder.io/)

**OSSEM** <br />
"Define and share a common data model in order to improve the data standardization and transformation of security event logs" <br />
[https://github.com/OTRF/OSSEM](https://github.com/OTRF/OSSEM)

**DeTT&CT** <br />

"DeTT&CT aims to assist blue teams in using ATT&CK to score and compare data log source quality, visibility coverage, detection coverage and threat actor behaviours." 
[https://github.com/rabobank-cdc/DeTTECT](https://github.com/rabobank-cdc/DeTTECT)

**MaGMa** <br />
The MaGMa Use Case Framework (UCF) from the Dutch Payments Association is a framework and tool for use case management and administration <br />
[https://www.betaalvereniging.nl/en/safety/magma/](https://www.betaalvereniging.nl/en/safety/magma/) <br />

## Commercial
SOC Prime - Paid packs with some free SIGMA rules <br />
[https://my.socprime.com/tdm/](https://my.socprime.com/tdm/)

## Feeds
I think use cases built to alert on feeds can be pretty hit and miss but this is very useful <br />
[https://iplists.firehol.org/](https://iplists.firehol.org/)

TLS Certificates used by Malware <br />
[https://sslbl.abuse.ch/ssl-certificates/](https://sslbl.abuse.ch/ssl-certificates/)

TOR Exit IP's <br />
[https://check.torproject.org/torbulkexitlist](https://check.torproject.org/torbulkexitlist)
