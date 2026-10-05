"""What can be read off an item's text without a model.

Everything here is a pattern match on what the publisher wrote. In particular the
ATT&CK ids are the ones that literally appear in the text: they are reported as
*mentioned*, and are not checked against the STIX bundle or inferred from a
description. Mapping prose to a technique is the main pipeline's job, behind its oracle.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_I = re.I

CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", _I)
ATTACK_ID = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")

# Indicators. A bare dotted quad is not counted: in this corpus it is far more often a
# version number than an address, so an IP needs to be defanged or carry a port.
_IOC = [
    re.compile(r"\b[a-f0-9]{64}\b", _I),                                   # sha256
    re.compile(r"\b[a-f0-9]{40}\b", _I),                                   # sha1
    re.compile(r"\b[a-f0-9]{32}\b", _I),                                   # md5
    re.compile(r"\b\d{1,3}(?:\[\.\]\d{1,3}){1,3}(?:\.\d{1,3})*\b"),        # defanged ip
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b"),                    # ip:port
    re.compile(r"\bhxxps?(?:://|\[:\]//)\S+", _I),                          # defanged url
    re.compile(r"\b[a-z0-9-]+(?:\[\.\][a-z0-9-]+)+\b", _I),                # defanged domain
]

# Actor designators and the naming families vendors publish them under.
_ACTOR = re.compile(
    r"\b(?:APT[- ]?\d{1,3}|UNC\d{3,5}|TA\d{3,5}|FIN\d{1,2}|DEV-\d{4}|Storm-\d{4}"
    r"|TAG-\d{2,4}|UAC-\d{4}|UAT-\d{4}|CL-[A-Z]{3}-\d{4})\b"
    r"|\b[A-Z][a-z]+ (?:Typhoon|Blizzard|Sandstorm|Sleet|Tempest|Tsunami|Panda|Kitten"
    r"|Spider|Chollima|Buffalo|Jackal)\b"
)

# Host and network artefacts a hunter can turn into a query. Each pattern counts once
# however often it matches: ten mentions of powershell are one behaviour, not ten.
_BEHAVIOUR = {
    "binary": r"\b[\w-]+\.(?:exe|dll|ps1|bat|vbs|lnk|msi|sys|hta|scr)\b",
    "registry": r"\bHK(?:LM|CU|CR|EY_[A-Z_]+)\\",
    "win-path": r"(?:\b[A-Za-z]:\\|%[A-Za-z]+%\\)[\w\\.-]+",
    "nix-path": r"(?<![\w.])/(?:tmp|etc|var|usr|opt|dev/shm)/[\w./-]+",
    "lolbin": r"\b(?:powershell|rundll32|regsvr32|mshta|certutil|wmic|schtasks|bitsadmin"
              r"|msiexec|cscript|wscript|psexec|cmd\.exe|osascript|launchctl|crontab)\b",
    "tooling": r"\b(?:mimikatz|cobalt strike|sliver|metasploit|impacket|bloodhound|rclone"
               r"|anydesk|ngrok|brute ratel)\b",
    "persistence": r"\bscheduled task|\brun key|\bstartup folder|\blaunch (?:agent|daemon)"
                   r"|\bsystemd service|\bpersistence\b",
    "injection": r"\bprocess (?:injection|hollowing)|\bDLL (?:side-?loading|hijacking|injection)",
    "credential": r"\bLSASS\b|\bcredential (?:dump|theft|harvest)|\bkerberoast|\bNTDS\b"
                  r"|\bpass-the-hash",
    "lateral": r"\blateral movement|\bRDP\b|\bSMB\b|\bWinRM\b|\bremote service",
    "shell": r"\bweb ?shell|\breverse shell|\bbase64[- ]encoded|\bobfuscat",
    "exfil": r"\bexfiltrat|\bdata staging|\bcommand[- ]and[- ]control\b|\bC2\b|\bbeacon",
}
_BEHAVIOUR_RE = {name: re.compile(rx, _I) for name, rx in _BEHAVIOUR.items()}

# Threat subject matter. These double as the `tags` column.
_TAGS = {
    "exploited-in-wild": r"actively exploited|\bin[- ]the[- ]wild\b"
                         r"|under active exploitation|known exploited|\bKEV\b"
                         r"|exploitation (?:observed|detected|attempts)",
    "zero-day": r"\bzero[- ]day\b|\b0[- ]day\b",
    "poc-public": r"proof[- ]of[- ]concept|\bPoC\b|exploit code|public exploit",
    "ransomware": r"ransomware|extortion",
    "malware": r"malware|trojan|backdoor|stealer\b|\bloader\b|botnet|\bRAT\b|rootkit|wiper\b"
               r"|spyware|cryptominer",
    "phishing": r"phish|smishing|vishing|social engineering|business email compromise",
    "supply-chain": r"supply[- ]chain|malicious (?:npm|pypi|package|extension)|typosquat",
    "vulnerability": r"vulnerabilit|\bCVE-\d|remote code execution|\bRCE\b"
                     r"|privilege escalation|authentication bypass|buffer overflow"
                     r"|SQL injection|deserializ|security (?:update|advisory|bulletin)",
    "intrusion": r"threat actor|intrusion|compromised|\bbreach|espionage|\bAPT\b"
                 r"|initial access|\battackers?\b|\bhackers?\b",
}
_TAG_RE = {name: re.compile(rx, _I) for name, rx in _TAGS.items()}

# What a marketing post sounds like. Whole-site vendor feeds mix these in with research,
# and a product announcement about ransomware still mentions ransomware.
_MARKETING = [
    r"\bwebinar|\bpodcast|\bebook\b|\bwhite ?paper|\bregister (?:now|today)|\bjoin us\b",
    r"\bannounc(?:es|ed|ing)\b|\bpartner(?:s|ship|ed)? with\b|\bnow available\b"
    r"|\bgeneral availability\b|\bintroducing\b|\brelease notes\b|\bnew feature",
    r"\bseries [A-E]\b|\bfunding\b|\braises \$|\bacquir(?:es|ed|ing)\b|\bappoints\b",
    r"\bnamed a leader\b|\bgartner\b|\bforrester\b|\bmagic quadrant\b|\baward",
    r"\bcustomer (?:story|stories|spotlight)\b|\bcase study\b|\bROI\b|\bbook a demo\b",
]
_MARKETING_RE = [re.compile(rx, _I) for rx in _MARKETING]


@dataclass(frozen=True)
class Signals:
    cves: tuple[str, ...] = ()
    attack_ids: tuple[str, ...] = ()
    actors: tuple[str, ...] = ()
    ioc_count: int = 0
    behaviours: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    lede_tags: int = 0
    marketing_hits: int = 0
    text_basis: str = "title"


def _distinct(pattern: re.Pattern[str], text: str, *, upper: bool = False) -> tuple[str, ...]:
    found = {m.group(0).upper() if upper else m.group(0) for m in pattern.finditer(text)}
    return tuple(sorted(found))


# What an item is *about* is said in its headline and opening. Further down, a vendor
# post of any kind ends in boilerplate that names ransomware, phishing and zero-days, so
# relevance is judged on the lede and the rest is left to specificity.
_LEDE_CHARS = 600


def extract(title: str, body: str) -> Signals:
    text = f"{title}\n{body}"
    lede = f"{title}\n{body[:_LEDE_CHARS]}"

    iocs: set[str] = set()
    for pattern in _IOC:
        iocs.update(m.group(0).lower() for m in pattern.finditer(text))

    # How much the publisher put in the feed. A title-only item scoring low on
    # specificity says nothing about the article behind it, and the reader of the CSV
    # needs to be able to tell those two cases apart.
    basis = "title" if len(body) < 80 else "summary" if len(body) < 1500 else "full"

    return Signals(
        cves=_distinct(CVE, text, upper=True),
        attack_ids=_distinct(ATTACK_ID, text),
        actors=_distinct(_ACTOR, text),
        ioc_count=len(iocs),
        behaviours=tuple(n for n, rx in _BEHAVIOUR_RE.items() if rx.search(text)),
        tags=tuple(n for n, rx in _TAG_RE.items() if rx.search(text)),
        lede_tags=sum(1 for rx in _TAG_RE.values() if rx.search(lede)),
        marketing_hits=sum(1 for rx in _MARKETING_RE if rx.search(lede)),
        text_basis=basis,
    )
