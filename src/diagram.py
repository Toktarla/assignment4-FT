from __future__ import annotations

from pathlib import Path

from .dataset import ROOT

OUT = ROOT / "diagrams" / "architecture.svg"


def svg() -> str:
    return '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1100 640" width="1100" height="640" font-family="Helvetica, Arial, sans-serif">
  <rect width="1100" height="640" fill="#ffffff"/>
  <text x="24" y="32" font-size="18" font-weight="700" fill="#1f4e79">Synthetic research-server architecture (AITU / Kazakhstan university context)</text>
  <text x="24" y="52" font-size="12" fill="#444444">MFA, segmentation, immutable backup, monitoring, IDS, secure failover, recovery environment</text>

  <rect x="24" y="70" width="160" height="64" rx="6" fill="#deebf7" stroke="#1f4e79"/>
  <text x="104" y="96" text-anchor="middle" font-size="12" font-weight="700" fill="#1f4e79">Researchers</text>
  <text x="104" y="114" text-anchor="middle" font-size="10" fill="#333333">campus + VPN</text>

  <rect x="220" y="70" width="200" height="64" rx="6" fill="#fff2cc" stroke="#7f6000"/>
  <text x="320" y="96" text-anchor="middle" font-size="12" font-weight="700" fill="#7f6000">MFA / IdP</text>
  <text x="320" y="114" text-anchor="middle" font-size="10" fill="#333333">TOTP + NCA RK certs</text>

  <rect x="460" y="70" width="200" height="64" rx="6" fill="#fce4d6" stroke="#c65911"/>
  <text x="560" y="96" text-anchor="middle" font-size="12" font-weight="700" fill="#c65911">Edge firewall / WAF</text>
  <text x="560" y="114" text-anchor="middle" font-size="10" fill="#333333">lockout, geo, rate limit</text>

  <rect x="700" y="70" width="180" height="64" rx="6" fill="#e2efda" stroke="#548235"/>
  <text x="790" y="96" text-anchor="middle" font-size="12" font-weight="700" fill="#548235">Egress proxy</text>
  <text x="790" y="114" text-anchor="middle" font-size="10" fill="#333333">allow-list only</text>

  <rect x="920" y="70" width="156" height="64" rx="6" fill="#f4f4f4" stroke="#666666"/>
  <text x="998" y="96" text-anchor="middle" font-size="12" font-weight="700" fill="#333333">Internet</text>
  <text x="998" y="114" text-anchor="middle" font-size="10" fill="#333333">unknown IPs blocked</text>

  <line x1="184" y1="102" x2="220" y2="102" stroke="#1f4e79" stroke-width="2" marker-end="url(#arrow)"/>
  <line x1="420" y1="102" x2="460" y2="102" stroke="#1f4e79" stroke-width="2" marker-end="url(#arrow)"/>
  <line x1="660" y1="102" x2="700" y2="102" stroke="#1f4e79" stroke-width="2" marker-end="url(#arrow)"/>
  <line x1="880" y1="102" x2="920" y2="102" stroke="#1f4e79" stroke-width="2" marker-end="url(#arrow)"/>

  <rect x="24" y="160" width="1052" height="36" rx="4" fill="#1f4e79"/>
  <text x="550" y="183" text-anchor="middle" font-size="13" fill="#ffffff">Core segmentation — research, management, backup and recovery VLANs are separate</text>

  <rect x="24" y="214" width="250" height="250" rx="8" fill="#deebf7" stroke="#1f4e79"/>
  <text x="149" y="238" text-anchor="middle" font-size="13" font-weight="700" fill="#1f4e79">Research VLAN</text>
  <rect x="44" y="254" width="210" height="70" rx="5" fill="#ffffff" stroke="#1f4e79"/>
  <text x="149" y="282" text-anchor="middle" font-size="12" font-weight="700">Research-Server-01</text>
  <text x="149" y="300" text-anchor="middle" font-size="10">production workload</text>
  <rect x="44" y="336" width="210" height="52" rx="5" fill="#ffffff" stroke="#1f4e79"/>
  <text x="149" y="358" text-anchor="middle" font-size="12" font-weight="700">EDR agent</text>
  <text x="149" y="374" text-anchor="middle" font-size="10">tamper protection</text>
  <text x="149" y="444" text-anchor="middle" font-size="10" fill="#333333">no path to vault delete API</text>

  <rect x="292" y="214" width="250" height="250" rx="8" fill="#fff2cc" stroke="#7f6000"/>
  <text x="417" y="238" text-anchor="middle" font-size="13" font-weight="700" fill="#7f6000">Management VLAN</text>
  <rect x="312" y="254" width="210" height="70" rx="5" fill="#ffffff" stroke="#7f6000"/>
  <text x="417" y="282" text-anchor="middle" font-size="12" font-weight="700">SIEM + monitoring</text>
  <text x="417" y="300" text-anchor="middle" font-size="10">login, file, CPU, DB, egress</text>
  <rect x="312" y="336" width="210" height="70" rx="5" fill="#ffffff" stroke="#7f6000"/>
  <text x="417" y="364" text-anchor="middle" font-size="12" font-weight="700">IDS / IPS</text>
  <text x="417" y="382" text-anchor="middle" font-size="10">anomaly score threshold 0.75</text>
  <text x="417" y="444" text-anchor="middle" font-size="10" fill="#333333">auto-isolate on critical</text>

  <rect x="560" y="214" width="250" height="250" rx="8" fill="#e2efda" stroke="#548235"/>
  <text x="685" y="238" text-anchor="middle" font-size="13" font-weight="700" fill="#548235">Backup VLAN</text>
  <rect x="580" y="254" width="210" height="90" rx="5" fill="#ffffff" stroke="#548235"/>
  <text x="685" y="286" text-anchor="middle" font-size="12" font-weight="700">Immutable vault</text>
  <text x="685" y="304" text-anchor="middle" font-size="10">WORM object lock 30 days</text>
  <text x="685" y="320" text-anchor="middle" font-size="10">snapshot every 5 min</text>
  <rect x="580" y="356" width="210" height="52" rx="5" fill="#ffffff" stroke="#548235"/>
  <text x="685" y="378" text-anchor="middle" font-size="12" font-weight="700">Separate IAM</text>
  <text x="685" y="394" text-anchor="middle" font-size="10">research host cannot delete</text>
  <text x="685" y="444" text-anchor="middle" font-size="10" fill="#333333">RPO limit: 5 minutes</text>

  <rect x="828" y="214" width="248" height="250" rx="8" fill="#fce4d6" stroke="#c65911"/>
  <text x="952" y="238" text-anchor="middle" font-size="13" font-weight="700" fill="#c65911">Recovery VLAN</text>
  <rect x="848" y="254" width="208" height="70" rx="5" fill="#ffffff" stroke="#c65911"/>
  <text x="952" y="282" text-anchor="middle" font-size="12" font-weight="700">Recovery host</text>
  <text x="952" y="300" text-anchor="middle" font-size="10">isolated restore target</text>
  <rect x="848" y="336" width="208" height="70" rx="5" fill="#ffffff" stroke="#c65911"/>
  <text x="952" y="364" text-anchor="middle" font-size="12" font-weight="700">Gold image + checksums</text>
  <text x="952" y="382" text-anchor="middle" font-size="10">verify then failover</text>
  <text x="952" y="444" text-anchor="middle" font-size="10" fill="#333333">RTO limit: 30 minutes</text>

  <rect x="24" y="484" width="1052" height="132" rx="8" fill="#f7f7f7" stroke="#888888"/>
  <text x="40" y="512" font-size="13" font-weight="700" fill="#1f4e79">Secure failover path</text>
  <text x="40" y="536" font-size="12" fill="#333333">1. IDS detects file-modification score 0.96  2. Firewall isolates Research-Server-01  3. Forensic snapshot is taken</text>
  <text x="40" y="556" font-size="12" fill="#333333">4. Vault exposes last clean snapshot (09:05)  5. Recovery host is built from gold image + snapshot  6. Checksums and service probes  7. DNS/VIP cutover</text>
  <text x="40" y="584" font-size="12" fill="#333333">The compromised disk is never returned to production. Restore is always into the recovery VLAN, then traffic is moved.</text>

  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#1f4e79"/>
    </marker>
  </defs>
</svg>
'''


def write() -> Path:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(svg())
    return OUT
