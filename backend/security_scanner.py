"""SentinelScan local-only security assessment engine.
All vulnerability demonstrations are synthetic and restricted to localhost.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class TestDefinition:
    test_id: str
    title: str
    category: str
    endpoint: str
    expected: str

TEST_CATALOG: List[TestDefinition] = [
    TestDefinition('AUTH-001','Unauthenticated protected route','Authentication','/api/lab/auth/protected','401'),
    TestDefinition('AUTH-002','Valid authenticated session','Authentication','/api/lab/auth/protected','200'),
    TestDefinition('AUTH-003','Invalid session rejected','Session management','/api/lab/auth/protected','401'),
    TestDefinition('AUTH-004','Expired session rejected','Session management','/api/lab/auth/protected','401'),
    TestDefinition('AUTHZ-001','Admin function authorization','Authorization','/api/lab/authz/admin','403'),
    TestDefinition('AUTHZ-002','IDOR object authorization','Authorization','/api/lab/vulnerable/idor?object_id=2','403'),
    TestDefinition('INPUT-001','Numeric input validation','Input validation','/api/lab/input?age=not-a-number','400/422'),
    TestDefinition('INPUT-002','Reflected XSS output encoding','Input validation','/api/lab/vulnerable/xss?q=%3Cscript%3E','encoded'),
    TestDefinition('API-001','Protected API authentication','API security','/api/lab/api/protected','401'),
    TestDefinition('API-002','JWT algorithm enforcement','API security','/api/lab/vulnerable/jwt','401'),
    TestDefinition('API-003','SSRF destination validation','API security','/api/lab/vulnerable/ssrf?url=http://127.0.0.1:8100/','blocked'),
    TestDefinition('API-004','HTTP method boundary','API security','/api/lab/api/protected','GET only'),
    TestDefinition('CLIENT-001','Client-side credential exposure','Client security','/index.html','no credentials'),
    TestDefinition('CLIENT-002','DOM sink review','Client security','/index.html','no unsafe sink pattern'),
    TestDefinition('TLS-001','TLS / certificate inspection','Transport security','https://target','valid or N/A for HTTP localhost'),
    TestDefinition('TLS-002','HSTS header inspection','Transport security','HTTP response headers','present on HTTPS'),
    TestDefinition('DATA-001','Protected data access','Data protection','/api/lab/data/private','403'),
    TestDefinition('DATA-002','Data minimization','Data protection','/api/lab/data/private','minimal response'),
    TestDefinition('DATA-003','Security header baseline','Transport security','HTTP response headers','recommended headers'),
    TestDefinition('DATA-004','Role boundary consistency','Authorization','/api/lab/authz/admin','403 for non-admin'),
]

# Kept for compatibility with the existing frontend/imports.
MANUAL_CATALOG = []

def cvss_from_observation(observed: dict) -> dict:
    """Conservative CVSS 3.1 mapping based only on observed synthetic impact."""
    av = observed.get('attack_vector','Network'); pr = observed.get('privileges','None')
    c = observed.get('confidentiality','None'); i = observed.get('integrity','None'); a = observed.get('availability','None')
    # These are intentionally conservative lab scores, not claims about production impact.
    table = {
      ('Network','None','High','High','None'): ('9.1','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'),
      ('Network','None','Low','Low','None'): ('6.5','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'),
      ('Network','Low','High','None','None'): ('6.5','CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'),
      ('Network','None','High','None','None'): ('7.5','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
      ('Network','None','Low','None','None'): ('5.3','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    }
    score, vector = table.get((av,pr,c,i,a), ('Not scored',''))
    return {'score':score,'vector':vector,'attack_vector':av,'complexity':'Low','privileges':pr,'interaction':'None','scope':'Unchanged','confidentiality':c,'integrity':i,'availability':a,
            'reason':'Score is derived from the observed local PoC impact only; it is not generalized to production without separate evidence.'}
