#!/bin/bash

echo "================================================================"
echo "   DATA EXPOSURE ASSESSMENT"
echo "================================================================"
echo
echo "COMPROMISED SYSTEM MAPPING:"
echo "  Host            Role                 Data Sensitivity   Access Level"
echo "  WS-RECV-03      Records Dept WS      PHI transient      CONFIRMED ACCESS"
echo "  SRV-HEALTH-DB   Health Records DB    CRITICAL (PHI)     CONFIRMED ACCESS"
echo "  SRV-INS-DB      Insurance DB         HIGH (PII/claims)  CONFIRMED ACCESS"
echo "  SRV-DC-01       Domain Controller    HIGH (auth)        CONFIRMED ACCESS"
echo
echo "  Other inventoried systems:"
echo "    SRV-FILE-01, SRV-HR-01, SRV-BACKUP-01, SRV-MAIL-01,"
echo "    WS-ADMIN-01: NO ACCESS established in the reconstructed"
echo "    lateral-movement chain."
echo
echo "CONFIRMED DATA ACCESS:"
echo "  SRV-HEALTH-DB:"
echo "    Full health_records.dbo.patients table extracted."
echo "    Records: 47,138"
echo "    Fields include patient ID, name, DOB, SSN and diagnosis codes."
echo "    Evidence: IR disk + Stage 4 reconstruction."
echo "    Status: CONFIRMED ACCESSED, STAGED AND EXFILTRATED"
echo
echo "  SRV-INS-DB:"
echo "    Full insurance_db.dbo.policies table extracted."
echo "    Records: 51,002"
echo "    Fields include policy/member ID, name, SSN and coverage data."
echo "    Evidence: IR disk + Stage 4 reconstruction."
echo "    Status: CONFIRMED ACCESSED, STAGED AND EXFILTRATED"
echo
echo "  SRV-DC-01:"
echo "    Full Get-ADUser enumeration exported."
echo "    Records: 1,184 domain users and service accounts."
echo "    Evidence: 4x04 hunt + IR disk."
echo "    Status: CONFIRMED ACCESSED, STAGED AND EXFILTRATED"
echo
echo "EXFILTRATION STATUS:"
echo "  Data staged on WS-RECV-03: YES"
echo "  Recovered staging artifacts: 3"
echo "  Total transmitted externally: 34,441,660 bytes"
echo "  Primary exfiltration destination: 185.220.101.45:443"
echo
echo "  2026-05-08:"
echo "    staging_export_001.zip -> 14,219,484 bytes"
echo "    47,138 patient records"
echo
echo "  2026-05-11:"
echo "    staging_export_002.zip -> 11,802,944 bytes"
echo "    51,002 insurance records"
echo
echo "  2026-05-13:"
echo "    query_results.csv -> 8,419,232 bytes"
echo "    1,184 AD user/service-account records"
echo
echo "  Evidence: IR disk artifact sizes exactly correlate with"
echo "  IR firewall outbound EXFIL_BURST byte counts."
echo
echo "  Confirmed sensitive patient/insurance records exfiltrated: 98,140"
echo "  Conclusion: EXFILTRATION CONFIRMED."
echo "  This was not merely attempted or interrupted staging."
echo
echo "DATA EXPOSURE BY TYPE:"
echo "  Patient health records (PHI):"
echo "    Status: CONFIRMED ACCESSED / STAGED / EXFILTRATED"
echo "    Scope: 47,138 records"
echo
echo "  Insurance and billing data:"
echo "    Status: CONFIRMED ACCESSED / STAGED / EXFILTRATED"
echo "    Scope: 51,002 records"
echo
echo "  Employee/domain identity records:"
echo "    Status: CONFIRMED ACCESSED / STAGED / EXFILTRATED"
echo "    Scope: 1,184 AD user/service-account records"
echo "    Note: supplied evidence does not establish access to the"
echo "    separate HR system or HR employee-record dataset."
echo
echo "  Operational data:"
echo "    Status: POTENTIALLY EXPOSED on compromised infrastructure,"
echo "    but no additional operational dataset is confirmed exfiltrated."
echo
echo "REGULATORY ASSESSMENT:"
echo "  HIPAA breach notification threshold: MET"
echo "  Basis:"
echo "    Confirmed PHI extraction and external transmission."
echo "    47,138 patient records include direct identifiers and"
echo "    diagnosis information."
echo "    Insurance extraction adds 51,002 member records containing"
echo "    identifiers including SSNs and coverage information."
echo
echo "  Estimated patient/insurance scope: 98,140 records"
echo
echo "  Mitigating factors:"
echo "    - WS-RECV-03 was isolated on 2026-05-15 at 13:42 CDT."
echo "    - Isolation blocked further C2 communication."
echo "    - No evidence establishes access to additional inventoried"
echo "      servers outside the confirmed lateral-movement chain."
echo "    - DNS exfiltration capability existed, but high-volume DNS"
echo "      exfiltration was not confirmed."
echo
echo "  Limitation:"
echo "    Encryption of the source data at rest does not negate the"
echo "    confirmed extraction because recovered staging artifacts"
echo "    contained readable record data."
echo
echo "  Recommended action:"
echo "    Treat as a confirmed reportable breach and use the verified"
echo "    98,140 patient/insurance records as the current evidence-based"
echo "    notification scope, subject to legal/compliance review."
echo
echo "================================================================"
