{
    "simulation": "Windows Attacker Simulation",
    "timestamp_format": "UTC ISO 8601",
    "actions_executed": 6,
    "actions": [
        {
            "action_number": 1,
            "description": "Create local user support_update",
            "timestamp": "2026-08-08T07:23:18.512Z",
            "expected_detection_source": "Security Event ID 4720; Sysmon Event ID 1",
            "mitre_attack_technique": "T1136.001 - Create Account: Local Account"
        },
        {
            "action_number": 2,
            "description": "Add support_update to Administrators group",
            "timestamp": "2026-08-08T07:23:18.528Z",
            "expected_detection_source": "Security Event ID 4732",
            "mitre_attack_technique": "T1098.007 - Account Manipulation: Additional Local or Domain Groups"
        },
        {
            "action_number": 3,
            "description": "Run encoded PowerShell harmless payload",
            "timestamp": "2026-08-08T07:23:19.110Z",
            "expected_detection_source": "Sysmon Event ID 1; PowerShell Event ID 4104",
            "mitre_attack_technique": "T1059.001 - Command and Scripting Interpreter: PowerShell"
        },
        {
            "action_number": 4,
            "description": "Create scheduled task for persistence",
            "timestamp": "2026-08-08T07:23:19.240Z",
            "expected_detection_source": "Security Event ID 4698; Sysmon Event ID 1",
            "mitre_attack_technique": "T1053.005 - Scheduled Task/Job: Scheduled Task"
        },
        {
            "action_number": 5,
            "description": "Initiate outbound TCP connection to 1.1.1.1:443",
            "timestamp": "2026-08-08T07:23:29.946Z",
            "expected_detection_source": "Sysmon Event ID 3",
            "mitre_attack_technique": "T1071.001 - Application Layer Protocol: Web Protocols"
        },
        {
            "action_number": 6,
            "description": "Drop file in Windows Startup directory",
            "timestamp": "2026-08-08T07:23:29.992Z",
            "expected_detection_source": "Sysmon Event ID 11",
            "mitre_attack_technique": "T1547.001 - Registry Run Keys / Startup Folder"
        }
    ]
}
