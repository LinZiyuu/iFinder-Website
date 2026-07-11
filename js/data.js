const VULN_DATA = {
  "metadata": {
    "total": 84,
    "vendors": [
      "open5gs",
      "oai",
      "free5gc",
      "SD-Core",
      "eupf"
    ],
    "vendor_display": {
      "SD-Core": "SD-Core",
      "eupf": "eUPF",
      "free5gc": "free5GC",
      "oai": "OpenAirInterface",
      "open5gs": "Open5GS"
    },
    "protocols": [
      "gtp-c",
      "pfcp"
    ],
    "protocol_display": {
      "gtp-c": "GTP-C",
      "pfcp": "PFCP"
    },
    "patterns": [
      "PA1",
      "PA2",
      "PB1",
      "PB2",
      "PB3",
      "PC1"
    ],
    "pattern_display": {
      "PA1": "Malformed Field",
      "PA2": "Absent Field",
      "PB1": "Invalid Value",
      "PB2": "Invalid State",
      "PB3": "Invalid Reference",
      "PC1": "Resource Exhaustion"
    }
  },
  "vulnerabilities": [
    {
      "id": "CVE-2025-15156",
      "dir_name": "CVE_2025_15156",
      "vendor": "SD-Core",
      "vendor_display": "SD-Core",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-15156: Session Establishment Request Missing NodeID Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "SD-Core UPF crashes with a nil pointer dereference when it receives a PFCP `Session Establishment Request` that omits the mandatory `NodeID` IE.\nIn the session-establishment handler, `sereq.NodeID` is dereferenced before nil validation, causing a panic and denial of service.",
      "root_cause": "`VULN-J15`:\n\nUPF will panic when `Session Establishment Request` omits mandatory `NodeID`.\n\nSource (real vulnerable code):  \n`omec-project/upf` `pfcpiface/messages_session.go` (commit `c7e25e8e194c913ec520b8f7e6a94a8f7e472dca`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: pfcpiface/messages_session.go\nfunc (pConn *PFCPConn) handleSessionEstablishmentRequest(msg message.Message) (message.Message, error) {\n\t// ...\n\tnodeID, err := sereq.NodeID.NodeID()\n\t// ^ nil pointer dereference when NodeID IE is missing\n\tif err != nil {\n\t\treturn errUnmarshalReply(err, sereq.NodeID)\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/omec-project/upf/issues/979",
      "rel_path": "vendor/SD-Core/pfcp/PA2/CVE_2025_15156",
      "cve": "CVE-2025-15156",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "2.1.3-dev",
      "anchor": "sd-core-pfcp-cve_2025_15156"
    },
    {
      "id": "CVE-2025-65563",
      "dir_name": "CVE_2025_65563",
      "vendor": "SD-Core",
      "vendor_display": "SD-Core",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-65563: Association Setup Request Missing NodeID Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "SD-Core UPF crashes with a nil pointer dereference when it receives a PFCP `Association Setup Request` that omits the mandatory `NodeID` IE.\nIn the association-setup handler, `asreq.NodeID` is dereferenced directly without a nil check, causing a panic and denial of service.",
      "root_cause": "`VULN-J16`:\n\nUPF will panic when `Association Setup Request` omits mandatory `NodeID`.\n\nSource (real vulnerable code):  \n`omec-project/upf` `pfcpiface/messages_conn.go` (vulnerable revision before fix `#963`, commit `df9a71ce97898364597a0088440f4efe46c10e54`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: pfcpiface/messages_conn.go\nfunc (pConn *PFCPConn) handleAssociationSetupRequest(msg message.Message) (message.Message, error) {\n\t// ...\n\tnodeID, err := asreq.NodeID.NodeID()\n\t// ^ nil pointer dereference when NodeID IE is missing\n\tif err != nil {\n\t\treturn nil, errUnmarshal(err)\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/omec-project/upf/issues/955",
      "rel_path": "vendor/SD-Core/pfcp/PA2/CVE_2025_65563",
      "cve": "CVE-2025-65563",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "2.1.3-dev",
      "anchor": "sd-core-pfcp-cve_2025_65563"
    },
    {
      "id": "CVE-2025-65564",
      "dir_name": "CVE_2025_65564",
      "vendor": "SD-Core",
      "vendor_display": "SD-Core",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-65564: Association Setup Request Missing Recovery Time Stamp Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "SD-Core UPF crashes with a nil pointer dereference when it receives a PFCP `Association Setup Request` that includes `NodeID` but omits the mandatory `Recovery Time Stamp` IE.\nIn the association-setup handler, `asreq.RecoveryTimeStamp` is dereferenced without a nil check, causing a panic and denial of service.",
      "root_cause": "`VULN-J17`:\n\nUPF will panic when `Association Setup Request` omits mandatory `Recovery Time Stamp`.\n\nSource (real vulnerable code):  \n`omec-project/upf` `pfcpiface/messages_conn.go` (vulnerable revision before fix `#964`, commit `118d952a6b4fcc912a798d7e486b1502020015d5`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: pfcpiface/messages_conn.go\nfunc (pConn *PFCPConn) handleAssociationSetupRequest(msg message.Message) (message.Message, error) {\n\t// NodeID was already checked in this revision\n\t// ...\n\tts, err := asreq.RecoveryTimeStamp.RecoveryTimeStamp()\n\t// ^ nil pointer dereference when RecoveryTimeStamp IE is missing\n\tif err != nil {\n\t\treturn nil, errUnmarshal(err)\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/omec-project/upf/issues/956",
      "rel_path": "vendor/SD-Core/pfcp/PA2/CVE_2025_65564",
      "cve": "CVE-2025-65564",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "2.1.3-dev",
      "anchor": "sd-core-pfcp-cve_2025_65564"
    },
    {
      "id": "CVE-2025-65565",
      "dir_name": "CVE_2025_65565",
      "vendor": "SD-Core",
      "vendor_display": "SD-Core",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-65565: Session Establishment Request Missing CPF-SEID Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "SD-Core UPF crashes with a nil pointer dereference when it receives a PFCP `Session Establishment Request` that includes `NodeID` but omits the mandatory `CPF-SEID` IE.\nIn the session-establishment handler, `sereq.CPFSEID` is dereferenced without a nil check, causing a panic and denial of service.",
      "root_cause": "`VULN-J18`:\n\nUPF will panic when `Session Establishment Request` omits mandatory `CPF-SEID`.\n\nSource (real vulnerable code):  \n`omec-project/upf` `pfcpiface/messages_session.go` (vulnerable revision before fix `#965`, commit `1d1d2a7a34bb7ae808cba5408c35c7b496a8b80d`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: pfcpiface/messages_session.go\nfunc (pConn *PFCPConn) handleSessionEstablishmentRequest(msg message.Message) (message.Message, error) {\n\t// ...\n\tfseid, err := sereq.CPFSEID.FSEID()\n\t// ^ nil pointer dereference when CPF-SEID IE is missing\n\tif err != nil {\n\t\treturn errUnmarshalReply(err, sereq.CPFSEID)\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/omec-project/upf/issues/957",
      "rel_path": "vendor/SD-Core/pfcp/PA2/CVE_2025_65565",
      "cve": "CVE-2025-65565",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "2.1.3-dev",
      "anchor": "sd-core-pfcp-cve_2025_65565"
    },
    {
      "id": "CVE-2025-65566",
      "dir_name": "CVE_2025_65566",
      "vendor": "SD-Core",
      "vendor_display": "SD-Core",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-65566: Session Report Response Missing Cause Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "SD-Core UPF crashes with a nil pointer dereference when it receives a PFCP `Session Report Response` that omits the mandatory `Cause` IE.\nIn the session-report-response handler, `srres.Cause` is dereferenced directly without a nil check, causing a panic and denial of service.",
      "root_cause": "`VULN-J19`:\n\nUPF will panic when `Session Report Response` omits mandatory `Cause`.\n\nSource (real vulnerable code):  \n`omec-project/upf` `pfcpiface/messages_session.go` (vulnerable revision before fix `#966`, commit `84fd632206ae38e3b18d94ffe59ac17988baae5f`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: pfcpiface/messages_session.go\nfunc (pConn *PFCPConn) handleSessionReportResponse(msg message.Message) error {\n\t// ...\n\tcause := srres.Cause.Payload[0]\n\t// ^ nil pointer dereference when Cause IE is missing\n\tif cause == ie.CauseRequestAccepted {\n\t\treturn nil\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/omec-project/upf/issues/958",
      "rel_path": "vendor/SD-Core/pfcp/PA2/CVE_2025_65566",
      "cve": "CVE-2025-65566",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "2.1.3-dev",
      "anchor": "sd-core-pfcp-cve_2025_65566"
    },
    {
      "id": "CVE-2025-65568",
      "dir_name": "CVE_2025_65568",
      "vendor": "SD-Core",
      "vendor_display": "SD-Core",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-65568: Session Report Response Missing Cause Crash (Variant)",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "This entry tracks the same root-cause bug family as issue #958: malformed `Session Report Response` with missing `Cause` can crash UPF.  \nThe vulnerable dereference occurs before validating the `Cause` IE presence.",
      "root_cause": "`VULN-J20`:\n\nUPF will panic when `Session Report Response` omits mandatory `Cause` IE.\n\nSource (real vulnerable code):  \n`omec-project/upf` `pfcpiface/messages_session.go` (vulnerable revision before fix `#966`, commit `84fd632206ae38e3b18d94ffe59ac17988baae5f`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: pfcpiface/messages_session.go\nfunc (pConn *PFCPConn) handleSessionReportResponse(msg message.Message) error {\n\tcause := srres.Cause.Payload[0]\n\t// ^ nil pointer dereference when Cause IE is missing\n\tif cause == ie.CauseRequestAccepted {\n\t\treturn nil\n\t}\n\treturn nil\n}"
        }
      ],
      "issue_url": "https://github.com/omec-project/upf/issues/958",
      "rel_path": "vendor/SD-Core/pfcp/PA2/CVE_2025_65568",
      "cve": "CVE-2025-65568",
      "cwe": "CWE-125: Out-of-bounds Read/CWE-129: Improper Validation of Array Index",
      "affected_version": "2.1.3-dev",
      "anchor": "sd-core-pfcp-cve_2025_65568"
    },
    {
      "id": "CVE-2025-65567",
      "dir_name": "CVE_2025_65567",
      "vendor": "SD-Core",
      "vendor_display": "SD-Core",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "CVE-2025-65567: Malformed SDF Flow-Description Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "SD-Core UPF panics with an index-out-of-range error when it receives a PFCP `Session Establishment Request` carrying a malformed SDF `Flow-Description` (for example `permit out ip from any`).\nIn the `parseFlowDesc` function, the Flow-Description parser performs an out-of-bounds array access on the truncated token list, causing a process crash and denial of service.",
      "root_cause": "`VULN-J21`:\n\nUPF will panic when Session Establishment carries malformed SDF Flow-Description that bypasses parser boundary checks.\n\nSource (real vulnerable code):  \nFlow-Description parser call path:  \n  \nOut-of-bounds parser access (fixed by `#967`):",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: pfcpiface/parse_pdr.go\nfunc (p *pdr) parseSDFFilter(ie *ie.IE) error {\n\tsdfFields, err := ie.SDFFilter()\n\tif err != nil {\n\t\treturn err\n\t}\n\tflowDesc := sdfFields.FlowDescription\n\tipf, err := parseFlowDesc(flowDesc, int2ip(p.ueAddress).String())\n\t// ^ malformed Flow-Description enters parseFlowDesc() here\n\tif err != nil {\n\t\treturn errBadFilterDesc\n\t}\n\treturn nil\n}"
        },
        {
          "lang": "go",
          "code": "// file: pfcpiface/parse_sdf.go (vulnerable revision)\nfunc parseFlowDesc(flowDesc, ueIP string) (*ipFilterRule, error) {\n\tfields := strings.Fields(flowDesc)\n\tfor i := 3; i < len(fields); i++ {\n\t\tswitch fields[i] {\n\t\tcase \"from\":\n\t\t\ti++\n\t\t\txform(i)\n\t\t\t// ...\n\t\t\tif fields[i+1] != \"to\" {\n\t\t\t\t// ^ out-of-bounds when malformed description truncates tokens\n\t\t\t}\n\t\t}\n\t}\n\treturn ipf, nil\n}"
        }
      ],
      "issue_url": "https://github.com/omec-project/upf/issues/959",
      "rel_path": "vendor/SD-Core/pfcp/PB1/CVE_2025_65567",
      "cve": "CVE-2025-65567",
      "cwe": "CWE-125: Out-of-bounds Read",
      "affected_version": "2.1.3-dev",
      "anchor": "sd-core-pfcp-cve_2025_65567"
    },
    {
      "id": "CVE-2025-66771",
      "dir_name": "CVE_2025_66771",
      "vendor": "eupf",
      "vendor_display": "eUPF",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-66771: Malformed Heartbeat Request Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "eUPF crashes when it receives a malformed PFCP `Heartbeat Request` that omits the mandatory `Recovery Time Stamp` IE.  \nThis triggers a nil pointer dereference in heartbeat request handling and can be used for denial of service.",
      "root_cause": "`VULN-J01`:\n\neUPF will panic when a PFCP `Heartbeat Request` is received without the mandatory `Recovery Time Stamp` IE.\n\nSource (real vulnerable code):  \n`edgecomllc/eupf` `cmd/core/pfcp_hearbeat.go` (`v0.7.1`, commit `faf939678d0c043dc9cb036bca8fa8b8e28cc7c3`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "func HandlePfcpHeartbeatRequest(conn *PfcpConnection, msg message.Message, addr string) (message.Message, error) {\n\thbreq := msg.(*message.HeartbeatRequest)\n\t// if RecoveryTimeStamp IE is absent in HeartbeatRequest...\n\tts, err := hbreq.RecoveryTimeStamp.RecoveryTimeStamp()\n\t// ^ nil pointer dereference happens here when hbreq.RecoveryTimeStamp == nil\n}"
        }
      ],
      "issue_url": "https://github.com/edgecomllc/eupf/issues/629",
      "rel_path": "vendor/eupf/pfcp/PA2/CVE_2025_66771",
      "cve": "CVE-2025-66771",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "a8d774a0533ad71ddd59899be26f4aee8a31b5d2",
      "anchor": "eupf-pfcp-cve_2025_66771"
    },
    {
      "id": "CVE-2025-66772",
      "dir_name": "CVE_2025_66772",
      "vendor": "eupf",
      "vendor_display": "eUPF",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-66772: Malformed Heartbeat Response Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "eUPF crashes when it processes a malformed PFCP `Heartbeat Response` that omits the mandatory `Recovery Time Stamp` IE.  \nThis can trigger a nil pointer dereference in heartbeat response handling and lead to denial of service.",
      "root_cause": "`VULN-J02`:\n\neUPF will panic when a PFCP `Heartbeat Response` is received without the mandatory `Recovery Time Stamp` IE.\n\nSource (real vulnerable code):  \n`edgecomllc/eupf` `cmd/core/pfcp_hearbeat.go` (`v0.7.1`, commit `faf939678d0c043dc9cb036bca8fa8b8e28cc7c3`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "func HandlePfcpHeartbeatResponse(conn *PfcpConnection, msg message.Message, addr string) (message.Message, error) {\n\thbresp := msg.(*message.HeartbeatResponse)\n\t// if RecoveryTimeStamp IE is absent in HeartbeatResponse...\n\tts, err := hbresp.RecoveryTimeStamp.RecoveryTimeStamp()\n\t// ^ nil pointer dereference happens here when hbresp.RecoveryTimeStamp == nil\n}"
        }
      ],
      "issue_url": "https://github.com/edgecomllc/eupf/issues/630",
      "rel_path": "vendor/eupf/pfcp/PA2/CVE_2025_66772",
      "cve": "CVE-2025-66772",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "a8d774a0533ad71ddd59899be26f4aee8a31b5d2",
      "anchor": "eupf-pfcp-cve_2025_66772"
    },
    {
      "id": "CVE-2025-66773",
      "dir_name": "CVE_2025_66773",
      "vendor": "eupf",
      "vendor_display": "eUPF",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-66773: Missing SourceInterface IE Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "eUPF may crash when handling a malformed PFCP `Session Establishment Request` whose `CreatePDR -> PDI` omits the mandatory `SourceInterface` IE.  \nThe PoC first establishes PFCP association, then sends the crafted session message and can trigger a panic path (for example inside `displayPdr()`).",
      "root_cause": "`VULN-J03`:\n\neUPF may panic if `CreatePDR -> PDI` is missing `SourceInterface`, because `displayPdr()` uses the result index without validating `-1`.\n\nSource (real vulnerable code):  \n`edgecomllc/eupf` `cmd/core/display_utils.go` (`v0.7.1`, commit `faf939678d0c043dc9cb036bca8fa8b8e28cc7c3`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: cmd/core/display_utils.go\nfunc displayPdr(sb *strings.Builder, pdr *ie.IE) {\n\t// ...\n\tif pdi, err := pdr.PDI(); err == nil {\n\t\tsrcIfacePdiId := findIEindex(pdi, 20) // IE Type source interface\n\t\t// if SourceInterface IE is absent in PDI...\n\t\tsrcInterface, _ := pdi[srcIfacePdiId].SourceInterface()\n\t\t// ^ panic: index out of range [-1]\n\t\twriteLineTabbed(sb, fmt.Sprintf(\"Source Interface: %d \", srcInterface), 2)\n\t}\n\t// ...\n}"
        }
      ],
      "issue_url": "https://github.com/edgecomllc/eupf/issues/631",
      "rel_path": "vendor/eupf/pfcp/PA2/CVE_2025_66773",
      "cve": "CVE-2025-66773",
      "cwe": "CWE-129: Improper Validation of Array Index",
      "affected_version": "a8d774a0533ad71ddd59899be26f4aee8a31b5d2",
      "anchor": "eupf-pfcp-cve_2025_66773"
    },
    {
      "id": "CVE-2025-66776",
      "dir_name": "CVE_2025_66776",
      "vendor": "eupf",
      "vendor_display": "eUPF",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB3",
      "pattern_display": "Invalid Reference",
      "title": "CVE-2025-66776: PFCP Session Modification Authorization Bypass",
      "target": "UPF",
      "crash_type": "Session Hijacking",
      "description": "eUPF accepts a malicious PFCP `Session Modification Request` where the attacker references a `FAR ID` that belongs to another active session.  \nBecause FAR ownership is not strictly validated during update/remove flows, an attacker with PFCP access can hijack forwarding behavior and redirect victim traffic.",
      "root_cause": "`VULN-J06`:\n\nSession Modification updates/deletes FAR by `GlobalId` derived from `session.GetFar(farid)` without verifying FAR ownership/existence. Missing FAR IDs fall back to zero-value `SFarInfo` (including `GlobalId=0`), and eBPF FAR IDs are allocated from index `0`, enabling cross-session impact.\n\nSource (real vulnerable code):  \nModification path (no existence/ownership check):\n  \nSession FAR getter (zero-value fallback):",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: cmd/core/session.go\nfunc (s *Session) GetFar(id uint32) SFarInfo {\n\t// if FAR ID does not exist in this session...\n\treturn s.FARs[id]\n\t// ^ map lookup returns zero-value SFarInfo (GlobalId=0) without error\n}"
        },
        {
          "lang": "go",
          "code": "// file: cmd/core/pfcp_session_handlers.go\nfunc HandlePfcpSessionModificationRequest(conn *PfcpConnection, msg message.Message, addr string) (message.Message, error) {\n\t// ...\n\tfor _, far := range req.UpdateFAR {\n\t\tfarid, err := far.FARID()\n\t\tif err != nil {\n\t\t\treturn nil, err\n\t\t}\n\n\t\tsFarInfo := session.GetFar(farid)\n\t\t// ^ no existence/ownership validation before using FAR global id\n\t\tif err := mapOperations.UpdateFar(sFarInfo.GlobalId, sFarInfo.FarInfo); err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t}\n\t// ...\n}"
        }
      ],
      "issue_url": "https://github.com/edgecomllc/eupf/issues/635",
      "rel_path": "vendor/eupf/pfcp/PB3/CVE_2025_66776",
      "cve": "CVE-2025-66776",
      "cwe": "CWE-668: Exposure of Resource to Wrong Sphere/CWE-284: Improper Access Control/CWE-703: Improper Check or Handling of Exceptional Conditions",
      "affected_version": "a8d774a0533ad71ddd59899be26f4aee8a31b5d2",
      "anchor": "eupf-pfcp-cve_2025_66776"
    },
    {
      "id": "CVE-2025-66775",
      "dir_name": "CVE_2025_66775",
      "vendor": "eupf",
      "vendor_display": "eUPF",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "CVE-2025-66775: UPF Resource Exhaustion via Invalid SDF Filter",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "eUPF can be driven into resource exhaustion by repeatedly sending PFCP `Session Establishment Request` messages with an invalid `SDF Filter`.  \nThe partial session creation path may leave FAR/QER-related resources allocated after failure, eventually causing allocation failures and potential DoS.",
      "root_cause": "`VULN-J05`:\n\nDuring Session Establishment, FAR/QER resources are allocated before PDR parsing is fully validated. If later parsing fails (for example malformed SDF), the request is rejected but allocated FAR/QER entries are not rolled back.\n\nSource (real vulnerable code):  \nAllocation before full validation and Failure path without rollback:\n  \n \nSDF parse error source:",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: cmd/core/pfcp_session_handlers.go\nfunc HandlePfcpSessionEstablishmentRequest(conn *PfcpConnection, msg message.Message, addr string) (message.Message, error) {\n\t// ...\n\t// #TODO: Implement rollback on error\n\tfor _, far := range req.CreateFAR {\n\t\tif internalId, err := mapOperations.NewFar(farInfo); err == nil {\n\t\t\tsession.NewFar(farid, internalId, farInfo)\n\t\t} else {\n\t\t\treturn nil, err\n\t\t}\n\t}\n\tfor _, qer := range req.CreateQER {\n\t\tif internalId, err := mapOperations.NewQer(qerInfo); err == nil {\n\t\t\tsession.NewQer(qerId, internalId, qerInfo)\n\t\t} else {\n\t\t\treturn nil, err\n\t\t}\n\t}\n\t// ...\n}"
        },
        {
          "lang": "go",
          "code": "// file: cmd/core/pdr_creation_context.go\nfunc (pdrContext *PDRCreationContext) extractPDR(pdr *ie.IE, spdrInfo *SPDRInfo) error {\n\t// ...\n\tif sdfFilter, err := pdr.SDFFilter(); err == nil {\n\t\tif sdfFilter.FlowDescription == \"\" {\n\t\t\t// ...\n\t\t} else if sdfFilterParsed, err := ParseSdfFilter(sdfFilter.FlowDescription); err == nil {\n\t\t\tspdrInfo.PdrInfo.SdfFilter = &sdfFilterParsed\n\t\t} else {\n\t\t\treturn err\n\t\t\t// ^ request fails here, but previously allocated FAR/QER are not rolled back\n\t\t}\n\t}\n\t// ...\n\treturn nil\n}"
        }
      ],
      "issue_url": "https://github.com/edgecomllc/eupf/issues/633",
      "rel_path": "vendor/eupf/pfcp/PC1/CVE_2025_66775",
      "cve": "CVE-2025-66775",
      "cwe": "CWE-400: Uncontrolled Resource Consumption",
      "affected_version": "a8d774a0533ad71ddd59899be26f4aee8a31b5d2",
      "anchor": "eupf-pfcp-cve_2025_66775"
    },
    {
      "id": "CVE-2026-2525",
      "dir_name": "CVE_2026_2525",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2026-2525: Malformed OuterHeaderCreation Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "free5GC UPF can be crashed by a malformed PFCP `Session Establishment Request` containing a crafted `CreateFAR -> ForwardingParameters -> OuterHeaderCreation` IE. The `go-pfcp` dependency parser panics on the malformed payload, and UPF's panic recovery handler calls `log.Fatalf`, terminating the process.",
      "root_cause": "`VULN-J01`:\n\nfree5GC v4.1.0 depends on `wmnsk/go-pfcp` for PFCP IE parsing. A malformed `OuterHeaderCreation` can trigger panic in dependency parser, and UPF panic handling exits the process.\n\nSource (real vulnerable code):  \nfree5GC parse call site:  \n  \nDependency parser (used by free5gc v4.1.0):  \n  \nUPF panic exit path:",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/upf/internal/pfcp/pfcp.go\nfunc (s *PfcpServer) main(wg *sync.WaitGroup) {\n\tfor {\n\t\t// ...\n\t\tmsg, err := message.Parse(rcvPkt.Buf)\n\t\t// ^ malformed PFCP IE enters go-pfcp parser here\n\t\t_ = msg\n\t\t_ = err\n\t}\n}"
        },
        {
          "lang": "go",
          "code": "// file: github.com/wmnsk/go-pfcp/ie/outer-header-creation.go\nfunc (f *OuterHeaderCreationFields) UnmarshalBinary(b []byte) error {\n\t// ...\n\tif has7thBit(uint8(f.OuterHeaderCreationDescription & 0xff)) {\n\t\tif l < offset+3 {\n\t\t\treturn io.ErrUnexpectedEOF\n\t\t}\n\t\tf.CTag = binary.BigEndian.Uint32(b[offset : offset+3])\n\t\t// ^ panic: Uint32 needs 4 bytes, but slice length is 3\n\t}\n\treturn nil\n}"
        },
        {
          "lang": "go",
          "code": "// file: NFs/upf/internal/pfcp/pfcp.go\nfunc (s *PfcpServer) main(wg *sync.WaitGroup) {\n\tdefer func() {\n\t\tif p := recover(); p != nil {\n\t\t\ts.log.Fatalf(\"panic: %v\\n%s\", p, string(debug.Stack()))\n\t\t\t// ^ process exits on parser panic\n\t\t}\n\t}()\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/796",
      "rel_path": "vendor/free5gc/pfcp/PA1/CVE_2026_2525",
      "cve": "CVE-2026-2525",
      "cwe": "CWE-129: Improper Validation of Array Index",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2026_2525"
    },
    {
      "id": "CVE-2026-1682",
      "dir_name": "CVE_2026_1682",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-1682: Missing NodeID in AssociationReleaseRequest Crash",
      "target": "SMF",
      "crash_type": "Denial of Service",
      "description": "free5GC SMF will panic when it receives a PFCP `Association Release Request` without the mandatory `NodeID` IE. The handler dereferences `pfcpMsg.NodeID` without nil checking, causing a nil pointer panic that terminates the process.",
      "root_cause": "`VULN-J02`:\n\nfree5GC SMF will panic when a PFCP `Association Release Request` is received without `NodeID`.\n\nSource (real vulnerable code):  \n`free5gc/free5gc` `NFs/smf/internal/pfcp/handler/handler.go` (`v4.1.0`, commit `de6bdb7a0d5963266c893cca59c86f55df348f57`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/smf/internal/pfcp/handler/handler.go\nfunc HandlePfcpAssociationReleaseRequest(msg *pfcpUdp.Message) {\n\tpfcpMsg := msg.PfcpMessage.Body.(pfcp.PFCPAssociationReleaseRequest)\n\n\tvar cause pfcpType.Cause\n\tupf := smf_context.RetrieveUPFNodeByNodeID(*pfcpMsg.NodeID)\n\t// ^ nil pointer dereference if NodeID IE is absent\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/794",
      "rel_path": "vendor/free5gc/pfcp/PA2/CVE_2026_1682",
      "cve": "CVE-2026-1682",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2026_1682"
    },
    {
      "id": "CVE-2026-1683",
      "dir_name": "CVE_2026_1683",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-1683: Session Report Missing ReportType IE Crash",
      "target": "SMF",
      "crash_type": "Denial of Service",
      "description": "free5GC SMF will panic when it receives a PFCP `Session Report Request` without the mandatory `ReportType` IE. The handler dereferences `req.ReportType` without nil checking (e.g., `req.ReportType.Dldr`), causing a nil pointer panic that terminates the process.",
      "root_cause": "`VULN-J03`:\n\nfree5GC SMF will panic when a PFCP `Session Report Request` is received without `ReportType`.\n\nSource (real vulnerable code):  \n`free5gc/free5gc` `NFs/smf/internal/pfcp/handler/handler.go` (`v4.1.0`, commit `de6bdb7a0d5963266c893cca59c86f55df348f57`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/smf/internal/pfcp/handler/handler.go\nfunc HandlePfcpSessionReportRequest(msg *pfcpUdp.Message) {\n\t// ...\n\tif smContext.UpCnxState == models.UpCnxState_DEACTIVATED {\n\t\tif req.ReportType.Dldr {\n\t\t\t// ^ nil pointer dereference when ReportType IE is absent\n\t\t}\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/804",
      "rel_path": "vendor/free5gc/pfcp/PA2/CVE_2026_1683",
      "cve": "CVE-2026-1683",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2026_1683"
    },
    {
      "id": "CVE-2026-1684",
      "dir_name": "CVE_2026_1684",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-1684: Session Report UsageReport Missing VolumeMeasurement Crash",
      "target": "SMF",
      "crash_type": "Denial of Service",
      "description": "free5GC SMF will panic when it receives a PFCP `Session Report Request` with `ReportType.Usar=true` and `UsageReport` present, but without the `VolumeMeasurement` sub-IE. The usage report handler dereferences `report.VolumeMeasurement` without nil checking, causing a nil pointer panic that terminates the process.",
      "root_cause": "`VULN-J04`:\n\nfree5GC SMF will panic when a PFCP `UsageReport` is parsed without `VolumeMeasurement`.\n\nSource (real vulnerable code):  \n`free5gc/free5gc` `NFs/smf/internal/context/pfcp_reports.go` (`v4.1.0`, commit `de6bdb7a0d5963266c893cca59c86f55df348f57`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/smf/internal/context/pfcp_reports.go\nfunc (smContext *SMContext) HandleReports(usageReportRequest []*pfcp.UsageReportPFCPSessionReportRequest, ...) {\n\tfor _, report := range usageReportRequest {\n\t\tusageReport.TotalVolume = report.VolumeMeasurement.TotalVolume\n\t\t// ^ nil pointer dereference when VolumeMeasurement sub-IE is absent\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/806",
      "rel_path": "vendor/free5gc/pfcp/PA2/CVE_2026_1684",
      "cve": "CVE-2026-1684",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2026_1684"
    },
    {
      "id": "CVE-2026-1973",
      "dir_name": "CVE_2026_1973",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-1973: Session Establishment Response Missing Cause IE Crash",
      "target": "SMF",
      "crash_type": "Denial of Service",
      "description": "free5GC SMF will panic when it receives a PFCP `Session Establishment Response` that omits the mandatory `Cause` IE. The else-branch of the cause-checking logic dereferences `rsp.Cause.CauseValue` even when `rsp.Cause` is nil, causing a nil pointer panic.",
      "root_cause": "`VULN-J05`:\n\nfree5GC SMF will panic when `Session Establishment Response` is missing `Cause` IE.\n\nSource (real vulnerable code):  \n`free5gc/free5gc` `NFs/smf/internal/sbi/processor/datapath.go` (`v4.1.0`, commit `de6bdb7a0d5963266c893cca59c86f55df348f57`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/smf/internal/sbi/processor/datapath.go\nfunc establishPfcpSession(smContext *smf_context.SMContext, state *PFCPState, resCh chan<- SendPfcpResult) {\n\t// ...\n\tif rsp.Cause != nil && rsp.Cause.CauseValue == pfcpType.CauseRequestAccepted {\n\t\t// ...\n\t} else {\n\t\tresCh <- SendPfcpResult{\n\t\t\tErr: fmt.Errorf(\"cause[%d] if not request accepted\", rsp.Cause.CauseValue),\n\t\t\t// ^ nil pointer dereference when rsp.Cause == nil\n\t\t}\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/815",
      "rel_path": "vendor/free5gc/pfcp/PA2/CVE_2026_1973",
      "cve": "CVE-2026-1973",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2026_1973"
    },
    {
      "id": "CVE-2026-1974",
      "dir_name": "CVE_2026_1974",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-1974: Session Establishment Response Missing NodeID IE Crash",
      "target": "SMF",
      "crash_type": "Denial of Service",
      "description": "free5GC SMF will panic when it receives a PFCP `Session Establishment Response` where `UPFSEID` is present but `NodeID` is omitted. The handler calls `rsp.NodeID.ResolveNodeIdToIp()` without nil checking, causing a nil pointer panic when `NodeID` is absent.",
      "root_cause": "`VULN-J06`:\n\nfree5GC SMF will panic when `UPFSEID` is present but `NodeID` is missing in `Session Establishment Response`.\n\nSource (real vulnerable code):  \n`free5gc/free5gc` `NFs/smf/internal/sbi/processor/datapath.go` (`v4.1.0`, commit `de6bdb7a0d5963266c893cca59c86f55df348f57`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/smf/internal/sbi/processor/datapath.go\nfunc establishPfcpSession(smContext *smf_context.SMContext, state *PFCPState, resCh chan<- SendPfcpResult) {\n\trsp := rcvMsg.PfcpMessage.Body.(pfcp.PFCPSessionEstablishmentResponse)\n\tif rsp.UPFSEID != nil {\n\t\tNodeIDtoIP := rsp.NodeID.ResolveNodeIdToIp().String()\n\t\t// ^ nil pointer dereference when NodeID IE is absent\n\t\tpfcpSessionCtx := smContext.PFCPContext[NodeIDtoIP]\n\t\tpfcpSessionCtx.RemoteSEID = rsp.UPFSEID.Seid\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/816",
      "rel_path": "vendor/free5gc/pfcp/PA2/CVE_2026_1974",
      "cve": "CVE-2026-1974",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2026_1974"
    },
    {
      "id": "CVE-2026-1975",
      "dir_name": "CVE_2026_1975",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-1975: Session Report Missing UsageReportTrigger Crash",
      "target": "SMF",
      "crash_type": "Denial of Service",
      "description": "free5GC SMF will panic when it receives a PFCP `Session Report Request` with `ReportType.Usar=true` and `UsageReport` present, but without the `UsageReportTrigger` sub-IE. The `identityTriggerType()` function dereferences the nil trigger pointer, causing a nil pointer panic.",
      "root_cause": "`VULN-J07`:\n\nfree5GC SMF will panic when `UsageReportTrigger` is missing in a `UsageReport`.\n\nSource (real vulnerable code):  \nHandleReports call site:  \n  \nTrigger dereference:",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/smf/internal/context/pfcp_reports.go\nfunc (smContext *SMContext) HandleReports(usageReportRequest []*pfcp.UsageReportPFCPSessionReportRequest, ...) {\n\tfor _, report := range usageReportRequest {\n\t\tusageReport.ReportTpye = identityTriggerType(report.UsageReportTrigger)\n\t\t// ^ passes nil when UsageReportTrigger sub-IE is absent\n\t}\n}\n\nfunc identityTriggerType(usarTrigger *pfcpType.UsageReportTrigger) models.ChfConvergedChargingTriggerType {\n\tswitch {\n\tcase usarTrigger.Volth:\n\t\t// ^ nil pointer dereference when usarTrigger == nil\n\t\treturn models.ChfConvergedChargingTriggerType_QUOTA_THRESHOLD\n\t}\n\treturn \"\"\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/814",
      "rel_path": "vendor/free5gc/pfcp/PA2/CVE_2026_1975",
      "cve": "CVE-2026-1975",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2026_1975"
    },
    {
      "id": "CVE-2026-1976",
      "dir_name": "CVE_2026_1976",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-1976: Session Deletion Response Missing Cause IE Crash",
      "target": "SMF",
      "crash_type": "Denial of Service",
      "description": "free5GC SMF will panic when it receives a PFCP `Session Deletion Response` that omits the `Cause` IE. The else-branch of the cause-checking logic dereferences `rsp.Cause.CauseValue` even when `rsp.Cause` is nil, causing a nil pointer panic.",
      "root_cause": "`VULN-J08`:\n\nfree5GC SMF will panic when `Session Deletion Response` is missing `Cause` IE.\n\nSource (real vulnerable code):  \n`free5gc/free5gc` `NFs/smf/internal/sbi/processor/datapath.go` (`v4.1.0`, commit `de6bdb7a0d5963266c893cca59c86f55df348f57`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/smf/internal/sbi/processor/datapath.go\nfunc deletePfcpSession(upf *smf_context.UPF, ctx *smf_context.SMContext, resCh chan<- SendPfcpResult) {\n\t// ...\n\tif rsp.Cause != nil && rsp.Cause.CauseValue == pfcpType.CauseRequestAccepted {\n\t\t// ...\n\t} else {\n\t\tresCh <- SendPfcpResult{\n\t\t\tErr: fmt.Errorf(\"cause[%d] if not request accepted\", rsp.Cause.CauseValue),\n\t\t\t// ^ nil pointer dereference when rsp.Cause == nil\n\t\t}\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/817",
      "rel_path": "vendor/free5gc/pfcp/PA2/CVE_2026_1976",
      "cve": "CVE-2026-1976",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2026_1976"
    },
    {
      "id": "CVE-2026-25501",
      "dir_name": "CVE_2026_25501",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "Issue #805: Missing DownlinkDataReport in SessionReportRequest Crash",
      "target": "SMF",
      "crash_type": "Denial of Service",
      "description": "free5GC SMF will crash when it receives a PFCP `Session Report Request` with `ReportType.Dldr=true` but without the `DownlinkDataReport` IE. The handler dereferences `req.DownlinkDataReport` without nil checking, causing a nil pointer panic when the IE is absent.",
      "root_cause": "`VULN-J11`:\n\nfree5GC SMF will panic when `Session Report Request` sets `ReportType.Dldr=true` but omits `DownlinkDataReport`.\n\nSource (real vulnerable code):  \n`free5gc/free5gc` `NFs/smf/internal/pfcp/handler/handler.go` (`v4.1.0`, commit `de6bdb7a0d5963266c893cca59c86f55df348f57`)",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/smf/internal/pfcp/handler/handler.go\nfunc HandlePfcpSessionReportRequest(msg *pfcpUdp.Message) {\n\t// ...\n\tif smContext.UpCnxState == models.UpCnxState_DEACTIVATED {\n\t\tif req.ReportType.Dldr {\n\t\t\tdownlinkDataReport := req.DownlinkDataReport\n\t\t\tif downlinkDataReport.DownlinkDataServiceInformation != nil {\n\t\t\t\t// ^ nil pointer dereference when DownlinkDataReport IE is absent\n\t\t\t}\n\t\t}\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/805",
      "rel_path": "vendor/free5gc/pfcp/PA2/CVE_2026_25501",
      "cve": "CVE-2026-25501",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2026_25501"
    },
    {
      "id": "CVE-2026-26025",
      "dir_name": "CVE_2026_26025",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "Issue #807: Missing URRID in UsageReport Crash",
      "target": "SMF",
      "crash_type": "Denial of Service",
      "description": "free5GC SMF will crash when it receives a PFCP `Session Report Request` with `ReportType.Usar=true` and `UsageReport` present, but without the mandatory `URRID` sub-IE. The usage report handler dereferences `report.URRID` without nil checking, causing a nil pointer panic.",
      "root_cause": "`VULN-J12`:\n\nfree5GC SMF will panic when `UsageReport` is missing `URRID`.\n\nSource (real vulnerable code):  \nUsage report call path:  \n  \nURRID dereference:",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/smf/internal/pfcp/handler/handler.go\nfunc HandlePfcpSessionReportRequest(msg *pfcpUdp.Message) {\n\t// ...\n\tif req.ReportType.Usar && req.UsageReport != nil {\n\t\tsmContext.HandleReports(req.UsageReport, nil, nil, upfNodeID, \"\")\n\t}\n}"
        },
        {
          "lang": "go",
          "code": "// file: NFs/smf/internal/context/pfcp_reports.go\nfunc (smContext *SMContext) HandleReports(usageReportRequest []*pfcp.UsageReportPFCPSessionReportRequest, ...) {\n\tfor _, report := range usageReportRequest {\n\t\tusageReport.UrrId = report.URRID.UrrIdValue\n\t\t// ^ nil pointer dereference when URRID sub-IE is absent\n\t}\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/807",
      "rel_path": "vendor/free5gc/pfcp/PA2/CVE_2026_26025",
      "cve": "CVE-2026-26025",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2026_26025"
    },
    {
      "id": "CVE-2025-65561",
      "dir_name": "CVE_2025_65561",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "CVE-2025-65561: Session Modification with Huge SEID Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "free5GC UPF will panic when it receives a PFCP `Session Modification Request` with `SEID=0xFFFFFFFFFFFFFFFF`. The `LocalNode.Sess()` function converts the uint64 SEID to `int`, which overflows to a negative value, causing an out-of-bounds array access panic.",
      "root_cause": "`VULN-J09`:\n\nfree5GC UPF will panic when `Session Modification Request` carries `SEID=0xFFFFFFFFFFFFFFFF`.\n\nSource (real vulnerable code):  \nSession lookup entry:  \n  \nOverflow-prone index conversion:",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/upf/internal/pfcp/session.go\nfunc (s *PfcpServer) handleSessionModificationRequest(req *message.SessionModificationRequest, addr net.Addr) {\n\tsess, err := s.lnode.Sess(req.SEID())\n\t// ^ large uint64 SEID enters LocalNode.Sess()\n}\n\n// file: NFs/upf/internal/pfcp/node.go\nfunc (n *LocalNode) Sess(lSeid uint64) (*Sess, error) {\n\ti := int(lSeid) - 1\n\tif i >= len(n.sess) {\n\t\treturn nil, errors.Errorf(\"Sess: sess not found (lSeid:%#x)\", lSeid)\n\t}\n\tsess := n.sess[i]\n\t// ^ when lSeid=0xFFFFFFFFFFFFFFFF, int(lSeid) becomes negative and n.sess[i] panics\n\treturn sess, nil\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/730",
      "rel_path": "vendor/free5gc/pfcp/PB1/CVE_2025_65561",
      "cve": "CVE-2025-65561",
      "cwe": "CWE-129: Improper Validation of Array Index",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2025_65561"
    },
    {
      "id": "CVE-2025-65562",
      "dir_name": "CVE_2025_65562",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "CVE-2025-65562: Session Deletion with Huge SEID Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "free5GC UPF will panic when it receives a PFCP `Session Deletion Request` with `SEID=0xFFFFFFFFFFFFFFFF`. The `LocalNode.DeleteSess()` function converts the uint64 SEID to `int`, which overflows to a negative value, causing an out-of-bounds array access panic.",
      "root_cause": "`VULN-J10`:\n\nfree5GC UPF will panic when `Session Deletion Request` carries a huge SEID value.\n\nSource (real vulnerable code):  \nSession deletion path:  \n  \nOverflow-prone delete index conversion:",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/upf/internal/pfcp/session.go\nfunc (s *PfcpServer) handleSessionDeletionRequest(req *message.SessionDeletionRequest, addr net.Addr) {\n\tlSeid := req.SEID()\n\tsess, err := s.lnode.Sess(lSeid)\n\t// ^ huge SEID reaches LocalNode.Sess()/DeleteSess() path\n}\n\n// file: NFs/upf/internal/pfcp/node.go\nfunc (n *LocalNode) DeleteSess(lSeid uint64) ([]report.USAReport, error) {\n\ti := int(lSeid) - 1\n\tif i >= len(n.sess) {\n\t\treturn nil, errors.Errorf(\"DeleteSess: sess not found (lSeid:%#x)\", lSeid)\n\t}\n\tif n.sess[i] == nil {\n\t\treturn nil, errors.Errorf(\"DeleteSess: sess not found (lSeid:%#x)\", lSeid)\n\t}\n\t// ^ when lSeid=0xFFFFFFFFFFFFFFFF, int(lSeid) becomes negative and n.sess[i] panics\n\tn.sess[i].log.Infoln(\"sess deleted\")\n\tusars := n.sess[i].Close()\n\tn.sess[i] = nil\n\tn.free = append(n.free, lSeid)\n\treturn usars, nil\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/731",
      "rel_path": "vendor/free5gc/pfcp/PB1/CVE_2025_65562",
      "cve": "CVE-2025-65562",
      "cwe": "CWE-129: Improper Validation of Array Index",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-cve_2025_65562"
    },
    {
      "id": "Issue #818",
      "dir_name": "818_issue",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "Issue #818: PFCP Session Establishment Flood Causes Session Pool Exhaustion",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "free5GC UPF can be driven into memory exhaustion by repeatedly receiving PFCP `Session Establishment Request` messages with unique SEIDs without corresponding deletion requests. Each request allocates a persistent session object appended to an unbounded slice, eventually exhausting memory and causing the process to crash.",
      "root_cause": "`VULN-J13`:\n\nfree5GC UPF can be driven into memory exhaustion by repeatedly creating PFCP sessions without teardown.\n\nSource (real vulnerable code):  \nSession allocation call site:  \n  \nUnbounded session append:",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/upf/internal/pfcp/session.go\nfunc (s *PfcpServer) handleSessionEstablishmentRequest(req *message.SessionEstablishmentRequest, addr net.Addr) {\n\t// ...\n\t// allocate a session\n\tsess := rnode.NewSess(fseid.SEID)\n\t// ^ each establishment allocates persistent session state\n}"
        },
        {
          "lang": "go",
          "code": "// file: NFs/upf/internal/pfcp/node.go\nfunc (n *LocalNode) NewSess(rSeid uint64, qlen int) *Sess {\n\ts := &Sess{ /* maps and queues allocated */ }\n\tlast := len(n.free) - 1\n\tif last >= 0 {\n\t\ts.LocalID = n.free[last]\n\t\tn.free = n.free[:last]\n\t\tn.sess[s.LocalID-1] = s\n\t} else {\n\t\tn.sess = append(n.sess, s)\n\t\t// ^ unbounded growth if attacker keeps creating sessions\n\t\ts.LocalID = uint64(len(n.sess))\n\t}\n\treturn s\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/818",
      "rel_path": "vendor/free5gc/pfcp/PC1/818_issue",
      "cwe": "CWE-400: Uncontrolled Resource Consumption",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-818_issue"
    },
    {
      "id": "Issue #819",
      "dir_name": "819_issue",
      "vendor": "free5gc",
      "vendor_display": "free5GC",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "Issue #819: PFCP Session Pool Growth Leads to UPF OOM",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "free5GC UPF lacks a bounded session-creation policy, allowing memory exhaustion through continuous PFCP `Session Establishment Request` messages. The session store grows without a hard cap as each valid request allocates persistent session state, eventually leading to OOM termination.",
      "root_cause": "`VULN-J14`:\n\nfree5GC UPF lacks a bounded session-creation policy in PFCP establishment path, enabling memory-exhaustion DoS.\n\nSource (real vulnerable code):  \nSession-establishment allocator path:  \n  \nSession store growth logic:",
      "code_snippets": [
        {
          "lang": "go",
          "code": "// file: NFs/upf/internal/pfcp/session.go\nfunc (s *PfcpServer) handleSessionEstablishmentRequest(req *message.SessionEstablishmentRequest, addr net.Addr) {\n\t// allocate a session for each valid request\n\tsess := rnode.NewSess(fseid.SEID)\n\t_ = sess\n}"
        },
        {
          "lang": "go",
          "code": "// file: NFs/upf/internal/pfcp/node.go\nfunc (n *LocalNode) NewSess(rSeid uint64, qlen int) *Sess {\n\ts := &Sess{ /* per-session maps/queues */ }\n\tif last := len(n.free) - 1; last >= 0 {\n\t\ts.LocalID = n.free[last]\n\t\tn.free = n.free[:last]\n\t\tn.sess[s.LocalID-1] = s\n\t} else {\n\t\tn.sess = append(n.sess, s)\n\t\t// ^ no quota/limit check before growing session pool\n\t\ts.LocalID = uint64(len(n.sess))\n\t}\n\treturn s\n}"
        }
      ],
      "issue_url": "https://github.com/free5gc/free5gc/issues/819",
      "rel_path": "vendor/free5gc/pfcp/PC1/819_issue",
      "cwe": "CWE-400: Uncontrolled Resource Consumption",
      "affected_version": "V4.1.0",
      "anchor": "free5gc-pfcp-819_issue"
    },
    {
      "id": "CVE-2026-36895",
      "dir_name": "CVE_2026_36895",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2026-36895: Unbounded Loop in Grouped IE Parser",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "OAI SGW-C enters an infinite loop and becomes unresponsive when it receives a CreateSessionRequest with a BearerContext grouped IE whose outer TLV length is set to 0xFFFF (65535) but only contains a small inner EBI IE. The `gtpv2c_grouped_ie::load_from()` function uses the attacker-controlled length to control a while loop. When inner IEs report smaller combined lengths than the outer TLV claims, `remaining_size` never reaches zero, causing the SGW-C GTPv2-C thread to consume 100% CPU indefinitely.",
      "root_cause": "`CVE-2026-36895`:\n\nThe `gtpv2c_grouped_ie::load_from()` function trusts the outer TLV length field to determine how many bytes of inner IEs to parse. When the declared length far exceeds the actual inner IE data, the loop never terminates because `remaining_size` remains positive indefinitely.\n\nSource (real vulnerable code):",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: oai-spgwc/src/gtpv2c/3gpp_29.274.hpp (lines 157-169)\nvoid gtpv2c_grouped_ie::load_from(std::istream& is) {\n  int32_t remaining_size = tlv.get_length();  // Attacker controls this via TLV length\n  while (remaining_size > 0) {\n    gtpv2c_ie* ie = new_gtpv2c_ie_from_stream(is);\n    if (ie) {\n      remaining_size -= (ie->tlv.get_length() + gtpv2c_tlv::tlv_ie_length);\n      ies.push_back(std::shared_ptr<gtpv2c_ie>(ie));\n    } else {\n      throw gtpc_tlv_bad_length_exception(tlv.get_type(), tlv.get_length());\n    }\n  }\n}"
        }
      ],
      "issue_url": "vulnDB",
      "rel_path": "vendor/oai/gtp-c/PA1/CVE_2026_36895",
      "anchor": "oai-gtp-c-cve_2026_36895",
      "cve": "CVE-2026-36895",
      "affected_version": "v1.2.0",
      "cwe": "CWE-834: Excessive Iteration"
    },
    {
      "id": "CVE-2026-36896",
      "dir_name": "CVE_2026_36896",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2026-36896: APN IE Stack Overflow via VLA",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "OAI SGW-C crashes with a segmentation fault when it receives a CreateSessionRequest with an APN IE whose TLV length is set to 65535. The `gtpv2c_access_point_name_ie::load_from()` function allocates a C99 variable-length array (VLA) on the stack using the untrusted `tlv.length` value. A 64KB stack allocation exceeds the process stack limit and hits the guard page, causing an immediate SIGSEGV that terminates the SGW-C process.",
      "root_cause": "`CVE-2026-36896`:\n\nThe `gtpv2c_access_point_name_ie::load_from()` function allocates a variable-length array on the stack using the untrusted TLV length field. When an attacker sets this length to a large value, the stack allocation exceeds the process stack limit, hitting the guard page and causing an immediate SIGSEGV.\n\nSource (real vulnerable code):",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: oai-spgwc/src/gtpv2c/3gpp_29.274.hpp (lines 771-776)\nvoid gtpv2c_access_point_name_ie::load_from(std::istream& is) {\n  char apn[tlv.length];  // VLA on stack - attacker controls tlv.length\n  is.read(apn, tlv.length);  // stack overflow when tlv.length >> stack size\n  access_point_name.assign(apn, tlv.length);\n}"
        }
      ],
      "issue_url": "vulnDB",
      "rel_path": "vendor/oai/gtp-c/PA1/CVE_2026_36896",
      "anchor": "oai-gtp-c-cve_2026_36896",
      "cve": "CVE-2026-36896",
      "affected_version": "v1.2.0",
      "cwe": "CWE-121: Stack-based Buffer Overflow"
    },
    {
      "id": "CVE-2026-36897",
      "dir_name": "CVE_2026_36897",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2026-36897: Missing Min/Max TLV Length Validation",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "OAI SGW-C accepts and processes IEs with out-of-spec lengths without any validation when it receives a CreateSessionRequest containing oversized IEs (e.g., IMSI with length=20, RAT Type with length=10). The TLV parser accepts any 16-bit length without checking against the 3GPP 29.274 min/max bounds for each IE type. This missing validation enables downstream buffer overflows (PA1-04), out-of-bounds reads (PA1-10), and other memory corruption vulnerabilities in the SGW-C process.",
      "root_cause": "`CVE-2026-36897`:\n\nThe GTPv2-C TLV parser in SPGWC does not enforce minimum or maximum length constraints defined in 3GPP TS 29.274 for individual IE types. Every `load_from()` function reads data based on the TLV length without first validating it against the expected size, allowing arbitrarily large or small values to propagate into downstream parsers.\n\nSource (real vulnerable code):",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: oai-spgwc/src/gtpv2c/3gpp_29.274.hpp (multiple load_from functions)\n// Example: gtpv2c_aggregate_maximum_bit_rate_ie\nvoid gtpv2c_aggregate_maximum_bit_rate_ie::load_from(std::istream& is) {\n  // No validation of tlv.get_length() against expected size (8 bytes)\n  is.read(reinterpret_cast<char*>(&apn_ambr_for_uplink),\n          sizeof(apn_ambr_for_uplink));\n  is.read(reinterpret_cast<char*>(&apn_ambr_for_downlink),\n          sizeof(apn_ambr_for_downlink));\n  apn_ambr_for_uplink = be32toh(apn_ambr_for_uplink);\n  apn_ambr_for_downlink = be32toh(apn_ambr_for_downlink);\n  // ^ No check: tlv.get_length() could be 0, 4, 100, or 65535\n}"
        }
      ],
      "issue_url": "vulnDB",
      "rel_path": "vendor/oai/gtp-c/PA1/CVE_2026_36897",
      "anchor": "oai-gtp-c-cve_2026_36897",
      "cve": "CVE-2026-36897",
      "affected_version": "v1.2.0",
      "cwe": "CWE-20: Improper Input Validation"
    },
    {
      "id": "CVE-2026-36898",
      "dir_name": "CVE_2026_36898",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2026-36898: IMSI IE Stack Buffer Overflow",
      "target": "SPGWC",
      "crash_type": "Denial of Service",
      "description": "OAI SPGWC crashes due to a stack buffer overflow when it receives a CreateSessionRequest with an IMSI IE whose length is set to 65 bytes (normal max is 8). The `gtpv2c_imsi_ie::load_from()` function reads `tlv.get_length()` bytes directly into a fixed 8-byte buffer `u1.b[IMSI_BCD8_SIZE]` without length validation, corrupting the return address on the stack and terminating the SPGWC process with a SIGSEGV.",
      "root_cause": "`CVE-2026-36898`:\n\nThe IMSI IE parser reads `tlv.get_length()` bytes directly into a fixed 8-byte stack buffer without validating that the length does not exceed `IMSI_BCD8_SIZE`. An attacker-controlled length field causes a stack buffer overflow.\n\nSource (real vulnerable code):",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: oai-spgwc/src/gtpv2c/3gpp_29.274.hpp (lines 578-586)\nvoid gtpv2c_imsi_ie::load_from(std::istream& is) {\n  is.read(reinterpret_cast<char*>(u1.b), tlv.get_length());\n  // ^ Reads tlv.get_length() bytes into u1.b[IMSI_BCD8_SIZE] (8 bytes)\n  //   No length validation - if tlv.get_length() > 8, stack overflow\n  num_digits = tlv.get_length() * 2;\n  if ((u1.b[tlv.get_length() - 1] & 0xF0) == 0xF0) {\n    num_digits -= 1;\n  }\n  if (num_digits > 15) num_digits = 15;\n}"
        }
      ],
      "issue_url": "vulnDB",
      "rel_path": "vendor/oai/gtp-c/PA1/CVE_2026_36898",
      "anchor": "oai-gtp-c-cve_2026_36898",
      "cve": "CVE-2026-36898",
      "affected_version": "v1.2.0",
      "cwe": "CWE-121: Stack-based Buffer Overflow"
    },
    {
      "id": "CVE-2026-36899",
      "dir_name": "CVE_2026_36899",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2026-36899: F-TEID IE Out-of-Bounds Read",
      "target": "SPGWC/SGW",
      "crash_type": "Denial of Service",
      "description": "OAI SPGWC/SGW performs an out-of-bounds memory read when it receives a CreateSessionRequest with an F-TEID IE that sets the IPv6 flag (V6=1) but provides only 6 bytes of data (insufficient for the 16-byte IPv6 address). The F-TEID parser copies 16 bytes for the IPv6 address without verifying the IE buffer contains enough data, causing the SGW to read 16 bytes beyond the IE boundary, which can result in a crash or information disclosure.",
      "root_cause": "`CVE-2026-36899`:\n\nThe F-TEID IE parser copies a 16-byte IPv6 address from the IE value buffer without checking that `ieLength` is large enough to contain the address, causing an out-of-bounds read when the IE is truncated.\n\nSource (real vulnerable code):",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: oai-hss/src/gtpv2-c/gtpv2c_ie_formatter/src/gtpv2c_ie_formatter.c\nnw_rc_t gtpv2c_fteid_ie_get(\n    uint8_t ieType, uint16_t ieLength, uint8_t ieInstance,\n    uint8_t *ieValue, void *arg) {\n  fteid_t *fteid = (fteid_t *)arg;\n  fteid->ipv6 = (ieValue[0] & 0x40) >> 6;\n  fteid->teid = ntoh_int32_buf(&ieValue[1]);\n  uint8_t offset = 0;\n  if (fteid->ipv4 == 1) { offset = 4; }\n  if (fteid->ipv6 == 1) {\n    memcpy(fteid->ipv6_address.__in6_u.__u6_addr8,\n           &ieValue[5 + offset], 16);  // No ieLength check! OOB read\n  }\n  return NW_OK;\n}"
        }
      ],
      "issue_url": "vulnDB",
      "rel_path": "vendor/oai/gtp-c/PA1/CVE_2026_36899",
      "anchor": "oai-gtp-c-cve_2026_36899",
      "cve": "CVE-2026-36899",
      "affected_version": "v1.2.0",
      "cwe": "CWE-125: Out-of-bounds Read"
    },
    {
      "id": "CVE-2026-36900",
      "dir_name": "CVE_2026_36900",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2026-36900: Empty Grouped IE Parser Stub",
      "target": "MME",
      "crash_type": "Denial of Service",
      "description": "OAI MME silently accepts malformed grouped IEs without any validation when it receives a CreateSessionRequest with a BearerContext grouped IE containing malformed nested IEs (e.g., F-TEID with length=100 but only 10 bytes of data). The `nwGtpv2cMsgGroupedIeParse()` function is an empty stub that logs a debug message and returns NW_OK without parsing or validating the nested IE structure, allowing malformed data to pass through unchecked to downstream handlers in the MME where it can trigger further vulnerabilities.",
      "root_cause": "`CVE-2026-36900`:\n\nThe grouped IE parser is an empty stub that unconditionally returns success without parsing or validating nested IE contents, allowing arbitrarily malformed grouped IEs to reach downstream handlers unchecked.\n\nSource (real vulnerable code):",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: oai-hss/src/gtpv2-c/nwgtpv2c-0.11/src/NwGtpv2cMsgIeParseInfo.c (lines 799-808)\nstatic nw_rc_t nwGtpv2cMsgGroupedIeParse(\n    NW_IN nw_gtpv2c_grouped_ie_parse_info_t *thiz,\n    NW_IN uint8_t ieType, NW_IN uint16_t ieLength,\n    NW_IN uint8_t ieInstance, NW_IN uint8_t *pIeValue) {\n  NW_ASSERT(thiz);\n  OAILOG_DEBUG(LOG_GTPV2C,\n      \"Received grouped IE %u with instance %u of length %u in msg-type %u!\\n\",\n      ieType, ieInstance, ieLength, thiz->groupedIeType);\n  return NW_OK;  // Always returns success without validation!\n}"
        }
      ],
      "issue_url": "vulnDB",
      "rel_path": "vendor/oai/gtp-c/PA1/CVE_2026_36900",
      "anchor": "oai-gtp-c-cve_2026_36900",
      "cve": "CVE-2026-36900",
      "affected_version": "v1.2.0",
      "cwe": "CWE-20: Improper Input Validation"
    },
    {
      "id": "CVE-2026-36901",
      "dir_name": "CVE_2026_36901",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-36901: Out-of-Bounds Vector Access on Empty BearerContext",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "OAI SGW-C crashes with an out-of-bounds memory access when it receives a CreateSessionRequest with TEID=0 and no BearerContext IEs for an IMSI that already has an existing bearer context. The SGW-C's `handle_itti_msg()` handler accesses `bearer_contexts_to_be_created[0]` without checking if the vector is empty when the `!csreq.teid` code path is taken, causing a segmentation fault or `std::out_of_range` exception that terminates the SGW-C process. Triggering this requires first sending a valid CreateSessionRequest to establish a bearer context for the target IMSI.",
      "root_cause": "`CVE-2026-36901`:\n\nThe CreateSessionRequest handler accesses `bearer_contexts_to_be_created[0]` without verifying the vector is non-empty when processing a request with TEID=0 for an IMSI that already has an existing bearer context.\n\nSource (real vulnerable code):",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: oai-spgwc/src/sgwc/sgwc_app.cpp (lines 419-424)\nvoid sgwc_app::handle_itti_msg(itti_s11_create_session_request& csreq) {\n  // ...\n  if (!csreq.teid) {\n    // NO SIZE CHECK HERE!\n    ebi = csreq.gtp_ies.bearer_contexts_to_be_created[0].eps_bearer_id;\n    // ^ Out-of-bounds access when vector is empty\n  }\n}"
        }
      ],
      "issue_url": "vulnDB",
      "rel_path": "vendor/oai/gtp-c/PA2/CVE_2026_36901",
      "anchor": "oai-gtp-c-cve_2026_36901",
      "cve": "CVE-2026-36901",
      "affected_version": "v1.2.0",
      "cwe": "CWE-125: Out-of-bounds Read"
    },
    {
      "id": "CVE-2025-65560",
      "dir_name": "CVE_2025_65560",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-65560: Missing F-TEID in PDR Causes UPF Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "OAI-cn-5g UPF crashes with SIGSEGV when it receives a PFCP Session Establishment Request containing a CreatePDR with a PDI that omits the mandatory F-TEID IE. The UPF processes the FAR successfully but fails during PDI validation due to the missing F-TEID, and the resulting exception is not caught.",
      "root_cause": "`CVE-2025-65560`:\n\nThe UPF does not properly validate the presence of mandatory F-TEID IE in CreatePDR before processing. When F-TEID is missing, PDR validation fails but the resulting exception is not caught, crashing the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: src/upf_app/simpleswitch/pfcp_session.cpp (commit 74d8ed9a)\nbool pfcp_session::create(\n    const pfcp::create_pdr& cr_pdr, pfcp::cause_t& cause,\n    uint16_t& offending_ie, pfcp::fteid_t& allocated_fteid) {\n  // ...\n  if (pdi.source_interface.second.interface_value == INTERFACE_VALUE_ACCESS) {\n    if (not pdi.local_fteid.first) {\n      cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;\n      offending_ie      = PFCP_IE_F_TEID;\n      return false;\n      // ^ Missing F-TEID causes PDR validation to fail, the exception\n      //   is not properly caught, leading to SIGSEGV\n    }\n  }\n}"
        }
      ],
      "issue_url": "https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/issues/23",
      "rel_path": "vendor/oai/pfcp/PA2/CVE_2025_65560",
      "cve": "CVE-2025-65560",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "74d8ed9a5e2475816225a3999de42dd36f243587",
      "anchor": "oai-pfcp-cve_2025_65560"
    },
    {
      "id": "CVE-2025-66777",
      "dir_name": "CVE_2025_66777",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-66777: Missing CreatePDR in Session Establishment Causes UPF Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "OAI-cn-5g UPF crashes when it receives a PFCP Session Establishment Request containing only a CreateFAR but no CreatePDR IEs. The UPF processes the FAR but finds no PDR, throwing an uncaught `std::runtime_error(\"No PDRs were found in session\")` that terminates the process.",
      "root_cause": "`CVE-2025-66777`:\n\nThe UPF does not validate the presence of mandatory CreatePDR IEs in Session Establishment Requests. When no CreatePDR is present, the session creation logic throws an uncaught `std::runtime_error` that terminates the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: src/upf_app/SessionManager.cpp (commit 74d8ed9a)\nvoid SessionManager::createBPFSession(\n    std::shared_ptr<pfcp::pfcp_session> pSession_establishment, ...) {\n  // ...\n  processPDRs(pSession_establishment);\n\n  if (pdrs_uplink.empty() && pdrs_downlink.empty()) {\n    logger.error(\"No PDRs were found in session: %d\", seid);\n    throw std::runtime_error(\"No PDRs were found in session\");\n    // ^ Exception thrown when no CreatePDR is present but not caught\n    //   by the caller, crashing the UPF process\n  }\n}"
        }
      ],
      "issue_url": "https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/issues/24",
      "rel_path": "vendor/oai/pfcp/PA2/CVE_2025_66777",
      "cve": "CVE-2025-66777",
      "cwe": "CWE-476: NULL Pointer Dereference",
      "affected_version": "74d8ed9a5e2475816225a3999de42dd36f243587",
      "anchor": "oai-pfcp-cve_2025_66777"
    },
    {
      "id": "CVE-2025-66780",
      "dir_name": "CVE_2025_66780",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-66780: Missing DL F-TEID in Session Modification Causes UPF Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "OAI-cn-5g UPF crashes when it receives a Session Modification Request that creates a new downlink PDR without the F-TEID IE (gNB IP). The UPF hits an unimplemented error branch that directly throws `std::runtime_error`, and since the caller has no catch block, the process terminates.",
      "root_cause": "`CVE-2025-66780`:\n\nThe UPF does not validate the presence of the F-TEID IE in CreatePDR within Session Modification Requests. When F-TEID is missing from a downlink PDR, the UPF attempts to update the ARP table without a gNB IP address, throwing an uncaught `std::runtime_error` that terminates the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: src/upf_app/SessionManager.cpp (commit 74d8ed9a)\nvoid SessionManager::processPDRDetails(\n    std::shared_ptr<pfcp::pfcp_session> pSession,\n    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedence, int interfaceValue,\n    const std::string& direction) {\n  // ...\n  if (!pdi.get(fteid)) {\n    if (fteid.ch) {\n    }\n    fteid.teid = -1;\n    logger.debug(\"FTEID is missing\");\n    logger.warn(\"TODO: This IE shall not be present if Traffic Endpoint ID...\");\n    // ^ Missing F-TEID silently sets invalid TEID (-1), leading to crash\n    //   when the UPF later tries to use the invalid value\n  }\n}"
        }
      ],
      "issue_url": "https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/issues/27",
      "rel_path": "vendor/oai/pfcp/PA2/CVE_2025_66780",
      "cve": "CVE-2025-66780",
      "cwe": "CWE-248 Uncaught Exception",
      "affected_version": "74d8ed9a5e2475816225a3999de42dd36f243587",
      "anchor": "oai-pfcp-cve_2025_66780"
    },
    {
      "id": "CVE-2026-36881",
      "dir_name": "CVE_2026_36881",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-36881: Missing UE IPv4 in PDI: Uncaught Exception Crashes UPF",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "OAI-cn-5g UPF crashes when it processes a Session Modification Request that removes an existing downlink PDR and creates a new one without a UE IPv4 address. The missing UE IP causes PDR creation to fail silently, leaving the session with no valid PDRs. When `modifyBpfSession()` subsequently runs, it finds no PDRs and throws an uncaught `std::runtime_error(\"Session modification failed: No pdr found.\")`, terminating the UPF process.",
      "root_cause": "`Vuln-PA3-01`:\n\nWhen a Session Modification creates a downlink PDR (Source Interface = Core), the UPF requires a UE IPv4 address in the PDI to register the PDR in the downlink lookup table. If the UE IP is missing, the PDR creation is rejected and the function returns `false`, but the caller does not check this return value and continues processing. The old PDR has already been removed, so the session ends up with zero PDRs. When `modifyBpfSession()` subsequently runs, it finds no PDRs and throws an uncaught `std::runtime_error`, terminating the UPF process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: src/upf_app/simpleswitch/pfcp_session.cpp (commit 74d8ed9a)\nbool pfcp_session::create(\n    const pfcp::create_pdr& cr_pdr, pfcp::cause_t& cause,\n    uint16_t& offending_ie, pfcp::fteid_t& allocated_fteid) {\n  // ...\n  } else if (pdi.source_interface.second.interface_value == INTERFACE_VALUE_CORE) {\n    if ((pdi.ue_ip_address.first) && (pdi.ue_ip_address.second.v4)) {\n      pfcp_switch_inst->add_pfcp_dl_pdr_by_ue_ip(\n          be32toh(pdi.ue_ip_address.second.ipv4_address.s_addr), spdr);\n    } else {\n      cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;\n      Logger::upf_n4().info(\n          \"Could not create_packet_in_access, cause accept only IPv4 UE IP \"\n          \"address! Rejecting PFCP_XXX_REQUEST\");\n      return false;\n      // ^ PDR creation rejected but session modification continues,\n      //   leaving session with no valid PDRs → uncaught exception\n    }\n  }\n}"
        }
      ],
      "issue_url": "https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/issues/30",
      "rel_path": "vendor/oai/pfcp/PA2/CVE_2026_36881",
      "cwe": "CWE-248 Uncaught Exception",
      "affected_version": "74d8ed9a5e2475816225a3999de42dd36f243587",
      "anchor": "oai-pfcp-cve_2026_36881",
      "cve": "CVE-2026-36881"
    },
    {
      "id": "CVE-2026-36880",
      "dir_name": "CVE_2026_36880",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "CVE-2026-36880: Stack Buffer Overflow: Oversized FQDN in Node ID IE Crashes UPF",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "OAI-cn-5g UPF crashes with a segmentation fault when it receives a PFCP Association Setup Request containing an oversized FQDN (~60KB) in the Node ID IE. The `pfcp_node_id_ie::load_from` function allocates a variable-length array (VLA) on the stack sized by the attacker-controlled length field, and the VLA allocation exceeds the available stack space.",
      "root_cause": "`CWE-121`:\n\nThe vulnerability is in the Node ID IE parsing. The `pfcp_node_id_ie::load_from` function allocates a variable-length array on the stack using the attacker-controlled `check_length` field from the FQDN Node ID IE. When this length is set to a large value (~60KB), the VLA allocation exceeds the available stack space, causing a stack overflow and segmentation fault that crashes the UPF process.\n\nSource (real vulnerable code):\nIssue report: [#28](",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: src/pfcp/3gpp_29.244.hpp (commit 74d8ed9a)\nvoid pfcp_node_id_ie::load_from(std::istream& is) {\n  is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));\n  uint16_t check_length = tlv.get_length() - 1;\n  switch (u1.bf.node_id_type) {\n    // ...\n    case pfcp::NODE_ID_TYPE_FQDN: {\n      if (check_length == 0) {\n        throw pfcp_tlv_bad_length_exception(...);\n      }\n      char e[check_length];  // VLA on stack - attacker controls 'check_length'\n      is.read(e, check_length);  // stack overflow when check_length >> stack size\n      std::string dot = {};\n      dot.assign(e, check_length);\n      pfcp_ie::dotted_to_string(dot, fqdn);\n    } break;\n  }\n}"
        }
      ],
      "issue_url": "https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/issues/28",
      "rel_path": "vendor/oai/pfcp/PB1/CVE_2026_36880",
      "cwe": "CWE-121 Stack-based Buffer Overflow",
      "affected_version": "74d8ed9a5e2475816225a3999de42dd36f243587",
      "anchor": "oai-pfcp-cve_2026_36880",
      "cve": "CVE-2026-36880"
    },
    {
      "id": "CVE-2026-36882",
      "dir_name": "CVE_2026_36882",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "CVE-2026-36882: Reachable Assertion: SEID 0xFFFFFFFFFFFFFFFF Triggers AtomicHashMap Assertion Failure",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "OAI-cn-5g UPF terminates due to an assertion failure when it receives a PFCP Session Modification Request with SEID set to `0xFFFFFFFFFFFFFFFF`. This value conflicts with `folly::AtomicHashMap`'s reserved `emptyKey` sentinel, triggering a `DCHECK(key != kEmptyKey_)` assertion failure in the session lookup that crashes the process.",
      "root_cause": "`CWE-617`:\n\nThe vulnerability is in the SEID lookup path. When a PFCP Session Modification Request arrives with SEID `0xFFFFFFFFFFFFFFFF`, the UPF performs a lookup in a `folly::AtomicHashMap` that reserves this value as its internal `emptyKey` sentinel. Using the sentinel value as a lookup key triggers a `DCHECK(key != kEmptyKey_)` assertion failure, which terminates the UPF process.\n\nSource (real vulnerable code):\nIssue report: [#31](",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: src/upf_app/simpleswitch/pfcp_switch.cpp (commit 74d8ed9a)\nbool pfcp_switch::get_pfcp_session_by_up_seid(\n    const uint64_t cp_seid,\n    std::shared_ptr<pfcp::pfcp_session>& session) const {\n  folly::AtomicHashMap<uint64_t, std::shared_ptr<pfcp::pfcp_session>>::\n      const_iterator sit = up_seid2pfcp_sessions.find(cp_seid);\n  // ^ SEID=0xFFFFFFFFFFFFFFFF conflicts with folly::AtomicHashMap's\n  //   reserved emptyKey, causing assertion failure or undefined behavior\n  if (sit == up_seid2pfcp_sessions.end()) {\n    return false;\n  }\n  session = sit->second;\n  return true;\n}"
        }
      ],
      "issue_url": "https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/issues/31",
      "rel_path": "vendor/oai/pfcp/PB1/CVE_2026_36882",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "74d8ed9a5e2475816225a3999de42dd36f243587",
      "anchor": "oai-pfcp-cve_2026_36882",
      "cve": "CVE-2026-36882"
    },
    {
      "id": "CVE-2026-36885",
      "dir_name": "CVE_2026_36885",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB2",
      "pattern_display": "Invalid State",
      "title": "CVE-2026-36885: Out-of-bounds Read: Removing All Uplink PDRs Crashes UPF",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "OAI-cn-5g UPF crashes when it processes a Session Modification Request that removes all uplink PDRs and only adds a downlink PDR. The `modifyBpfSession` function unconditionally accesses `pdrs_uplink[0]` on the now-empty vector without checking whether uplink PDRs exist, causing an out-of-bounds read that terminates the process.",
      "root_cause": "`CWE-125`:\n\nThe vulnerability is in the session manager's PDR update logic. When a PFCP Session Modification Request removes all uplink PDRs, the `pdrs_uplink` vector becomes empty. However, the code unconditionally accesses `pdrs_uplink[0]` without checking whether the vector is empty, causing an out-of-bounds read that crashes the UPF process.\n\nSource (real vulnerable code):\nIssue report: [#34](",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: src/upf_app/SessionManager.cpp (commit 74d8ed9a)\nvoid SessionManager::updateBPFSession(\n    std::shared_ptr<pfcp::pfcp_session> pSession, ...) {\n  // ...\n  if (pdrs_uplink_size != pSession->pdrs_uplink.size()) {\n    std::sort(\n        pSession->pdrs_uplink.begin(), pSession->pdrs_uplink.end(),\n        SessionManager::comparePDR);\n    auto pdrHighPrecedenceUl = pSession->pdrs_uplink[0];\n    // ^ Out-of-bounds access: pdrs_uplink is empty after removing all\n    //   uplink PDRs but code unconditionally accesses index [0]\n  }\n}"
        }
      ],
      "issue_url": "https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/issues/34",
      "rel_path": "vendor/oai/pfcp/PB2/CVE_2026_36885",
      "cwe": "CWE-125 Out-of-bounds Read",
      "affected_version": "74d8ed9a5e2475816225a3999de42dd36f243587",
      "anchor": "oai-pfcp-cve_2026_36885",
      "cve": "CVE-2026-36885"
    },
    {
      "id": "CVE-2025-66778",
      "dir_name": "CVE_2025_66778",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB3",
      "pattern_display": "Invalid Reference",
      "title": "Use After Free: PDR References Non-Existent FAR Causes Dangling Pointer Dereference",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "OAI-cn-5g UPF crashes due to a use-after-free when it receives a PFCP Session Establishment Request containing a CreatePDR that references a non-existent FAR ID (9999). Session creation fails and the session object is deleted, but `call_datapath()` still dereferences the freed session pointer, causing a use-after-free crash.",
      "root_cause": "`CWE-416`:\n\nThe vulnerability lies in the order of operations during session establishment. When a PFCP Session Establishment Request contains a PDR referencing a non-existent FAR ID, the session creation fails validation and the session object is deleted. However, `call_datapath()` is still invoked with the now-dangling pointer to the freed session, causing a use-after-free crash in the BPF datapath.\n\nSource (real vulnerable code):\nIssue report: [#25](",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: src/upf_app/SessionManager.cpp (commit 74d8ed9a)\nbool SessionManager::extractFar(\n    std::shared_ptr<pfcp::pfcp_pdr> pdr,\n    std::shared_ptr<pfcp::pfcp_session> session,\n    std::shared_ptr<pfcp::pfcp_far>& outFar) {\n  pfcp::far_id_t farId;\n  return (pdr->get(farId) && session->get(farId.far_id, outFar));\n  // ^ FAR ID 9999 not found → session creation fails → session deleted\n  //   but call_datapath() still uses the dangling pointer\n}"
        }
      ],
      "issue_url": "https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/issues/25",
      "rel_path": "vendor/oai/pfcp/PB3/CVE_2025_66778",
      "cve": "CVE-2025-66778",
      "cwe": "CWE-416: Use After Free",
      "affected_version": "74d8ed9a5e2475816225a3999de42dd36f243587",
      "anchor": "oai-pfcp-cve_2025_66778"
    },
    {
      "id": "CVE-2026-36884",
      "dir_name": "CVE_2026_36884",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB3",
      "pattern_display": "Invalid Reference",
      "title": "CVE-2026-36884: Improper Input Validation: Duplicate PDR Enables Traffic Interception via Precedence Manipulation",
      "target": "UPF",
      "crash_type": "Session Hijacking",
      "description": "OAI-cn-5g UPF accepts a Session Modification Request that creates a duplicate PDR with higher priority (Precedence=10) alongside an existing uplink PDR (Precedence=100). Because PDRs with smaller Precedence values are matched first, the UPF silently forwards traffic to the attacker-controlled FAR destination instead of the legitimate one, enabling traffic interception without any validation or rejection of the conflicting PDR.",
      "root_cause": "`CWE-20`:\n\nThe vulnerability is in the PDR matching and insertion logic. The UPF sorts PDRs by precedence value (lower value = higher priority) and uses the first matching PDR. An attacker can inject a malicious PDR with a lower precedence value and a corresponding FAR that forwards traffic to an attacker-controlled destination. The UPF does not validate duplicate PDR IDs or enforce authorization checks on Session Modification requests, allowing traffic interception.\n\nSource (real vulnerable code):\nIssue report: [#33](",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: src/upf_app/simpleswitch/pfcp_pdr.hpp (commit 74d8ed9a)\nclass pfcp_pdr {\n  // For sorting in collections\n  bool operator<(const pfcp_pdr& rhs) const {\n    return (precedence.second.precedence < rhs.precedence.second.precedence);\n    // ^ Only compares precedence, does not check for duplicate PDR IDs\n  }\n};\n\n// file: src/upf_app/simpleswitch/pfcp_switch.cpp (commit 74d8ed9a)\nvoid pfcp_switch::add_pfcp_dl_pdr_by_ue_ip(\n    const uint32_t ue_ip, std::shared_ptr<pfcp::pfcp_pdr>& pdr) {\n  // ...\n  for (auto it = pdrs->begin(); it < pdrs->end(); ++it) {\n    if (*(it->get()) < *(pdr.get())) {\n      pit->second->insert(it, pdr);  // Malicious PDR inserted before legitimate one\n      return;\n    }\n  }\n}"
        }
      ],
      "issue_url": "https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/issues/33",
      "rel_path": "vendor/oai/pfcp/PB3/CVE_2026_36884",
      "cwe": "CWE-20 Improper Input Validation",
      "affected_version": "74d8ed9a5e2475816225a3999de42dd36f243587",
      "anchor": "oai-pfcp-cve_2026_36884",
      "cve": "CVE-2026-36884"
    },
    {
      "id": "CVE-2025-66779",
      "dir_name": "CVE_2025_66779",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "DL PDR Count Exceeds 32: Out-of-Bounds Write via Unbounded PDR Vector",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "OAI-cn-5g UPF crashes when the number of downlink PDRs in a session exceeds the internal limit of 32. The UPF does not enforce a size check on the PDR vector during Session Modification, so repeated additions of downlink PDRs grow the vector past `PFCP_SWITCH_MAX_PDRS`, causing memory corruption or an uncaught exception that terminates the process.",
      "root_cause": "`CVE-2025-66779`:\n\nThe UPF stores downlink PDRs in an unbounded vector indexed by UE IP. When a Session Modification adds a new PDR, the insertion path in `add_pfcp_dl_pdr_by_ue_ip()` never checks the vector size against `PFCP_SWITCH_MAX_PDRS` (32). An attacker who repeatedly adds downlink PDRs via Session Modification Requests can grow the vector past the assumed maximum, causing an out-of-bounds write or an uncaught exception that crashes the UPF.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: src/upf_app/simpleswitch/pfcp_switch.cpp (commit 74d8ed9a)\nvoid pfcp_switch::add_pfcp_dl_pdr_by_ue_ip(\n    const uint32_t ue_ip, std::shared_ptr<pfcp::pfcp_pdr>& pdr) {\n  std::vector<std::shared_ptr<pfcp::pfcp_pdr>>* pdrs = pit->second.get();\n  for (auto it = pdrs->begin(); it < pdrs->end(); ++it) {\n    if (*(it->get()) < *(pdr.get())) {\n      pit->second->insert(it, pdr);\n      // ^ No size limit check against PFCP_SWITCH_MAX_PDRS\n      //   Vector grows unbounded, causing OOB write or exception\n      return;\n    }\n  }\n}"
        }
      ],
      "issue_url": "https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/issues/26",
      "rel_path": "vendor/oai/pfcp/PC1/CVE_2025_66779",
      "cve": "CVE-2025-66779",
      "cwe": "CWE-787 Out-of-bounds Write/CWE-248: Uncaught Exception",
      "affected_version": "74d8ed9a5e2475816225a3999de42dd36f243587",
      "anchor": "oai-pfcp-cve_2025_66779"
    },
    {
      "id": "CVE-2026-36883",
      "dir_name": "CVE_2026_36883",
      "vendor": "oai",
      "vendor_display": "OpenAirInterface",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "CVE-2026-36883: SEID Exhaustion: Unbounded Session Map Causes Memory Exhaustion",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "OAI-cn-5g UPF creates a new session entry in the `mSeidToSession` map for every incoming PFCP Session Establishment Request without enforcing any limit on the number of sessions. When it receives a stream of requests with extreme SEID values (near `0xFFFFFFFFFFFFFFFF`), memory consumption grows without bound until the UPF process is killed by the OS or becomes unresponsive.",
      "root_cause": "`CVE-2026-36883`:\n\nThe UPF's `SessionManager` stores every established session in an `std::unordered_map` keyed by SEID. There is no maximum session count, no eviction policy, and no rate limiting on session creation. An attacker can send a stream of Session Establishment Requests with arbitrary SEID values, each allocating a new session object and map entry, growing memory consumption without bound until the UPF process is killed by the OS or becomes unresponsive.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "cpp",
          "code": "// file: src/upf_app/SessionManager.cpp (commit 74d8ed9a)\nvoid SessionManager::createBPFSession(\n    std::shared_ptr<pfcp::pfcp_session> pSession_establishment, ...) {\n  // ...\n  createSessionDirection(pSession_establishment, pdrs_uplink, \"Uplink\");\n  createSessionDirection(pSession_establishment, pdrs_downlink, \"Downlink\");\n\n  mSeidToSession[seid] = pSession_establishment;\n  // ^ Map grows without limit. No eviction policy, no maximum session count.\n  //   Attacker can create arbitrary number of sessions, exhausting memory.\n}"
        }
      ],
      "issue_url": "https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/issues/32",
      "rel_path": "vendor/oai/pfcp/PC1/CVE_2026_36883",
      "cwe": "CWE-770 Allocation of Resources Without Limits or Throttling",
      "affected_version": "74d8ed9a5e2475816225a3999de42dd36f243587",
      "anchor": "oai-pfcp-cve_2026_36883",
      "cve": "CVE-2026-36883"
    },
    {
      "id": "CVE-2025-15418",
      "dir_name": "CVE_2025_15418",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2025-15418: Malformed Bearer QoS IE Crash",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash when it receives a GTPv2-C Create Session Request containing a Bearer Context with a Bearer QoS IE whose length field is invalid (7 bytes instead of the required 22). The malformed length reaches an assert-based parser path in `ogs_gtp2_parse_bearer_qos()`, which triggers `ogs_abort()` and terminates the SGW-C process.",
      "root_cause": "`CVE-2025-15418`:\n\nOpen5GS v2.7.6 SGW-C's `ogs_gtp2_parse_bearer_qos()` contains a hard assertion `ogs_assert(octet->len == GTP2_BEARER_QOS_LEN)` that triggers `ogs_abort()` when the Bearer QoS IE length doesn't match the expected 22 bytes, causing remote DoS.\n\nSource (real vulnerable code):\nIssue report:\n\nBearer QoS parser assert in `ogs_gtp2_parse_bearer_qos()` (v2.7.6):\n\nS11 handler assertion in `sgwc_s11_handle_create_session_request()` (v2.7.6):\n\nAssert macro abort path:\n\nRelated fix commit:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s11-handler.c (v2.7.6)\nvoid sgwc_s11_handle_create_session_request(\n        sgwc_sess_t *sess, ogs_gtp2_message_t *message)\n{\n    for (i = 0; i < OGS_BEARER_PER_UE; i++) {\n        if (req->bearer_contexts_to_be_created[i].bearer_level_qos.presence == 0) {\n            ogs_error(\"No Bearer QoS\");\n            break;\n        }\n\n        decoded = ogs_gtp2_parse_bearer_qos(&bearer_qos,\n                &req->bearer_contexts_to_be_created[i].bearer_level_qos);\n        ogs_assert(decoded ==\n                req->bearer_contexts_to_be_created[i].bearer_level_qos.len);\n        // ^ no length validation before parser assert path\n    }\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/gtp/v2/types.c (v2.7.6)\nint16_t ogs_gtp2_parse_bearer_qos(\n        ogs_gtp2_bearer_qos_t *bearer_qos, ogs_tlv_octet_t *octet)\n{\n    ogs_assert(bearer_qos);\n    ogs_assert(octet);\n    ogs_assert(octet->len == GTP2_BEARER_QOS_LEN);\n    // ^ malformed IE length triggers reachable assert → ogs_abort()\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/core/ogs-log.h (v2.7.6)\n#define ogs_assert(expr) \\\n    do { \\\n        if (ogs_likely(expr)) ; \\\n        else { \\\n            ogs_fatal(\"%s: Assertion `%s' failed.\", OGS_FUNC, #expr); \\\n            ogs_abort(); \\\n            // ^ process abort on assert failure\n        } \\\n    } while(0)"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4217",
      "rel_path": "vendor/open5gs/gtp-c/PA1/CVE_2025_15418",
      "cve": "CVE-2025-15418",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2025_15418"
    },
    {
      "id": "CVE-2026-2517",
      "dir_name": "CVE_2026_2517",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2026-2517: TFT Length Validation Failure Crash",
      "target": "SMF",
      "crash_type": "Denial of Service",
      "description": "Open5GS SMF will crash when it receives a GTPv2-C Bearer Resource Command containing a malformed Traffic Flow Template (TFT) IE whose packet filter content length field is set to 255, far exceeding the actual data provided (9 bytes). The TFT parser in `ogs_gtp2_parse_tft()` enters a while loop bounded by this inflated length, reads beyond the buffer, and triggers an assertion failure that terminates the SMF process.",
      "root_cause": "`CVE-2026-2517`:\n\nOpen5GS v2.7.6 SMF's `ogs_gtp2_parse_tft()` uses the attacker-controlled `pf[i].content.length` field to bound a while loop without first validating it against the remaining buffer size. When the length exceeds the actual data, the loop reads out of bounds and triggers a reachable assertion, causing remote DoS.\n\nSource (real vulnerable code):\nIssue report:\n[",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/gtp/v2/types.c (v2.7.6)\nwhile(len < tft->pf[i].content.length) {\n    // Multiple assertions check bounds\n    ogs_assert(size+len+sizeof(...) <= octet->len);\n    ...\n}\n// ^ pf[i].content.length is read directly from the network packet\n// with no validation against remaining buffer size, triggering\n// assertion failure when length exceeds actual data"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4281",
      "rel_path": "vendor/open5gs/gtp-c/PA1/CVE_2026_2517",
      "cve": "CVE-2026-2517",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_2517",
      "cwe": "CWE-125: Out-of-bounds Read"
    },
    {
      "id": "CVE-2026-2521",
      "dir_name": "CVE_2026_2521",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "Vuln-PA1-08: Oversized PAA in CreateSessionResponse (SGW-C)",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with a segmentation fault when it receives a CreateSessionResponse on the S5-C interface containing a PDN Address Allocation (PAA) IE with an inflated length field (200 bytes instead of the maximum 21). The `memcpy` in `sgwc_s5c_handle_create_session_response()` copies the oversized PAA data into the fixed-size `sess->paa` buffer, causing a buffer overflow that terminates the SGW-C process.",
      "root_cause": "`Vuln-PA1-08`:\n\nThe SGW-C fails to validate the length field of the PAA IE before copying its contents into a fixed-size buffer. A malicious PGW can send an oversized PAA IE to trigger a buffer overflow and crash the SGW-C process.\n\nSource (real vulnerable code):\nIssue report:\n[",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s5c-handler.c (v2.7.6)\nvoid sgwc_s5c_handle_create_session_response(\n        sgwc_sess_t *sess, ogs_gtp_xact_t *s5c_xact,\n        ogs_gtp2_message_t *message)\n{\n    int len = rsp->pdn_address_allocation.len;\n    memcpy(&sess->paa, rsp->pdn_address_allocation.data, len);\n    // ^ no bounds check on len; oversized PAA overflows fixed-size buffer\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4282",
      "rel_path": "vendor/open5gs/gtp-c/PA1/CVE_2026_2521",
      "cve": "CVE-2026-2521",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_2521",
      "cwe": "CWE-787: Out-of-bounds Write"
    },
    {
      "id": "CVE-2026-2522",
      "dir_name": "CVE_2026_2522",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "Vuln-PA1-09: Oversized PAA in CreateSessionResponse (MME)",
      "target": "MME",
      "crash_type": "Denial of Service",
      "description": "Open5GS MME will crash with a segmentation fault when it receives a CreateSessionResponse on the S11 interface containing a PDN Address Allocation (PAA) IE with an inflated length (200 bytes instead of the maximum 21). The `memcpy` in `mme_s11_handle_create_session_response()` copies the oversized PAA data into a fixed-size buffer, causing a buffer overflow that terminates the MME process.",
      "root_cause": "`Vuln-PA1-09`:\n\nThe MME fails to validate the length field of the PAA IE before copying its contents into a fixed-size buffer. A malicious SGW can send an oversized PAA IE to trigger a buffer overflow and crash the MME process.\n\nSource (real vulnerable code):\nIssue report:\n[",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/mme/mme-s11-handler.c (v2.7.6)\nvoid mme_s11_handle_create_session_response(\n        mme_ue_t *mme_ue, ogs_gtp_xact_t *xact,\n        ogs_gtp2_message_t *message)\n{\n    int len = rsp->pdn_address_allocation.len;\n    memcpy(&sess->paa, rsp->pdn_address_allocation.data, len);\n    // ^ no bounds check on len; oversized PAA overflows fixed-size buffer\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4283",
      "rel_path": "vendor/open5gs/gtp-c/PA1/CVE_2026_2522",
      "cve": "CVE-2026-2522",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_2522",
      "cwe": "CWE-787: Out-of-bounds Write"
    },
    {
      "id": "CVE-2026-2524",
      "dir_name": "CVE_2026_2524",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2026-2524: MME Bearer QoS Length Assertion in CreateSessionResponse",
      "target": "MME",
      "crash_type": "Denial of Service",
      "description": "Open5GS MME will crash when it receives a CreateSessionResponse on the S11 interface containing a Bearer QoS IE with an invalid length (1 byte instead of the required 22). The parser function `ogs_gtp2_parse_bearer_qos()` asserts that the IE length equals `GTP2_BEARER_QOS_LEN` (22 bytes), and the mismatched length triggers `ogs_abort()`, terminating the MME process.",
      "root_cause": "`CVE-2026-2524`:\n\nThe MME does not validate the length of the Bearer QoS IE before passing it to the parser. The parser function `ogs_gtp2_parse_bearer_qos()` unconditionally asserts that the IE length equals `GTP2_BEARER_QOS_LEN` (22 bytes). A malicious SGW can send a response with a truncated Bearer QoS IE (e.g., 1 byte) to trigger the assertion and crash the MME.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/mme/mme-s11-handler.c (v2.7.6)\nvoid mme_s11_handle_create_session_response(\n        mme_ue_t *mme_ue, ogs_gtp_xact_t *xact,\n        ogs_gtp2_message_t *message)\n{\n    decoded = ogs_gtp2_parse_bearer_qos(&bearer_qos,\n            &rsp->bearer_contexts_created.bearer_level_qos);\n    // ^ calls parser with unchecked IE length\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/gtp/v2/types.c (v2.7.6)\nint16_t ogs_gtp2_parse_bearer_qos(\n        ogs_gtp2_bearer_qos_t *bearer_qos, ogs_tlv_octet_t *octet)\n{\n    ogs_assert(octet->len == GTP2_BEARER_QOS_LEN);\n    // ^ malformed length triggers abort\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4284",
      "rel_path": "vendor/open5gs/gtp-c/PA1/CVE_2026_2524",
      "cve": "CVE-2026-2524",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_2524",
      "cwe": "CWE-617: Reachable Assertion"
    },
    {
      "id": "CVE-2025-15417",
      "dir_name": "CVE_2025_15417",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-15417: Malformed F-TEID in CreateSessionRequest",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash when it receives a CreateSessionRequest containing an S1-U eNB F-TEID IE whose flags byte has V4=0 and V6=0, meaning no IP address is included. The SGW-C handler validates the presence of the F-TEID IE but not its content; when `ogs_gtp2_f_teid_to_ip()` returns `OGS_ERROR` for this invalid input, the return value is wrapped in `ogs_assert()`, which triggers `ogs_abort()` and terminates the SGW-C process. No prior session state is required to trigger this crash.",
      "root_cause": "",
      "code_snippets": [
        {
          "lang": "c",
          "code": "ogs_assert(OGS_OK ==\n    ogs_gtp2_f_teid_to_ip(enb_s1u_teid, &ul_tunnel->remote_ip));"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4203",
      "rel_path": "vendor/open5gs/gtp-c/PA2/CVE_2025_15417",
      "cve": "CVE-2025-15417",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2025_15417"
    },
    {
      "id": "CVE-2025-15419",
      "dir_name": "CVE_2025_15419",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-15419: Orphan CreateBearerResponse PFCP FAR Activate Assert",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash when it processes an orphan CreateBearerResponse on the S11 interface after session establishment. The missing S5-C TEID causes the corresponding PFCP FAR to never be initialized with a FORW apply-action, and the subsequent call to `ogs_pfcp_build_update_far_activate()` hits a fatal assertion on the missing action flag, terminating the SGW-C process.",
      "root_cause": "`CVE-2025-15419`:\n\nWhen SGW-C processes a CreateBearerResponse without a valid S5-C TEID, the corresponding PFCP FAR is never initialized with a FORW apply-action. The subsequent call to build an Update FAR hits a fatal assertion on the missing action flag.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/pfcp/build.c (v2.7.6)\nogs_pkbuf_t *ogs_pfcp_build_update_far_activate(\n        ogs_pfcp_far_t *far)\n{\n    ogs_assert(far->apply_action & OGS_PFCP_APPLY_ACTION_FORW);\n    // ^ FAR not initialized with FORW action when S5-C TEID missing\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4224",
      "rel_path": "vendor/open5gs/gtp-c/PA2/CVE_2025_15419",
      "cve": "CVE-2025-15419",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2025_15419"
    },
    {
      "id": "CVE-2026-1586",
      "dir_name": "CVE_2026_1586",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-1586: Malformed F-TEID in ModifyBearerRequest",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash when it receives a ModifyBearerRequest containing an S1-U eNB F-TEID IE whose flags byte has both V4 and V6 set to 0, meaning no valid IP address is included. The SGW-C handler validates the presence of the F-TEID IE but not its flags content; when `ogs_gtp2_f_teid_to_ip()` returns `OGS_ERROR` for this invalid input, the return value is wrapped in `ogs_assert()`, which triggers `ogs_abort()` and terminates the SGW-C process. An established GTP-C session is required before this crash can be triggered.",
      "root_cause": "`CVE-2026-1586`:\n\nThe SGW-C's S11 handler validates the presence of the S1-U eNB F-TEID IE but not its content. When a ModifyBearerRequest arrives with a F-TEID whose flags indicate neither IPv4 nor IPv6, `ogs_gtp2_f_teid_to_ip()` fails and the assertion crashes the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s11-handler.c:540 (v2.7.6)\nogs_assert(OGS_OK ==\n    ogs_gtp2_f_teid_to_ip(enb_s1u_teid, &remote_ip));\n// ^ returns OGS_ERROR when F-TEID flags byte has V4=0 and V6=0"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4273",
      "rel_path": "vendor/open5gs/gtp-c/PA2/CVE_2026_1586",
      "cve": "CVE-2026-1586",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_1586",
      "cwe": "CWE-476: NULL Pointer Dereference"
    },
    {
      "id": "CVE-2026-2062",
      "dir_name": "CVE_2026_2062",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-2062: OI Flag Uninitialized PGW S5U Address Crash",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash when it receives a CreateSessionRequest with the OI (Operation Indication) flag set. In this code path, the SGW-C sends a ModifyBearerRequest to the PGW instead of a CreateSessionRequest. When the PGW responds, the SGW-C does not parse the Bearer Context from the ModifyBearerResponse, leaving `ul_tunnel->remote_ip` uninitialized. The crash occurs when the SGW-C builds the CreateSessionResponse, because `ogs_gtp2_ip_to_f_teid()` fails on the zeroed address and the assertion aborts the process.",
      "root_cause": "`CVE-2026-2062`:\n\nWhen the OI flag is set in a CreateSessionRequest, the SGW-C takes an alternate code path that sends a ModifyBearerRequest to the PGW. The handler for the ModifyBearerResponse does not parse the Bearer Context IE, so the uplink tunnel's remote IP is never populated. When the SGW-C later builds the CreateSessionResponse, `ogs_gtp2_ip_to_f_teid()` fails on the zeroed address and the assertion aborts the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s5c-handler.c (v2.7.6)\nvoid sgwc_s5c_handle_modify_bearer_response(\n        sgwc_sess_t *sess, ogs_gtp_xact_t *xact,\n        ogs_gtp2_message_t *message)\n{\n    // Does NOT parse Bearer Context from ModifyBearerResponse\n    // ul_tunnel->remote_ip is never initialized from PGW response\n}"
        },
        {
          "lang": "c",
          "code": "// file: src/sgwc/s11-build.c (v2.7.6)\nogs_pkbuf_t *sgwc_s11_build_create_session_response(\n        sgwc_sess_t *sess)\n{\n    rv = ogs_gtp2_ip_to_f_teid(&ul_tunnel->remote_ip, ...);\n    ogs_assert(rv == OGS_OK);\n    // ^ fails because remote_ip has no IPv4 or IPv6\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4257",
      "rel_path": "vendor/open5gs/gtp-c/PA2/CVE_2026_2062",
      "cve": "CVE-2026-2062",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_2062",
      "cwe": "CWE-476: NULL Pointer Dereference"
    },
    {
      "id": "CVE-2026-2523",
      "dir_name": "CVE_2026_2523",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2026-2523: Missing End User Address in CreatePDPContextRequest",
      "target": "SMF/PGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SMF/PGW-C will crash when it receives a GTPv1-C CreatePDPContextRequest on the Gn interface without the End User Address (EUA) IE. The SMF's mandatory IE checks pass because EUA is not in the initial check list, but the handler later dereferences the NULL EUA pointer and hits `ogs_assert(eua)`, which triggers `ogs_abort()` and terminates the SMF process.",
      "root_cause": "`CVE-2026-2523`:\n\nThe SMF's Gn interface handler does not properly validate the presence of the End User Address IE before attempting to dereference it. When a CreatePDPContextRequest arrives without this IE, the NULL pointer dereference and assertion crash the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/smf/gn-handler.c (v2.7.6)\nvoid smf_gn_handle_create_pdp_context_request(\n        smf_sess_t *sess, ogs_gtp_xact_t *xact,\n        ogs_gtp1_message_t *message)\n{\n    ogs_gtp1_tlv_octet_t *eua =\n        &req->end_user_address;\n    ogs_assert(eua);\n    // ^ NULL when End User Address IE is missing from request\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4285",
      "rel_path": "vendor/open5gs/gtp-c/PA2/CVE_2026_2523",
      "cve": "CVE-2026-2523",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_2523",
      "cwe": "CWE-476: NULL Pointer Dereference"
    },
    {
      "id": "CVE-2025-15530",
      "dir_name": "CVE_2025_15530",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "CVE-2025-15530: CreateIndirectDataForwardingTunnelRequest with Invalid EBI",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives a CreateIndirectDataForwardingTunnelRequest containing an EPSBearerID that does not match any bearer in the established session. The bearer lookup via `sgwc_bearer_find_by_ue_ebi()` returns NULL for the non-existent EBI, and the unconditional `ogs_assert(bearer)` aborts the process.",
      "root_cause": "`Vuln-PB1-01`:\n\nAn invalid EPSBearerID value (e.g., 99) in a CreateIndirectDataForwardingTunnelRequest causes the bearer lookup to return NULL. The code asserts on the bearer pointer without a NULL check, crashing the SGW-C process.\n\nSource (real vulnerable code):\nIssue report: [#4231](",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s11-handler.c (v2.7.6)\nvoid sgwc_s11_handle_create_indirect_data_forwarding_tunnel_request(\n        sgwc_sess_t *sess, ogs_gtp_xact_t *xact,\n        ogs_gtp2_message_t *message)\n{\n    // ...\n    bearer = sgwc_bearer_find_by_ue_ebi(sgwc_ue,\n                req->bearer_contexts[i].eps_bearer_id.u8);\n    ogs_assert(bearer);\n    // ^ crashes when EPSBearerID does not exist in the session (returns NULL)\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4231",
      "rel_path": "vendor/open5gs/gtp-c/PB1/CVE_2025_15530",
      "cve": "CVE-2025-15530",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2025_15530",
      "cwe": "CWE-617: Reachable Assertion"
    },
    {
      "id": "CVE-2026-1587",
      "dir_name": "CVE_2026_1587",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "Vuln-PB1-18: ModifyBearerRequest After Invalid PDN Type",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C (v2.7.6) will crash when its session state is poisoned by a CreateSessionResponse containing an invalid PDN type (type 4, only types 1-3 are valid) in the PAA IE, and a subsequent ModifyBearerRequest is received from the MME. The SGW-C accepts and stores the invalid PDN type during session establishment, and when it later processes the modify bearer request, it hits `ogs_assert_if_reached()` at the unrecognized session_type switch case, aborting the process.",
      "root_cause": "`Vuln-PB1-18`:\n\nAn invalid PDN type value (4) is accepted and stored in the session state during CreateSessionResponse processing. When a subsequent ModifyBearerRequest is processed, the switch statement in the handler encounters the poisoned invalid session_type value and triggers an assertion failure, crashing the SGW-C process.\n\nSource (real vulnerable code):\nIssue report: [#4272](",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s11-handler.c (v2.7.6)\nvoid sgwc_s11_handle_modify_bearer_request(\n        sgwc_sess_t *sess, ogs_gtp_xact_t *xact,\n        ogs_gtp2_message_t *message)\n{\n    switch (sess->session_type) {\n    case OGS_PDN_TYPE_IPV4:\n        // ...\n    case OGS_PDN_TYPE_IPV6:\n        // ...\n    case OGS_PDN_TYPE_IPV4V6:\n        // ...\n    default:\n        ogs_assert_if_reached();\n        // ^ reached when session_type is poisoned (e.g., 4) by invalid PAA\n    }\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4272",
      "rel_path": "vendor/open5gs/gtp-c/PB1/CVE_2026_1587",
      "cve": "CVE-2026-1587",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_1587",
      "cwe": "CWE-20: Improper Input Validation"
    },
    {
      "id": "CVE-2026-1736",
      "dir_name": "CVE_2026_1736",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "Vuln-PB1-20: CreateIndirectDataForwardingTunnelRequest After Invalid PDN Type",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C (v2.7.6) will crash when its session state is poisoned by a CreateSessionResponse containing an invalid PDN type (type 4) in the PAA IE, and a subsequent CreateIndirectDataForwardingTunnelRequest is received from the MME. The SGW-C accepts and stores the invalid PDN type during session establishment, and when it later processes the forwarding tunnel request, it hits `ogs_assert_if_reached()` at the unrecognized session_type switch case, aborting the process.",
      "root_cause": "`Vuln-PB1-20`:\n\nAn invalid PDN type value (4) is accepted and stored in the session state during CreateSessionResponse processing. When a subsequent CreateIndirectDataForwardingTunnelRequest is processed, the switch statement in the handler encounters the poisoned invalid session_type value and triggers an assertion failure, crashing the SGW-C process.\n\nSource (real vulnerable code):\nIssue report: [#4270](",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s11-handler.c (v2.7.6)\nvoid sgwc_s11_handle_create_indirect_data_forwarding_tunnel_request(\n        sgwc_sess_t *sess, ogs_gtp_xact_t *xact,\n        ogs_gtp2_message_t *message)\n{\n    switch (sess->session_type) {\n    case OGS_PDN_TYPE_IPV4:\n        // ...\n    case OGS_PDN_TYPE_IPV6:\n        // ...\n    case OGS_PDN_TYPE_IPV4V6:\n        // ...\n    default:\n        ogs_error(\"Invalid session_type [%d]\", sess->session_type);\n        ogs_assert_if_reached();\n        // ^ reached when session_type is poisoned (e.g., 4) by invalid PAA\n    }\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4270",
      "rel_path": "vendor/open5gs/gtp-c/PB1/CVE_2026_1736",
      "cve": "CVE-2026-1736",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_1736",
      "cwe": "CWE-20: Improper Input Validation"
    },
    {
      "id": "CVE-2026-1737",
      "dir_name": "CVE_2026_1737",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "Vuln-PB1-19: CreateBearerResponse After Invalid PDN Type",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C (v2.7.6) will crash when its session state is poisoned by a CreateSessionResponse containing an invalid PDN type (type 4) in the PAA IE, and a subsequent CreateBearerRequest is received from the PGW. The SGW-C accepts and stores the invalid PDN type during session establishment, and when it later processes the bearer creation request, it hits `ogs_assert_if_reached()` at the unrecognized session_type switch case in the S5-C handler, aborting the process.",
      "root_cause": "`Vuln-PB1-19`:\n\nAn invalid PDN type value (4) is accepted and stored in the session state during CreateSessionResponse processing. When a subsequent CreateBearerRequest is received from the PGW, the switch statement in the S5-C handler encounters the poisoned invalid session_type value and triggers an assertion failure, crashing the SGW-C process.\n\nSource (real vulnerable code):\nIssue report: [#4271](",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s5c-handler.c (v2.7.6)\nvoid sgwc_s5c_handle_create_bearer_request(\n        sgwc_sess_t *sess, ogs_gtp_xact_t *xact,\n        ogs_gtp2_message_t *message)\n{\n    switch (sess->session_type) {\n    case OGS_PDN_TYPE_IPV4:\n        // ...\n    case OGS_PDN_TYPE_IPV6:\n        // ...\n    case OGS_PDN_TYPE_IPV4V6:\n        // ...\n    default:\n        ogs_assert_if_reached();\n        // ^ reached when session_type is poisoned (e.g., 4) by invalid PAA\n    }\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4271",
      "rel_path": "vendor/open5gs/gtp-c/PB1/CVE_2026_1737",
      "cve": "CVE-2026-1737",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_1737",
      "cwe": "CWE-20: Improper Input Validation"
    },
    {
      "id": "CVE-2025-15529",
      "dir_name": "CVE_2025_15529",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB2",
      "pattern_display": "Invalid State",
      "title": "CVE-2025-15529: Delayed S5-C CreateSessionResponse Missing S11 Transaction",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives a CreateSessionResponse on the S5-C interface after the corresponding S11 transaction has already timed out. The associated S11 transaction pointer becomes NULL, and the unconditional `ogs_assert(s11_xact)` aborts the process.",
      "root_cause": "`CVE-2025-15529`:\n\nWhen the PGW delays its CreateSessionResponse long enough for the S11 transaction between MME and SGW-C to time out, the associated S11 transaction pointer becomes NULL. SGW-C unconditionally asserts on this pointer when processing the late S5-C response, crashing the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s5c-handler.c (v2.7.6)\nvoid sgwc_s5c_handle_create_session_response(\n        sgwc_sess_t *sess, ogs_gtp_xact_t *s5c_xact,\n        ogs_gtp2_message_t *message)\n{\n    s11_xact = s5c_xact->assoc_xact;\n    ogs_assert(s11_xact);\n    // ^ NULL when S11 transaction already timed out\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4226",
      "rel_path": "vendor/open5gs/gtp-c/PB2/CVE_2025_15529",
      "cve": "CVE-2025-15529",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2025_15529"
    },
    {
      "id": "CVE-2025-15539",
      "dir_name": "CVE_2025_15539",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB2",
      "pattern_display": "Invalid State",
      "title": "Vuln-PB2-05: Delayed DDN Ack After Session Teardown",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives a Downlink Data Notification Acknowledgement after the corresponding session and bearer have already been torn down. The default bearer lookup returns NULL, and the unconditional `ogs_assert(bearer)` aborts the process.",
      "root_cause": "`Vuln-PB2-05`:\n\nThe SGW-C does not validate that the bearer still exists when processing a Downlink Data Notification Ack. If the session is deleted between the DDN and its Ack, the default bearer lookup returns NULL and the unconditional `ogs_assert(bearer)` terminates the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s11-handler.c (v2.7.6)\nvoid sgwc_s11_handle_downlink_data_notification_ack(\n        sgwc_sess_t *sess, ogs_gtp_xact_t *xact,\n        ogs_gtp2_message_t *message)\n{\n    bearer = sgwc_default_bearer_in_sess(sess);\n    ogs_assert(bearer);\n    // ^ NULL when session deleted before DDN Ack arrives\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4230",
      "rel_path": "vendor/open5gs/gtp-c/PB2/CVE_2025_15539",
      "cve": "CVE-2025-15539",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2025_15539",
      "cwe": "CWE-617: Reachable Assertion"
    },
    {
      "id": "CVE-2026-1521",
      "dir_name": "CVE_2026_1521",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB2",
      "pattern_display": "Invalid State",
      "title": "CVE-2026-1521: BearerResourceFailureIndication Stale S11 Transaction",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives a BearerResourceFailureIndication on the S5-C interface after the associated S11 transaction has already timed out. The handler retrieves the S11 transaction via `ogs_gtp_xact_find_by_id()`, which returns NULL for the expired transaction, and the unconditional `ogs_assert(s11_xact)` aborts the process.",
      "root_cause": "**Vuln-PB2-08**: Stale associated transaction lookup in BearerResourceFailureIndication handler causes assertion failure.\n\n**Root Cause**: The handler unconditionally asserts that the associated S11 transaction exists after a lookup by ID. When the S11 transaction has already expired due to a timeout, `ogs_gtp_xact_find_by_id()` returns NULL and the assertion crashes the process.\n\n**Source**: [src/sgwc/s5c-handler.c#L992](",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// src/sgwc/s5c-handler.c:990-992\nogs_assert(s5c_xact);\ns11_xact = ogs_gtp_xact_find_by_id(s5c_xact->assoc_xact_id);\nogs_assert(s11_xact);  // CRASH if s11_xact is NULL"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4268",
      "rel_path": "vendor/open5gs/gtp-c/PB2/CVE_2026_1521",
      "cve": "CVE-2026-1521",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_1521",
      "cwe": "CWE-617: Reachable Assertion"
    },
    {
      "id": "CVE-2026-1522",
      "dir_name": "CVE_2026_1522",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB2",
      "pattern_display": "Invalid State",
      "title": "CVE-2026-1522: ModifyBearerResponse Stale S11 Transaction",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives a ModifyBearerResponse on the S5-C interface after the corresponding S11 transaction has already timed out. The handler looks up the associated S11 transaction by ID, which returns NULL for the expired transaction, and the unconditional `ogs_assert(s11_xact)` aborts the process.",
      "root_cause": "`Vuln-PB2-06`:\n\nThe SGW-C does not validate that the associated S11 transaction still exists when processing a ModifyBearerResponse on the S5c interface. If the S11 transaction times out before the PGW sends its response, `ogs_gtp_xact_find_by_id()` returns NULL and the unconditional `ogs_assert(s11_xact)` terminates the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s5c-handler.c (v2.7.6)\nogs_assert(s5c_xact);\ns11_xact = ogs_gtp_xact_find_by_id(s5c_xact->assoc_xact_id);\nogs_assert(s11_xact);  // CRASH if s11_xact is NULL"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4266",
      "rel_path": "vendor/open5gs/gtp-c/PB2/CVE_2026_1522",
      "cve": "CVE-2026-1522",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_1522",
      "cwe": "CWE-617: Reachable Assertion"
    },
    {
      "id": "CVE-2026-36888",
      "dir_name": "CVE_2026_36888",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB2",
      "pattern_display": "Invalid State",
      "title": "CVE-2026-36888: UpdateBearerResponse After Bearer Deletion",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives an UpdateBearerResponse after the corresponding bearer has already been deleted by a prior DeleteSessionRequest. The bearer lookup via `sgwc_bearer_find_by_id()` returns NULL, and the unconditional `ogs_assert(bearer)` aborts the process.",
      "root_cause": "`CVE-2026-36888`:\n\nWhen SGW-C receives an UpdateBearerResponse, it looks up the bearer by ID. If the bearer has already been deleted by a prior DeleteSessionRequest, the lookup returns NULL and the unconditional assertion crashes the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s11-handler.c (v2.7.6)\nvoid sgwc_s11_handle_update_bearer_response(\n        sgwc_sess_t *sess, ogs_gtp_xact_t *xact,\n        ogs_gtp2_message_t *message)\n{\n    bearer = sgwc_bearer_find_by_id(bearer_id);\n    ogs_assert(bearer);\n    // ^ NULL when bearer deleted by prior DeleteSessionRequest\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4228",
      "rel_path": "vendor/open5gs/gtp-c/PB2/CVE_2026_36888",
      "cve": "CVE-2026-36888",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_36888",
      "cwe": "CWE-617: Reachable Assertion"
    },
    {
      "id": "CVE-2026-36889",
      "dir_name": "CVE_2026_36889",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB2",
      "pattern_display": "Invalid State",
      "title": "CVE-2026-36889: DeleteBearerResponse After Bearer Deletion",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C (v2.7.6) will crash when it receives a stale DeleteBearerResponse for a bearer that has already been deleted. When the PGW initiates a DeleteBearerRequest and the MME deletes the session before sending back the DeleteBearerResponse, the SGW-C attempts to look up the already-deleted bearer, gets a NULL result, and hits an unconditional assertion that aborts the process.",
      "root_cause": "`CVE-2026-36889`:\n\nWhen SGW-C receives a DeleteBearerResponse, it looks up the bearer by ID. If the bearer has already been deleted by a prior DeleteSessionRequest, the lookup returns NULL and the unconditional assertion crashes the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s11-handler.c (v2.7.6)\nvoid sgwc_s11_handle_delete_bearer_response(\n        sgwc_sess_t *sess, ogs_gtp_xact_t *xact,\n        ogs_gtp2_message_t *message)\n{\n    bearer = sgwc_bearer_find_by_id(bearer_id);\n    ogs_assert(bearer);\n    // ^ NULL when bearer deleted by prior DeleteSessionRequest\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4229",
      "rel_path": "vendor/open5gs/gtp-c/PB2/CVE_2026_36889",
      "cve": "CVE-2026-36889",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_36889",
      "cwe": "CWE-617: Reachable Assertion"
    },
    {
      "id": "CVE-2026-36893",
      "dir_name": "CVE_2026_36893",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB2",
      "pattern_display": "Invalid State",
      "title": "CVE-2026-36893: DeleteSessionResponse Stale S11 Transaction",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives a DeleteSessionResponse on the S5-C interface after the corresponding S11 transaction has already timed out. The handler retrieves the associated S11 transaction via `ogs_gtp_xact_find_by_id()`, which returns NULL for the expired transaction, and the unconditional `ogs_assert(s11_xact)` in `sgwc_s5c_handle_delete_session_response` aborts the process.",
      "root_cause": "`CVE-2026-36893`:\n\nWhen SGW-C receives a DeleteSessionResponse on S5-C, it retrieves the associated S11 transaction via `ogs_gtp_xact_find_by_id`. If the S11 transaction has already timed out and been cleaned up, the lookup returns NULL and the unconditional `ogs_assert(s11_xact)` crashes the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s5c-handler.c (v2.7.6)\nvoid sgwc_s5c_handle_delete_session_response(...)\n{\n    ogs_assert(s5c_xact);\n    s11_xact = ogs_gtp_xact_find_by_id(s5c_xact->assoc_xact_id);\n    ogs_assert(s11_xact);\n    // ^ NULL when S11 transaction already timed out\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4267",
      "rel_path": "vendor/open5gs/gtp-c/PB2/CVE_2026_36893",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_36893",
      "cve": "CVE-2026-36893",
      "cwe": "CWE-617: Reachable Assertion"
    },
    {
      "id": "CVE-2025-15528",
      "dir_name": "CVE_2025_15528",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB3",
      "pattern_display": "Invalid Reference",
      "title": "CVE-2025-15528: Orphan CreateBearerResponse sgwc_ue Assert",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives a CreateBearerResponse on the S11 interface after the associated UE context has already been cleaned up. If a DeleteSession occurs between the CreateBearerRequest and the CreateBearerResponse, the `sgwc_ue` lookup returns NULL and the unconditional `ogs_assert(sgwc_ue)` aborts the process.",
      "root_cause": "`CVE-2025-15528`:\n\nWhen SGW-C receives a CreateBearerResponse, it looks up the UE context via the session. If the UE context has already been cleaned up (e.g., by a preceding DeleteSession), the lookup returns NULL and the unconditional assertion crashes the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s11-handler.c (v2.7.6)\nvoid sgwc_s11_handle_create_bearer_response(\n        sgwc_sess_t *sess, ogs_gtp_xact_t *xact,\n        ogs_gtp2_message_t *message)\n{\n    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);\n    ogs_assert(sgwc_ue);\n    // ^ NULL when UE context cleaned up before response arrives\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4225",
      "rel_path": "vendor/open5gs/gtp-c/PB3/CVE_2025_15528",
      "cve": "CVE-2025-15528",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2025_15528"
    },
    {
      "id": "CVE-2026-36894",
      "dir_name": "CVE_2026_36894",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PB3",
      "pattern_display": "Invalid Reference",
      "title": "CVE-2026-36894: UpdateBearerResponse Stale Bearer Context",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives an UpdateBearerResponse via the Bearer Resource Command flow after the corresponding bearer has already been deleted. In the code path where `s11_xact->xid` has the `OGS_GTP_CMD_XACT_ID` flag set, the bearer ID is retrieved from `s5c_xact->data`, but if the bearer was removed by a preceding DeleteSessionRequest, `sgwc_bearer_find_by_id()` returns NULL and the unconditional `ogs_assert(bearer)` at line 1064 in `s11-handler.c` aborts the process.",
      "root_cause": "`CVE-2026-36894`:\n\nIn `sgwc_s11_handle_update_bearer_response()`, there are two code paths for retrieving `bearer_id` depending on whether the transaction originated from a Bearer Resource Command. When the `OGS_GTP_CMD_XACT_ID` flag is set, the bearer ID is read from `s5c_xact->data`. If the bearer was deleted between the original command and the response, `sgwc_bearer_find_by_id()` returns NULL and the unconditional assertion crashes the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/s11-handler.c (v2.7.6)\nif (s11_xact->xid & OGS_GTP_CMD_XACT_ID) {\n    /* Bearer Resource Command flow */\n    ogs_assert(s5c_xact->data);\n    bearer_id = OGS_POINTER_TO_UINT(s5c_xact->data);  // From s5c_xact\n    bearer = sgwc_bearer_find_by_id(bearer_id);\n    ogs_assert(bearer);  // LINE 1064 - CRASH if bearer was deleted\n} else {\n    /* Normal Update Bearer flow */\n    bearer_id = OGS_POINTER_TO_UINT(s11_xact->data);  // From s11_xact\n    bearer = sgwc_bearer_find_by_id(bearer_id);\n    ogs_assert(bearer);  // LINE 1072 - PB3-07 targets this\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4269",
      "rel_path": "vendor/open5gs/gtp-c/PB3/CVE_2026_36894",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_36894",
      "cve": "CVE-2026-36894",
      "cwe": "CWE-617: Reachable Assertion"
    },
    {
      "id": "CVE-2025-15531",
      "dir_name": "CVE_2025_15531",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "Vuln-PC1-04: Bearer Pool Exhaustion Crash",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C (v2.7.6) will crash when it receives a flood of CreateSessionRequests, each containing multiple bearer contexts (up to 11 per request). Once the configured bearer pool limit is exhausted, subsequent bearer allocation attempts return NULL and the SGW-C asserts on the NULL pointer, causing the process to abort.",
      "root_cause": "`Vuln-PC1-04`:\n\nThe SGW-C bearer pool allocation does not gracefully handle exhaustion, instead using an unconditional assertion that crashes the entire process. When the pool reaches its limit, subsequent allocation attempts return NULL and the assertion triggers immediately.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/context.c (v2.7.6)\nsgwc_bearer_t *sgwc_bearer_add(\n        sgwc_sess_t *sess)\n{\n    sgwc_bearer_t *bearer = NULL;\n    bearer = ogs_pool_alloc(&sgwc_bearer_pool, bearer);\n    ogs_assert(bearer);\n    // ^ NULL when bearer pool is exhausted → process abort\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4233",
      "rel_path": "vendor/open5gs/gtp-c/PC1/CVE_2025_15531",
      "cve": "CVE-2025-15531",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2025_15531",
      "cwe": "CWE-400: Uncontrolled Resource Consumption"
    },
    {
      "id": "CVE-2025-15532",
      "dir_name": "CVE_2025_15532",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "CVE-2025-15532: UE Pool Exhaustion via CreateSessionRequest Flood",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives a flood of CreateSessionRequests with unique IMSIs that exhaust the fixed-size UE context pool. Each request allocates a new `sgwc_ue_t` from the pool, and once the pool is full, `ogs_pool_alloc()` returns NULL and the unconditional `ogs_assert(sgwc_ue)` in `sgwc_ue_add()` aborts the process.",
      "root_cause": "`CVE-2025-15532`:\n\nThe SGW-C allocates UE contexts from a fixed-size pool without any limit on the number of concurrent UEs. When an attacker floods the SGW-C with CreateSessionRequests using unique IMSIs, the pool is exhausted and `ogs_pool_alloc()` returns NULL. The unconditional assertion on the result crashes the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/context.c (v2.7.6)\nsgwc_ue_t *sgwc_ue_add(ogs_gtp_node_t *gnode, ...)\n{\n    sgwc_ue_t *sgwc_ue = NULL;\n    ogs_pool_alloc(&sgwc_ue_pool, &sgwc_ue);\n    ogs_assert(sgwc_ue);\n    // ^ NULL when UE pool is exhausted → process abort\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4220",
      "rel_path": "vendor/open5gs/gtp-c/PC1/CVE_2025_15532",
      "cve": "CVE-2025-15532",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2025_15532"
    },
    {
      "id": "CVE-2026-1738",
      "dir_name": "CVE_2026_1738",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "CVE-2026-1738: PDR Pool Exhaustion in sgwc_tunnel_add",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives CreateIndirectDataForwardingTunnelRequests that exhaust the per-session PDR pool. Each tunnel creation allocates a PFCP PDR, and the per-session limit is 16 (`OGS_MAX_NUM_OF_PDR`). Once the pool is full, `ogs_pfcp_pdr_add()` returns NULL and the unconditional assertion in `sgwc_tunnel_add()` aborts the process.",
      "root_cause": "`CVE-2026-1738`:\n\nThe SGW-C allocates a PFCP PDR for each new tunnel created via CreateIndirectDataForwardingTunnelRequest. The per-session PDR ID pool has a fixed limit of 16 entries. When an attacker sends repeated requests that exhaust this pool, `ogs_pfcp_pdr_add()` returns NULL and the unconditional assertion in `sgwc_tunnel_add()` aborts the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/context.c (v2.7.6)\nsgwc_tunnel_t *sgwc_tunnel_add(\n        sgwc_bearer_t *bearer, uint8_t type)\n{\n    ogs_pfcp_pdr_t *pdr = NULL;\n    pdr = ogs_pfcp_pdr_add(&sess->pfcp);\n    ogs_assert(pdr);\n    // ^ NULL when per-session PDR pool (limit 16) is exhausted → process abort\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4261",
      "rel_path": "vendor/open5gs/gtp-c/PC1/CVE_2026_1738",
      "cve": "CVE-2026-1738",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_1738",
      "cwe": "CWE-400: Uncontrolled Resource Consumption"
    },
    {
      "id": "CVE-2026-36892",
      "dir_name": "CVE_2026_36892",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "CVE-2026-36892: PFCP Transaction Pool Exhaustion",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives a flood of CreateSessionRequests on the S11 interface that exhaust the fixed-size PFCP transaction pool. Each request triggers a PFCP Session Establishment Request toward SGW-U, allocating a PFCP transaction. Once the pool is full, `ogs_pool_alloc()` returns NULL and the unconditional `ogs_assert(xact)` aborts the process.",
      "root_cause": "| Vuln ID | Root Cause |\n|---|---|\n| Vuln-PC1-03 | Unbounded PFCP transaction allocation from a fixed-size pool on each CreateSessionRequest, leading to assertion failure on exhaustion. |\n\n**Source**: [`lib/pfcp/xact.c`](",
      "code_snippets": [
        {
          "lang": "c",
          "code": "ogs_pfcp_xact_t *ogs_pfcp_xact_local_create(...)\n{\n    ogs_pfcp_xact_t *xact = NULL;\n    ogs_pool_alloc(&pool, &xact);\n    ogs_assert(xact);  // CRASH when pool exhausted!\n    ...\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4260",
      "rel_path": "vendor/open5gs/gtp-c/PC1/CVE_2026_36892",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_36892",
      "cve": "CVE-2026-36892",
      "cwe": "CWE-400: Uncontrolled Resource Consumption"
    },
    {
      "id": "CVE-2026-36887",
      "dir_name": "CVE_2026_36887",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "CVE-2026-36887: Event Pool Exhaustion via GTPv2-C Flooding",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives a flood of GTPv2-C messages that exhaust the fixed-size event pool. Every incoming message triggers an event allocation via `sgwc_event_new()` regardless of message type or session validity -- no authentication is required. Once the pool is full, `ogs_pool_alloc` returns NULL and the unconditional `ogs_assert(e)` aborts the process.",
      "root_cause": "`CVE-2026-36887`:\n\nThe SGW-C event pool has a fixed size. Each incoming GTPv2-C message allocates an event from this pool without any rate limiting or admission control. Once the pool is exhausted, the assertion on the allocation result terminates the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: src/sgwc/event.c (v2.7.6)\nsgwc_event_t *sgwc_event_new(int id)\n{\n    sgwc_event_t *e = NULL;\n    ogs_pool_alloc(&pool, &e);\n    ogs_assert(e);  // CRASH when pool exhausted\n    ...\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4221",
      "rel_path": "vendor/open5gs/gtp-c/PC1/CVE_2026_36887",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_36887",
      "cve": "CVE-2026-36887"
    },
    {
      "id": "CVE-2026-36891",
      "dir_name": "CVE_2026_36891",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "CVE-2026-36891: GTP Remote Transaction Pool Exhaustion",
      "target": "SGW-C",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGW-C will crash with an assertion failure when it receives a flood of CreateSessionRequests on the S11 interface without the PGW F-TEID IE. Without a PGW destination, the SGW-C only creates remote transactions (no forwarding), each allocating 3 timers from a fixed-size timer pool. The timer pool exhausts before the transaction pool, causing `ogs_timer_add()` to return NULL and the unconditional `ogs_assert(xact->tm_peer)` to abort the process.",
      "root_cause": "`CVE-2026-36891`:\n\nA resource exhaustion vulnerability exists in the SGW-C's GTP transaction handling. When CreateSessionRequests arrive without a PGW F-TEID, the SGW-C creates remote transactions that each consume 3 timers. The timer pool exhausts before the transaction pool, and the NULL return from `ogs_timer_add()` triggers a fatal assertion.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/gtp/xact.c (v2.7.6)\nogs_gtp_xact_t *ogs_gtp_xact_remote_create(\n        ogs_gtp_node_t *gnode, uint8_t org, uint32_t xid)\n{\n    xact->tm_peer = ogs_timer_add(\n            g_timer_manager, ogs_gtp_xact_timeout, xact);\n    ogs_assert(xact->tm_peer);\n    // ^ NULL when timer pool is exhausted\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4259",
      "rel_path": "vendor/open5gs/gtp-c/PC1/CVE_2026_36891",
      "cve": "CVE-2026-36891",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_36891",
      "cwe": "CWE-400: Uncontrolled Resource Consumption"
    },
    {
      "id": "CVE-2026-36890",
      "dir_name": "CVE_2026_36890",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "gtp-c",
      "protocol_display": "GTP-C",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "CVE-2026-36890: Timer Pool Exhaustion via GTPv1-C Flooding",
      "target": "SMF",
      "crash_type": "Denial of Service",
      "description": "Open5GS SMF will crash with an assertion failure when it receives a flood of GTPv1-C messages on the Gn interface that exhaust the fixed-size timer pool. Each incoming message creates a remote transaction that allocates timers, and once the pool is full, `ogs_timer_add()` returns NULL and the unconditional assertion in `ogs_gtp_xact_remote_create()` aborts the process.",
      "root_cause": "`CVE-2026-36890`:\n\nThe SMF creates a remote GTP transaction for every incoming GTPv1-C message, and each transaction allocates timers from a shared fixed-size pool. When an attacker sends messages faster than the SMF can process and free them, the timer pool is exhausted. The `ogs_timer_add()` call returns NULL, and the unconditional assertion on the timer pointer crashes the process.\n\nSource (real vulnerable code):\nIssue report:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/gtp/xact.c (v2.7.6)\nogs_gtp_xact_t *ogs_gtp_xact_remote_create(\n        ogs_gtp_node_t *gnode, uint8_t org, uint32_t xid)\n{\n    xact->tm_holding = ogs_timer_add(\n            g_timer_manager, ogs_gtp_xact_timeout, xact);\n    ogs_assert(xact->tm_holding);\n    // ^ NULL when timer pool is exhausted → process abort\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4235",
      "rel_path": "vendor/open5gs/gtp-c/PC1/CVE_2026_36890",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-gtp-c-cve_2026_36890",
      "cve": "CVE-2026-36890",
      "cwe": "CWE-400: Uncontrolled Resource Consumption"
    },
    {
      "id": "CVE-2025-66783",
      "dir_name": "CVE_2025_66783",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2025-66783: Malformed BitRate IE Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "Open5GS UPF (v2.7.6) crashes when it receives a PFCP `Session Establishment Request` containing a `CreateQER -> MBR (Maximum Bitrate)` IE with an invalid length.\nThe malformed IE reaches an assert-based parser path that terminates the UPF process.",
      "root_cause": "`VULN-J01`:\n\nOpen5GS v2.7.6 accepts `CreateQER/UpdateQER` BitRate IEs and directly calls the bitrate parser without validating IE length first.  \nA malformed MBR can trigger `ogs_assert(octet->len == OGS_PFCP_BITRATE_LEN)` in `ogs_pfcp_parse_bitrate()`, and `ogs_assert` aborts the process, causing remote DoS.\n\nSource (real vulnerable code):  \nIssue report:  \n  \nQER handlers call parser without length validation (v2.7.6):  \n  \n  \nBitRate parser assert (v2.7.6):  \n  \nAssert macro abort path:  \n  \nRelated fix commit:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/pfcp/handler.c (v2.7.6)\nogs_pfcp_qer_t *ogs_pfcp_handle_create_qer(\n        ogs_pfcp_sess_t *sess, ogs_pfcp_tlv_create_qer_t *message,\n        uint8_t *cause_value, uint8_t *offending_ie_value)\n{\n    if (message->maximum_bitrate.presence)\n        ogs_pfcp_parse_bitrate(&qer->mbr, &message->maximum_bitrate);\n    if (message->guaranteed_bitrate.presence)\n        ogs_pfcp_parse_bitrate(&qer->gbr, &message->guaranteed_bitrate);\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/pfcp/types.c (v2.7.6)\nint16_t ogs_pfcp_parse_bitrate(\n        ogs_pfcp_bitrate_t *bitrate, ogs_tlv_octet_t *octet)\n{\n    ogs_assert(bitrate);\n    ogs_assert(octet);\n    ogs_assert(octet->len == OGS_PFCP_BITRATE_LEN);\n    // ^ malformed IE length triggers reachable assert\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/core/ogs-log.h (v2.7.6)\n#define ogs_assert(expr) \\\n    do { \\\n        if (ogs_likely(expr)) ; \\\n        else { \\\n            ogs_fatal(\"%s: Assertion `%s' failed.\", OGS_FUNC, #expr); \\\n            ogs_abort(); \\\n            // ^ process abort on assert failure\n        } \\\n    } while(0)"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4153",
      "rel_path": "vendor/open5gs/pfcp/PA1/CVE_2025_66783",
      "cve": "CVE-2025-66783",
      "cwe": "CWE-617: Reachable Assertion",
      "affected_version": "v2.7.5",
      "anchor": "open5gs-pfcp-cve_2025_66783"
    },
    {
      "id": "CVE-2025-66784",
      "dir_name": "CVE_2025_66784",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA1",
      "pattern_display": "Malformed Field",
      "title": "CVE-2025-66784: Malformed Dropped-DL-Traffic-Threshold IE Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "Open5GS UPF (v2.7.6) crashes when it receives a PFCP `Session Establishment Request` containing a malformed `CreateURR -> Dropped-DL-Traffic-Threshold` IE.\nA decode-size mismatch in the IE drives execution into an assert path that terminates the UPF process.",
      "root_cause": "`VULN-J01`:\n\nOpen5GS v2.7.6 parses `Dropped-DL-Traffic-Threshold` in `CreateURR/UpdateURR` without validating decoded length against IE length at the call site.  \nThe parser ends with `ogs_assert(size == octet->len)`, so malformed data can trigger reachable assert and process abort (remote DoS).\n\nSource (real vulnerable code):  \nIssue report:  \n  \nCreate/Update URR handlers call parser without length check (v2.7.6):  \n  \n  \nDropped-DL parser assert (v2.7.6):  \n  \nAssert macro abort path:  \n  \nRelated fix commit:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/pfcp/handler.c (v2.7.6)\nogs_pfcp_urr_t *ogs_pfcp_handle_create_urr(ogs_pfcp_sess_t *sess,\n        ogs_pfcp_tlv_create_urr_t *message,\n        uint8_t *cause_value, uint8_t *offending_ie_value)\n{\n    if (message->dropped_dl_traffic_threshold.presence) {\n        ogs_pfcp_parse_dropped_dl_traffic_threshold(\n                &urr->dropped_dl_traffic_threshold,\n                &message->dropped_dl_traffic_threshold);\n        // ^ no decoded-length validation before parser assert path\n    }\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/pfcp/types.c (v2.7.6)\nint16_t ogs_pfcp_parse_dropped_dl_traffic_threshold(\n        ogs_pfcp_dropped_dl_traffic_threshold_t *threshold,\n        ogs_tlv_octet_t *octet)\n{\n    // ...\n    ogs_assert(size == octet->len);\n    // ^ malformed IE can reach this assert\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/core/ogs-log.h (v2.7.6)\n#define ogs_assert(expr) \\\n    do { \\\n        if (ogs_likely(expr)) ; \\\n        else { \\\n            ogs_fatal(\"%s: Assertion `%s' failed.\", OGS_FUNC, #expr); \\\n            ogs_abort(); \\\n            // ^ process abort on assert failure\n        } \\\n    } while(0)"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4154",
      "rel_path": "vendor/open5gs/pfcp/PA1/CVE_2025_66784",
      "cve": "CVE-2025-66784",
      "cwe": "CWE-617: Reachable Assertion",
      "affected_version": "v2.7.5",
      "anchor": "open5gs-pfcp-cve_2025_66784"
    },
    {
      "id": "CVE-2025-14953",
      "dir_name": "CVE_2025_14953",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-14953: Missing FAR-ID in CreatePDR Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "Open5GS UPF (v2.7.6) crashes when it accepts a PFCP `Session Establishment Request` with a `CreatePDR` missing the mandatory `FAR-ID` IE, and subsequently receives matching GTP-U traffic.\nThe control path accepts the malformed PDR with `pdr->far == NULL`, and the user-plane fast path later asserts on the `far` dereference, terminating the process.",
      "root_cause": "`VULN-J01`:\n\nOpen5GS v2.7.6 accepted `CreatePDR` without mandatory `FAR-ID` and left `pdr->far` unset (`NULL`).  \nWhen matching traffic arrived, fast path `ogs_pfcp_up_handle_pdr()` executed `ogs_assert(far)` and aborted UPF, causing remote DoS.\n\nSource (real vulnerable code):  \nIssue report:  \n  \nFast-path assert on NULL FAR (v2.7.6):  \n  \nCreatePDR leaves `pdr->far` NULL and only sets it when FAR-ID exists (v2.7.6):  \n  \nAssert macro abort path:  \n  \nRelated fix commit (reject missing FAR-ID in CreatePDR):",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/pfcp/handler.c (v2.7.6)\nbool ogs_pfcp_up_handle_pdr(\n        ogs_pfcp_pdr_t *pdr, uint8_t type,\n        ogs_gtp2_header_desc_t *recvhdr, ogs_pkbuf_t *sendbuf,\n        ogs_pfcp_user_plane_report_t *report)\n{\n    far = pdr->far;\n    ogs_assert(far);\n    // ^ data-path assert when malformed CreatePDR omitted FAR-ID\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/pfcp/handler.c (v2.7.6)\nogs_pfcp_pdr_t *ogs_pfcp_handle_create_pdr(ogs_pfcp_sess_t *sess,\n        ogs_pfcp_tlv_create_pdr_t *message,\n        uint8_t *cause_value, uint8_t *offending_ie_value)\n{\n    pdr->far = NULL;\n    if (message->far_id.presence) {\n        far = ogs_pfcp_far_find_or_add(sess, message->far_id.u32);\n        ogs_assert(far);\n        ogs_pfcp_pdr_associate_far(pdr, far);\n    }\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4179",
      "rel_path": "vendor/open5gs/pfcp/PA2/CVE_2025_14953",
      "cve": "CVE-2025-14953",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.5",
      "anchor": "open5gs-pfcp-cve_2025_14953"
    },
    {
      "id": "CVE-2025-14955",
      "dir_name": "CVE_2025_14955",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-14955: Zero-length F-TEID IE Crash (SGWU)",
      "target": "SGWU",
      "crash_type": "Denial of Service",
      "description": "Open5GS SGWU (v2.7.6) crashes when it receives a PFCP `Session Establishment Request` containing a `CreatePDR -> PDI -> F-TEID` IE with zero length.\nThe zero-length IE reaches an assert path that terminates the SGWU process.",
      "root_cause": "`VULN-J01`:\n\nOpen5GS v2.7.6 `CreatePDR` path copies `PDI.local_f_teid` and directly asserts `pdr->f_teid.ipv4 || pdr->f_teid.ipv6` without first rejecting zero-length F-TEID.  \nWith `len=0`, `pdr->f_teid` remains zeroed and the reachable assert aborts SGWU, causing remote DoS.\n\nSource (real vulnerable code):  \nIssue report:  \n  \nCreatePDR F-TEID assert path (v2.7.6):  \n  \nAlso reachable in CreatedPDR handling (v2.7.6):  \n  \nAssert macro abort path:  \n  \nRelated fix commit:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/pfcp/handler.c (v2.7.6)\nogs_pfcp_pdr_t *ogs_pfcp_handle_create_pdr(ogs_pfcp_sess_t *sess,\n        ogs_pfcp_tlv_create_pdr_t *message,\n        uint8_t *cause_value, uint8_t *offending_ie_value)\n{\n    if (message->pdi.local_f_teid.presence) {\n        pdr->f_teid_len =\n            ogs_min(message->pdi.local_f_teid.len, sizeof(pdr->f_teid));\n        memcpy(&pdr->f_teid, message->pdi.local_f_teid.data, pdr->f_teid_len);\n        ogs_assert(pdr->f_teid.ipv4 || pdr->f_teid.ipv6);\n        // ^ zero-length F-TEID can trigger reachable assert\n    }\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/core/ogs-log.h (v2.7.6)\n#define ogs_assert(expr) \\\n    do { \\\n        if (ogs_likely(expr)) ; \\\n        else { \\\n            ogs_fatal(\"%s: Assertion `%s' failed.\", OGS_FUNC, #expr); \\\n            ogs_abort(); \\\n            // ^ process abort on assert failure\n        } \\\n    } while(0)"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4182",
      "rel_path": "vendor/open5gs/pfcp/PA2/CVE_2025_14955",
      "cve": "CVE-2025-14955",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.5",
      "anchor": "open5gs-pfcp-cve_2025_14955"
    },
    {
      "id": "CVE-2025-66782",
      "dir_name": "CVE_2025_66782",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PA2",
      "pattern_display": "Absent Field",
      "title": "CVE-2025-66782: Zero-length Outer Header Creation IE Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "Open5GS UPF (v2.7.6) crashes when it receives a PFCP `Session Establishment Request` containing a `CreateFAR -> ForwardingParameters -> OuterHeaderCreation` IE with zero length.\nThe zero-length IE triggers an assert path that terminates the UPF process.",
      "root_cause": "`VULN-J01`:\n\nOpen5GS v2.7.6 `CreateFAR/UpdateFAR` handlers assert that `Outer Header Creation` length is non-zero.  \nA zero-length IE reaches `ogs_assert(outer_header_creation->len)`, and `ogs_assert` aborts the process, causing remote DoS.\n\nSource (real vulnerable code):  \nIssue report:  \n  \nCreateFAR zero-length assert path (v2.7.6):  \n  \nUpdateFAR zero-length assert path (v2.7.6):  \n  \nAssert macro abort path:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/pfcp/handler.c (v2.7.6)\nogs_pfcp_far_t *ogs_pfcp_handle_create_far(ogs_pfcp_sess_t *sess,\n        ogs_pfcp_tlv_create_far_t *message,\n        uint8_t *cause_value, uint8_t *offending_ie_value)\n{\n    if (message->forwarding_parameters.outer_header_creation.presence) {\n        ogs_pfcp_tlv_outer_header_creation_t *outer_header_creation =\n            &message->forwarding_parameters.outer_header_creation;\n\n        ogs_assert(outer_header_creation->data);\n        ogs_assert(outer_header_creation->len);\n        // ^ zero-length Outer Header Creation triggers reachable assert\n    }\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/pfcp/handler.c (v2.7.6)\nogs_pfcp_far_t *ogs_pfcp_handle_update_far(ogs_pfcp_sess_t *sess,\n        ogs_pfcp_tlv_update_far_t *message,\n        uint8_t *cause_value, uint8_t *offending_ie_value)\n{\n    if (message->update_forwarding_parameters.outer_header_creation.presence) {\n        ogs_pfcp_tlv_outer_header_creation_t *outer_header_creation =\n            &message->update_forwarding_parameters.outer_header_creation;\n\n        ogs_assert(outer_header_creation->data);\n        ogs_assert(outer_header_creation->len);\n    }\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/core/ogs-log.h (v2.7.6)\n#define ogs_assert(expr) \\\n    do { \\\n        if (ogs_likely(expr)) ; \\\n        else { \\\n            ogs_fatal(\"%s: Assertion `%s' failed.\", OGS_FUNC, #expr); \\\n            ogs_abort(); \\\n            // ^ process abort on assert failure\n        } \\\n    } while(0)"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4152",
      "rel_path": "vendor/open5gs/pfcp/PA2/CVE_2025_66782",
      "cve": "CVE-2025-66782",
      "cwe": "CWE-617: Reachable Assertion",
      "affected_version": "v2.7.5",
      "anchor": "open5gs-pfcp-cve_2025_66782"
    },
    {
      "id": "CVE-2025-65559",
      "dir_name": "CVE_2025_65559",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "CVE-2025-65559: CH F-TEID Address Family Mismatch Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "Open5GS UPF (v2.7.6) crashes when it receives a PFCP `Session Establishment Request` with `F-TEID` set to `CH=1` and IPv4/IPv6 family flags that do not match the selected DNN GTP-U resource.\nThe CH F-TEID generation logic uses assert-based checks that abort the UPF process on address family mismatch.",
      "root_cause": "`VULN-J01`:\n\nOpen5GS v2.7.6 uses assert-based checks in CH F-TEID allocation logic.  \nWhen incoming CH F-TEID family flags do not match UPF resource/local GTP-U address family, reachable asserts can abort the UPF process.\n\nSource (real vulnerable code):  \nIssue report:  \n  \nCH F-TEID family asserts in object TEID setup (v2.7.6):  \n  \n  \nAssert macro abort path:  \n  \nRelated fix commit:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/pfcp/context.c (v2.7.6)\nvoid ogs_pfcp_object_teid_hash_set(\n        ogs_pfcp_object_type_e type, ogs_pfcp_pdr_t *pdr,\n        bool restoration_indication)\n{\n    if (resource) {\n        ogs_assert(\n            (resource->info.v4 && pdr->f_teid.ipv4) ||\n            (resource->info.v6 && pdr->f_teid.ipv6));\n        ogs_assert(OGS_OK ==\n            ogs_pfcp_user_plane_ip_resource_info_to_f_teid(\n            &resource->info, &pdr->f_teid, &pdr->f_teid_len));\n        // ^ In CH=1 flow, convert matched DNN GTP-U resource into local F-TEID.\n        //   Family mismatch or conversion failure returns non-OGS_OK and triggers abort.\n    } else {\n        ogs_assert(\n            (ogs_gtp_self()->gtpu_addr && pdr->f_teid.ipv4) ||\n            (ogs_gtp_self()->gtpu_addr6 && pdr->f_teid.ipv6));\n        ogs_assert(OGS_OK ==\n            ogs_pfcp_sockaddr_to_f_teid(...));\n        // ^ Fallback path: build F-TEID from local gtpu_addr/gtpu_addr6.\n        //   If requested F-TEID family does not match local address (or conversion fails),\n        //   this returns non-OGS_OK and the assert aborts the process.\n    }\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/core/ogs-log.h (v2.7.6)\n#define ogs_assert(expr) \\\n    do { \\\n        if (ogs_likely(expr)) ; \\\n        else { \\\n            ogs_fatal(\"%s: Assertion `%s' failed.\", OGS_FUNC, #expr); \\\n            ogs_abort(); \\\n            // ^ process abort on assert failure\n        } \\\n    } while(0)"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4135",
      "rel_path": "vendor/open5gs/pfcp/PB1/CVE_2025_65559",
      "cve": "CVE-2025-65559",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.5",
      "anchor": "open5gs-pfcp-cve_2025_65559"
    },
    {
      "id": "CVE-2025-66781",
      "dir_name": "CVE_2025_66781",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "CVE-2025-66781: Invalid SDF Filter Flow-Description Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "Open5GS UPF (v2.7.6) crashes when it receives a PFCP `Session Establishment Request` containing invalid SDF Filter Flow-Description values.\nMalformed flow strings drive `ogs_ipfw_compile_rule()` into a NULL dereference path, and the PFCP handler call sites use assert-based error handling (`ogs_assert(rv == OGS_OK)`) that aborts the UPF process.",
      "root_cause": "`VULN-J01`:\n\nOpen5GS v2.7.6 had unsafe SDF filter handling in both parser and handler paths.  \n`ogs_ipfw_compile_rule()` dereferenced `token` without NULL check for invalid Flow-Description, and PFCP handlers asserted successful compile result, so malformed input could crash UPF.\n\nSource (real vulnerable code):  \nIssue report:  \n  \nNULL dereference condition in ipfw parser (v2.7.6):  \n  \nAssert-based handler callsites (v2.7.6):  \n  \n  \nAssert macro abort path:  \n  \nRelated fix commit:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/ipfw/ogs-ipfw.c (v2.7.6)\nint ogs_ipfw_compile_rule(ogs_ipfw_rule_t *ipfw_rule, char *flow_description)\n{\n    dir = token = ogs_strtok_r(NULL, \" \", &saveptr);\n    if (strcmp(token, \"out\") != 0) {\n        // ^ token may be NULL for malformed \"permit\" style input\n        return OGS_ERROR;\n    }\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/pfcp/handler.c (v2.7.6)\nogs_pfcp_pdr_t *ogs_pfcp_handle_create_pdr(ogs_pfcp_sess_t *sess,\n        ogs_pfcp_tlv_create_pdr_t *message,\n        uint8_t *cause_value, uint8_t *offending_ie_value)\n{\n    rv = ogs_ipfw_compile_rule(&rule->ipfw, flow_description);\n    ogs_assert(rv == OGS_OK);\n    // ^ malformed SDF flow can reach assert-triggered abort path\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4151",
      "rel_path": "vendor/open5gs/pfcp/PB1/CVE_2025_66781",
      "cve": "CVE-2025-66781",
      "cwe": "CWE-476: NULL Pointer Dereference/CWE-617: Reachable Assertion",
      "affected_version": "v2.7.5",
      "anchor": "open5gs-pfcp-cve_2025_66781"
    },
    {
      "id": "CVE-2025-66785",
      "dir_name": "CVE_2025_66785",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PB1",
      "pattern_display": "Invalid Value",
      "title": "CVE-2025-66785: Out-of-range URR-ID Crash (ISTM=1)",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "Open5GS UPF (v2.7.6) crashes when it receives a PFCP `Session Establishment Request` with a `CreateURR` using an out-of-range `URR-ID` (e.g., 65535) and Measurement Information `ISTM=1`.\nThe URR-ID range is not validated during `CreatePDR` processing, and the subsequent accounting/timer paths index the fixed-size `sess->urr_acc[]` array with assert-based checks that abort the UPF process.",
      "root_cause": "`VULN-J01`:\n\nOpen5GS v2.7.6 accepted out-of-range URR-ID references during PDR handling and later used `urr->id-1` to index fixed-size per-session URR accounting arrays guarded by asserts.  \nMalformed URR-ID can therefore reach assertion failure and process abort.\n\nSource (real vulnerable code):  \nIssue report:  \n  \nCreatePDR associates URR without URR-ID range validation (v2.7.6):  \n  \nURR max constant (v2.7.6):  \n  \nUPF URR accounting/timer assert + array index (v2.7.6):  \n  \n  \nRelated fix commit:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/pfcp/handler.c (v2.7.6)\nogs_pfcp_pdr_t *ogs_pfcp_handle_create_pdr(ogs_pfcp_sess_t *sess,\n        ogs_pfcp_tlv_create_pdr_t *message,\n        uint8_t *cause_value, uint8_t *offending_ie_value)\n{\n    for (i = 0; i < OGS_ARRAY_SIZE(message->urr_id); i++) {\n        if (message->urr_id[i].presence) {\n            urr = ogs_pfcp_urr_find_or_add(sess, message->urr_id[i].u32);\n            ogs_assert(urr);\n            ogs_pfcp_pdr_associate_urr(pdr, urr);\n            // ^ no URR-ID range check before association\n        }\n    }\n}"
        },
        {
          "lang": "c",
          "code": "// file: src/upf/context.c (v2.7.6)\nvoid upf_sess_urr_acc_timers_setup(upf_sess_t *sess, ogs_pfcp_urr_t *urr)\n{\n    ogs_assert(urr->id > 0 && urr->id <= OGS_MAX_NUM_OF_URR);\n    urr_acc = &sess->urr_acc[urr->id-1];\n    // ^ out-of-range URR-ID reaches assert/index path\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4169",
      "rel_path": "vendor/open5gs/pfcp/PB1/CVE_2025_66785",
      "cve": "CVE-2025-66785",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.5",
      "anchor": "open5gs-pfcp-cve_2025_66785"
    },
    {
      "id": "CVE-2025-14954",
      "dir_name": "CVE_2025_14954",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "CVE-2025-14954: QER Pool Exhaustion Crash",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "Open5GS UPF (v2.7.6) crashes when it receives a PFCP `Session Establishment Request` containing multiple `CreatePDR` IEs that each reference a unique `QER-ID` without corresponding `CreateQER` IEs.\nThe UPF implicitly allocates QER objects for each referenced QER-ID using assert-based allocation checks, and exceeding the per-session QER limit terminates the process.",
      "root_cause": "`VULN-J01`:\n\nOpen5GS v2.7.6 uses implicit QER allocation for PDR-referenced QER-ID and enforces allocation with `ogs_assert(qer)`.  \nBy exhausting the session QER pool, attacker-controlled PFCP requests can trigger assert-based process abort (remote DoS).\n\nSource (real vulnerable code):  \nIssue report:  \n  \nQER pool size constant (v2.7.6):  \n  \nQER allocation assert in find-or-add (v2.7.6):  \n  \nCreatePDR assert after implicit QER allocation (v2.7.6):  \n  \nAssert macro abort path:  \n  \nRelated fix commit:",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/pfcp/context.c (v2.7.6)\nogs_pfcp_qer_t *ogs_pfcp_qer_find_or_add(\n        ogs_pfcp_sess_t *sess, ogs_pfcp_qer_id_t id)\n{\n    qer = ogs_pfcp_qer_find(sess, id);\n    if (!qer) {\n        qer = ogs_pfcp_qer_add(sess);\n        ogs_assert(qer);\n        // ^ pool exhaustion can trigger reachable assert\n        qer->id = id;\n    }\n}"
        },
        {
          "lang": "c",
          "code": "// file: lib/pfcp/handler.c (v2.7.6)\nogs_pfcp_pdr_t *ogs_pfcp_handle_create_pdr(ogs_pfcp_sess_t *sess,\n        ogs_pfcp_tlv_create_pdr_t *message,\n        uint8_t *cause_value, uint8_t *offending_ie_value)\n{\n    if (message->qer_id.presence) {\n        qer = ogs_pfcp_qer_find_or_add(sess, message->qer_id.u32);\n        ogs_assert(qer);\n        ogs_pfcp_pdr_associate_qer(pdr, qer);\n    }\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4181",
      "rel_path": "vendor/open5gs/pfcp/PC1/CVE_2025_14954",
      "cve": "CVE-2025-14954",
      "cwe": "CWE-617 Reachable Assertion",
      "affected_version": "v2.7.5",
      "anchor": "open5gs-pfcp-cve_2025_14954"
    },
    {
      "id": "Issue #4204",
      "dir_name": "4204_issue",
      "vendor": "open5gs",
      "vendor_display": "Open5GS",
      "protocol": "pfcp",
      "protocol_display": "PFCP",
      "pattern": "PC1",
      "pattern_display": "Resource Exhaustion",
      "title": "Issue #4204: UPF DoS via PFCP Association Pool Exhaustion",
      "target": "UPF",
      "crash_type": "Denial of Service",
      "description": "Open5GS UPF maintains a fixed-size pool of PFCP peer nodes (`MAX_NUM_OF_PEER = 64`). An attacker can exhaust this pool by sending 65 or more concurrent PFCP `Association Setup Request` messages, each with a unique NodeID. The first 64 requests consume every available slot; subsequent requests fail with `ogs_pool_alloc() failed` / `ogs_pfcp_node_add() failed`, preventing legitimate SMF nodes from establishing new PFCP associations. By keeping the associations alive (answering Heartbeats), the attacker sustains a persistent denial of service.",
      "root_cause": "`Issue #4204`:\n\nThe UPF allocates PFCP peer nodes from a fixed pool sized by `MAX_NUM_OF_PEER` with no per-source rate limiting and no eviction of idle associations. Once the pool is exhausted, no new SMF can associate, yielding a persistent DoS.\n\nSource (real vulnerable code):\nIssue report:\nhttps://github.com/open5gs/open5gs/issues/4204",
      "code_snippets": [
        {
          "lang": "c",
          "code": "// file: lib/pfcp/context.c (v2.7.6)\nogs_pfcp_node_t *ogs_pfcp_node_add(\n        ogs_list_t *list, ogs_sockaddr_t *addr)\n{\n    ogs_pfcp_node_t *node = NULL;\n    ogs_pool_alloc(&ogs_pfcp_node_pool, &node);\n    // ^ line 880: fails once MAX_NUM_OF_PEER (64) slots are used\n    if (!node) {\n        ogs_error(\"No memory: ogs_pfcp_node_add() failed\");\n        return NULL; // line 955: no eviction / rate limiting\n    }\n    // ...\n    return node;\n}"
        }
      ],
      "issue_url": "https://github.com/open5gs/open5gs/issues/4204",
      "rel_path": "vendor/open5gs/pfcp/PC1/4204_issue",
      "cwe": "CWE-400: Uncontrolled Resource Consumption",
      "affected_version": "v2.7.6",
      "anchor": "open5gs-pfcp-4204_issue"
    }
  ]
};
