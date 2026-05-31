# CVE Information

Vendor: OAI (https://gitlab.eurecom.fr/oai)

Affected Product: oai-cn5g-smf

Affected Version: <= v2.2.1

Vulnerability Type: Buffer Overflow

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)

## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through root cause analysis, a sample packet capture, and a screenshot of the trigger.

After receiving the PDU Session Modification Request packet, OAI first performs decoding twice, and enters QosRules.cpp during the second decoding.

After passing the length check, it attempts to decode the specific QosRule. However, the content is only 1 byte, which is shorter than the minimum required length, so it exits the loop.

<img width="951" height="353" alt="图片" src="https://github.com/user-attachments/assets/5763f08c-22d1-413f-9ea0-86393bbf34ab" />

Then, after dispatching, update_qos_info retrieves the wire length and the rule list from the decoded QosRules object. The loop is driven by the wire length, and the boundary check here contains an off-by-one error. After execution, the process terminates.

<img width="900" height="471" alt="图片" src="https://github.com/user-attachments/assets/7087715f-c1a1-457f-84ca-df148cddf2b0" />


## Description
When OAI SMF processes a PDU Session Modification Request message, if the wire length field of the Requested QoS Rules IE is non-zero while the contained QosRule is invalid (content less than 4 bytes), a null pointer dereference can be triggered, causing the SMF to crash.

### Log File
```text
[2026-05-31 09:58:08.449] [nas] [debug] Decoding Nas5gsmHeader
[2026-05-31 09:58:08.449] [nas] [debug] Decoding PDU Session Identity
[2026-05-31 09:58:08.449] [nas] [debug] Decoded value 0x1
[2026-05-31 09:58:08.449] [nas] [debug] Decoded PDU Session Identity, len (1)
[2026-05-31 09:58:08.449] [nas] [debug] Decoding Procedure Transaction Identity
[2026-05-31 09:58:08.449] [nas] [debug] Decoded value 0x2
[2026-05-31 09:58:08.449] [nas] [debug] Decoded Procedure Transaction Identity, len (1)
[2026-05-31 09:58:08.449] [nas] [debug] Decoded Nas5gsmHeader len (4 octets)
[2026-05-31 09:58:08.449] [nas] [debug] Decoded Nas5gsmMessage len (4 octets)
[2026-05-31 09:58:08.449] [nas] [debug] Decoding PduSessionModificationRequest message
[2026-05-31 09:58:08.449] [nas] [debug] Decoding Nas5gsmMessage
[2026-05-31 09:58:08.450] [nas] [debug] Decoding Nas5gsmHeader
[2026-05-31 09:58:08.450] [nas] [debug] Decoding PDU Session Identity
[2026-05-31 09:58:08.450] [nas] [debug] Decoded value 0x1
[2026-05-31 09:58:08.450] [nas] [debug] Decoded PDU Session Identity, len (1)
[2026-05-31 09:58:08.450] [nas] [debug] Decoding Procedure Transaction Identity
[2026-05-31 09:58:08.450] [nas] [debug] Decoded value 0x2
[2026-05-31 09:58:08.450] [nas] [debug] Decoded Procedure Transaction Identity, len (1)
[2026-05-31 09:58:08.450] [nas] [debug] Decoded Nas5gsmHeader len (4 octets)
[2026-05-31 09:58:08.450] [nas] [debug] Decoded Nas5gsmMessage len (4 octets)
[2026-05-31 09:58:08.450] [nas] [debug] First option IEI (0x7a)
[2026-05-31 09:58:08.450] [nas] [debug] Decoding IEI 0x7a
[2026-05-31 09:58:08.450] [nas] [debug] Decoding QoS Rules
[2026-05-31 09:58:08.450] [nas] [debug] Decoding QosRule
[2026-05-31 09:58:08.450] [nas] [error] Buffer length is less than the minimum length of this IE (4 octet)
[2026-05-31 09:58:08.450] [nas] [debug] Decoded QoS Rules (len 3)
[2026-05-31 09:58:08.450] [nas] [debug] Next IEI (0x0)
[2026-05-31 09:58:08.450] [nas] [debug] Decoded PduSessionModificationRequest message len (7)
[2026-05-31 09:58:08.450] [smf_app] [debug] PDU_SESSION_MODIFICATION_REQUEST
[2026-05-31 09:58:08.450] [smf_app] [info] PTI 2
```

<img width="1341" height="816" alt="图片" src="https://github.com/user-attachments/assets/a29cef05-2035-4d9a-8846-8a452040ed93" />


