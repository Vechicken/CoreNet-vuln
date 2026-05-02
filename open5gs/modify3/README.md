# CVE Information

Vendor: open5gs (https://open5gs.org)

Affected Product: open5gs SMF (Session Management Function)

Affected Version: <= v2.7.7

Vulnerability Type: Buffer Overflow

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)
## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through root cause analysis, a sample packet capture, and a screenshot of the trigger.

Vulnerable code (lib/nas/common/types.c:502):
```c
  uint64_t ogs_nas_bitrate_to_uint64(ogs_nas_bitrate_t *nas_bitrate)
  {
      switch (nas_bitrate->unit) {
      case OGS_NAS_BR_UNIT_1K:    // 1
          return nas_bitrate->value * 1000;
      // ... other case ...
      default:
          ogs_fatal("Unknown unit [%d]", nas_bitrate->unit);
          ogs_assert_if_reached();  // ← Vulnerability point
      }
  }
```
Caller code (src/smf/gsm-handler.c:413-432):
```c
        for (j = 0; j < qos_flow_description[i].num_of_parameter; j++) {
            switch(qos_flow_description[i].param[j].identifier) {
            case OGS_NAX_QOS_FLOW_PARAMETER_ID_5QI:
                /* Nothing */
                break;
            case OGS_NAX_QOS_FLOW_PARAMETER_ID_GFBR_UPLINK:
                qos_flow->qos.gbr.uplink = ogs_nas_bitrate_to_uint64(
                        &qos_flow_description[i].param[j].br);
                break;
            case OGS_NAX_QOS_FLOW_PARAMETER_ID_GFBR_DOWNLINK:
                qos_flow->qos.gbr.downlink = ogs_nas_bitrate_to_uint64(
                        &qos_flow_description[i].param[j].br);
                break;
            case OGS_NAX_QOS_FLOW_PARAMETER_ID_MFBR_UPLINK:
                qos_flow->qos.mbr.uplink = ogs_nas_bitrate_to_uint64(
                        &qos_flow_description[i].param[j].br);
                break;
            case OGS_NAX_QOS_FLOW_PARAMETER_ID_MFBR_DOWNLINK:
                qos_flow->qos.mbr.downlink = ogs_nas_bitrate_to_uint64(
                        &qos_flow_description[i].param[j].br);
                break;
```

Steps to reproduce
1. Complete normal registration + PDU session establishment (QFI=1 already exists)
2. Send a Modification Request carrying invalid bitrate unit. (0 or bigger than 25)
3. When the SMF processes the messgae, SMF process terminates, causing all PDU sessions to be interrupted.

   
  UE → gNB → AMF → SMF
  NAS PDU Session Modification Request
  → Nsmf_PDUSession_UpdateSMContext (SBI)
  → gsm_handle_pdu_session_modification_request()
  → gsm_handle_pdu_session_modification_qos_flow_descriptions()
  → ogs_nas_bitrate_to_uint64() [types.c:502]
  → ogs_assert_if_reached() → abort()


Vulnerable packet:
	in appendix

Screen shot:
<img width="1854" height="786" alt="9d99d135551fcb6ca29d0a824fa8cb39" src="https://github.com/user-attachments/assets/784692a9-4b1b-498e-8b36-632684420341" />



## Description
Open5GS SMF does not validate the legality of the unit field in the bitrate parameter when processing the QoS Flow Description parameter in a NAS PDU Session Modification Request message. When the unit value is 0 or greater than 25, the ogs_nas_bitrate_to_uint64() function invokes ogs_assert_if_reached(), causing the SMF process to crash with an abort.

### Reference
- https://github.com/open5gs/open5gs/issues/4429

### Log File

```text
05/02 00:18:17.211: [amf] INFO: [imsi-999700000000007:1:11][0:0:NULL] /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify (../src/amf/nsmf-handler.c:954)
05/02 00:18:31.985: [scp] INFO: Setup NF EndPoint(addr) [127.0.0.4:7777] (../src/scp/sbi-path.c:463)
05/02 00:18:31.986: [nas] FATAL: Unknown unit [0] (../lib/nas/common/types.c:502)
05/02 00:18:31.986: [nas] FATAL: ogs_nas_bitrate_to_uint64: should not be reached. (../lib/nas/common/types.c:503)
05/02 00:18:31.986: [core] FATAL: backtrace() returned 12 addresses (../lib/core/ogs-abort.c:37)
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogsnas-common.so.2(ogs_nas_bitrate_to_uint64+0x4d7) [0x7ffb5d9f64f2]
./bin/open5gs-smfd(+0xbb2e8) [0x55e36688e2e8]
./bin/open5gs-smfd(+0xbb9b0) [0x55e36688e9b0]
./bin/open5gs-smfd(+0x35ea9) [0x55e366808ea9]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(ogs_fsm_dispatch+0x113) [0x7ffb5e6792de]
./bin/open5gs-smfd(+0x2ed88) [0x55e366801d88]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(ogs_fsm_dispatch+0x113) [0x7ffb5e6792de]
./bin/open5gs-smfd(+0x11e81) [0x55e3667e4e81]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(+0x12960) [0x7ffb5e669960]
/lib/x86_64-linux-gnu/libpthread.so.0(+0x8609) [0x7ffb5d6dc609]
/lib/x86_64-linux-gnu/libc.so.6(clone+0x43) [0x7ffb5d601353]
05/02 00:18:32.219: [sbi] WARNING: Couldn't connect to server (7): Failed to connect to 127.0.0.4 port 7777: Connection refused (../lib/sbi/client.c:767)
05/02 00:18:32.219: [scp] WARNING: response_handler() failed [-1] (../src/scp/sbi-path.c:678)

[10]+  Stopped                 sudo ./bin/open5gs-smfd -c ./etc/open5gs/smf.yaml
Aborted
05/02 00:18:32.220: [amf] ERROR: [1:0] No SmContextUpdateError [500] (../src/amf/nsmf-handler.c:991)
05/02 00:18:34.858: [nrf] WARNING: [fd31e020-45f6-41f1-a7f5-7d6ad9ed6237] No heartbeat (../src/nrf/nrf-sm.c:288)
05/02 00:18:34.859: [nrf] INFO: [fd31e020-45f6-41f1-a7f5-7d6ad9ed6237] NF de-registered (../src/nrf/nf-sm.c:220)
05/02 00:18:34.860: [sbi] INFO: [fd31e020-45f6-41f1-a7f5-7d6ad9ed6237] (NRF-notify) NF_DEREGISTERED event [type:SMF] (../lib/sbi/nnrf-handler.c:1191)
05/02 00:18:34.861: [scp] INFO: Setup NF EndPoint(addr) [127.0.0.5:7777] (../src/scp/sbi-path.c:463)
05/02 00:18:34.862: [sbi] INFO: [fd31e020-45f6-41f1-a7f5-7d6ad9ed6237] (NRF-notify) NF_DEREGISTERED event [type:SMF] (../lib/sbi/nnrf-handler.c:1191)
05/02 00:18:40.966: [amf] WARNING: Implicit NG release (../src/amf/amf-sm.c:1074)
05/02 00:18:40.966: [amf] WARNING:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[1] (../src/amf/amf-sm.c:1075)
05/02 00:18:40.966: [amf] INFO: UE Context Release [Action:1] (../src/amf/ngap-handler.c:1827)
```



