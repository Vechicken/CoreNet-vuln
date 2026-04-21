# CVE Information

Vendor: open5gs (https://open5gs.org)

Affected Product: open5gs SMF (Session Management Function)

Affected Version: <= v2.7.7

Vulnerability Type: Buffer Overflow

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)
## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through root cause analysis, a sample packet capture, and a screenshot of the trigger.

Vulnerable code (src/smf/gsm-handler.c:274-275):
```c
  for (j = 0; j < qos_rule[i].num_of_packet_filter &&                             
              j < OGS_MAX_NUM_OF_FLOW_IN_NAS; j++) {                               
      pf = smf_pf_add(qos_flow);                                                          
      ogs_assert(pf);                                                          
      ogs_assert(                  
          reconfigure_packet_filter(pf, &qos_rule[i], i) > 0);   
  }   
```

Steps to reproduce
1. Complete normal registration + PDU session establishment (QFI=1 already exists)
2. Send a Modification Request carrying two rules: [id=1, CREATE_NEW, downlink, QFI=1]
3. When the SMF processes the two rules sequentially, the second rule uses the same id to issue another CREATE, causing an internal data structure exception.


Vulnerable packet:
	in appendix

Screen shot:
<img width="1826" height="627" alt="图片" src="https://github.com/user-attachments/assets/6c112b29-c632-4a82-a845-d6edbdba745e" />


## Description
In SMF's gsm_handle_pdu_session_modification_qos_rules(), when processing the QoS Rules IE in a UE-initiated PDU Session Modification Request, an incorrect loop variable is passed as a parameter. Subsequently, when accessing an array, that parameter is used to access illegal memory, triggering ogs_assert.

### Reference
- https://github.com/open5gs/open5gs/issues/4429

### Log File

```text
04/20 00:58:03.239: [amf] INFO: [imsi-999700000000003:1:11][0:0:NULL] /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify (../src/amf/nsmf-handler.c:954)
04/20 00:58:18.195: [scp] INFO: Setup NF EndPoint(addr) [127.0.0.4:7777] (../src/scp/sbi-path.c:463)
04/20 00:58:18.196: [gsm] FATAL: gsm_handle_pdu_session_modification_qos_rules: Assertion `reconfigure_packet_filter(pf, &qos_rule[i], i) > 0' failed. (../src/smf/gsm-handler.c:274)
04/20 00:58:18.196: [core] FATAL: backtrace() returned 11 addresses (../lib/core/ogs-abort.c:37)
./bin/open5gs-smfd(+0xba573) [0x55fa5714b573]
./bin/open5gs-smfd(+0xbb93b) [0x55fa5714c93b]
./bin/open5gs-smfd(+0x35ea9) [0x55fa570c6ea9]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(ogs_fsm_dispatch+0x113) [0x7f94f71752de]
./bin/open5gs-smfd(+0x2ed88) [0x55fa570bfd88]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(ogs_fsm_dispatch+0x113) [0x7f94f71752de]
./bin/open5gs-smfd(+0x11e81) [0x55fa570a2e81]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(+0x12960) [0x7f94f7165960]
/lib/x86_64-linux-gnu/libpthread.so.0(+0x8609) [0x7f94f61d8609]
/lib/x86_64-linux-gnu/libc.so.6(clone+0x43) [0x7f94f60fd353]
04/20 00:58:18.355: [sbi] WARNING: Couldn't connect to server (7): Failed to connect to 127.0.0.4 port 7777: Connection refused (../lib/sbi/client.c:767)
04/20 00:58:18.355: [scp] WARNING: response_handler() failed [-1] (../src/scp/sbi-path.c:678)
Aborted
04/20 00:58:18.355: [amf] ERROR: [1:0] No SmContextUpdateError [500] (../src/amf/nsmf-handler.c:991)
```



