# CVE Information

Vendor: open5gs (https://open5gs.org)

Affected Product: open5gs SMF (Session Management Function)

Affected Version: <= v2.7.7

Vulnerability Type: Buffer Overflow

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)
## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through root cause analysis, a sample packet capture, and a screenshot of the trigger.

Vulnerable code (src/smf/gsm-handler.c:413-437):
```c                                                     
  for (j = 0; j < qos_flow_description[i].num_of_parameter; j++) {                                                                                                                                                                                                                                                      
      switch(qos_flow_description[i].param[j].identifier) {                                                                                                                                                                                                                                                             
      case 1: ... break;                                                                                                                                                                                                                                                                                                
      case 2: ... break;                                                                                                                                                                                                                                                                                                
      ...                                                         
      default:                                                                                                                                                                                                                                                                                                          
          ogs_fatal("Unknown qos_flow parameter identifier [%d]", 
                  qos_flow_description[i].param[i].identifier);  // Another instance of i/j confusion.                                                                                                                                                                                                                                     
          ogs_assert_if_reached();  // CRASH                                                                                                                                                                                                                                                                            
      }                                                                                                                                                                                                                                                                                                                 
  }      
```

Steps to reproduce
1. Complete normal registration + PDU session establishment
2. Send a Modification Request containing a malformed QoS Flow Descriptions IE:
[QFI=1, code=CREATE, E=1, num_params=9] header + 8×[5QI, len=1, val=9] + [0,0,0]
3. During parsing, open5gs SMF detects a mismatch between declared and actual number of parameters, causing an abnormal state machine exit and session deletion.


Vulnerable packet:
	in appendix

Screen shot:
<img width="1821" height="651" alt="图片" src="https://github.com/user-attachments/assets/e1461c5c-53a6-4610-902b-9881f7af4636" />


## Description
The NAS parser limits the loop upper bound of num_of_parameter to 8, but retains the original value from the wire. The handler gsm_handle_pdu_session_modification_qos_flow_descriptions() directly uses the uncorrected num_of_parameter as the loop upper bound. When num_of_parameter > 8, the handler reads zero or garbage values, enters the default branch, and triggers ogs_assert_if_reached().

### Reference
- https://github.com/open5gs/open5gs/issues/4430

### Log File

```text
04/20 02:11:46.919: [amf] INFO: [imsi-999700000000007:1:11][0:0:NULL] /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify (../src/amf/nsmf-handler.c:954)
04/20 02:12:01.832: [scp] INFO: Setup NF EndPoint(addr) [127.0.0.4:7777] (../src/scp/sbi-path.c:463)
04/20 02:12:01.832: [gsm] FATAL: Unknown qos_flow parameter identifier [1] (../src/smf/gsm-handler.c:435)
04/20 02:12:01.832: [gsm] FATAL: gsm_handle_pdu_session_modification_qos_flow_descriptions: should not be reached. (../src/smf/gsm-handler.c:437)
04/20 02:12:01.832: [core] FATAL: backtrace() returned 11 addresses (../lib/core/ogs-abort.c:37)
./bin/open5gs-smfd(+0xbb4d2) [0x55f0992084d2]
./bin/open5gs-smfd(+0xbb9b0) [0x55f0992089b0]
./bin/open5gs-smfd(+0x35ea9) [0x55f099182ea9]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(ogs_fsm_dispatch+0x113) [0x7f0750f1b2de]
./bin/open5gs-smfd(+0x2ed88) [0x55f09917bd88]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(ogs_fsm_dispatch+0x113) [0x7f0750f1b2de]
./bin/open5gs-smfd(+0x11e81) [0x55f09915ee81]
/home/xiaoyugan/5G/open5gs_test/install/lib/x86_64-linux-gnu/libogscore.so.2(+0x12960) [0x7f0750f0b960]
/lib/x86_64-linux-gnu/libpthread.so.0(+0x8609) [0x7f074ff7e609]
/lib/x86_64-linux-gnu/libc.so.6(clone+0x43) [0x7f074fea3353]
Aborted
04/20 02:12:01.984: [sbi] WARNING: Couldn't connect to server (7): Failed to connect to 127.0.0.4 port 7777: Connection refused (../lib/sbi/client.c:767)
04/20 02:12:01.984: [scp] WARNING: response_handler() failed [-1] (../src/scp/sbi-path.c:678)
04/20 02:12:01.984: [amf] ERROR: [1:0] No SmContextUpdateError [500] (../src/amf/nsmf-handler.c:991)
```





