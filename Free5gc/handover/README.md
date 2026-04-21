# CVE Information

Vendor: free5gc (https://free5gc.org)

Affected Product: free5gc AMF (Access and Mobility Management Function)

Affected Version: <= v4.2.1

Vulnerability Type: Buffer Overflow

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)
## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through root cause analysis, a sample packet capture, and a screenshot of the trigger.

Vulnerable code (NFs/amf/internal/ngap/handler.go:1403-1408):
```go
  defer func(hoFailCause *string) {
      if utils.ReadStringPtr(hoFailCause) != "" {
          business_metrics.IncrHoEventCounter(...,
              targetUe.HandOverStartTime)  // PANIC: targetUe is nil
      }
  }(&hoFailCause)
```
Vulnerable packet:
	in appendix

Screen shot:
<img width="1857" height="794" alt="图片" src="https://github.com/user-attachments/assets/fd3f4e02-14ff-43ec-857c-fb6209959471" />




## Description
AMF crashes due to nil pointer dereference in handleHandoverRequestAcknowledgeMain deferred function accessing targetUe.HandOverStartTime when receiving a HandoverRequestAcknowledge without AMF-UE-NGAP-ID IE, causing the NGAP worker goroutine to panic and die.

### Reference
- https://github.com/free5gc/free5gc/issues/1018

### Log File

```text
2026-04-17T20:21:50.595567823-07:00 [INFO][AMF][Ngap] [AMF] SCTP Accept from: 127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:43652
2026-04-17T20:21:50.595951042-07:00 [INFO][AMF][Ngap] Create a new NG connection for: 127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:43652
2026-04-17T20:21:50.596081834-07:00 [INFO][AMF][Ngap][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:43652] Handle NGSetupRequest
2026-04-17T20:21:50.596127639-07:00 [INFO][AMF][Ngap][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:43652] Send NG-Setup response
2026-04-17T20:21:55.252809121-07:00 [INFO][UPF][PFCP][LAddr:127.0.0.8:8805] handleHeartbeatRequest
2026-04-17T20:21:55.607794619-07:00 [INFO][AMF][Ngap][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:43652] Handle HandoverRequestAcknowledge
2026-04-17T20:21:55.607945853-07:00 [WARN][AMF][Ngap][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:43652] Missing IE AMF-UE-NGAP-ID
2026-04-17T20:21:55.608005954-07:00 [WARN][AMF][Ngap][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:43652] Missing IE RAN-UE-NGAP-ID
2026-04-17T20:21:55.608074462-07:00 [WARN][AMF][Ngap][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:43652] Missing IE PDUSessionResourceAdmittedList
2026-04-17T20:21:55.608217812-07:00 [ERRO][AMF][Ngap][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:43652] Target Ue is missing
2026-04-17T20:21:55.610116763-07:00 [FATA][AMF][Ngap] panic: runtime error: invalid memory address or nil pointer dereference
goroutine 82 [running]:
runtime/debug.Stack()
	/home/xiaoyugan/sdk/go1.24.1/src/runtime/debug/stack.go:26 +0x5e
github.com/free5gc/amf/internal/ngap/service.handleConnection.func1()
	/home/xiaoyugan/5G/free5gc/NFs/amf/internal/ngap/service/service.go:186 +0x65
panic({0xf60bc0?, 0x1a4d540?})
	/home/xiaoyugan/sdk/go1.24.1/src/runtime/panic.go:792 +0x132
github.com/free5gc/amf/internal/ngap.handleHandoverRequestAcknowledgeMain.func1(0xc000694bf0?)
	/home/xiaoyugan/5G/free5gc/NFs/amf/internal/ngap/handler.go:1401 +0x54
github.com/free5gc/amf/internal/ngap.handleHandoverRequestAcknowledgeMain(0xc00018a000, 0x0, 0xc000439da0?, 0x0, 0x0, 0xc00050ec18, 0xc000732000?)
	/home/xiaoyugan/5G/free5gc/NFs/amf/internal/ngap/handler.go:1412 +0x3d2
github.com/free5gc/amf/internal/ngap.handlerHandoverRequestAcknowledge(0xc00018a000, 0xc00058a2c0)
	/home/xiaoyugan/5G/free5gc/NFs/amf/internal/ngap/handler_generated.go:3271 +0x1385
github.com/free5gc/amf/internal/ngap.dispatchMain(0xc00018a000, 0xd?)
	/home/xiaoyugan/5G/free5gc/NFs/amf/internal/ngap/dispatcher_generated.go:157 +0xa45
github.com/free5gc/amf/internal/ngap.Dispatch({0x12e6470, 0xc000694000}, {0xc000732000, 0xd, 0x40000})
	/home/xiaoyugan/5G/free5gc/NFs/amf/internal/ngap/dispatcher.go:49 +0x274
github.com/free5gc/amf/internal/ngap/service.handleConnection(0xc000694000, 0x40000, {0x1191c48?, 0x1191c58?, 0x1191c50?})
	/home/xiaoyugan/5G/free5gc/NFs/amf/internal/ngap/service/service.go:239 +0x472
created by github.com/free5gc/amf/internal/ngap/service.listenAndServe in goroutine 55
	/home/xiaoyugan/5G/free5gc/NFs/amf/internal/ngap/service/service.go:160 +0xa17

```



