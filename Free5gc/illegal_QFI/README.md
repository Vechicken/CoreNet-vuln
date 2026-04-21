# CVE Information

Vendor: free5gc (https://free5gc.org)

Affected Product: free5gc SMF (Session Management Function)

Affected Version: <= v4.2.1

Vulnerability Type: Buffer Overflow

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)
## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through root cause analysis, a sample packet capture, and a screenshot of the trigger.

Vulnerable code (NFs/smf/internal/context/ngap_handler.go:108-122):
```go
  if qosInfoList := resourceModifyResponseTransfer.QosFlowAddOrModifyResponseList; qosInfoList != nil {
      for _, item := range qosInfoList.List {
          qfi := uint8(item.QosFlowIdentifier.Value)
          ctx.AdditonalQosFlows[qfi].State = QoSFlowSet  // PANIC: nil if qfi not in map
      }
  }
  if qosFailedInfoList := resourceModifyResponseTransfer.QosFlowFailedToAddOrModifyList; qosFailedInfoList != nil {
      for _, item := range qosFailedInfoList.List {
          qfi := uint8(item.QosFlowIdentifier.Value)
          ...
          ctx.AdditonalQosFlows[qfi].State = QoSFlowUnset  // PANIC: nil if qfi not in map
      }
  }

```

Vulnerable packet:
	in appendix

Steps to reproduce the behavior:
1. Use default free5gc configuration (no config changes required).
2. Start all NFs (./run.sh).
3. Connect a gNB simulator, complete NG Setup, register a UE, and establish a PDU Session (PDU Session ID=1). Record the AMF-UE-NGAP-ID and RAN-UE-NGAP-ID assigned during registration.
4. From the gNB simulator, send an unsolicited NGAP PDUSessionResourceModifyResponse with the following structure:

PDUSessionResourceModifyResponse {
AMF-UE-NGAP-ID:
RAN-UE-NGAP-ID:
PDUSessionResourceModifyListModRes: [{
PDUSessionID: 1
PDUSessionResourceModifyResponseTransfer: <APER-encoded, containing:
QosFlowAddOrModifyResponseList: [{
QosFlowIdentifier: 1 // QFI=1 is reserved for default QoS,
}] // never present in AdditonalQosFlows
>
}]
}

Screen shot:
<img width="2286" height="1500" alt="图片" src="https://github.com/user-attachments/assets/dd9672ad-86f5-4c3c-99cf-ae73845ba3b3" />


## Description
SMF's HandlePDUSessionResourceModifyResponseTransfer does not validate whether a QFI from the NGAP QosFlowAddOrModifyResponseList exists in ctx.AdditonalQosFlows before accessing it. The panic causes the N11 SM Context Update request to return HTTP 500 to the AMF, leaving the SM Context's QoS flow state potentially inconsistent with the actual radio bearer state on the gNB side.

### Reference
- https://github.com/free5gc/free5gc/issues/1016

### Log File

```text
2026-04-17T06:13:34.520089854-07:00 [INFO][AMF][Ngap][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22/172.17.0.1:45601] Handle PDUSessionResourceSetupResponse
2026-04-17T06:13:34.520179128-07:00 [INFO][AMF][Ngap][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22/172.17.0.1:45601] Not comprehended IE ID 0x0079 (criticality: ignore)
2026-04-17T06:13:34.520232358-07:00 [INFO][AMF][Ngap][amf_ue_ngap_id:RU:1,AU:1(3GPP)][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22/172.17.0.1:45601] Handle PDUSessionResourceSetupResponse (RAN UE NGAP ID: 1)
2026-04-17T06:13:34.520963821-07:00 [INFO][NRF][Token] In HTTPAccessTokenRequest
2026-04-17T06:13:34.522109732-07:00 [WARN][NRF][Token] Certificate verify: x509: certificate signed by unknown authority (possibly because of "x509: invalid signature: parent certificate cannot sign this kind of certificate" while trying to verify candidate authority certificate "free5gc")
2026-04-17T06:13:34.524742016-07:00 [INFO][NRF][GIN] | 200 |       127.0.0.1 | POST    | /oauth2/token |  |
2026-04-17T06:13:34.526518750-07:00 [INFO][SMF][PduSess] Receive Update SM Context Request
2026-04-17T06:13:34.527158136-07:00 [INFO][UPF][PFCP][LAddr:127.0.0.8:8805] handleSessionModificationRequest
2026-04-17T06:13:34.528880374-07:00 [INFO][SMF][PduSess] Received PFCP Session Modification Accepted Response from AN UPF
2026-04-17T06:13:34.529016192-07:00 [INFO][SMF][GIN] | 200 |       127.0.0.1 | POST    | /nsmf-pdusession/v1/sm-contexts/urn:uuid:93e54df6-7af4-460a-a324-c63b4e846293/modify |  |
2026-04-17T06:13:44.224163688-07:00 [INFO][UPF][PFCP][LAddr:127.0.0.8:8805] handleHeartbeatRequest
2026-04-17T06:13:49.178826173-07:00 [INFO][AMF][Ngap][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22/172.17.0.1:45601] Handle PDUSessionResourceModifyResponse
2026-04-17T06:13:49.178965255-07:00 [INFO][AMF][Ngap][amf_ue_ngap_id:RU:1,AU:1(3GPP)][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22/172.17.0.1:45601] Handle PDUSessionResourceModifyResponse (RAN UE NGAP ID: 1)
2026-04-17T06:13:49.180353219-07:00 [INFO][NRF][Token] In HTTPAccessTokenRequest
2026-04-17T06:13:49.182125928-07:00 [WARN][NRF][Token] Certificate verify: x509: certificate signed by unknown authority (possibly because of "x509: invalid signature: parent certificate cannot sign this kind of certificate" while trying to verify candidate authority certificate "free5gc")
2026-04-17T06:13:49.185608435-07:00 [INFO][NRF][GIN] | 200 |       127.0.0.1 | POST    | /oauth2/token |  |
2026-04-17T06:13:49.187910448-07:00 [INFO][SMF][PduSess] Receive Update SM Context Request
2026-04-17T06:13:49.188561931-07:00 [ERRO][SMF][GIN] panic: runtime error: invalid memory address or nil pointer dereference
goroutine 185 [running]:
runtime/debug.Stack()
	/home/xiaoyugan/sdk/go1.24.1/src/runtime/debug/stack.go:26 +0x5e
github.com/free5gc/util/logger.NewGinWithLogrus.ginRecover.func2.1()
	/home/xiaoyugan/go/pkg/mod/github.com/free5gc/util@v1.2.0/logger/logger.go:298 +0x117
panic({0xeab8e0?, 0x1971bd0?})
	/home/xiaoyugan/sdk/go1.24.1/src/runtime/panic.go:792 +0x132
github.com/free5gc/smf/internal/context.HandlePDUSessionResourceModifyResponseTransfer({0xc000828580, 0x3, 0x578}, 0xc000272008)
	/home/xiaoyugan/5G/free5gc/NFs/smf/internal/context/ngap_handler.go:111 +0x2ef
github.com/free5gc/smf/internal/sbi/processor.(*Processor).HandlePDUSessionSMContextUpdate(0xc0000403f0, 0xc0002e0100, {0xc00081a308, {0x0, 0x0, 0x0}, {0xc000828580, 0x3, 0x578}, {0x0, ...}}, ...)
	/home/xiaoyugan/5G/free5gc/NFs/smf/internal/sbi/processor/pdu_session.go:658 +0x1dce
github.com/free5gc/smf/internal/sbi.(*Server).HTTPUpdateSmContext(0xc000284ac0, 0xc0002e0100)
	/home/xiaoyugan/5G/free5gc/NFs/smf/internal/sbi/api_pdusession.go:138 +0x32d
github.com/gin-gonic/gin.(*Context).Next(0xc0002e0100)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/context.go:185 +0x2b
github.com/free5gc/smf/internal/sbi.newRouter.InboundMetrics.func4(0xc0002e0100)
	/home/xiaoyugan/go/pkg/mod/github.com/free5gc/util@v1.2.0/metrics/middleware.go:15 +0x45
github.com/gin-gonic/gin.(*Context).Next(0xc0002e0100)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/context.go:185 +0x2b
github.com/free5gc/util/logger.NewGinWithLogrus.ginRecover.func2(0xc000462460?)
	/home/xiaoyugan/go/pkg/mod/github.com/free5gc/util@v1.2.0/logger/logger.go:330 +0x48
github.com/gin-gonic/gin.(*Context).Next(0xc0002e0100)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/context.go:185 +0x2b
github.com/free5gc/util/logger.NewGinWithLogrus.ginToLogrus.func1(0xc0002e0100)
	/home/xiaoyugan/go/pkg/mod/github.com/free5gc/util@v1.2.0/logger/logger.go:256 +0x65
github.com/gin-gonic/gin.(*Context).Next(...)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/context.go:185
github.com/gin-gonic/gin.(*Engine).handleHTTPRequest(0xc0003c4340, 0xc0002e0100)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/gin.go:633 +0x872
github.com/gin-gonic/gin.(*Engine).ServeHTTP(0xc0003c4340, {0x120ced8, 0xc000604b90}, 0xc00041fcc0)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/gin.go:589 +0x1aa
golang.org/x/net/http2.(*serverConn).runHandler(0x44b1d2?, 0xc000040030?, 0xc0007e8db8?, 0xc0004627a8?)
	/home/xiaoyugan/go/pkg/mod/golang.org/x/net@v0.38.0/http2/server.go:2433 +0xf5
created by golang.org/x/net/http2.(*serverConn).scheduleHandler in goroutine 156
	/home/xiaoyugan/go/pkg/mod/golang.org/x/net@v0.38.0/http2/server.go:2367 +0x21d
2026-04-17T06:13:49.188720864-07:00 [INFO][SMF][GIN] | 500 |       127.0.0.1 | POST    | /nsmf-pdusession/v1/sm-contexts/urn:uuid:93e54df6-7af4-460a-a324-c63b4e846293/modify |  |
2026-04-17T06:13:49.189221775-07:00 [ERRO][AMF][Ngap][amf_ue_ngap_id:RU:1,AU:1(3GPP)][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22/172.17.0.1:45601] SendUpdateSmContextN2Info[PDUSessionResourceModifyResponseTransfer] Error: undefined response type
github.com/free5gc/openapi.Deserialize

```

