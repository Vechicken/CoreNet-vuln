# CVE Information

Vendor: free5gc (https://free5gc.org)

Affected Product: free5gc SMF (Session Management Function)

Affected Version: <= v4.2.1

Vulnerability Type: Buffer Overflow

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)
## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through root cause analysis, a sample packet capture, and a screenshot of the trigger.

Vulnerable code (ngap_handler.go:245-247):
```go
  if ctx.NrdcIndicator {
      ieExtensions := pathSwitchRequestTransfer.IEExtensions
      for _, ie := range ieExtensions.List {  // PANIC: ieExtensions can be nil
```
Vulnerable packet:
	in appendix

Steps to reproduce the behavior:

1. Use default free5gc configuration.
2. Start all NFs (./run.sh).
3. gNB sends PDUSessionResourceSetupResponse with PDUSessionResourceSetupResponseTransfer containing the optional AdditionalDLQosFlowPerTNLInformation field.
4. gNB sends PathSwitchRequest for the same PDU session, with a standard PathSwitchRequestTransfer that does NOT include the optional IEExtensions field.


Screen shot:
<img width="1848" height="1179" alt="图片" src="https://github.com/user-attachments/assets/faeea306-3f96-4961-bbbe-29a696928c0a" />



## Description
SMF has a nil pointer dereference in HandlePathSwitchRequestTransfer. When SMContext.NrdcIndicator is true, the function accesses pathSwitchRequestTransfer.IEExtensions.List without checking whether IEExtensions is nil. Since IEExtensions is an aper:"optional" field in PathSwitchRequestTransfer, a legitimate or crafted PathSwitchRequest that omits IEExtensions will cause a nil pointer dereference panic.

### Reference
- https://github.com/free5gc/free5gc/issues/1019

### Log File

```text
2026-04-19T06:28:39.539084951-07:00 [INFO][AMF][Ngap][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:52015] Handle PathSwitchRequest
2026-04-19T06:28:39.539323153-07:00 [INFO][AMF][Ngap][amf_ue_ngap_id:RU:1,AU:1(3GPP)][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:52015] Send PathSwitchRequestTransfer to SMF
2026-04-19T06:28:39.541067766-07:00 [INFO][NRF][Token] In HTTPAccessTokenRequest
2026-04-19T06:28:39.544464191-07:00 [WARN][NRF][Token] Certificate verify: x509: certificate signed by unknown authority (possibly because of "x509: invalid signature: parent certificate cannot sign this kind of certificate" while trying to verify candidate authority certificate "free5gc")
2026-04-19T06:28:39.548338419-07:00 [INFO][NRF][GIN] | 200 |       127.0.0.1 | POST    | /oauth2/token |  |
2026-04-19T06:28:39.550820138-07:00 [INFO][SMF][PduSess] Receive Update SM Context Request
2026-04-19T06:28:39.551332041-07:00 [ERRO][SMF][GIN] panic: runtime error: invalid memory address or nil pointer dereference
goroutine 171 [running]:
runtime/debug.Stack()
	/home/xiaoyugan/sdk/go1.24.1/src/runtime/debug/stack.go:26 +0x5e
github.com/free5gc/util/logger.NewGinWithLogrus.ginRecover.func2.1()
	/home/xiaoyugan/go/pkg/mod/github.com/free5gc/util@v1.2.0/logger/logger.go:298 +0x117
panic({0xeab8e0?, 0x1971bd0?})
	/home/xiaoyugan/sdk/go1.24.1/src/runtime/panic.go:792 +0x132
github.com/free5gc/smf/internal/context.HandlePathSwitchRequestTransfer({0xc00073c580, 0xc, 0x578}, 0xc000666008)
	/home/xiaoyugan/5G/free5gc_test/NFs/smf/internal/context/ngap_handler.go:247 +0x2d4
github.com/free5gc/smf/internal/sbi/processor.(*Processor).HandlePDUSessionSMContextUpdate(0xc000400ad0, 0xc0003e8400, {0xc000740008, {0x0, 0x0, 0x0}, {0xc00073c580, 0xc, 0x578}, {0x0, ...}}, ...)
	/home/xiaoyugan/5G/free5gc_test/NFs/smf/internal/sbi/processor/pdu_session.go:856 +0x1f6e
github.com/free5gc/smf/internal/sbi.(*Server).HTTPUpdateSmContext(0xc000298340, 0xc0003e8400)
	/home/xiaoyugan/5G/free5gc_test/NFs/smf/internal/sbi/api_pdusession.go:138 +0x32d
github.com/gin-gonic/gin.(*Context).Next(0xc0003e8400)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/context.go:185 +0x2b
github.com/free5gc/smf/internal/sbi.newRouter.InboundMetrics.func4(0xc0003e8400)
	/home/xiaoyugan/go/pkg/mod/github.com/free5gc/util@v1.2.0/metrics/middleware.go:15 +0x45
github.com/gin-gonic/gin.(*Context).Next(0xc0003e8400)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/context.go:185 +0x2b
github.com/free5gc/util/logger.NewGinWithLogrus.ginRecover.func2(0x4be95f?)
	/home/xiaoyugan/go/pkg/mod/github.com/free5gc/util@v1.2.0/logger/logger.go:330 +0x48
github.com/gin-gonic/gin.(*Context).Next(0xc0003e8400)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/context.go:185 +0x2b
github.com/free5gc/util/logger.NewGinWithLogrus.ginToLogrus.func1(0xc0003e8400)
	/home/xiaoyugan/go/pkg/mod/github.com/free5gc/util@v1.2.0/logger/logger.go:256 +0x65
github.com/gin-gonic/gin.(*Context).Next(...)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/context.go:185
github.com/gin-gonic/gin.(*Engine).handleHTTPRequest(0xc0003fc9c0, 0xc0003e8400)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/gin.go:633 +0x872
github.com/gin-gonic/gin.(*Engine).ServeHTTP(0xc0003fc9c0, {0x120cef8, 0xc000136268}, 0xc0002eb400)
	/home/xiaoyugan/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/gin.go:589 +0x1aa
golang.org/x/net/http2.(*serverConn).runHandler(0xc00061a700?, 0xc0004ff7d0?, 0x959b45?, 0xc0001d8780?)
	/home/xiaoyugan/go/pkg/mod/golang.org/x/net@v0.38.0/http2/server.go:2433 +0xf5
created by golang.org/x/net/http2.(*serverConn).scheduleHandler in goroutine 167
	/home/xiaoyugan/go/pkg/mod/golang.org/x/net@v0.38.0/http2/server.go:2367 +0x21d
2026-04-19T06:28:39.551599244-07:00 [INFO][SMF][GIN] | 500 |       127.0.0.1 | POST    | /nsmf-pdusession/v1/sm-contexts/urn:uuid:974fd278-9228-472d-880d-4009b0669fe7/modify |  |
2026-04-19T06:28:39.552297549-07:00 [ERRO][AMF][Ngap][amf_ue_ngap_id:RU:1,AU:1(3GPP)][ran_addr:127.0.0.1/192.168.213.132/10.10.10.12/10.10.10.22:52015] SendUpdateSmContextXnHandover[PathSwitchRequestTransfer] Error:
undefined response type
```


