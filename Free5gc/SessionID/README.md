# CVE Information

Vendor: free5gc (https://free5gc.org)

Affected Product: free5gc AMF (Access and Mobility Management Function)

Affected Version: <= v4.1.0

Vulnerability Type: Buffer Overflow

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)
## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), 
it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through root cause analysis, a sample packet capture, and a screenshot of the trigger.

In the CreatePDUSession function, the code does not check the range of the PDU Session ID and directly uses it to create and store the SmContext.
<img width="1131" height="471" alt="图片" src="https://github.com/user-attachments/assets/c3670034-ebbd-40ab-a07a-d323fe5cf5e3" />
Therefore, a session with ID=20 can be successfully established and stored in ue.SmContextList.
<img width="1374" height="170" alt="图片" src="https://github.com/user-attachments/assets/639d3c4a-a067-4d5e-967f-da4f0625a806" />
When a Service Request contains UplinkDataStatus or PDUSessionStatus, a crash occurs in the releaseInactivePDUSession function due to out-of-bounds read and out-of-bounds write operations.
<img width="1560" height="555" alt="图片" src="https://github.com/user-attachments/assets/f6026a5c-0ab3-45ed-99f9-7ceba369211a" />
<img width="1647" height="390" alt="图片" src="https://github.com/user-attachments/assets/8c5b3d6e-f168-4bcd-aa20-553b56c91b2b" />

<img width="1638" height="873" alt="图片" src="https://github.com/user-attachments/assets/3fef5e82-6634-460a-9d07-4182fe35dbe3" />

## Description
When the AMF receives a PDU session establishment request carrying an illegal PDU session ID IE and subsequently receives any message (such as a Service Request) that triggers the traversal of SmContextList.Range and uses the pduSessionID as an array index from a gNB, the AMF process crashes.

### Reference
- https://github.com/free5gc/free5gc/issues/795

### Log File

```text
2026-01-13T18:53:20.864905012-08:00 [FATA][AMF][Ngap] panic: runtime error: index out of range [20] with length 16
goroutine 32 [running]:
runtime/debug.Stack()
	/home/xiaoyugan/sdk/go1.24.1/src/runtime/debug/stack.go:26 +0x5e
github.com/free5gc/amf/internal/ngap/service.handleConnection.func1()
	/home/xiaoyugan/free5gc/NFs/amf/internal/ngap/service/service.go:186 +0x45
panic({0x104ec40?, 0xc00039d3f8?})
	/home/xiaoyugan/sdk/go1.24.1/src/runtime/panic.go:792 +0x132
github.com/free5gc/amf/internal/gmm.reactivatePendingULDataPDUSession.func1({0xeba280?, 0x12be020?}, {0x10a2580?, 0xc0005c8000?})
	/home/xiaoyugan/free5gc/NFs/amf/internal/gmm/handler.go:1335 +0x58b
internal/sync.(*HashTrieMap[...]).iter(0x12b9820, 0xc000856d20, 0xc00065b250)
	/home/xiaoyugan/sdk/go1.24.1/src/internal/sync/hashtriemap.go:512 +0xea
internal/sync.(*HashTrieMap[...]).Range(0x10f4923?, 0xb?)
	/home/xiaoyugan/sdk/go1.24.1/src/internal/sync/hashtriemap.go:495 +0x57
sync.(*Map).Range(...)
	/home/xiaoyugan/sdk/go1.24.1/src/sync/hashtriemap.go:115
github.com/free5gc/amf/internal/gmm.reactivatePendingULDataPDUSession(0xc000056a08?, {0x10f4923?, 0xc00065b318?}, 0x3f?, 0x496c85?, 0x65b328?, 0xc00065b378?, 0xc00065b378?, {0x0, 0x0, ...}, ...)
	/home/xiaoyugan/free5gc/NFs/amf/internal/gmm/handler.go:1330 +0x9b
github.com/free5gc/amf/internal/gmm.HandleServiceRequest(0xc000174608, {0x10f4923, 0xb}, 0xc0007ba240)
	/home/xiaoyugan/free5gc/NFs/amf/internal/gmm/handler.go:1818 +0x19ad
github.com/free5gc/amf/internal/gmm.Registered(0xc0005d8960, {0x10f50be, 0xb}, 0xc0007ba2a0)
	/home/xiaoyugan/free5gc/NFs/amf/internal/gmm/sm.go:109 +0x628
github.com/free5gc/util/fsm.(*FSM).SendEvent(0xc00051aea0, 0xc0005d8960, {0x10f50be, 0xb}, 0xc0007ba2a0, 0xc000517260)
	/home/xiaoyugan/go/pkg/mod/github.com/free5gc/util@v1.2.0/fsm/fsm.go:124 +0x2c5
github.com/free5gc/amf/internal/nas.Dispatch(0xc000174608, {0x10f4923, 0xb}, 0x2e, 0xc000376760)
	/home/xiaoyugan/free5gc/NFs/amf/internal/nas/dispatch.go:28 +0x23b
github.com/free5gc/amf/internal/nas.HandleNAS(0xc0002a62c0, 0x2e, {0xc00039d3c8, 0x18, 0x18}, 0x0?)
	/home/xiaoyugan/free5gc/NFs/amf/internal/nas/handler.go:71 +0x40d
github.com/free5gc/amf/internal/ngap.handleUplinkNASTransportMain(0xc0000f5260?, 0xc0002a62c0, 0xc00000f068?, 0x100?)
	/home/xiaoyugan/free5gc/NFs/amf/internal/ngap/handler.go:124 +0x6a
github.com/free5gc/amf/internal/ngap.handlerUplinkNASTransport(0xc00011e000, 0xc0008be000)
	/home/xiaoyugan/free5gc/NFs/amf/internal/ngap/handler_generated.go:11684 +0x12c5
github.com/free5gc/amf/internal/ngap.dispatchMain(0xc00011e000, 0x43?)
	/home/xiaoyugan/free5gc/NFs/amf/internal/ngap/dispatcher_generated.go:112 +0x2cd
github.com/free5gc/amf/internal/ngap.Dispatch({0x12a94b0, 0xc0000b6010}, {0xc000980000, 0x43, 0x40000})
	/home/xiaoyugan/free5gc/NFs/amf/internal/ngap/dispatcher.go:49 +0x1d5
github.com/free5gc/amf/internal/ngap/service.handleConnection(0xc0000b6010, 0x40000, {0x11572a0?, 0x11572b0?, 0x11572a8?})
	/home/xiaoyugan/free5gc/NFs/amf/internal/ngap/service/service.go:239 +0x3d5
created by github.com/free5gc/amf/internal/ngap/service.listenAndServe in goroutine 34
	/home/xiaoyugan/free5gc/NFs/amf/internal/ngap/service/service.go:160 +0x88a
```

