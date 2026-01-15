# CVE Information

Vendor: free5gc (https://free5gc.org)

Affected Product: free5gc AMF (Access and Mobility Management Function)

Affected Version: <= v4.1.0

Vulnerability Type: Other

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)
## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through a sample packet capture and a screenshot of the trigger.
<img width="1908" height="1449" alt="图片" src="https://github.com/user-attachments/assets/a9f65a75-01fc-492c-af7f-1677206d9278" />

## Description
The AMF performs an incorrect state transition under specific packet sequences. If a Registration Complete message is sent immediately after establishing a security context with the AMF, the AMF will directly transition from the context setup state to the registered state.

### Reference
- https://github.com/free5gc/free5gc/issues/808

### Log File

```text
2026-01-15T01:42:42.780076977-08:00 [INFO][AMF][Gmm] Handle event[SecurityMode Success], transition from [SecurityMode] to [ContextSetup]
2026-01-15T01:42:42.780117974-08:00 [INFO][AMF][Gmm][amf_ue_ngap_id:RU:1,AU:3(3GPP)][supi:SUPI:imsi-208930000000001] Handle InitialRegistration
2026-01-15T01:42:42.781215194-08:00 [INFO][NRF][Token] In HTTPAccessTokenRequest
2026-01-15T01:42:42.783185448-08:00 [WARN][NRF][Token] Certificate verify: x509: certificate signed by unknown authority (possibly because of "x509: invalid signature: parent certificate cannot sign this kind of certificate" while trying to verify candidate authority certificate "free5gc")
2026-01-15T01:42:42.783825401-08:00 [INFO][NRF][GIN] | 200 |       127.0.0.1 | POST    | /oauth2/token |  |
2026-01-15T01:42:42.784839826-08:00 [INFO][NRF][DISC] Handle NFDiscoveryRequest
2026-01-15T01:42:42.786077635-08:00 [INFO][NRF][GIN] | 200 |       127.0.0.1 | GET     | /nnrf-disc/v1/nf-instances?requester-nf-type=AMF&supi=imsi-208930000000001&target-nf-type=UDM |  |
2026-01-15T01:42:42.787449934-08:00 [INFO][NRF][Token] In HTTPAccessTokenRequest
2026-01-15T01:42:42.789085414-08:00 [WARN][NRF][Token] Certificate verify: x509: certificate signed by unknown authority (possibly because of "x509: invalid signature: parent certificate cannot sign this kind of certificate" while trying to verify candidate authority certificate "free5gc")
2026-01-15T01:42:42.790533507-08:00 [INFO][NRF][GIN] | 200 |       127.0.0.1 | POST    | /oauth2/token |  |
2026-01-15T01:42:42.792056395-08:00 [INFO][UDM][Consumer] TwoLayerPathHandlerFunc,  imsi-208930000000001 nssai
2026-01-15T01:42:42.792095792-08:00 [INFO][UDM][SDM] Handle GetNssai
2026-01-15T01:42:42.793021624-08:00 [INFO][NRF][Token] In HTTPAccessTokenRequest
2026-01-15T01:42:42.794776294-08:00 [WARN][NRF][Token] Certificate verify: x509: certificate signed by unknown authority (possibly because of "x509: invalid signature: parent certificate cannot sign this kind of certificate" while trying to verify candidate authority certificate "free5gc")
2026-01-15T01:42:42.796738450-08:00 [INFO][NRF][GIN] | 200 |       127.0.0.1 | POST    | /oauth2/token |  |
2026-01-15T01:42:42.798270337-08:00 [INFO][UDR][DataRepo] QueryAmDataProcedure: ueId: imsi-208930000000001, servingPlmnId: 20893
2026-01-15T01:42:42.798986984-08:00 [INFO][UDR][GIN] | 200 |       127.0.0.1 | GET     | /nudr-dr/v2/subscription-data/imsi-208930000000001/20893/provisioned-data/am-data?supported-features= |  |
2026-01-15T01:42:42.799349857-08:00 [INFO][UDM][GIN] | 200 |       127.0.0.1 | GET     | /nudm-sdm/v2/imsi-208930000000001/nssai?plmn-id=%7B%22mcc%22%3A%22208%22%2C%22mnc%22%3A%2293%22%7D |  |
2026-01-15T01:42:42.799791125-08:00 [INFO][AMF][Gmm][amf_ue_ngap_id:RU:1,AU:3(3GPP)][supi:SUPI:imsi-208930000000001] Send Identity Request
2026-01-15T01:42:42.799847521-08:00 [INFO][AMF][Ngap][amf_ue_ngap_id:RU:1,AU:3(3GPP)][ran_addr:127.0.0.1/10.10.10.22/10.10.10.12/192.168.213.132:48247] Send Downlink Nas Transport
2026-01-15T01:42:42.800897443-08:00 [INFO][AMF][Ngap][ran_addr:127.0.0.1/10.10.10.22/10.10.10.12/192.168.213.132:48247] Handle UplinkNASTransport
2026-01-15T01:42:42.800931541-08:00 [INFO][AMF][Ngap][amf_ue_ngap_id:RU:1,AU:3(3GPP)][ran_addr:127.0.0.1/10.10.10.22/10.10.10.12/192.168.213.132:48247] Handle UplinkNASTransport (RAN UE NGAP ID: 1)
2026-01-15T01:42:42.800991936-08:00 [INFO][AMF][Gmm] Handle event[Gmm Message], transition from [ContextSetup] to [ContextSetup]
2026-01-15T01:42:42.801017534-08:00 [INFO][AMF][Gmm][amf_ue_ngap_id:RU:1,AU:3(3GPP)][supi:SUPI:imsi-208930000000001] Handle Registration Complete
2026-01-15T01:42:42.801056231-08:00 [INFO][AMF][Gmm][amf_ue_ngap_id:RU:1,AU:3(3GPP)][supi:SUPI:imsi-208930000000001] Send Configuration Update Command
2026-01-15T01:42:42.801083529-08:00 [INFO][AMF][Ngap][amf_ue_ngap_id:RU:1,AU:3(3GPP)][ran_addr:127.0.0.1/10.10.10.22/10.10.10.12/192.168.213.132:48247] Send Downlink Nas Transport
2026-01-15T01:42:42.801176423-08:00 [INFO][AMF][Gmm] Handle event[ContextSetup Success], transition from [ContextSetup] to [Registered]
2026-01-15T01:42:42.801352910-08:00 [INFO][AMF][Ngap][ran_addr:127.0.0.1/10.10.10.22/10.10.10.12/192.168.213.132:48247] Handle UplinkNASTransport
```

