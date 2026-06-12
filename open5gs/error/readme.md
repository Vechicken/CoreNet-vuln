# CVE Information

Vendor: open5gs (https://open5gs.org)

Affected Product: open5gs AMF (Access and Mobility Management Function)

Affected Version: <= v2.7.7

Vulnerability Type: Buffer Overflow

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)
## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through root cause analysis, a sample packet capture, and a screenshot of the trigger.

Vulnerable code (src/amf/ngap-handler.c):
```c
// ngap-handler.c:5084-5115
if (ran_ue) {
    amf_ue_t *amf_ue = NULL;
    int xact_count = 0;

    ogs_warn("    Performing local release for "
            "RAN_UE_NGAP_ID[%lld] AMF_UE_NGAP_ID[%lld]",
            (long long)ran_ue->ran_ue_ngap_id,
            (long long)ran_ue->amf_ue_ngap_id);

    amf_ue = amf_ue_find_by_id(ran_ue->amf_ue_id);
    if (amf_ue) {                                       // (1) 
        CLEAR_AMF_UE_ALL_TIMERS(amf_ue);

        xact_count = amf_sess_xact_count(amf_ue);

        amf_sbi_send_deactivate_all_sessions(           // (2)
                ran_ue, amf_ue,
                AMF_REMOVE_N2_CONTEXT_BY_ERROR_INDICATION,
                Cause->present,                         // (3) NULL deref
                (int)Cause->choice.radioNetwork);       // (3) NULL deref
        ...
    }
}
```

Steps to reproduce
1. Complete normal registration
2. Send a ErrorIndication without Cause IE
3. Observe AMF crashes


Vulnerable packet:
	in appendix

Screen shot:
<img width="1386" height="474" alt="图片" src="https://github.com/user-attachments/assets/39199f77-a45a-47f3-bb43-4bea09f67483" />



## Description
In the AMF’s ngap_handle_error_indication() function, when a UE context exists, Open5GS AMF crashes due to a NULL pointer dereference of the Cause field when processing an NGAP Error Indication message sent by the gNB with a missing Cause IE.

### Reference
- https://github.com/open5gs/open5gs/issues/4619

### Log File

```text
06/12 07:29:27.586: [sbi] INFO: [4354dbbe-65fc-41f1-9540-2b309c17215c] Setup NF Instance [type:PCF] (../lib/sbi/path.c:307)
06/12 07:29:27.587: [scp] INFO: Setup NF EndPoint(addr) [127.0.0.13:7777] (../src/scp/sbi-path.c:463)
06/12 07:29:27.587: [pcf] WARNING: UnRef NF EndPoint(addr) [127.0.0.5:7777] (../src/pcf/npcf-handler.c:114)
06/12 07:29:27.587: [pcf] INFO: Setup NF EndPoint(addr) [127.0.0.5:7777] (../src/pcf/npcf-handler.c:114)
06/12 07:29:27.587: [scp] INFO: Setup NF EndPoint(addr) [127.0.0.20:7777] (../src/scp/sbi-path.c:463)
06/12 07:29:27.589: [amf] INFO: Setup NF EndPoint(addr) [127.0.0.13:7777] (../src/amf/npcf-handler.c:143)
06/12 07:29:27.590: [gmm] INFO: [imsi-999700000000007] Registration complete (../src/amf/gmm-sm.c:3146)
06/12 07:29:27.590: [amf] INFO: [imsi-999700000000007] Configuration update command (../src/amf/nas-path.c:609)
06/12 07:29:27.590: [gmm] INFO:     UTC [2026-06-12T14:29:27] Timezone[0]/DST[0] (../src/amf/gmm-build.c:551)
06/12 07:29:27.590: [gmm] INFO:     LOCAL [2026-06-12T07:29:27] Timezone[-25200]/DST[1] (../src/amf/gmm-build.c:556)
06/12 07:29:27.591: [amf] WARNING: ErrorIndication (../src/amf/ngap-handler.c:5026)
06/12 07:29:27.591: [amf] WARNING:     IP[127.0.0.1] RAN_ID[16] (../src/amf/ngap-handler.c:5045)
06/12 07:29:27.591: [amf] WARNING:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[1] (../src/amf/ngap-handler.c:5064)
06/12 07:29:27.591: [amf] WARNING:     Performing local release for RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[1] (../src/amf/ngap-handler.c:5088)
Segmentation fault
```




