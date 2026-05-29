# CVE Information

Vendor: OAI (https://gitlab.eurecom.fr/oai)

Affected Product: oai-cn5g-amf (Access and Mobility Management Function)

Affected Version: <= v2.2.1

Vulnerability Type: Buffer Overflow

Impact: Denial of Service (DoS)

Attack Vector: Remote (requires gNB connection)

## Proof of Concept (PoC)
Since the vulnerability is triggered in the deeper layers of the GMM procedure, where the UE's Authentication Response needs to calculate the RES* field using the random number sent by the core network in the current registration (no key is required, and any valid IMSI can complete this), it is not possible to provide a hardcoded PoC. Here, the trigger process is illustrated through root cause analysis, a sample packet capture, and a screenshot of the trigger.

In the AMF function uplink_nas_msg_handle(), the kAuthenticationFailure branch is excluded from the nc initialization logic, leaving nc as a null shared_ptr throughout.
<img width="1023" height="402" alt="图片" src="https://github.com/user-attachments/assets/e34da4c1-054a-4b0d-a80e-a80c3e1164fb" />

Then, in authentication_failure_handle(), the mm_cause <= 0 check treats the valid uint8_t value 0x00 as “missing” and directly returns false.
<img width="1047" height="285" alt="图片" src="https://github.com/user-attachments/assets/a639e22f-9b96-454c-b6b7-35d84130c83b" />

However, at the call site, when authentication_failure_handle() returns false, the corresponding handling path unconditionally invokes complete_common_procedure(*nc) without checking whether nc is valid.
<img width="876" height="212" alt="图片" src="https://github.com/user-attachments/assets/40653dd7-d9b3-4e84-a4af-fc7456f06b21" />

As a result, the attacker only needs to set the 5GMM Cause field to 0x00 to make authentication_failure_handle() return false, thereby triggering a null-pointer dereference.

## Description
Oai-cn5g-amf lacks pointer initialization for the Authentication Failure message handling path and also fails to check whether the pointer is null before use. As a result, an unauthenticated attacker can crash the AMF process with a single NAS message after gNB registration, rendering the authentication service of the entire 5G core network unavailable.

### Log File
```text
20:53:13 ubuntu kernel: oai_amf[1880271]: segfault at 39 ip 000055815af558e4 sp 00007f35ebffe7b8 error 4 in oai_amf[558159f42000+142e000]
20:53:13 ubuntu kernel: Code: 66 0f 1f 44 00 00 f3 0f 1e fa 88 56 38 c3 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 88 56 39 c3 0f 1f 84 00 00 00 00 00 f3 0f 1e fa <0f> b6 46 39 c6 46 39 00 c3 90 66 90 f3 0f 1e fa 0f b6 46 39 c6 46
20:53:13 ubuntu dockerd[1827]: time="2026-05-28T20:53:13.847666928-07:00" level=error msg="stream copy error: reading from a closed fifo"
20:53:13 ubuntu dockerd[1827]: time="2026-05-28T20:53:13.847709028-07:00" level=error msg="stream copy error: reading from a closed fifo"
20:53:13 ubuntu dockerd[1827]: time="2026-05-28T20:53:13.853351420-07:00" level=warning msg="Health check for container bf8e4f4619cefc1182428097d75130aab96260d8f47219a994ce0062e5901128 error: OCI runtime exec failed: exec failed: unable to create new parent process: namespace path: lstat /proc/1879894/ns/ipc: no such file or directory: unknown"
20:53:13 ubuntu dockerd[1827]: time="2026-05-28T20:53:13.868727500-07:00" level=info msg="ignoring event" container=bf8e4f4619cefc1182428097d75130aab96260d8f47219a994ce0062e5901128 module=libcontainerd namespace=moby topic=/tasks/delete type="*events.TaskDelete"
20:53:13 ubuntu containerd[1213]: time="2026-05-28T20:53:13.870206897-07:00" level=info msg="shim disconnected" id=bf8e4f4619cefc1182428097d75130aab96260d8f47219a994ce0062e5901128 namespace=moby
20:53:13 ubuntu containerd[1213]: time="2026-05-28T20:53:13.870295197-07:00" level=warning msg="cleaning up after shim disconnected" id=bf8e4f4619cefc1182428097d75130aab96260d8f47219a994ce0062e5901128 namespace=moby
20:53:13 ubuntu containerd[1213]: time="2026-05-28T20:53:13.870312297-07:00" level=info msg="cleaning up dead shim" namespace=moby
20:53:13 ubuntu systemd-networkd[602]: veth4f45646: Lost carrier
20:53:13 ubuntu kernel: demo-oai: port 4(veth4f45646) entered disabled state
20:53:13 ubuntu kernel: veth90641ea: renamed from eth0
20:53:14 ubuntu networkd-dispatcher[1097]: WARNING:Unknown index 73 seen, reloading interface list
20:53:14 ubuntu NetworkManager[1088]: <info>  [1780026794.0083] manager: (veth90641ea): new Veth device (/org/freedesktop/NetworkManager/Devices/99)
20:53:14 ubuntu systemd-udevd[2015301]: ethtool: autonegotiation is unset or enabled, the speed and duplex are not writable.
20:53:14 ubuntu systemd-udevd[2015301]: Using default interface naming scheme 'v245'.
20:53:14 ubuntu avahi-daemon[1080]: Interface veth4f45646.IPv6 no longer relevant for mDNS.
20:53:14 ubuntu avahi-daemon[1080]: Leaving mDNS multicast group on interface veth4f45646.IPv6 with address fe80::689a:2fff:fe7d:f0c2.
20:53:14 ubuntu systemd-networkd[602]: veth4f45646: Link DOWN
20:53:14 ubuntu kernel: demo-oai: port 4(veth4f45646) entered disabled state
20:53:14 ubuntu kernel: device veth4f45646 left promiscuous mode
20:53:14 ubuntu kernel: demo-oai: port 4(veth4f45646) entered disabled state
20:53:14 ubuntu systemd-networkd[602]: rtnl: received neighbor for link '74' we don't know about, ignoring.
20:53:14 ubuntu systemd-networkd[602]: rtnl: received neighbor for link '74' we don't know about, ignoring.
20:53:14 ubuntu avahi-daemon[1080]: Withdrawing address record for fe80::689a:2fff:fe7d:f0c2 on veth4f45646.
20:53:14 ubuntu NetworkManager[1088]: <info>  [1780026794.0464] device (veth4f45646): released from master device demo-oai
```
<img width="2202" height="1065" alt="7e7ffa1c2c0dbdb35798d2403348ff57" src="https://github.com/user-attachments/assets/9885c4cb-d04f-4540-8ab1-0de8a44855f0" />


