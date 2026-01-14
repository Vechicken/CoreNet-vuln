#Bug Decription

free5GC AMF crashes when it receives an out-of-sequence NAS message during the registration procedure.

Specifically, after the AMF enters the state Waiting for IdentityResponse (after processing Security Mode Complete), sending a UplinkNASTransport that carries a Registration Complete NAS message causes the AMF process to crash.

This appears to be a missing state/transition validation (or missing nil/defensive checks) for handling Registration Complete when the UE has not yet completed the expected Identity Response step.
