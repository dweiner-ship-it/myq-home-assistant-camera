# MyQ Home Assistant Camera

Private HACS fork of `bvdcode/myq-home-assistant` with experimental **Video Keypad** TC-series camera support. Existing garage-door controls remain unchanged.

## Scope
- Exact Tend alias match: `Video Keypad` and TC-series device ID required.
- Video only for the first release; no audio or talkback.
- Never falls back to the unrelated `falcon-camera` record.
- Uses Tend CXS signaling, SDNK UDP hole punching, AES-128-CBC decryption, H.264 decoding with PyAV, and JPEG frames through Home Assistant camera APIs.
- OAuth tokens remain owned by the existing MyQ auth object; camera code does not persist or log OAuth tokens, AES keys, device IDs, MACs, IP addresses, relay endpoints, or session identifiers.

## Rollback
Remove this custom repository and reinstall upstream `bvdcode/myq-home-assistant`. The config-entry storage schema is unchanged.

Experimental interoperability code for hardware owned by the repository owner.
