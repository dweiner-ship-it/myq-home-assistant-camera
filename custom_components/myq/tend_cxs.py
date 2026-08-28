from __future__ import annotations

import asyncio
import logging
import re
import ssl
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from uuid import uuid4

_LOGGER = logging.getLogger(__name__)
_SSL_CONTEXT = ssl.create_default_context()

LOGIN_HOST = "server.tend-us.tendplatform.com"
LOGIN_PORT = 5104
ACTION_COMMAND = 411
ACTION_LOGIN = 519
ACTION_KEEPALIVE = 526
CLIENT_TYPE_PLUTO = 121
FIXED_HEADER = 27
SESSION_OPTIONS_SIZE = 16
MAX_PACKET = 2 * 1024 * 1024

AccessTokenProvider = Callable[[], Awaitable[str]]


@dataclass(slots=True)
class CxsPacket:
    action: int
    body: bytes = b""
    options: bytes = bytes(SESSION_OPTIONS_SIZE)
    source: bytes = b""
    result: int = 2
    client_type: int = CLIENT_TYPE_PLUTO
    destination: bytes = b"**"
    target_id: int = 0
    version: int = 3


@dataclass(frozen=True, slots=True)
class TendCamera:
    device_id: str
    alias: str
    aes_key: str
    online: bool
    local_ip: str
    local_port: int
    cxs_destination: str


@dataclass(frozen=True, slots=True)
class ConnectionInfo:
    mode: int
    peer_ip: str
    peer_port: int
    relay_host: str
    relay_port: int
    p2p_host: str
    p2p_udp_port: int
    p2p_tcp_port: int
    aes_key: str
    cxs_destination: str
    correlation: str


def _escape_property(value: str, key: bool = False) -> str:
    out: list[str] = []
    for index, character in enumerate(value):
        if character == "\\":
            out.append("\\\\")
        elif character == "\t":
            out.append("\\t")
        elif character == "\n":
            out.append("\\n")
        elif character == "\r":
            out.append("\\r")
        elif character == "\f":
            out.append("\\f")
        elif character in "=:" or (key and character in " #!"):
            out.append("\\" + character)
        elif character == " " and index == 0:
            out.append("\\ ")
        elif ord(character) < 0x20 or ord(character) > 0x7E:
            out.append(f"\\u{ord(character):04x}")
        else:
            out.append(character)
    return "".join(out)


def _store_properties(values: dict[str, str]) -> bytes:
    lines = ["#myq-ha-camera"]
    lines.extend(
        f"{_escape_property(key, True)}={_escape_property(value)}"
        for key, value in values.items()
    )
    return ("\n".join(lines) + "\n").encode("latin1")


def _unescape_property(value: str) -> str:
    def repl(match: re.Match[str]) -> str:
        escaped = match.group(1)
        if escaped.startswith("u") and len(escaped) == 5:
            return chr(int(escaped[1:], 16))
        return {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}.get(escaped, escaped)

    return re.sub(r"\\(u[0-9a-fA-F]{4}|.)", repl, value)


def _load_properties(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    logical = ""
    for physical in data.decode("latin1", errors="replace").splitlines():
        logical += physical
        if logical.endswith("\\") and not logical.endswith("\\\\"):
            logical = logical[:-1]
            continue
        line, logical = logical, ""
        stripped = line.lstrip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        split_at = -1
        escaped = False
        for index, character in enumerate(line):
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character in "=:" or character.isspace():
                split_at = index
                break
        if split_at < 0:
            key, value = line, ""
        else:
            key = line[:split_at]
            value = line[split_at + 1 :].lstrip()
            if value.startswith(("=", ":")):
                value = value[1:].lstrip()
        result[_unescape_property(key)] = _unescape_property(value)
    return result


def _encode_packet(value: CxsPacket) -> bytes:
    if len(value.options) % 16 != 0 or len(value.destination) != 2:
        raise ValueError("invalid CXS packet")
    header_length = FIXED_HEADER + len(value.options) + len(value.source)
    if header_length > 0xFFFF or len(value.body) > MAX_PACKET:
        raise ValueError("CXS packet too large")
    header = bytearray(FIXED_HEADER)
    header[0] = 0x41
    header[1] = value.version
    struct.pack_into("<H", header, 2, header_length)
    struct.pack_into("<H", header, 4, len(value.options))
    header[6] = 0
    struct.pack_into("<I", header, 7, len(value.body))
    struct.pack_into("<H", header, 11, value.client_type)
    struct.pack_into("<H", header, 13, value.action)
    struct.pack_into("<H", header, 15, value.result)
    header[17:19] = value.destination
    struct.pack_into("<Q", header, 19, value.target_id)
    return bytes(header) + value.options + value.source + value.body


async def _read_packet(reader: asyncio.StreamReader, timeout: float = 10.0) -> CxsPacket:
    fixed = await asyncio.wait_for(reader.readexactly(FIXED_HEADER), timeout)
    if fixed[0] != 0x41:
        raise RuntimeError("invalid CXS marker")
    header_length = struct.unpack_from("<H", fixed, 2)[0]
    options_length = struct.unpack_from("<H", fixed, 4)[0]
    body_length = struct.unpack_from("<I", fixed, 7)[0]
    source_length = header_length - FIXED_HEADER - options_length
    if source_length < 0 or header_length + body_length > MAX_PACKET:
        raise RuntimeError("invalid CXS lengths")
    rest = await asyncio.wait_for(
        reader.readexactly(options_length + source_length + body_length), timeout
    )
    options = rest[:options_length]
    source = rest[options_length : options_length + source_length]
    body = rest[options_length + source_length :]
    return CxsPacket(
        action=struct.unpack_from("<H", fixed, 13)[0],
        body=body,
        options=options,
        source=source,
        result=struct.unpack_from("<H", fixed, 15)[0],
        client_type=struct.unpack_from("<H", fixed, 11)[0],
        destination=fixed[17:19],
        target_id=struct.unpack_from("<Q", fixed, 19)[0],
        version=fixed[1],
    )


class TendCxsClient:
    def __init__(self, access_token_provider: AccessTokenProvider, expected_device_id: str | None = None) -> None:
        self._access_token_provider = access_token_provider
        self._expected_device_id = expected_device_id
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._options = bytes(SESSION_OPTIONS_SIZE)
        self._properties: dict[str, str] = {}
        self._camera: TendCamera | None = None
        self._lock = asyncio.Lock()

    @property
    def camera(self) -> TendCamera | None:
        return self._camera

    def _login_packet(self, access_token: str) -> CxsPacket:
        source = _store_properties(
            {
                "partner-id": "myQ",
                "CX_UNAME": "",
                "client_type": "Python myqcam",
                "sdk_version": "2.1.0.56",
                "CX_PASSWD": f"myQ.accessToken:{access_token}",
                "current_version": "5.243.1.73243",
                "os_name": "Python",
                "app-id": "com.chamberlain.android.liftmaster.myq",
                "os_version": "device-free",
            }
        )
        mode = _store_properties({"CX_UNAME": "", "mode": "0"})
        return CxsPacket(action=ACTION_LOGIN, source=source, body=mode + mode)

    async def _connect(self, host: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(
                host=host,
                port=LOGIN_PORT,
                ssl=_SSL_CONTEXT,
                server_hostname=LOGIN_HOST,
            ),
            10.0,
        )

    async def async_login(self) -> TendCamera | None:
        async with self._lock:
            if self._writer is not None and self._camera is not None:
                return self._camera
            await self.async_close()
            token = await self._access_token_provider()
            login = self._login_packet(token)
            try:
                reader, writer = await self._connect(LOGIN_HOST)
                writer.write(_encode_packet(login))
                await writer.drain()
                redirect = await _read_packet(reader, 6.0)
                redirect_properties = _load_properties(redirect.body)
                redirect_host = redirect_properties.get("redirectHost")
                if not redirect_host:
                    numbered = next(
                        (
                            value
                            for key, value in redirect_properties.items()
                            if key.isdigit()
                        ),
                        None,
                    )
                    if numbered:
                        redirect_host = numbered.rsplit(":", 1)[0]
                writer.close()
                await writer.wait_closed()
                if not redirect_host:
                    raise RuntimeError("CXS redirect missing")

                reader, writer = await self._connect(redirect_host)
                await asyncio.sleep(0.25)
                writer.write(_encode_packet(login))
                await writer.drain()

                session_properties: dict[str, str] | None = None
                options = bytes(SESSION_OPTIONS_SIZE)
                for _ in range(5):
                    response = await _read_packet(reader, 6.0)
                    properties = _load_properties(response.body)
                    if properties.get("sid") or properties.get("session-id"):
                        session_properties = properties
                        options = response.options
                        break
                if session_properties is None:
                    writer.close()
                    await writer.wait_closed()
                    raise RuntimeError("CXS session missing")

                self._reader = reader
                self._writer = writer
                self._properties = session_properties
                self._options = options
                self._camera = self._select_video_keypad(session_properties)
                return self._camera
            except Exception as error:
                await self.async_close()
                _LOGGER.warning(
                    "MyQ camera signaling login failed (stage=cxs_login, error_type=%s)",
                    type(error).__name__,
                )
                return None

    def _select_video_keypad(self, properties: dict[str, str]) -> TendCamera | None:
        aliases: dict[str, str] = {}
        for line in properties.get("self-list", "").splitlines():
            fields = line.split(",")
            if fields and ":" in fields[0] and len(fields) >= 6:
                aliases[fields[0]] = fields[5]

        candidates: list[TendCamera] = []
        candidate_profiles: list[dict[str, object]] = []
        for line in properties.get("device-info-list", "").splitlines():
            comma = line.find(",")
            if comma < 0:
                continue
            destination = line[:comma]
            if ":" not in destination:
                continue
            device_id = destination.split(":", 1)[0]
            alias = aliases.get(destination, "")
            raw: dict[str, str] = {}
            for item in line[comma + 1 :].split("+"):
                if "=" in item:
                    key, value = item.split("=", 1)
                    raw[key] = value
            local_port = 0
            try:
                local_port = int(raw.get("LPORT", "0"))
            except ValueError:
                pass
            candidates.append(
                TendCamera(
                    device_id=device_id,
                    alias=alias,
                    aes_key=raw.get("AES", ""),
                    online=raw.get("PWR_SLEEP_MODE") != "DEEP",
                    local_ip=raw.get("LIP", ""),
                    local_port=local_port,
                    cxs_destination=destination,
                )
            )
            alias_folded = alias.strip().casefold()
            identity_keys = sorted(
                key
                for key in raw
                if any(
                    token in key.upper()
                    for token in ("MODEL", "TYPE", "PRODUCT", "SERIAL", "NAME", "DEVICE")
                )
            )
            candidate_profiles.append(
                {
                    "slot": len(candidates),
                    "id_length": len("".join(ch for ch in device_id if ch.isalnum())),
                    "alias_present": bool(alias_folded),
                    "alias_length": len(alias.strip()),
                    "alias_has_video": "video" in alias_folded,
                    "alias_has_keypad": "keypad" in alias_folded,
                    "alias_has_garage": "garage" in alias_folded,
                    "has_aes": bool(raw.get("AES")),
                    "has_local_ip": bool(raw.get("LIP")),
                    "has_local_port": bool(raw.get("LPORT")),
                    "has_mac": bool(raw.get("MAC")),
                    "deep_sleep": raw.get("PWR_SLEEP_MODE") == "DEEP",
                    "identity_keys": identity_keys,
                    "capability_key_count": len(raw),
                }
            )

        def normalized(value: str) -> str:
            return "".join(ch for ch in value.casefold() if ch.isalnum())

        exact_matches: list[TendCamera] = []
        if self._expected_device_id is not None:
            expected = normalized(self._expected_device_id)
            exact_matches = [
                camera for camera in candidates if normalized(camera.device_id) == expected
            ]
            if len(exact_matches) == 1:
                _LOGGER.debug("MyQ camera selected (selection=expected_id)")
                return exact_matches[0]

        alias_matches = [
            camera
            for camera in candidates
            if camera.alias.strip().casefold() == "video keypad"
        ]
        if len(alias_matches) == 1:
            _LOGGER.debug("MyQ camera selected (selection=video_keypad_alias)")
            return alias_matches[0]

        _LOGGER.warning(
            "MyQ camera selector found no unique Video Keypad match "
            "(candidate_count=%d, exact_id_matches=%d, alias_matches=%d)",
            len(candidates),
            len(exact_matches),
            len(alias_matches),
        )
        expected_normalized = (
            normalized(self._expected_device_id)
            if self._expected_device_id is not None
            else ""
        )
        for camera, profile in zip(candidates, candidate_profiles, strict=True):
            candidate_normalized = normalized(camera.device_id)
            profile["expected_contains_candidate"] = bool(
                expected_normalized
                and candidate_normalized
                and candidate_normalized in expected_normalized
            )
            profile["candidate_contains_expected"] = bool(
                expected_normalized
                and candidate_normalized
                and expected_normalized in candidate_normalized
            )
            profile["common_prefix_length"] = next(
                (
                    index
                    for index, pair in enumerate(
                        zip(expected_normalized, candidate_normalized, strict=False)
                    )
                    if pair[0] != pair[1]
                ),
                min(len(expected_normalized), len(candidate_normalized)),
            )
            profile["common_suffix_length"] = next(
                (
                    index
                    for index, pair in enumerate(
                        zip(expected_normalized[::-1], candidate_normalized[::-1], strict=False)
                    )
                    if pair[0] != pair[1]
                ),
                min(len(expected_normalized), len(candidate_normalized)),
            )
            _LOGGER.warning("MyQ camera candidate profile: %s", profile)
        return None

    def _connection_info(
        self, camera: TendCamera, offer: CxsPacket, correlation: str
    ) -> ConnectionInfo:
        relay = re.search(rb"rtp://([^:/]+):(\d+)", offer.source)
        p2p = self._properties.get("p2p-host", "").split(":")
        relay_host = relay.group(1).decode("ascii", errors="ignore") if relay else ""
        relay_port = int(relay.group(2)) if relay else 0
        return ConnectionInfo(
            mode=9 if camera.aes_key else 8,
            peer_ip=camera.local_ip,
            peer_port=camera.local_port,
            relay_host=relay_host,
            relay_port=relay_port,
            p2p_host=p2p[0] if p2p else "",
            p2p_udp_port=int(p2p[1]) if len(p2p) > 1 and p2p[1].isdigit() else 0,
            p2p_tcp_port=int(p2p[2]) if len(p2p) > 2 and p2p[2].isdigit() else 0,
            aes_key=camera.aes_key,
            cxs_destination=camera.cxs_destination,
            correlation=correlation,
        )

    async def _send_command(
        self, command: str, destination: str, correlation: str | None = None
    ) -> str:
        if self._writer is None:
            raise RuntimeError("CXS not connected")
        correlation = correlation or f"LOG-{uuid4().hex}"
        packet = CxsPacket(
            action=ACTION_COMMAND,
            options=self._options,
            source=_store_properties(
                {"CorrelationID": correlation, "CX_DSTID": destination}
            ),
            body=command.encode(),
        )
        self._writer.write(_encode_packet(packet))
        await self._writer.drain()
        return correlation

    async def _wait_for(self, prefix: bytes, timeout: float = 15.0) -> CxsPacket:
        if self._reader is None:
            raise RuntimeError("CXS not connected")
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError
            packet = await _read_packet(self._reader, remaining)
            if packet.body.startswith(prefix):
                return packet

    async def async_get_video_connection(
        self, camera: TendCamera
    ) -> ConnectionInfo:
        correlation = await self._send_command(
            f"require-video-send|{camera.device_id}|9|",
            camera.cxs_destination,
        )
        offer = await self._wait_for(b"accept-video-receive|")
        return self._connection_info(camera, offer, correlation)

    async def async_start_video(
        self, camera: TendCamera, info: ConnectionInfo
    ) -> None:
        await self._send_command(
            f"start-video-receive|{camera.device_id}|9|",
            camera.cxs_destination,
            info.correlation,
        )
        await self._send_command(
            f"modify-device|{camera.device_id}|QTY=3+FPS=20+SIZE=0+SAVE=0|",
            camera.cxs_destination,
        )

    async def async_stop_video(
        self, camera: TendCamera, info: ConnectionInfo
    ) -> None:
        if self._writer is None:
            return
        try:
            await self._send_command(
                f"stop-video-receive|{camera.device_id}|9|",
                camera.cxs_destination,
                info.correlation,
            )
        except Exception:
            _LOGGER.debug("MyQ camera stop signaling failed")

    async def async_keepalive(self) -> None:
        if self._writer is None:
            return
        self._writer.write(
            _encode_packet(CxsPacket(action=ACTION_KEEPALIVE, options=self._options))
        )
        await self._writer.drain()

    async def async_close(self) -> None:
        writer = self._writer
        self._reader = None
        self._writer = None
        self._camera = None
        self._properties = {}
        self._options = bytes(SESSION_OPTIONS_SIZE)
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
