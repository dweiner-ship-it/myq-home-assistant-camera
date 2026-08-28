from __future__ import annotations

import asyncio
import hashlib
import io
import logging
from collections.abc import Awaitable, Callable
from contextlib import suppress

import av

from .tend_cxs import TendCxsClient, TendCamera, ConnectionInfo
from .tend_p2p import P2PVideoSession

_LOGGER = logging.getLogger(__name__)
AccessTokenProvider = Callable[[], Awaitable[str]]

NAL_IDR = 5
NAL_SPS = 7
NAL_PPS = 8


def _nals(data: bytes) -> list[tuple[int, bytes]]:
    starts: list[int] = []
    index = 0
    while index + 3 <= len(data):
        if data[index : index + 3] == b"\x00\x00\x01":
            starts.append(index)
            index += 3
        elif index + 4 <= len(data) and data[index : index + 4] == b"\x00\x00\x00\x01":
            starts.append(index)
            index += 4
        else:
            index += 1
    result: list[tuple[int, bytes]] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(data)
        nal = data[start:end]
        offset = 3 if nal[2] == 1 else 4
        if len(nal) > offset:
            result.append((nal[offset] & 0x1F, nal))
    return result


class TendCameraManager:
    def __init__(self, access_token_provider: AccessTokenProvider, expected_device_id: str | None = None) -> None:
        self._cxs = TendCxsClient(access_token_provider, expected_device_id)
        self._expected_device_id = expected_device_id
        self._camera: TendCamera | None = None
        self._info: ConnectionInfo | None = None
        self._p2p: P2PVideoSession | None = None
        self._open_lock = asyncio.Lock()
        self._latest_jpeg: bytes | None = None
        self._latest_frame_at = 0.0
        self._new_frame = asyncio.Event()
        self._record_queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=8)
        self._worker_task: asyncio.Task[None] | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._idle_task: asyncio.Task[None] | None = None
        self._decoder: av.CodecContext | None = None
        self._sps: bytes | None = None
        self._pps: bytes | None = None
        self._gate_open = False
        self._records_seen = 0
        self._nal_units_seen = 0
        self._sps_seen = 0
        self._pps_seen = 0
        self._idr_seen = 0
        self._decode_attempts = 0
        self._decode_errors = 0
        self._decoded_jpegs = 0
        self._last_release_at = 0.0
        self._closed = False
        self._discovered = False
        self._unique_id: str | None = (
            "video-keypad-" + hashlib.sha256(expected_device_id.encode()).hexdigest()[:16]
            if expected_device_id
            else None
        )

    @property
    def discovered(self) -> bool:
        return self._discovered

    @property
    def unique_id(self) -> str | None:
        return self._unique_id

    async def async_discover(self) -> bool:
        if self._closed:
            return False
        camera = await self._cxs.async_login()
        if camera is None:
            self._discovered = False
            return False
        self._camera = camera
        self._unique_id = "video-keypad-" + hashlib.sha256(
            camera.device_id.encode()
        ).hexdigest()[:16]
        self._discovered = True
        if self._keepalive_task is None or self._keepalive_task.done():
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())
        return True

    async def async_get_image(self, timeout: float = 12.0) -> bytes | None:
        if self._closed:
            return None
        loop = asyncio.get_running_loop()
        if self._latest_jpeg is not None and loop.time() - self._latest_frame_at < 2.0:
            self._arm_idle_close()
            return self._latest_jpeg

        if not await self._ensure_open():
            return self._latest_jpeg

        self._new_frame.clear()
        if self._latest_jpeg is not None and loop.time() - self._latest_frame_at < 2.0:
            self._arm_idle_close()
            return self._latest_jpeg

        with suppress(TimeoutError):
            async with asyncio.timeout(timeout):
                await self._new_frame.wait()
        self._arm_idle_close()
        if self._latest_jpeg is None:
            diagnostics = self._p2p.diagnostics if self._p2p is not None else {}
            _LOGGER.warning(
                "MyQ camera image timed out (stage=frame_wait, p2p=%s, "
                "records=%d, nal_units=%d, sps=%d, pps=%d, idr=%d, "
                "decode_attempts=%d, decode_errors=%d, decoded_jpegs=%d)",
                diagnostics,
                self._records_seen,
                self._nal_units_seen,
                self._sps_seen,
                self._pps_seen,
                self._idr_seen,
                self._decode_attempts,
                self._decode_errors,
                self._decoded_jpegs,
            )
        return self._latest_jpeg

    async def _ensure_open(self) -> bool:
        async with self._open_lock:
            if self._p2p is not None:
                return True
            if self._camera is None and not await self.async_discover():
                return False
            camera = self._camera
            if camera is None:
                return False

            loop = asyncio.get_running_loop()
            remaining = 3.0 - (loop.time() - self._last_release_at)
            if self._last_release_at and remaining > 0:
                await asyncio.sleep(remaining)

            try:
                info = await self._cxs.async_get_video_connection(camera)
                p2p = P2PVideoSession(camera, info, self._on_record)
                await p2p.async_punch(timeout=8.0)
                await self._cxs.async_start_video(camera, info)
            except Exception as error:
                _LOGGER.warning(
                    "MyQ camera session open failed (stage=video_open, error_type=%s)",
                    type(error).__name__,
                )
                if "p2p" in locals():
                    p2p.close()
                return False

            self._info = info
            self._p2p = p2p
            self._reset_decoder()
            if self._worker_task is None or self._worker_task.done():
                self._worker_task = asyncio.create_task(self._decode_worker())
            return True

    def _on_record(self, record: bytes) -> None:
        if self._closed:
            return
        self._records_seen += 1
        units = _nals(record)
        self._nal_units_seen += len(units)
        idr = False
        for nal_type, nal in units:
            if nal_type == NAL_SPS:
                self._sps_seen += 1
                self._sps = nal
            elif nal_type == NAL_PPS:
                self._pps_seen += 1
                self._pps = nal
            elif nal_type == NAL_IDR:
                self._idr_seen += 1
                idr = True

        frames: list[bytes] = []
        if self._gate_open:
            frames.append(record)
        elif idr and self._sps is not None and self._pps is not None:
            self._gate_open = True
            if units and units[0][0] in (NAL_SPS, NAL_PPS):
                frames.append(record)
            else:
                frames.extend((self._sps, self._pps, record))

        for frame in frames:
            if self._record_queue.full():
                with suppress(asyncio.QueueEmpty):
                    self._record_queue.get_nowait()
            with suppress(asyncio.QueueFull):
                self._record_queue.put_nowait(frame)

    async def _decode_worker(self) -> None:
        while not self._closed:
            record = await self._record_queue.get()
            try:
                self._decode_attempts += 1
                jpeg = await asyncio.to_thread(self._decode_record, record)
            except Exception as error:
                self._decode_errors += 1
                _LOGGER.debug(
                    "MyQ camera frame decode failed (error_type=%s)",
                    type(error).__name__,
                )
                continue
            if jpeg is not None:
                self._decoded_jpegs += 1
                self._latest_jpeg = jpeg
                self._latest_frame_at = asyncio.get_running_loop().time()
                self._new_frame.set()

    def _decode_record(self, record: bytes) -> bytes | None:
        if self._decoder is None:
            self._decoder = av.CodecContext.create("h264", "r")
        frames = []
        for packet in self._decoder.parse(record):
            frames.extend(self._decoder.decode(packet))
        if not frames:
            return None
        image = frames[-1].to_image()
        output = io.BytesIO()
        image.save(output, format="JPEG", quality=85)
        return output.getvalue()

    def _reset_decoder(self) -> None:
        self._decoder = None
        self._sps = None
        self._pps = None
        self._gate_open = False
        self._records_seen = 0
        self._nal_units_seen = 0
        self._sps_seen = 0
        self._pps_seen = 0
        self._idr_seen = 0
        self._decode_attempts = 0
        self._decode_errors = 0
        self._decoded_jpegs = 0
        while not self._record_queue.empty():
            with suppress(asyncio.QueueEmpty):
                self._record_queue.get_nowait()

    def _arm_idle_close(self) -> None:
        if self._idle_task is not None and not self._idle_task.done():
            self._idle_task.cancel()
        self._idle_task = asyncio.create_task(self._idle_close())

    async def _idle_close(self) -> None:
        try:
            await asyncio.sleep(20.0)
            await self._close_media()
        except asyncio.CancelledError:
            raise

    async def _close_media(self) -> None:
        p2p = self._p2p
        info = self._info
        camera = self._camera
        self._p2p = None
        self._info = None
        self._reset_decoder()
        if camera is not None and info is not None:
            await self._cxs.async_stop_video(camera, info)
        if p2p is not None:
            p2p.close()
            self._last_release_at = asyncio.get_running_loop().time()

    async def _keepalive_loop(self) -> None:
        while not self._closed:
            try:
                await asyncio.sleep(20.0)
                await self._cxs.async_keepalive()
            except asyncio.CancelledError:
                raise
            except Exception as error:
                _LOGGER.debug(
                    "MyQ camera signaling keepalive failed (error_type=%s)",
                    type(error).__name__,
                )

    async def async_close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._idle_task is not None:
            self._idle_task.cancel()
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
        await self._close_media()
        if self._worker_task is not None:
            self._worker_task.cancel()
        tasks = [
            task
            for task in (self._idle_task, self._keepalive_task, self._worker_task)
            if task is not None
        ]
        for task in tasks:
            with suppress(asyncio.CancelledError):
                await task
        await self._cxs.async_close()
