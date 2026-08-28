from __future__ import annotations

from typing import Any

from aiohttp import web
from homeassistant.components.camera import Camera, async_get_still_stream
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import DOMAIN
from .models import MyQRuntimeData
from .tend_camera import TendCameraManager


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry[MyQRuntimeData],
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    manager = entry.runtime_data.camera_manager
    if not await manager.async_discover():
        return
    async_add_entities([MyQVideoKeypadCamera(manager)])


class MyQVideoKeypadCamera(Camera):
    _attr_name = "Video Keypad Camera"
    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_is_on = True
    _attr_model = "MyQ Video Keypad"

    def __init__(self, manager: TendCameraManager) -> None:
        super().__init__()
        self._manager = manager
        self._attr_unique_id = manager.unique_id

    @property
    def available(self) -> bool:
        return self._manager.discovered

    @property
    def device_info(self) -> DeviceInfo | None:
        if self._manager.unique_id is None:
            return None
        return DeviceInfo(
            identifiers={(DOMAIN, self._manager.unique_id)},
            name="Video Keypad",
            manufacturer="Chamberlain Group",
            model="MyQ Video Keypad",
        )

    async def async_camera_image(
        self,
        width: int | None = None,
        height: int | None = None,
    ) -> bytes | None:
        return await self._manager.async_get_image()

    async def handle_async_mjpeg_stream(
        self, request: web.Request
    ) -> web.StreamResponse | None:
        return await async_get_still_stream(
            request,
            self._manager.async_get_image,
            self.content_type,
            1.0,
        )
