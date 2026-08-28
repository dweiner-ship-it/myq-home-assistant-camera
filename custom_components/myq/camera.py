from __future__ import annotations

from aiohttp import web
from homeassistant.components.camera import Camera, async_get_still_stream
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import DOMAIN
from .models import MyQConfigEntry, MyQCamera
from .tend_camera import TendCameraManager


async def async_setup_entry(
    hass: HomeAssistant,
    entry: MyQConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    cameras = await entry.runtime_data.client.async_get_cameras()
    video_keypads = [
        camera
        for camera in cameras
        if camera.device_model == "vkp-camera"
        and camera.serial_number.startswith("TC")
    ]
    if not video_keypads:
        return
    camera = video_keypads[0]
    manager = TendCameraManager(
        entry.runtime_data.client.async_access_token,
        camera.serial_number,
    )
    async_add_entities([MyQVideoKeypadCamera(camera, manager)])


class MyQVideoKeypadCamera(Camera):
    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_is_on = True
    _attr_name = "Camera"
    _attr_model = "MyQ Video Keypad"

    def __init__(self, camera: MyQCamera, manager: TendCameraManager) -> None:
        super().__init__()
        self._camera = camera
        self._manager = manager
        self._attr_unique_id = manager.unique_id

    @property
    def available(self) -> bool:
        return self._camera.online is not False

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._camera.serial_number)},
            name=self._camera.name,
            manufacturer="Chamberlain Group",
            model="MyQ Video Keypad",
        )

    async def async_will_remove_from_hass(self) -> None:
        await self._manager.async_close()

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
