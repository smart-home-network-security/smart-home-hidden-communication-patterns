"""
Power on/off the device through a controllable power plug.
"""

from __future__ import annotations
import sys
import os
from enum import StrEnum
import threading
import asyncio
from kasa import Device
from tapo import ApiClient, PlugEnergyMonitoringHandler

import logging
logger_name = os.path.basename(__name__)
logger = logging.getLogger(logger_name)


class PLUG(StrEnum):
    """
    Enumeration of the controllable power plugs.
    """
    TpLinkPlug = "TpLinkPlug"
    TapoPlug   = "TapoPlug"


class POWER(StrEnum):
    """
    Enumeration of the power cycle directions.
    """
    BOOT     = "boot"
    SHUTDOWN = "shutdown"


### PLUG CLASSES ###

class Plug:
    """
    Abstract base class for controllable power plugs.
    """

    @staticmethod
    def init_plug(name: str, **kwargs) -> Plug:
        """
        Factory method to initialize a plug based on its name.

        Args:
            name (str): The name of the plug.
            kwargs (dict): Additional arguments for plug initialization (e.g., ipv4 address, username, password).
        Returns:
            Plug: An instance of the corresponding plug class.
        """
        # Check if the plug name is valid
        try:
            PLUG(name)
        except ValueError:
            raise ValueError(f"Unknown plug type: {name}")
        
        # Plug name is valid
        # Initialize the plug based on its type
        this_module = sys.modules[__name__]
        plug_class = getattr(this_module, name, None)
        if plug_class is None:
            raise ValueError(f"Plug class {name} not found in module {__name__}")

        return plug_class(**kwargs)
    

    def __init__(self, ipv4: str) -> None:
        """
        Constructor.
        Initialize the device with its IP address and start the asyncio event loop.

        Args:
            ipv4 (str): The device's IPv4 address.
        """
        # Device's IPv4 address
        self.ipv4 = ipv4

        # asyncio event loop
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._start_loop, daemon=True)
        self.thread.start()
    

    def _start_loop(self):
        """
        Start the asyncio event loop, and run it forever.
        """
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()
    

    async def _async_boot(self) -> None:
        """
        Asynchronously turn on the plug.
        This method should be overridden by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method.")


    def boot(self):
        """
        Turn on the plug.
        """
        asyncio.run_coroutine_threadsafe(self._async_boot(), self.loop)

    
    async def _async_shutdown(self):
        """
        Asynchronously turn off the plug.
        This method should be overridden by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method.")


    def shutdown(self):
        """
        Turn off the plug.
        """
        asyncio.run_coroutine_threadsafe(self._async_shutdown(), self.loop)


class TpLinkPlug(Plug):
    """
    Class representing a controllable TP-Link HS110 power plug.
    """

    def __init__(self, ipv4: str) -> None:
        """
        Constructor.

        Args:
            ipv4 (str): The IPv4 address of the plug.
        """
        # Superclass constructor
        super().__init__(ipv4)

        # TP-Link connector
        self.device_tplink: Device = None


    async def _async_boot(self) -> None:
        """
        Asynchronously turn on the TP-Link plug.
        """
        if self.device_tplink is None:
            self.device_tplink = await Device.connect(host=self.ipv4)

        await self.device_tplink.turn_on()


    async def _async_shutdown(self):
        """
        Asynchronously turn off the TP-Link plug.
        """
        if self.device_tplink is None:
            self.device_tplink = await Device.connect(host=self.ipv4)

        await self.device_tplink.turn_off()


class TapoPlug(Plug):
    """
    Class representing a controllable Tapo P110 power plug.
    """

    def __init__(self, ipv4: str, username: str, password: str) -> None:
        """
        Constructor.

        Args:
            ipv4 (str): The IP address of the plug.
            username (str): The Tapo account username.
            password (str): The Tapo account password.
        """
        # Superclass constructor
        super().__init__(ipv4)

        # Tapo connector
        self.client = ApiClient(username=username, password=password)
        self.device: PlugEnergyMonitoringHandler = None
    

    async def _async_boot(self):
        """
        Asynchronously turn on the Tapo plug.
        """
        if self.device is None:
            # Create a Tapo plug device handler
            self.device = await self.client.p110(self.ipv4)
        
        # Turn on the plug
        await self.device.on()


    async def _async_shutdown(self):
        """
        Asynchronously turn off the Tapo plug.
        """
        if self.device is None:
            # Create a Tapo plug device handler
            self.device = await self.client.p110(self.ipv4)

        # Turn off the plug
        await self.device.off()
