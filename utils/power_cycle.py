"""
Power on/off the device through a controllable power plug.
"""

from __future__ import annotations
import sys
import os
from enum import StrEnum
import asyncio
from kasa import Discover
from tapo import ApiClient

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


    def boot(self):
        """
        Turn on the plug.
        """
        raise NotImplementedError("Subclasses must implement this method.")


    def shutdown(self):
        """
        Turn off the plug.
        """
        raise NotImplementedError("Subclasses must implement this method.")


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
        self.ipv4 = ipv4
    

    async def _async_boot(self):
        """
        Asynchronously turn on the TP-Link plug.
        """
        plug = await Discover.discover_single(self.ipv4)
        await plug.turn_on()
    

    def boot(self):
        """
        Turn on the TP-Link plug.
        """
        asyncio.run(self._async_boot())


    async def _async_shutdown(self):
        """
        Asynchronously turn off the TP-Link plug.
        """
        plug = await Discover.discover_single(self.ipv4)
        await plug.turn_off()
    

    def shutdown(self):
        """
        Turn off the TP-Link plug.
        """
        asyncio.run(self._async_shutdown())


class TapoPlug(Plug):
    """
    Class representing a controllable Tapo P110 power plug.
    """

    def __init__(self, username: str, password: str, ipv4: str) -> None:
        """
        Constructor.

        Args:
            username (str): The Tapo account username.
            password (str): The Tapo account password.
            ipv4 (str): The IP address of the plug.
        """
        self.client = ApiClient(username, password)
        self.ipv4 = ipv4
    

    async def _async_boot(self):
        """
        Turn on the Tapo plug.
        """
        plug = await self.client.p110(self.ipv4)
        await plug.on()

    
    def boot(self):
        """
        Turn on the TP-Link plug.
        """
        asyncio.run(self._async_boot())


    async def _async_shutdown(self):
        """
        Turn off the Tapo plug.
        """
        plug = await self.client.p110(self.ipv4)
        await plug.off()

    
    def shutdown(self):
        """
        Turn on the TP-Link plug.
        """
        asyncio.run(self._async_shutdown())
