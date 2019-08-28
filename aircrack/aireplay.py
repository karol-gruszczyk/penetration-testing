import os
import shlex
import subprocess
import typing as t

from aircrack.models import WifiAdapter, Station


class Aireplay:
    def __init__(self, wifi_adapter: WifiAdapter, station: Station, count: int):
        self.packet_count = count
        self.process = subprocess.Popen(shlex.split(
            f'aireplay-ng {wifi_adapter.interface} --deauth {count} -a {station.bssid} -c {station.station_mac}'
        ), stdout=subprocess.PIPE, creationflags=subprocess.DETACHED_PROCESS)

    def fetch_progress(self) -> t.Tuple[int, int]:
        return 5, 5

    @classmethod
    def send_deauth(cls, wifi_adapter: WifiAdapter, station: Station, count: int):
        subprocess.call(shlex.split(
            f'aireplay-ng {wifi_adapter.interface} --deauth {count} -a {station.bssid} -c {station.station_mac}'
        ), stdout=subprocess.PIPE)
