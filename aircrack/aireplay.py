import shlex
import subprocess

from aircrack.models import WifiAdapter, Station


class Aireplay:
    @classmethod
    def send_deauth(cls, wifi_adapter: WifiAdapter, station: Station, count: int):
        subprocess.call(shlex.split(
            f'aireplay-ng {wifi_adapter.interface} --deauth {count} -a {station.bssid} -c {station.station_mac}'
        ), stdout=subprocess.PIPE)
