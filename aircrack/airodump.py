import asyncio
import csv
import io
import os
import shlex
import subprocess
import time
import typing as t
from datetime import datetime

from .models import AccessPoint, Station


class Airodump:
    def __init__(self, interface: str, access_point: AccessPoint = None):
        self.interface = interface
        self.prefix = f'.aircrack-ng/{self.interface}'

        dirname = os.path.dirname(self.prefix)
        if not os.path.exists(dirname):
            os.mkdir(dirname)

        if access_point:
            self.prefix = f'{self.prefix}_{access_point.essid}'
        command = f'airodump-ng {self.interface} --write {self.prefix}'
        if access_point:
            command = f'{command} --bssid {access_point.bssid} --channel {access_point.channel}'
        self.process = subprocess.Popen(shlex.split(command), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

    def fetch(self) -> t.Optional[t.List[AccessPoint]]:
        file = self.get_latest_file()
        if file:
            return self.parse_file(file)

    def get_latest_file(self, extension: str = '.csv') -> t.Optional[str]:
        dirname = os.path.dirname(self.prefix)
        basenames = {
            name.split('.', 1)[0] for name in os.listdir(dirname)
            if name.startswith(f'{os.path.basename(self.prefix)}-')
            and os.path.getsize(os.path.join(dirname, name))
        }
        if basenames:
            return os.path.join(dirname, sorted(basenames, reverse=True)[0] + extension)

    async def stream_data(self, refresh: float = 1) -> t.AsyncIterator[t.List[AccessPoint]]:
        existing_latest = self.get_latest_file()
        while self.process.poll() is None or True:
            latest = self.get_latest_file()
            if latest and latest != existing_latest:
                yield self.parse_file(latest)
            await asyncio.sleep(refresh)

    @classmethod
    def parse_file(cls, path: str) -> t.List[AccessPoint]:
        """
        BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher,
            Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
        [...]

        Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
        [...]
        """
        with open(path, 'r') as file:
            output = file.read().strip()
            lines = output.split('\n')
            stripped = '\n'.join(','.join(i.strip() for i in line.split(',')) for line in lines)
            access_points, stations = stripped.split('\n\n')
            access_points_reader = csv.DictReader(io.StringIO(access_points))

            access_points: t.Dict[str, AccessPoint] = {}
            for row in access_points_reader:
                access_points[row['BSSID']] = AccessPoint(
                    bssid=row['BSSID'],
                    first_seen=datetime.fromisoformat(row['First time seen']),
                    last_seen=datetime.fromisoformat(row['Last time seen']),
                    channel=int(row['channel']),
                    speed=int(row['Speed']),
                    privacy=row['Privacy'],
                    cipher=row['Cipher'],
                    authentication=row['Authentication'],
                    power=int(row['Power']),
                    beacons=int(row['# beacons']),
                    iv=row['# IV'],
                    lan_ip=row['LAN IP'],
                    id_length=int(row['ID-length']),
                    essid=row['ESSID'],
                    key=row['Key'],
                )

            stations_reader = csv.DictReader(io.StringIO(stations))
            for row in stations_reader:
                bssid = row['BSSID']
                if bssid == '(not associated)':
                    continue

                access_points[bssid].stations.append(Station(
                    station_mac=row['Station MAC'],
                    first_seen=datetime.fromisoformat(row['First time seen']),
                    last_seen=datetime.fromisoformat(row['Last time seen']),
                    power=int(row['Power']),
                    packets=int(row['# packets']),
                    bssid=bssid,
                    probed_essids=row['Probed ESSIDs'],
                ))
            return list(access_points.values())

    def __del__(self):
        self.process.terminate()
