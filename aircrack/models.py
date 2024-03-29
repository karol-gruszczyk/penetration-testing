from __future__ import annotations

import dataclasses
import math
from datetime import datetime
import typing as t


@dataclasses.dataclass()
class WifiAdapter:
    phy: str
    interface: str
    driver: str
    chipset: str

    def __str__(self) -> str:
        return '\t'.join(f'{field.name}: {getattr(self, field.name)}' for field in dataclasses.fields(self))

    @property
    def monitoring_enabled(self) -> bool:
        return self.interface.endswith('mon')

def _db_to_percentage(power: float) -> float:
    return 100 * math.log(power)


@dataclasses.dataclass()
class AccessPoint:
    bssid: str
    first_seen: datetime
    last_seen: datetime
    channel: int
    speed: int
    privacy: str
    cipher: str
    authentication: str
    power: int
    beacons: int
    iv: str
    lan_ip: str
    id_length: int
    essid: str
    key: str
    stations: t.List[Station] = dataclasses.field(default_factory=list)

    @property
    def num_stations(self) -> int:
        return len(self.stations)

    @property
    def power_human(self) -> str:
        return '???' if self.power == -1 else f'{100 - abs(round(self.power))}%'


@dataclasses.dataclass()
class Station:
    station_mac: str
    first_seen: datetime
    last_seen: datetime
    power: int
    packets: int
    bssid: int
    probed_essids: str

    @property
    def power_human(self) -> str:
        return '???' if self.power == '-1' else f'{100 - abs(round(self.power))}%'
