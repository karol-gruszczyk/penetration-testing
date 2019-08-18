import dataclasses
from datetime import datetime
import typing as t


@dataclasses.dataclass()
class WifiCard:
    phy: str
    interface: str
    chipset: str
    driver: str

    def __str__(self) -> str:
        return '\t'.join(f'{field.name}: {getattr(self, field.name)}' for field in dataclasses.fields(self))

    @property
    def monitoring_enabled(self) -> bool:
        return self.interface.endswith('mon')


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
    stations: t.List = dataclasses.field(default_factory=list)


@dataclasses.dataclass()
class Station:
    station_mac: str
    first_seen: datetime
    last_seen: datetime
    power: int
    packets: int
    bssid: int
    probed_essids: str
