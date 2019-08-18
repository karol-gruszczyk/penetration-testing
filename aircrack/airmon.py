import re
import shlex
import subprocess
import warnings
import typing as t

from .models import WifiCard


class Airmon:
    def __init__(self):
        pass

    @classmethod
    def start_monitoring(cls, wifi_card: WifiCard):
        print(f'Starting monitoring on {wifi_card.interface} ...')
        with subprocess.Popen(shlex.split(f'airmon-ng start {wifi_card.interface}'), stdout=subprocess.PIPE) as process:
            output = process.stdout.read().decode()

        if f'monitor mode already enabled for [{wifi_card.phy}]{wifi_card.interface}' in output:
            warnings.warn(f'Monitoring already enabled on {wifi_card.interface}')
            return

        cls._set_new_interface(wifi_card, output)

    @classmethod
    def stop_monitoring(cls, wifi_card: WifiCard):
        print(f'Stopping monitoring on {wifi_card.interface} ...')
        with subprocess.Popen(shlex.split(f'airmon-ng stop {wifi_card.interface}'), stdout=subprocess.PIPE) as process:
            output = process.stdout.read().decode()

        if f'monitor mode vif disabled for [{wifi_card.phy}]{wifi_card.interface}' not in output:
            warnings.warn(f'Disabling monitoring on {wifi_card.interface} failed with the following output:\n{output}')

        cls._set_new_interface(wifi_card, output)

    @classmethod
    def _set_new_interface(cls, wifi_card: WifiCard, output: str):
        interface_re: t.Optional[t.Match] = re.search(r'mode vif enabled on \[\w+\](\w+)', output)
        if interface_re is None:
            warnings.warn(f'Unexpected output:\n{output}')
            raise RuntimeError(f'Command failed {wifi_card.interface} failed')
        interface = interface_re.group(1)
        if interface != wifi_card.interface:
            print(f'Interface {wifi_card.interface} is now {interface}')
            wifi_card.interface = interface

    @classmethod
    def get_wifi_cards(cls) -> t.Iterator[WifiCard]:
        lines = iter(cls._get_lines('airmon-ng'))

        header = next(lines)
        assert header == ['PHY', 'Interface', 'Driver', 'Chipset']

        for wifi_card in lines:
            yield WifiCard(*wifi_card)

    @classmethod
    def _get_lines(cls, command: str, line_seperator='\n', item_seperator='\t') -> t.Iterator[t.List[str]]:
        with subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE) as process:
            for line in process.stdout.read().decode().split(line_seperator):
                if not line:
                    continue
                yield [i for i in line.split(item_seperator) if i]
