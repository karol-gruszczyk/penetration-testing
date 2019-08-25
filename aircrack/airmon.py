import re
import shlex
import subprocess
import warnings
import typing as t

from .models import WifiAdapter


class Airmon:
    def __init__(self):
        pass

    @classmethod
    def start_monitoring(cls, adapter: WifiAdapter):
        with subprocess.Popen(
                shlex.split(f'airmon-ng start {adapter.interface}'), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        ) as process:
            output = process.stdout.read().decode()

        if f'monitor mode already enabled for [{adapter.phy}]{adapter.interface}' in output:
            warnings.warn(f'Monitoring already enabled on {adapter.interface}')
            return

        cls._set_new_interface(adapter, output)

    @classmethod
    def stop_monitoring(cls, adapter: WifiAdapter):
        with subprocess.Popen(
                shlex.split(f'airmon-ng stop {adapter.interface}'), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        ) as process:
            output = process.stdout.read().decode()

        if f'monitor mode vif disabled for [{adapter.phy}]{adapter.interface}' not in output:
            warnings.warn(f'Disabling monitoring on {adapter.interface} failed with the following output:\n{output}')

        cls._set_new_interface(adapter, output)

    @classmethod
    def _set_new_interface(cls, adapter: WifiAdapter, output: str):
        interface_re: t.Optional[t.Match] = re.search(r'mode vif enabled on \[\w+\](\w+)', output)
        interface_re = interface_re or re.search(
            rf'monitor mode vif enabled for \[{adapter.phy}\]{adapter.interface} on \[\w+\](\w+)', output
        )
        if interface_re is None:
            warnings.warn(f'Unexpected output:\n{output}')
            raise RuntimeError(f'Command failed {adapter.interface} failed')
        interface = interface_re.group(1)
        if interface != adapter.interface:
            adapter.interface = interface

    @classmethod
    def get_wifi_adapters(cls) -> t.Iterator[WifiAdapter]:
        lines = iter(cls._get_lines('airmon-ng'))

        header = next(lines)
        assert header == ['PHY', 'Interface', 'Driver', 'Chipset']

        for wifi_card in lines:
            yield WifiAdapter(
                phy=wifi_card[0],
                interface=wifi_card[1],
                driver=wifi_card[2],
                chipset=wifi_card[3],
            )

    @classmethod
    def _get_lines(cls, command: str, line_seperator='\n', item_seperator='\t') -> t.Iterator[t.List[str]]:
        with subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            for line in process.stdout.read().decode().split(line_seperator):
                if not line:
                    continue
                yield [i for i in line.split(item_seperator) if i]
