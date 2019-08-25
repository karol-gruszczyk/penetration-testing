#!/usr/bin/env python3

import functools
import operator
import os
import traceback
import typing as t

import urwid

from aircrack.airmon import Airmon
from aircrack.airodump import Airodump
from aircrack.models import WifiAdapter, AccessPoint
from urwid_components import OkCancelDialog, StyledButton, SimpleButton

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
            columns: t.Iterable[str],
            fields: t.Iterable[str],
            sort_by: t.Optional[str] = None,
    ):
        self.loop = loop

        self.elements = list(elements)
        self.columns = list(columns)
        self.fields = list(fields)
        self.sort_by = sort_by

        self.elements_list_widget = urwid.ListBox(urwid.SimpleFocusListWalker([]))
        self.update_list_widget()

        main = urwid.LineBox(
            urwid.Padding(
                urwid.Frame(header=LOGO, body=self.elements_list_widget),
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
                sorted(self.elements, key=operator.attrgetter(self.sort_by))
                if self.sort_by else self.elements
            )
        ])

        if self.elements:
            focus = focus and min(focus, len(self.elements) - 1) or 1
            self.elements_list_widget.set_focus(focus)

    def select_element(self, element: t.Any, button):
        pass


class NetworkScreen(SelectableListView):
    def __init__(self, loop: urwid.MainLoop, adapter: WifiAdapter, network: AccessPoint):
        self.network = network
        self.airodump = Airodump(adapter.interface, access_point=self.network)

        super().__init__(loop, network.stations, )

    def fetch_network(self):
        self.network = self.airodump.fetch()
        self.elements = self.network.stations


class NetworkListScreen(SelectableListView):
    def __init__(self, loop: urwid.MainLoop, adapter: WifiAdapter):
        if not adapter.monitoring_enabled:
            Airmon.start_monitoring(adapter)

        self.airodump = Airodump(adapter.interface)
        self.adapter = adapter

        super().__init__(
            loop,
            elements=[],
            columns=['BSSID', 'ESSID', 'Channel', 'Stations', 'Power', 'Privacy', 'Cipher', 'Authentication'],
            fields=['bssid', 'essid', 'channel', 'num_stations', 'power', 'privacy', 'cipher', 'authentication'],
            sort_by='power',
        )
        self.loop.set_alarm_in(1, self.fetch_networks, None)

    def fetch_networks(self, *args):
        try:
            self.elements = self.airodump.fetch()
            self.update_list_widget()
        except ValueError:  # not fully written
            pass
        self.loop.set_alarm_in(1, self.fetch_networks, None)

    def select_element(self, element: AccessPoint, button):
        self.loop.widget = NetworkScreen(self.loop, self.adapter, element)


class WifiAdapterScreen(SelectableListView):
    def __init__(self, loop: urwid.MainLoop, adapters: t.Iterable[WifiAdapter]):
        columns = ['PHY', 'Interface', 'Driver', 'Chipset']
        super().__init__(loop, list(adapters), columns=columns, fields=[c.lower() for c in columns])

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
