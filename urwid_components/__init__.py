import urwid.escape

urwid.escape.SHOW_CURSOR = ''


class SimpleButton(urwid.WidgetWrap):
    def __init__(self, label, on_press):
        button = urwid.Button(label, on_press=on_press)
        button._set_w(
            urwid.AttrMap(
                urwid.SelectableIcon(label, 0), None, "reversed"
            )
        )
        super().__init__(button)


class StyledButton(urwid.WidgetWrap):
    def __init__(self, label, on_press):
        button = urwid.Button(label, on_press=on_press)
        button._set_w(
            urwid.AttrMap(
                urwid.SelectableIcon([u"\N{BULLET}", label], 0), None, "reversed"
            )
        )
        super().__init__(urwid.LineBox(button))


class Dialog(urwid.WidgetWrap):
    def __init__(self, body, message, title):
        frame = urwid.Frame(
            header=urwid.Pile(
                [
                    urwid.Divider(),
                    urwid.Text(message, align=urwid.CENTER),
                    urwid.Divider(),
                ]
            ),
            body=body,
        )
        widget = urwid.LineBox(urwid.Padding(frame, left=2, right=2), title=title)
        super().__init__(widget)


class OkDialog(urwid.WidgetWrap):
    def __init__(
            self, parent: urwid.Widget, loop: urwid.MainLoop, message: str, title: str
    ):
        self.loop = loop
        body = urwid.Filler(StyledButton("OK", on_press=self.close))
        dialog = Dialog(body, message=message, title=title)
        widget = urwid.Overlay(
            dialog, parent, align=urwid.CENTER, valign=urwid.MIDDLE, width=40, height=10
        )
        super().__init__(widget)

    def close(self, button):
        self.loop.widget = self._w.bottom_w


class OkCancelDialog(urwid.WidgetWrap):
    def __init__(
            self,
            parent: urwid.Widget,
            loop: urwid.MainLoop,
            message: str,
            title: str,
            on_ok,
    ):
        self.loop = loop
        body = urwid.Filler(
            urwid.Columns(
                [
                    StyledButton("CANCEL", on_press=self.close),
                    StyledButton("OK", on_press=on_ok),
                ]
            )
        )
        dialog = Dialog(body, message=message, title=title)
        widget = urwid.Overlay(
            dialog, parent, align=urwid.CENTER, valign=urwid.MIDDLE, width=40, height=10
        )
        super().__init__(widget)

    def close(self, button):
        self.loop.widget = self._w.bottom_w
