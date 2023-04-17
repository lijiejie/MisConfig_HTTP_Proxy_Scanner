#!/usr/bin/env python3
import httpx
import wx
import threading
from lib.common import get_abs_path, user_agent


class ViewHTMLFrame(wx.Frame):
    def __init__(self, parent):
        wx.Frame.__init__(self, None, -1, "View HTML", size=(700, 700),
                          style=wx.DEFAULT_FRAME_STYLE & ~wx.RESIZE_BORDER & ~wx.MAXIMIZE_BOX | wx.STAY_ON_TOP)
        self.parent = parent
        icon = wx.Icon()
        icon.CopyFromBitmap(wx.Image(get_abs_path('ui/icon.png')).ConvertToBitmap())
        self.SetIcon(icon)
        self.SetBackgroundColour('white')
        panel = wx.Panel(self, -1)
        self.text_url = wx.TextCtrl(panel, -1)
        self.text = wx.TextCtrl(panel, -1, style=wx.TE_MULTILINE | wx.TE_RICH2 | wx.TE_NOHIDESEL)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.text_url, 0, wx.EXPAND | wx.TOP | wx.LEFT | wx.RIGHT, 15)
        sizer.Add(self.text, 1, wx.EXPAND | wx.ALL, 15)
        panel.SetSizer(sizer)
        self.Center(wx.BOTH)

    def show_source_code(self, protocol, ip_port, domain):
        protocol = 'https' if protocol == 0 else 'http'
        self.url = "%s://%s" % (protocol, ip_port)
        self.domain = domain

        self.text_url.WriteText("%s  --  %s" % (self.url, domain))
        wx.CallAfter(self.text_url.SetInsertionPoint, 0)
        threading.Thread(target=self.get_html).start()

    def get_html(self):
        headers = {'User-Agent': user_agent, 'Range': 'bytes=0-2048000', 'Host': self.domain}
        try:
            with httpx.Client(verify=False) as client:
                r = client.get(self.url, headers=headers, timeout=30)
            headers = ''
            for k in r.headers:
                headers += '%s: %s\n' % (k, r.headers[k])

            self.text.write(headers + '\n' + r.text)
            wx.CallAfter(self.text.SetInsertionPoint, 0)
        except Exception as e:
            self.text.WriteText('Exception:\n\n' + str(e))


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    frame = ViewHTMLFrame(None)
    frame.Show()
    app.MainLoop()
