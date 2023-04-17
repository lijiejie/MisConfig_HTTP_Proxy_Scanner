import wx


class SettingsPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1, style=wx.CLIP_CHILDREN)
        box = wx.StaticBox(self, -1, "Settings", size=(500, 60))

        lbl_ports = wx.StaticText(box, -1, "Port List")
        lbl_ports.SetForegroundColour((72, 118, 255))
        self.txt_ports = wx.TextCtrl(box, -1, "", size=(250, -1))
        self.txt_ports.SetValue('80,443,8080,8000,8888')

        lbl_threads = wx.StaticText(box, -1, "Threads")
        lbl_threads.SetForegroundColour((72, 118, 255))
        self.txt_threads = wx.TextCtrl(box, -1, "", size=(50, -1))
        self.txt_threads.SetValue('30')

        sizer_box = wx.BoxSizer(wx.HORIZONTAL)
        sizer_box.Add((0, 0), 0, wx.LEFT, 10)
        sizer_box.Add(lbl_ports, 0, wx.TOP, 23)
        sizer_box.Add((5, 5), 0, wx.ALL, 2)
        sizer_box.Add(self.txt_ports, 0, wx.EXPAND | wx.TOP | wx.BOTTOM, 20)
        sizer_box.Add((30, 0))
        sizer_box.Add(lbl_threads, 0, wx.TOP, 23)
        sizer_box.Add((5, 5), 0, wx.ALL, 2)
        sizer_box.Add(self.txt_threads, 0, wx.EXPAND | wx.TOP | wx.BOTTOM, 20)
        box.SetSizer(sizer_box)
        box.Layout()
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(box, 0, wx.TOP | wx.LEFT, 15)
        self.SetSizer(sizer)


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    frame = wx.Frame(None, -1, "Test", size=(600, 500))
    panel = wx.Panel(frame, -1)
    target_panel = SettingsPanel(panel)
    sizer = wx.BoxSizer(wx.VERTICAL)
    sizer.Add(target_panel, 0, wx.LEFT, 0)
    panel.SetSizer(sizer)
    frame.Center(wx.BOTH)
    frame.Show()
    app.MainLoop()
