import wx
import os
from lib.common import get_abs_path


class TargetFileDropTarget(wx.FileDropTarget):
    def __init__(self, panel):
        wx.FileDropTarget.__init__(self)
        self.panel = panel

    def OnDropFiles(self, x, y, filenames):
        path = filenames[0]
        if os.stat(path).st_size > 1024 * 1024:
            wx.MessageBox("Can not import file of which size is >= 1024 kB", "File too large")
        else:
            with open(path) as f:
                self.panel.txt_domain_ips.SetValue(f.read())
        return True


class TargetsPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1, style=wx.CLIP_CHILDREN)
        box = wx.StaticBox(self, -1, "Target Domains / IPs")

        lbl_drag_file = wx.StaticText(box, -1, "Enter targets or drag in a file")
        lbl_drag_file.SetForegroundColour((72, 118, 255))
        self.txt_domain_ips = wx.TextCtrl(box, -1, "", style=wx.TE_MULTILINE, size=(250, 300))
        file_drop_targets = TargetFileDropTarget(self)
        self.txt_domain_ips.SetDropTarget(file_drop_targets)

        self.btn_open = wx.Button(box, -1, "Import")
        self.btn_open.SetBitmap(
            wx.Image(get_abs_path('ui/import_targets_16.png')).ConvertToBitmap(), wx.LEFT)
        self.btn_open.SetBitmapMargins((2, 2))
        self.btn_open.SetInitialSize()
        self.Bind(wx.EVT_BUTTON, self.import_targets, self.btn_open)
        sizer_box = wx.BoxSizer(wx.VERTICAL)

        sizer_box.Add((0, 0), 0, wx.ALL, 5)
        sizer_box.Add(lbl_drag_file, 0, wx.LEFT | wx.ALIGN_LEFT | wx.TOP, 15)
        sizer_box.Add((5, 5), 0, wx.ALL, 2)
        sizer_box.Add(self.txt_domain_ips, 0, wx.LEFT | wx.RIGHT | wx.EXPAND | wx.BOTTOM, 15)
        sizer_box.Add(self.btn_open, 0, wx.LEFT | wx.BOTTOM, 15)
        box.SetSizer(sizer_box)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(box, 0, wx.TOP | wx.LEFT, 15)
        self.SetSizer(sizer)

    def import_targets(self, event):
        dlg = wx.FileDialog(self, message="Import targets from file", defaultDir=os.getcwd(), defaultFile="",
                            style=wx.FD_OPEN | wx.FD_CHANGE_DIR | wx.FD_FILE_MUST_EXIST | wx.FD_PREVIEW)
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPaths()[0]
            if os.stat(path).st_size > 1024 * 1024:
                wx.MessageBox("Can not import file of which size is >= 1024 kB", "File too large")
            else:
                with open(path) as f:
                    self.txt_domain_ips.SetValue(f.read())
        dlg.Destroy()


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    frame = wx.Frame(None, -1, "Test", size=(400, 500))
    panel = wx.Panel(frame, -1)
    target_panel = TargetsPanel(panel)
    sizer = wx.BoxSizer(wx.VERTICAL)
    sizer.Add(target_panel, 0, wx.LEFT, 0)
    panel.SetSizer(sizer)
    frame.Center(wx.BOTH)
    frame.Show()
    app.MainLoop()
