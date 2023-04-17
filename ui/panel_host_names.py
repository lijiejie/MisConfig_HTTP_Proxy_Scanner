import wx
import os
from lib.common import get_abs_path


class DomainFileDropTarget(wx.FileDropTarget):
    def __init__(self, panel):
        wx.FileDropTarget.__init__(self)
        self.panel = panel

    def OnDropFiles(self, x, y, filenames):
        path = filenames[0]
        if os.stat(path).st_size > 10 * 1024 * 1024:
            wx.MessageBox("Can not import file of which size is >= 10 MB", "File too large")
        else:
            with open(path) as f:
                self.panel.txt_domain_ips.SetValue(f.read())
        return True


class DictFileDropTarget(wx.FileDropTarget):
    def __init__(self, panel):
        wx.FileDropTarget.__init__(self)
        self.panel = panel

    def OnDropFiles(self, x, y, filenames):
        path = filenames[0]
        if os.stat(path).st_size > 10 * 1024 * 1024:
            wx.MessageBox("Can not import file of which size is >= 10 MB", "File too large")
        else:
            self.panel.txt_dict_path.SetValue(path)
        return True


class HostNamesPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1, style=wx.CLIP_CHILDREN, size=(400, 380))
        box = wx.StaticBox(self, -1, "Domain names to be tested")
        self.notebook = wx.Notebook(box, -1, style=wx.CLIP_CHILDREN, size=(400, 380))
        self.domains_panel = domains_panel = wx.Panel(self.notebook, -1)
        self.domain_brute_panel = domain_brute_panel = wx.Panel(self.notebook, -1, size=(400, 380))
        self.notebook.AddPage(domains_panel, " Known Domains ")

        lbl_drag_file = wx.StaticText(domains_panel, -1, "Enter domains or drag in a file")
        lbl_drag_file.SetForegroundColour((72, 118, 255))
        self.txt_domain_ips = wx.TextCtrl(domains_panel, -1, "", style=wx.TE_MULTILINE, size=(300, 300))
        file_drop_targets = DomainFileDropTarget(self)
        self.txt_domain_ips.SetDropTarget(file_drop_targets)
        self.btn_open = wx.Button(domains_panel, -1, "Import")
        self.btn_open.SetBitmap(
            wx.Image(get_abs_path('ui/import_targets_16.png')).ConvertToBitmap(), wx.LEFT)
        self.btn_open.SetBitmapMargins((2, 2))
        self.btn_open.SetInitialSize()
        self.Bind(wx.EVT_BUTTON, self.import_targets, self.btn_open)
        sizer_domains_panel = wx.BoxSizer(wx.VERTICAL)
        sizer_domains_panel.Add((0, 0), 0, wx.TOP, 5)
        sizer_domains_panel.Add(lbl_drag_file, 0, wx.LEFT, 5)
        sizer_domains_panel.Add((0, 0), 0, wx.TOP, 5)
        sizer_domains_panel.Add(self.txt_domain_ips, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 5)
        sizer_domains_panel.Add((0, 0), 0, wx.TOP, 5)
        sizer_domains_panel.Add(self.btn_open, 0, wx.ALL, 5)
        sizer_domains_panel.Add((0, 0), 0, wx.TOP, 5)
        domains_panel.SetSizer(sizer_domains_panel)

        self.notebook.AddPage(domain_brute_panel, " Brute Force Attack ")
        lbl_drag_file = wx.StaticText(domain_brute_panel, -1, "Browse to choose or drag in a dict file")
        lbl_drag_file.SetForegroundColour((72, 118, 255))
        self.txt_dict_path = wx.TextCtrl(domain_brute_panel, -1, "", style=wx.TE_MULTILINE, size=(300, 50))
        file_drop_targets = DictFileDropTarget(self)
        self.txt_dict_path.SetDropTarget(file_drop_targets)
        if os.path.exists(get_abs_path('dict/subnames.txt')):
            self.txt_dict_path.SetValue(get_abs_path('dict/subnames.txt'))
        self.btn_browse = wx.Button(domain_brute_panel, -1, "Browse")
        self.btn_browse.SetBitmap(
            wx.Image(get_abs_path('ui/import_targets_16.png')).ConvertToBitmap(), wx.LEFT)
        self.btn_browse.SetBitmapMargins((2, 2))
        self.btn_browse.SetInitialSize()
        self.Bind(wx.EVT_BUTTON, self.choose_dict_file, self.btn_browse)
        lbl_zone = wx.StaticText(domain_brute_panel, -1, "Enter internal domains to brute")
        lbl_zone.SetForegroundColour((72, 118, 255))
        self.txt_zone = wx.TextCtrl(domain_brute_panel, -1, "", style=wx.TE_MULTILINE, size=(300, 300))
        self.txt_zone.SetValue('company.internal\ncompany.local\ncompany-inc.net')
        sizer_brute_panel = wx.BoxSizer(wx.VERTICAL)
        sizer_brute_panel.Add((0, 0), 0, wx.TOP, 5)
        sizer_brute_panel.Add(lbl_drag_file, 0, wx.LEFT, 5)
        sizer_brute_panel.Add((0, 0), 0, wx.TOP, 5)
        sizer_brute_panel.Add(self.txt_dict_path, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 5)
        sizer_brute_panel.Add((0, 0), 0, wx.TOP, 5)
        sizer_brute_panel.Add(self.btn_browse, 0, wx.ALL, 5)
        sizer_brute_panel.Add((0, 0), 0, wx.TOP, 15)
        sizer_brute_panel.Add(lbl_zone, 0, wx.LEFT, 5)
        sizer_brute_panel.Add(self.txt_zone, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 5)
        sizer_brute_panel.Add((0, 0), 0, wx.TOP, 25)
        domain_brute_panel.SetSizer(sizer_brute_panel)

        sizer_box = wx.BoxSizer(wx.VERTICAL)
        sizer_box.Add((0, 20), 0)
        sizer_box.Add(self.notebook, 1, wx.EXPAND | wx.ALL, 10)
        box.SetSizer(sizer_box)
        sizer_panel = wx.BoxSizer(wx.VERTICAL)
        sizer_panel.Add(box, 1, wx.TOP, 15)
        self.SetSizer(sizer_panel)

    def import_targets(self, event):
        dlg = wx.FileDialog(self, message="Import targets from file", defaultDir=get_abs_path(''), defaultFile="",
                            style=wx.FD_OPEN | wx.FD_CHANGE_DIR | wx.FD_FILE_MUST_EXIST | wx.FD_PREVIEW)
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPaths()[0]
            if os.stat(path).st_size > 10 * 1024 * 1024:
                wx.MessageBox("Can not import file of which size is >= 10 MB", "File too large")
            else:
                with open(path) as f:
                    self.txt_domain_ips.SetValue(f.read())
        dlg.Destroy()

    def choose_dict_file(self, event):
        dlg = wx.FileDialog(self, message="Choose Dict File", defaultDir=get_abs_path('dict'), defaultFile="",
                            style=wx.FD_OPEN | wx.FD_CHANGE_DIR | wx.FD_FILE_MUST_EXIST)
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPaths()[0]
            if os.stat(path).st_size > 10 * 1024 * 1024:
                wx.MessageBox("Can not import file of which size is >= 10 MB", "File too large")
            else:
                self.txt_dict_path.SetValue(path)
        dlg.Destroy()


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    frame = wx.Frame(None, -1, "Test", size=(450, 500))
    panel = wx.Panel(frame, -1)
    discover_panel = HostNamesPanel(panel)
    sizer = wx.BoxSizer(wx.VERTICAL)
    sizer.Add(discover_panel, 0, wx.LEFT, 5)
    panel.SetSizer(sizer)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
