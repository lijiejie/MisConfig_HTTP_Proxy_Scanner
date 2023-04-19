#!/usr/bin/env python

import wx
from lib.common import get_abs_path
import wx.lib.mixins.listctrl as list_mix
from ui.frame_html_viewer import ViewHTMLFrame


class VulnerabilityListCtrl(wx.ListCtrl, list_mix.ListCtrlAutoWidthMixin):
    def __init__(self, parent, pos=wx.DefaultPosition, size=wx.DefaultSize, style=0):
        wx.ListCtrl.__init__(self, parent, -1, pos, size, style)
        list_mix.ListCtrlAutoWidthMixin.__init__(self)


class ResultPanel(wx.Panel, list_mix.ColumnSorterMixin):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1, style=wx.WANTS_CHARS, size=(-1, 425))
        # image list
        self.image_list = wx.ImageList(16, 16)
        self.img_0 = self.image_list.Add(wx.Image(get_abs_path("ui/ssl.png")).ConvertToBitmap())
        self.img_0 = self.image_list.Add(wx.Image(get_abs_path("ui/http.png")).ConvertToBitmap())
        self.sort_up = self.image_list.Add(wx.Image(get_abs_path("ui/sort_up.png")).ConvertToBitmap())
        self.sort_down = self.image_list.Add(wx.Image(get_abs_path("ui/sort_down.png")).ConvertToBitmap())
        self.list = VulnerabilityListCtrl(self, style=wx.LC_REPORT | wx.BORDER_SUNKEN | wx.LC_SORT_ASCENDING)
        self.list.SetImageList(self.image_list, wx.IMAGE_LIST_SMALL)

        self.lbl_selected = wx.StaticText(self, -1, "")
        self.lbl_selected.SetForegroundColour((100, 100, 100))

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.list, 1, wx.EXPAND)

        self.populate_list()

        list_mix.ColumnSorterMixin.__init__(self, 4)
        # self.SortListItems(2, False)

        self.SetSizer(sizer)
        self.SetAutoLayout(True)

        self.list.Bind(wx.EVT_LIST_ITEM_SELECTED, self.update_current_item)
        self.list.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.update_current_item)
        self.list.Bind(wx.EVT_LIST_ITEM_FOCUSED, self.update_current_item)

        self.list.Bind(wx.EVT_LEFT_DCLICK, self.double_click_select)

        self.list.Bind(wx.EVT_COMMAND_RIGHT_CLICK, self.popup_menu)    # for wxMSW
        self.list.Bind(wx.EVT_RIGHT_UP, self.popup_menu)    # for wxGTK
        self.current_item = None
        self.id_view_vul = wx.NewIdRef()

    def update_current_item(self, event):
        self.current_item = event.Index

    def populate_list(self):
        info = wx.ListItem()
        info.Mask = wx.LIST_MASK_TEXT | wx.LIST_MASK_IMAGE | wx.LIST_MASK_FORMAT
        info.Image = -1
        info.Align = 0
        info.Text = "Target"
        self.list.InsertColumn(0, info)
        info.Text = "Domain"
        self.list.InsertColumn(1, info)
        info.Text = "Status"
        self.list.InsertColumn(2, info)
        info.Text = "HTTP Title"
        self.list.InsertColumn(3, info)

        self.list.SetColumnWidth(0, 130)
        self.list.SetColumnWidth(1, 150)
        self.list.SetColumnWidth(2, 60)
        self.list.SetColumnWidth(3, 100)
        self.current_item = 0

    # Used by the ColumnSorterMixin
    def GetListCtrl(self):
        return self.list

    # Used by the ColumnSorterMixin
    def GetSortImages(self):
        return self.sort_down, self.sort_up

    def get_column_text(self, index, col):
        item = self.list.GetItem(index, col)
        return item.GetText()

    def popup_menu(self, event):
        if self.list.GetItemCount() < 1:
            return
        menu = wx.Menu()
        self.view_source = wx.MenuItem(menu, self.id_view_vul, 'View HTML')
        self.view_source.SetBitmap(wx.Image(get_abs_path('ui/view_html.png')).ConvertToBitmap())
        self.Bind(wx.EVT_MENU, self.view_source_code, id=self.id_view_vul)

        menu.Append(self.view_source)
        self.PopupMenu(menu)
        menu.Destroy()

    def view_source_code(self, event):
        if self.list.GetItemCount() < 1:
            return

        idx = self.list.GetItemData(self.current_item)
        data = self.itemDataMap[idx]
        ip_port = data[0]
        domain = data[1]
        protocol = data[4]
        frame = ViewHTMLFrame(self)
        frame.show_source_code(protocol, ip_port, domain)
        frame.Center(wx.BOTH)
        frame.Show()

    def double_click_select(self, event):
        if self.list.GetItemCount() < 1:
            return
        self.view_source_code(None)

    def add_vulnerability(self, vul):
        self.itemDataMap[self.list.GetItemCount()+1] = vul
        index = self.list.InsertItem(self.list.GetItemCount(), vul[0], 0 if vul[4] == 'https' else 1)
        self.list.SetItem(index, 1, vul[1])
        self.list.SetItem(index, 2, vul[2])
        self.list.SetItem(index, 3, vul[3])
        self.list.SetItemData(index, self.list.GetItemCount())


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    frame = wx.Frame(None, -1, "Test", size=(900, 700))
    win = ResultPanel(frame)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
