#!/bin/env python3
"""
  The scanner helps to:

  1) Scan misconfigured reverse proxy servers, to find those web services designed Intranet access only
     but accidentally exposed to the Internet.

  2) Attack known forward proxy servers, brute with generated intranet domains to find those existed ones, like
     *.company.internal
     *.company.local
     *.company-inc.net

  By Li JieJie 2023/04
"""

import datetime
import os
import wx
import webbrowser
import threading
from ui.panel_host_names import HostNamesPanel
from ui.panel_targets_input import TargetsPanel
from ui.panel_result import ResultPanel
from ui.panel_settings import SettingsPanel
import lib.common
from lib.common import get_abs_path, Log_EVT_BINDER, Vul_EVT_BINDER, show_log, set_button_img
from lib.scanner import scan
import lib.scanner


class ScannerApp(wx.App):
    def OnInit(self):
        self.SetAppName("MisConfig HTTP Proxy Scanner")
        lib.common.REF_FRAME = frame = wx.Frame(None, -1, "MisConfig HTTP Proxy Scanner v1.0", size=(700, 700),
                                                style=wx.DEFAULT_FRAME_STYLE | wx.NO_FULL_REPAINT_ON_RESIZE)
        frame.SetMinSize((700, 700))
        frame.Centre(wx.BOTH)
        icon = wx.Icon()
        icon.CopyFromBitmap(wx.Image('ui/icon.png').ConvertToBitmap())
        frame.SetIcon(icon)
        panel = wx.Panel(frame, -1)    # the main panel

        self.panel_targets_input = TargetsPanel(panel)
        self.panel_host_names = HostNamesPanel(panel)

        self.sizer_up = sizer_up = wx.BoxSizer(wx.HORIZONTAL)
        sizer_up.Add(self.panel_targets_input, 0, wx.LEFT | wx.RIGHT, 5)
        sizer_up.Add((0, 0), 0, wx.LEFT, 15)
        sizer_up.Add(self.panel_host_names, 0, wx.RIGHT | wx.EXPAND, 15)

        self.panel_result = ResultPanel(panel)
        self.panel_result.Hide()

        self.btn_scan = btn_scan = wx.Button(panel, -1, "Scan")
        self.STOP_ME = False
        btn_scan.SetBitmap(wx.Image(get_abs_path('ui/scan_start.png')).ConvertToBitmap(), wx.LEFT)
        btn_scan.SetBitmapMargins((2, 2))
        btn_scan.SetInitialSize()
        btn_scan.Bind(wx.EVT_BUTTON, self.scan_start)
        self.active_indicator = wx.ActivityIndicator(panel)
        self.active_indicator.Hide()
        self.panel_settings = SettingsPanel(panel)

        self.sizer_scan = sizer_scan = wx.BoxSizer(wx.HORIZONTAL)
        sizer_scan.Add(btn_scan, 0, wx.TOP, 20)
        sizer_scan.Add(self.active_indicator, 0, wx.TOP | wx.LEFT, 30)
        sizer_scan.Add((40, 0), 0)
        sizer_scan.Add(self.panel_settings, 1, wx.EXPAND)

        self.lbl_status = lbl_status = wx.StaticText(panel, -1, "For research only.")
        lbl_bug_report = wx.StaticText(panel, -1, "By Li JieJie 2023")
        lbl_bug_report.SetForegroundColour((72, 118, 255))
        btn_bug_report = wx.Button(panel, -1, "", size=(24, 24), style=wx.NO_BORDER)
        btn_bug_report.SetToolTip("Bug Report")
        btn_bug_report.SetBackgroundColour(wx.WHITE)
        btn_bug_report.SetBitmap(wx.Image(get_abs_path('ui/bug-report.png')).ConvertToBitmap())
        btn_bug_report.Bind(wx.EVT_BUTTON, self.bug_report)
        sizer_bug_report = wx.BoxSizer(wx.HORIZONTAL)
        sizer_bug_report.Add(lbl_status, 1, wx.EXPAND | wx.LEFT, 20)
        sizer_bug_report.Add(lbl_bug_report, 0)
        sizer_bug_report.Add((10, 0))
        sizer_bug_report.Add(btn_bug_report, 0)

        self.txt_logs = wx.TextCtrl(panel, -1, "", style=wx.TE_MULTILINE)

        self.sizer = sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(sizer_up, 0)
        sizer.Add(self.panel_result, 1, wx.LEFT | wx.RIGHT | wx.EXPAND, 20)
        sizer.Add(sizer_scan, 0, wx.LEFT, 20)
        sizer.Add(self.txt_logs, 1, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP, 20)
        sizer.Add(sizer_bug_report, 0, wx.EXPAND | wx.TOP, 5)
        panel.SetSizer(sizer)
        show_log('Scanner started')
        self.Bind(Log_EVT_BINDER, self.process_log_event)
        self.Bind(Vul_EVT_BINDER, self.add_vulnerability)
        self.load_files()
        self.menu_bar = wx.MenuBar()
        menu = wx.Menu()
        item = wx.MenuItem(menu, -1, 'Show Results Panel')
        menu.Append(item)
        self.Bind(wx.EVT_MENU, self.menu_show_results_panel, item)
        self.menu_bar.Append(menu, '&File')
        frame.SetMenuBar(self.menu_bar)
        frame.Show()
        self.timer_status = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.update_progress)
        return True

    def menu_show_results_panel(self, event):
        if self.btn_scan.GetLabel() == 'Scan':
            self.panel_targets_input.Hide()
            self.panel_host_names.Hide()
            self.panel_result.Show()
            self.sizer.Layout()
            return

    def InitLocale(self):
        # do nothing if wx version is 4.2.0
        ver = wx.VERSION
        if ver[0] == 4 and ver[1] == 2 and ver[2] == 0 and 'wxMSW' in wx.PlatformInfo:
            return
        self.ResetLocale()
        if 'wxMSW' in wx.PlatformInfo:
            import locale
            try:
                lang, enc = locale.getdefaultlocale()
                self._initial_locale = wx.Locale(lang, lang[:2], lang)
                locale.setlocale(locale.LC_ALL, lang)
            except (ValueError, locale.Error) as ex:
                pass

    def scan_start(self, event):
        ports = self.panel_settings.txt_ports.GetValue().replace('，', ',').strip(',').strip().split(',')
        if ports[0] == '':
            wx.MessageDialog(lib.common.REF_FRAME, 'Port list can not be empty',
                             'MisConfig HTTP Proxy Scanner', wx.ICON_INFORMATION).ShowModal()
            return
        if self.btn_scan.GetLabel() == 'Stop':
            self.STOP_ME = True
            self.scan_stop()
            return
        if self.panel_result.IsShown():
            self.panel_targets_input.Show()
            self.panel_host_names.Show()
            self.panel_result.Hide()
            self.sizer.Layout()
            return

        self.timer_status.Start(100)
        self.STOP_ME = False
        self.active_indicator.Start()
        self.active_indicator.Show()
        self.btn_scan.SetLabel('Stop')
        set_button_img(self.btn_scan, get_abs_path('ui/scan_stop.png'))
        self.panel_targets_input.Hide()
        self.panel_host_names.Hide()
        self.panel_result.Show()
        self.panel_settings.txt_ports.Enable(False)
        self.panel_settings.txt_threads.Enable(False)
        self.sizer.Layout()
        show_log('Scan start, do domain name look up')
        self.panel_result.list.DeleteAllItems()
        self.panel_result.itemDataMap = {}
        threading.Thread(target=scan, args=(self,)).start()

    def scan_stop(self, user_aborted=True):
        self.timer_status.Stop()
        self.btn_scan.SetLabel('Scan')
        set_button_img(self.btn_scan, get_abs_path('ui/scan_start.png'))
        self.panel_settings.txt_ports.Enable(True)
        self.panel_settings.txt_threads.Enable(True)
        self.sizer.Layout()
        if user_aborted:
            show_log('User aborted the scan')
        self.active_indicator.Stop()
        self.active_indicator.Hide()
        self.sizer_scan.Layout()

    def bug_report(self, event):
        webbrowser.open_new_tab('https://github.com/lijiejie/MisConfig_HTTP_Proxy_Scanner')

    def load_files(self):
        path = get_abs_path('targets.txt')
        if os.path.exists(path) and os.stat(path).st_size < 5 * 1024 * 1024:
            with open(path) as f:
                self.panel_targets_input.txt_domain_ips.SetValue(f.read())
            show_log('Load targets.txt')
        path = get_abs_path('domains.txt')
        if os.path.exists(path) and os.stat(path).st_size < 5 * 1024 * 1024:
            with open(path) as f:
                self.panel_host_names.txt_domain_ips.SetValue(f.read())
            show_log('Load domains.txt')

    def get_domains_count(self):
        lib.common.domains_to_test = []
        count = 0
        if self.panel_host_names.notebook.GetSelection() == 0:
            domains = self.panel_host_names.txt_domain_ips.GetValue().strip().split('\n')
            for domain in domains:
                if domain and domain.strip():
                    count += 1
                    lib.common.domains_to_test.append(domain)
        else:
            path = self.panel_host_names.txt_dict_path.GetValue()
            zones = self.panel_host_names.txt_zone.GetValue().strip().split('\n')
            for zone in zones:
                if zone and zone.strip():
                    with open(path) as f:
                        domains = f.read().strip().split('\n')
                        for domain in domains:
                            if domain and domain.strip():
                                count += 1
                                lib.common.domains_to_test.append(domain + '.' + zone)

        return count

    def process_log_event(self, event):
        text = event.msg
        if not text.endswith('\n'):
            text += '\n'
        str_time = datetime.datetime.now().strftime('%H:%M:%S')
        self.txt_logs.AppendText('[%s] %s' % (str_time, text))

    def add_vulnerability(self, event):
        self.panel_result.add_vulnerability(event.vul)

    def update_progress(self, event):
        status = ''
        if lib.scanner.domain_queue.qsize() > 0:
            status = 'Do domain name resolve, items left [%s]' % lib.scanner.domain_queue.qsize()
        elif lib.scanner.port_scan_queue.qsize() > 0:
            status = 'Do port scan, items left [%s]' % lib.scanner.port_scan_queue.qsize()
        elif lib.scanner.open_port_queue.qsize() > 0 or lib.scanner.open_port_domain_queue.qsize() > 0:
            status = 'Do proxy scan, targets left [%s], tests left [%s]' % \
                     (lib.scanner.open_port_queue.qsize(), lib.scanner.open_port_domain_queue.qsize())
        self.lbl_status.SetLabel(status)


if __name__ == '__main__':
    app = ScannerApp()
    app.MainLoop()
