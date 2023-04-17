import os
import wx.lib.newevent


user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' \
             '(KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'

LogEvent, Log_EVT_BINDER = wx.lib.newevent.NewEvent()
VulEvent, Vul_EVT_BINDER = wx.lib.newevent.NewEvent()
REF_FRAME = None
targets = set()
not_existed_domain_page_info = {}
domains_to_test = None


def get_abs_path(path):
    try:
        cwd = os.path.split(__file__)[0]
        root_dir = os.path.join(cwd, '..')
        return os.path.abspath(os.path.join(root_dir, path))
    except Exception as e:
        print('Invalid path: %s' % path)
        return ''


def show_log(msg):
    event = LogEvent(msg=msg)
    wx.PostEvent(REF_FRAME, event)


def set_button_img(button, img):
    img = wx.Image(img).ConvertToBitmap()
    button.SetBitmap(img)
    button.SetBitmapCurrent(img)
    button.SetBitmapPressed(img)
    button.SetBitmapFocus(img)
