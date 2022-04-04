import base64
import hashlib
import hmac
import math
import os.path
import random
import re
import string
import time
import wx

from PIL import ImageGrab
from pysqlitecipher import sqlitewrapper
from pyzbar import pyzbar
from urllib import parse

TITLE = 'TOTPASS'

ABOUT_INFO = """
TOTPass 0.0.1\n
Password + TOTP manager\n
Mikhail Parshev, 2022\n
"""

#BUILD CMD: pyinstaller -F -w -i app.ico --add-data app.ico;. --add-binary lib\libiconv.dll;. --add-binary lib\libzbar-64.dll;. totpass.py

ERROR = 'Error'

def calculate_TOTP(secret):
    if not secret: raise ValueError('TOTP secret must not be empty')
    secret = secret.replace(' ','')
    while len(secret) % 8 !=0 : secret += '='
    t_step = math.floor( math.floor(time.time()) / 30 )
    hash = hmac.new(
        base64.b32decode(secret),
        t_step.to_bytes(length=8, byteorder='big'),
        hashlib.sha256
    )
    dig = hash.digest()
    off = int(dig[-1]) & 0xf
    bin = int.from_bytes(dig[off:off+4],byteorder='big') & 0x7fffffff
    otp = str(bin).zfill(9)[-8:]
    return otp, (t_step+1)*30-time.time()


def scan_QRcode():
    img = ImageGrab.grab()
    data = pyzbar.decode(img)
    for d in data:
        p = parse.urlparse(d.data)
        q = parse.parse_qs(p.query)
        path = str(p.path, 'utf-8')
        login = ''
        m = re.match('/(.+):(\w+)', path)
        if m: path, login = m.group(1), m.group(2)
        secret = str(q[b'secret'][0],'utf-8')
        return path, login, secret 
    raise RuntimeError("No QR code found.")


def generate_password(minLength=18, charsets = [string.ascii_uppercase, string.ascii_lowercase, string.digits, string.punctuation]):
    if not charsets: raise ValueError('At least one charset must be selected')
    password = ''
    unused_charsets = list(charsets)
    random.seed()
    while len(password) < minLength:
        if len(password) + len(unused_charsets) < minLength:
            mm = ''.join(charsets)
        else:
            mm = ''.join(unused_charsets)
        ch = random.choice(mm)
        unused_charsets = [ x for x in unused_charsets if not ch in x ]
        password += ch
    return password


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


#------------------------------------------------------------------------------    

class Database:

    def __init__(self, dataBasePath, password, createTable=False):

        self.TABLE = 'otpauth'
        self.COLUMNS = [
            [ 'path', 'TEXT'],
            [ 'login', 'TEXT' ],
            [ 'password', 'TEXT'],
            [ 'secret', 'TEXT']
        ]
        
        self.conn = sqlitewrapper.SqliteCipher(dataBasePath=dataBasePath , checkSameThread=False , password=password)
        if createTable:
            self.conn.createTable(self.TABLE, self.COLUMNS, makeSecure=True, commit=True)

    
    def InsertData(self, data):
        self.conn.insertIntoTable(self.TABLE, data, commit=True)

        
    def DeleteData(self, idValue):
        self.conn.deleteDataInTable(self.TABLE, idValue, commit=True, raiseError=False, updateId=True)

        
    def UpdateData(self, idValue, data):
        for i, ff in enumerate(self.COLUMNS):
            self.conn.updateInTable(self.TABLE, idValue, ff[0], data[i]) 


    def GetData(self):
        _, data = self.conn.getDataFromTable(self.TABLE, raiseConversionError = True , omitID = False)
        return data


#------------------------------------------------------------------------------

import wx.lib.sized_controls as sc

class TextWithCopy(sc.SizedPanel):
    def __init__(self, parent):
        sc.SizedPanel.__init__(self, parent)
        self.SetSizerType('horizontal')
        self.txText = wx.TextCtrl(self, -1, '', size=(200,-1), style=wx.TE_READONLY)
        self.txText.SetSizerProp('expand', True)
        self.btCopy = wx.Button(self, -1, ".", style=wx.BU_EXACTFIT)
        self.Bind(wx.EVT_BUTTON, self.OnCopy, self.btCopy)

    def GetValue(self):
        return self.txText.GetValue()
        
    def SetValue(self, value):
        self.txText.SetValue(value)
        
    def OnCopy(self, ev):
        if wx.TheClipboard.Open():
            wx.TheClipboard.SetData(wx.TextDataObject(text=self.GetValue()))
            wx.TheClipboard.Close()


#------------------------------------------------------------------------------

class PswdProps(sc.SizedPanel):
    def __init__(self, parent):
        sc.SizedPanel.__init__(self, parent)
        self.SetSizerType('horizontal')
        self.spLength = wx.SpinCtrl(self,-1)
        self.spLength.SetValue(12)
        self.chUpper = wx.CheckBox(self, -1, 'A')
        self.chUpper.SetValue(True)
        self.chLower = wx.CheckBox(self, -1, 'a')
        self.chLower.SetValue(True)
        self.chDigit = wx.CheckBox(self, -1, '2')
        self.chDigit.SetValue(True)
        self.chSpecl = wx.CheckBox(self, -1, '@')
        self.chSpecl.SetValue(True)

    def GetLength(self):
        return self.spLength.GetValue()
        
    def GetCharsets(self):
        charsets = []
        if self.chUpper.GetValue(): charsets.append(string.ascii_uppercase)
        if self.chLower.GetValue(): charsets.append(string.ascii_lowercase)
        if self.chDigit.GetValue(): charsets.append(string.digits) 
        if self.chSpecl.GetValue(): charsets.append(string.punctuation)
        return charsets


#------------------------------------------------------------------------------

class ItemDialog(wx.Dialog):

    def __init__(self, parent, title=TITLE, idValue=-1, data=['','','','']):
        wx.Dialog.__init__(self, parent, -1, title)
        
        self.caller = parent
        self.idValue = idValue
        
        self.panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.VERTICAL)

        self.stPath = wx.StaticText(self.panel, -1, 'Path:')
        sizer.Add(self.stPath, 0, wx.ALL, 5)
        self.txPath = wx.TextCtrl(self.panel, -1, '', size=(230,-1))
        self.txPath.SetValue(data[0])
        sizer.Add(self.txPath, 0, wx.ALL, 5)

        self.stLogin = wx.StaticText(self.panel, -1, 'Login:')
        sizer.Add(self.stLogin, 0, wx.ALL, 5)
        self.txLogin = wx.TextCtrl(self.panel, -1, '', size=(230,-1))
        self.txLogin.SetValue(data[1])
        sizer.Add(self.txLogin, 0, wx.ALL, 5)
        
        self.stPassword = wx.StaticText(self.panel, -1, 'Password:')
        sizer.Add(self.stPassword, 0, wx.ALL, 5)
        self.txPassword = wx.TextCtrl(self.panel, -1, '', size=(230,-1))
        self.txPassword.SetValue(data[2])
        sizer.Add(self.txPassword, 0, wx.ALL, 5)
        
        self.ctPswdProps = PswdProps(self.panel)
        sizer.Add(self.ctPswdProps)

        self.btGenPswd = wx.Button(self.panel, -1, "Generate")
        self.Bind(wx.EVT_BUTTON, self.OnGenPswd, self.btGenPswd)
        sizer.Add(self.btGenPswd, 0, wx.ALL, 5)
        
        self.stSecret = wx.StaticText(self.panel, -1, 'TOTP Secret:')
        sizer.Add(self.stSecret, 0, wx.ALL, 5)

        self.txSecret = wx.TextCtrl(self.panel, -1, '', size=(230,-1))
        self.txSecret.SetValue(data[3])
        sizer.Add(self.txSecret, 0, wx.ALL, 5)

        self.txTotp = wx.TextCtrl(self.panel, -1, '', size=(230,-1), style=wx.TE_READONLY)
        self.txTotp.SetValue('')
        sizer.Add(self.txTotp, 0, wx.ALL, 5)

        sizer2 = wx.BoxSizer(wx.HORIZONTAL)
        
        self.btQRCode = wx.Button(self.panel, -1, "QR code")
        self.Bind(wx.EVT_BUTTON, self.OnQRCode, self.btQRCode)
        sizer2.Add(self.btQRCode, 0, wx.ALL, 5)

        self.btVerify = wx.Button(self.panel, -1, "Verify")
        self.Bind(wx.EVT_BUTTON, self.OnVerify, self.btVerify)
        sizer2.Add(self.btVerify, 0, wx.ALL, 5)

        sizer.Add(sizer2)
        
        # Dialog buttons
        self.StaticSizer = wx.StaticBox(self.panel, -1, '')
        sizer1 = wx.StaticBoxSizer(self.StaticSizer, wx.HORIZONTAL)
        
        self.btSave = wx.Button(self.panel, -1, "&Save")
        self.Bind(wx.EVT_BUTTON, self.OnSave, self.btSave)
        sizer1.Add(self.btSave, 0, wx.ALL, 5)
        
        self.btClose = wx.Button(self.panel, -1, "&Close")
        self.Bind(wx.EVT_BUTTON, self.OnExit, self.btClose)
        sizer1.Add(self.btClose, 0, wx.ALL, 5)
        
        sizer.Add(sizer1, 0, wx.ALL | wx.EXPAND, 5)
        
        self.panel.SetSizer(sizer)
        sizer.Fit(self)

        
    def OnGenPswd(self, ev):
        try:
            self.txPassword.SetValue(generate_password(self.ctPswdProps.GetLength(), self.ctPswdProps.GetCharsets()))
        except Exception as ex:
            wx.MessageBox(str(ex), ERROR, wx.OK | wx.ICON_ERROR)
        
    def OnQRCode(self, ev):
        try:
            _, _, secr = scan_QRcode()
            self.txSecret.SetValue(secr)
        except Exception as ex:
            wx.MessageBox(str(ex), ERROR, wx.OK | wx.ICON_ERROR)

            
    def VerifySecret(self):
        secret = self.txSecret.GetValue()
        if secret:
            try:
                totp, _ = calculate_TOTP(secret)
                self.txTotp.SetValue(totp)
            except Exception as ex:
                wx.MessageBox(str(ex), ERROR, wx.OK | wx.ICON_ERROR)
                return False
        return True

    
    def OnVerify(self, ev):
        self.VerifySecret()

    
    def OnSave(self, ev):
        if not self.VerifySecret(): return
        data = [
            self.txPath.GetValue(),
            self.txLogin.GetValue(),
            self.txPassword.GetValue(),
            self.txSecret.GetValue()
        ]
        if self.idValue < 0:
            self.caller.conn.InsertData(data)
        else:
            self.caller.conn.UpdateData(self.idValue, data)
        self.OnExit(ev)

        
    def OnExit(self, ev):
        self.Destroy()


#------------------------------------------------------------------------------

class MainWindow(wx.Frame):

    def __init__(self):
        wx.Frame.__init__(self, None, title=TITLE)
        self.SetSize(600, 600)
        self.SetIcon(wx.Icon(resource_path('app.ico')))
        self.conn = None
        self.CreateMenu()
        self.CreateCtrls()
        self.ConnectDb('totpass.db')
        self.Show(True)

    def CreateMenu(self):
        #self.CreateStatusBar()
        fileMenu = wx.Menu()

        menuOpen = fileMenu.Append(wx.ID_OPEN, "&Open", "Open database")
        self.Bind(wx.EVT_MENU, self.OnOpen, menuOpen)
        fileMenu.AppendSeparator()

        menuAbout = fileMenu.Append(wx.ID_ABOUT, "&About", "About info")
        self.Bind(wx.EVT_MENU, self.OnAbout, menuAbout)

        fileMenu.AppendSeparator()

        menuExit = fileMenu.Append(wx.ID_EXIT, "E&xit", "Exit program")
        self.Bind(wx.EVT_MENU, self.OnExit, menuExit)

        menuBar = wx.MenuBar()
        menuBar.Append(fileMenu, "&File")
        self.SetMenuBar(menuBar)

    def CreateCtrls(self):

        self.panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        # listCtrl
        self.listCtrl = wx.ListCtrl(self.panel, style=wx.LC_REPORT | wx.LC_NO_HEADER | wx.LC_SINGLE_SEL | wx.LC_VRULES | wx.BORDER_SUNKEN)
        self.listCtrl.InsertColumn(col=0, heading='Id', format=wx.LIST_FORMAT_LEFT)
        self.listCtrl.SetColumnWidth(col=0, width=30)
        self.listCtrl.InsertColumn(col=1, heading='Data', format=wx.LIST_FORMAT_LEFT)
        self.listCtrl.SetColumnWidth(col=1, width=500)
        
        self.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.OnItemActivated, self.listCtrl)
        self.Bind(wx.EVT_LIST_ITEM_DESELECTED, self.OnItemDeselected, self.listCtrl)

        sizer.Add(self.listCtrl, 1, wx.ALL | wx.EXPAND, 5)

        # right panel
        sizer1 = wx.BoxSizer(wx.VERTICAL)

        self.stPath = wx.StaticText(self.panel, -1, 'Path:')
        self.txPath = TextWithCopy(self.panel)
        sizer1.AddMany([ self.stPath, self.txPath ])
        
        self.stLogin = wx.StaticText(self.panel, -1, 'Login:')
        #self.txLogin = wx.TextCtrl(self.panel, -1, '', size=(200,-1), style=wx.TE_READONLY)
        self.txLogin = TextWithCopy(self.panel)
        sizer1.AddMany([ self.stLogin, self.txLogin ])

        self.stPassword = wx.StaticText(self.panel, -1, 'Password:')
        self.txPassword = TextWithCopy(self.panel)
        sizer1.AddMany([ self.stPassword, self.txPassword ])

        self.stTotp = wx.StaticText(self.panel, -1, 'TOTP:')
        #self.txTotp = wx.TextCtrl(self.panel, -1, '', size=(200,-1), style=wx.TE_READONLY)
        self.txTotp = TextWithCopy(self.panel)
        sizer1.AddMany([ self.stTotp, self.txTotp ])

        sizer1.AddSpacer(5)
        self.gauge = wx.Gauge(self.panel, -1, range=30, size=(200,-1), style=wx.GA_HORIZONTAL)
        sizer1.Add(self.gauge)

        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.OnTimer, self.timer)
        
        # Buttons
        sizer1.AddSpacer(20)
        
        self.btInsert = wx.Button(self.panel, -1, "&Insert")
        self.Bind(wx.EVT_BUTTON, self.OnInsert, self.btInsert)
        sizer1.Add(self.btInsert, 0, wx.TOP, 5)

        self.btUpdate = wx.Button(self.panel, -1, "&Update")
        self.Bind(wx.EVT_BUTTON, self.OnUpdate, self.btUpdate)
        sizer1.Add(self.btUpdate, 0, wx.TOP, 5)
        
        self.btDelete = wx.Button(self.panel, -1, "&Delete")
        self.Bind(wx.EVT_BUTTON, self.OnDelete, self.btDelete)
        sizer1.Add(self.btDelete, 0, wx.TOP, 5)
        
        sizer1.AddSpacer(20)
        
        self.btQRCode = wx.Button(self.panel, -1, "&QR code")
        self.Bind(wx.EVT_BUTTON, self.OnQRCode, self.btQRCode)
        sizer1.Add(self.btQRCode, 0, wx.TOP, 5)
        
        sizer.Add(sizer1, 0, wx.ALL, 5)
        sizer.AddSpacer(5)

        self.panel.SetSizerAndFit(sizer)


    def ConnectDb(self, dataBasePath):

        self.HideSecrets()
        self.listCtrl.DeleteAllItems()
        self.panel.Disable()

        self.conn = None
        self.data = None

        with wx.PasswordEntryDialog(self, 'Password for '+dataBasePath+' :', 'Password', '') as dlg:
            if dlg.ShowModal() == wx.ID_OK:
                try:
                    self.conn = Database(dataBasePath, dlg.GetValue(), not os.path.isfile(dataBasePath))
                    self.RetrieveData()
                    self.SetTitle(TITLE+' : '+dataBasePath)
                    self.panel.Enable()
                except Exception as ex:
                    wx.MessageBox(str(ex), ERROR, wx.OK | wx.ICON_ERROR)


    def RetrieveData(self):

        self.HideSecrets()
        self.listCtrl.DeleteAllItems()

        if not self.conn: return
        self.data = self.conn.GetData()

        for dd in self.data:
            index = self.listCtrl.InsertItem(self.listCtrl.GetItemCount(), str(dd[0]))
            self.listCtrl.SetItem(index, 1, dd[2]+' @ '+dd[1])

        
    def OnOpen(self, e):
        with wx.FileDialog(self, "Open Database", wildcard="TOTPass files (*.db)|*.db" ) as dlg:
            if dlg.ShowModal() == wx.ID_OK:
                pathname = dlg.GetPath()
                self.ConnectDb(pathname)


    def ShowSecrets(self, index):
        dd = self.data[index]
        self.txPath.SetValue(dd[1])
        self.txLogin.SetValue(dd[2])
        self.txPassword.SetValue(dd[3])
        self.txTotp.SetValue('')
        self.gauge.SetValue(0)
        self.secret = dd[4]
        if self.secret:
            try:
                totp, time_left = calculate_TOTP(self.secret)
                self.txTotp.SetValue(totp)
                self.gauge.SetValue(round(time_left))
                self.timer.Start(1000)
            except Exception as ex:
                wx.MessageBox(str(ex), ERROR, wx.OK | wx.ICON_ERROR) # must not be
                self.txTotp.SetValue('')
                self.secret = None


    def OnTimer(self, e):
        if self.secret:
            totp, time_left = calculate_TOTP(self.secret)
            self.txTotp.SetValue(totp)
            self.gauge.SetValue(round(time_left))
        else:
            self.timer.Stop()   # must not be


    def HideSecrets(self):
        self.timer.Stop()
        self.secret = None
        self.txPath.SetValue('')
        self.txLogin.SetValue('')
        self.txPassword.SetValue('')
        self.txTotp.SetValue('')
        self.gauge.SetValue(0)


    def OnItemActivated(self, e):
        self.ShowSecrets(e.GetIndex())


    def OnItemDeselected(self, e):
        self.HideSecrets()

    def OnInsert(self, e):
        with ItemDialog(self) as dlg:
            dlg.ShowModal()
        self.RetrieveData()


    def OnUpdate(self, e):
        index = self.listCtrl.GetFirstSelected()
        if index < 0: return wx.MessageBox("Select an item!", ERROR, wx.OK | wx.ICON_ERROR)
        with ItemDialog(self, idValue=self.data[index][0], data=self.data[index][1:]) as dlg:
            dlg.ShowModal()
        self.RetrieveData()


    def OnDelete(self, e):
        index = self.listCtrl.GetFirstSelected()
        if index < 0: return wx.MessageBox("Select an item!", ERROR, wx.OK | wx.ICON_ERROR)
        with wx.MessageDialog(None, "Delete selected item?", "Attention", wx.YES_NO | wx.ICON_QUESTION) as dlg:
            if dlg.ShowModal() == wx.ID_YES:
                self.conn.DeleteData(self.data[index][0])
        self.RetrieveData()

    def OnQRCode(self, e):
        try:
            path, login, secret = scan_QRcode()
            with ItemDialog(self, data=[path, login, '', secret]) as dlg:
                dlg.ShowModal()
        except Exception as ex:
            wx.MessageBox(str(ex), ERROR, wx.OK | wx.ICON_ERROR)
        self.RetrieveData()


    def OnAbout(self, e):
        with wx.MessageDialog(self, ABOUT_INFO, "About") as dlg:
            dlg.ShowModal()

        
    def OnExit(self, e):
        self.Close(True)


#------------------------------------------------------------------------------ 

app = wx.App(False)
frame = MainWindow()
app.MainLoop()
