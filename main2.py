import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDial, QDialog, QApplication, QStackedWidget, QFileDialog
import elgamal
import sha256
import cv2

# ---------------------------------UTILITIES---------------------------------


def goBack():
    # widget.setCurrentIndex(widget.currentIndex() - 1)
    widget.removeWidget(widget.currentWidget())

# ---------------------------------HOME---------------------------------


class HomeScreen(QDialog):
    def __init__(self):
        super(HomeScreen, self).__init__()
        loadUi("UI/main.ui", self)

        self.Keygen.clicked.connect(self.goToKeygen)
        self.sign.clicked.connect(self.goToSign)
        self.verify.clicked.connect(self.goToVerify)

    def goToKeygen(self):
        keygen = ElGamalKeyGenScreen()
        widget.addWidget(keygen)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def goToSign(self):
        sign = signScreen()
        widget.addWidget(sign)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def goToVerify(self):
        verify = verifyScreen()
        widget.addWidget(verify)
        widget.setCurrentIndex(widget.currentIndex()+1)

# ---------------------------------El Gamal---------------------------------


class ElGamalKeyGenScreen(QDialog):
    def __init__(self):
        super(ElGamalKeyGenScreen, self).__init__()
        loadUi("UI/ElGamal/ElGamal-keygen.ui", self)
        self.mode = "encrypt"
        self.message = ""
        self.outputPath = ""
        self.key = ""
        self.curve = ""

        # actions
        self.goButton.clicked.connect(self.runGenerateKey)  # generate key
        self.backButton.clicked.connect(goBack)

    def runGenerateKey(self):
        path = self.outputKeyFileField.text()
        elgamal.elgamal_generate_key(16, path)

# ---------------------------------Sign---------------------------------


class signScreen(QDialog):
    def __init__(self):
        super(signScreen, self).__init__()
        loadUi("UI/ElGamal/Sign.ui", self)
        self.mode = "sign"
        self.message = ""
        self.outputPath = ""
        self.key = ""
        self.curve = ""

        # actions
        self.fileRadio.toggled.connect(self.togglefileRadio)
        self.keyboardRadio.toggled.connect(self.togglekeyboardRadio)
        self.SeparateFile.toggled.connect(self.toggleSeparateFile)
        self.InsideFile.toggled.connect(self.toggleInsideFile)
        self.messageFileButton.clicked.connect(self.browseInput)
        self.goButton.clicked.connect(self.runSign)  # generate key
        self.backButton.clicked.connect(goBack)

    def browseInput(self):
        f = QFileDialog.getOpenFileName(
            self, 'Open file', '~/shifa/Desktop')
        self.inputFileField.setText(f[0])

    def togglefileRadio(self): self.btnInputState(self.fileRadio)

    def togglekeyboardRadio(self): self.btnInputState(self.keyboardRadio)

    def toggleSeparateFile(self): self.btnInputState2(self.SeparateFile)

    def toggleInsideFile(self): self.btnInputState2(self.InsideFile)

    def btnInputState(self, b):
        if b.text() == "File":
            if b.isChecked():
                self.inputKeyboardField.setReadOnly(True)
                self.messageFileButton.setEnabled(True)
                self.fileInputMethod = "File"
                self.inputKeyboardField.setText("")
        elif b.text() == "Keyboard":
            if b.isChecked():
                self.inputKeyboardField.setReadOnly(False)
                self.messageFileButton.setEnabled(False)
                self.fileInputMethod = "Keyboard"
                self.inputFileField.setText("")

    def btnInputState2(self, b):
        if b.text() == "Separate File":
            if b.isChecked():
                self.signatureLocation = "Separate File"
        elif b.text() == "Inside File":
            if b.isChecked():
                self.signatureLocation = "Inside File"

    def getMessage(self):
        if (self.fileInputMethod == "File"):
            path = self.inputFileField.text()
            f = open(path, "r")
            self.message = f.read()
            f.close()
        else:
            self.message = self.inputKeyboardField.text()

    def getKey(self):
        self.key = (
            int(self.XField.text()),
            int(self.PField.text()),
            int(self.GField.text())
        )

    def getOutputPath(self):
        self.outputPath = "save/" + self.outputFileField.text() + "-signed.txt"
        self.outputMsgPath = "save/" + self.outputFileField.text() + "-message.txt"

    def runSign(self):
        self.getMessage()
        self.getKey()
        self.getOutputPath()

        hashed = int.from_bytes(sha256.hash(
            self.message).hex().encode('utf8'), 'big')

        signature = elgamal.elgamal_dss_sign(
            self.key[0], self.key[1], self.key[2], hashed)

        if self.fileInputMethod == 'Keyboard':
            with open(self.outputMsgPath, "w") as f:
                f.write(self.message + '\n')
            f.close()

        if (self.signatureLocation == "Inside File"):
            elgamal.save_eof(signature[0], signature[1],
                             signature[2], self.outputPath)
        elif (self.signatureLocation == "Separate File"):
            elgamal.save_nf(signature[0], signature[1],
                            signature[2], self.outputPath)

        self.Status.setText('Hash Success!')


class verifyScreen(QDialog):
    def __init__(self):
        super(verifyScreen, self).__init__()
        loadUi("UI/ElGamal/Verify.ui", self)
        self.mode = "verify"
        self.message = ""
        self.outputPath = ""
        self.key = ""
        self.curve = ""

        # actions
        self.SeparateFile.toggled.connect(self.toggleSeparateFile)
        self.InsideFile.toggled.connect(self.toggleInsideFile)
        self.messageFileButton.clicked.connect(self.browseInputMessage)
        self.signatureFileButton.clicked.connect(self.browseInputSignature)
        self.goButton.clicked.connect(self.runVerify)  # generate key
        self.backButton.clicked.connect(goBack)

    def toggleSeparateFile(self): self.btnInputState(self.SeparateFile)

    def toggleInsideFile(self): self.btnInputState(self.InsideFile)

    def browseInputMessage(self):
        f = QFileDialog.getOpenFileName(
            self, 'Open file', '~/shifa/Desktop')
        self.messageField.setText(f[0])

    def browseInputSignature(self):
        f = QFileDialog.getOpenFileName(
            self, 'Open file', '~/shifa/Desktop')
        self.signatureFileField.setText(f[0])

    def btnInputState(self, b):
        if b.text() == "Separate File":
            if b.isChecked():
                self.messageFileButton.setEnabled(True)
                self.signatureFileButton.setEnabled(True)
                self.signatureLocation = "Separate File"
        elif b.text() == "Inside File":
            if b.isChecked():
                self.messageFileButton.setEnabled(True)
                self.signatureFileButton.setEnabled(False)
                self.signatureLocation = "Inside File"
                self.signatureFileField.setText("")

    def getMessage(self):
        if self.signatureLocation == "Separate File":
            self.message, self.r, self.s = elgamal.read_nf(
                self.messageField.text(), self.signatureFileField.text())
        elif self.signatureLocation == "Inside File":
            self.message, self.r, self.s = elgamal.read_eof(
                self.messageField.text())

    def getKey(self):
        self.key = (
            int(self.yField.text()),
            int(self.gField.text()),
            int(self.pField.text())
        )

    def runVerify(self):
        self.getMessage()
        self.getKey()

        print(self.message)

        hashed = int.from_bytes(sha256.hash(
            self.message).hex().encode('utf8'), 'big')

        verify = elgamal.elgamal_dss_verify(
            int(self.key[0]), int(self.key[1]), int(self.key[2]), hashed, int(self.r), int(self.s))

        print(verify)
        if verify:
            self.Status.setText('Verified!')
        else:
            self.Status.setText('Unverified!')


# main
app = QApplication(sys.argv)
widget = QStackedWidget()

home = HomeScreen()

widget.addWidget(home)
widget.setFixedWidth(1201)
widget.setFixedHeight(821)
widget.show()
try:
    sys.exit(app.exec_())
except:
    print("Exiting")
