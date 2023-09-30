from PDForensic import PDForensic
from pathlib import Path

from tkinter import *

class myparser(PDForensic):
    def __init__(self,pdf):
        super().__init__(pdf, process_data = True, process_tags = False, filter_ = True, strings = ["/Pages"], hexa = ["000102"], regexs = ['[0-9a-f]{32}'], types = ["xref"], ids = [2])
    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        print(type_, data, typename)

def scan():
    var.set(f"Reultat du fichier \"{chemin.get()}\"")
    if Path(chemin.get()).is_file():
        var2.set("Veillez patienter")
        scan = myparser(chemin.get())
        scan.parse()
        report = scan.report()

        var2.set(f"{str(report['malicious'])}")

    else:
        var2.set(f"le fichier \"{chemin.get()}\" n'exite pas")
    
root = Tk() # fenetre principal
var =StringVar()
var2 = StringVar()
m = Label(
    root,
    text="Scan tes PDF",
    padx=120,
    font=("broadway",20))
    
chemin = Entry(root,bg="green")

button = Button(root,text="scan",command=scan)
resultat1 = Label(root,textvariable = var)
resultat2 = Label(root,textvariable = var2 )

m.pack()
chemin.pack()
button.pack()
resultat1.pack()
resultat2.pack()

root.mainloop()
