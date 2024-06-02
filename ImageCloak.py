from tkinter import *
from tkinter import filedialog
from PIL import Image, ImageTk
import os
from stegano import lsb
import sys
from cryptography.fernet import Fernet


def resource_path(relative_path):
    
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


root = Tk()
root.title("BTP_21it3016")
root.geometry("950x750")
root.resizable(False, False)
root.configure(bg="#34495e")
root.iconbitmap(resource_path("assets/Logo.ico"))



def show_image():
    global filename
    filename = filedialog.askopenfilename(
        initialdir=os.getcwd(),
        title="Select Image",
        filetype=(
            ("Image Files", "*.png *.jpeg *.jpg *.bmp *.gif *.tiff"),
            ("All Files", "*.*")
        )
    )
    img = Image.open(filename)
    img = img.resize((450, 450), Image.LANCZOS)
    img = ImageTk.PhotoImage(img)
    lbl.configure(image=img)
    lbl.image = img

# Encryption function using a basic Caesar cipher
def encrypt(message, key=3):
    encrypted_message = ""
    for char in message:
        if char.isalpha():
            shifted = ord(char) + key
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_message += chr(shifted)
        else:
            encrypted_message += char
    return encrypted_message

# Decryption function for the Caesar cipher
def decrypt(encrypted_message, key=3):
    return encrypt(encrypted_message, -key)

def hide_data():
    global secret
    message = text1.get(1.0, END).strip()
    
    # Encrypt the message
    encrypted_message = encrypt(message)
  
    # Hide the encrypted message in the image
    secret = lsb.hide(str(filename), encrypted_message)

# ... (rest of the code remains the same)

def show_data():
    # Reveal the hidden data from the image
    encrypted_message = lsb.reveal(filename)
    
    # Decrypt the message
    decrypted_message = decrypt(encrypted_message)
  
    text1.delete(1.0, END)
    text1.insert(END, decrypted_message)

def save():
    if 'secret' in globals():
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=(("PNG Files", "*.png"), ("All Files", "*.*"))  # Limit file types to PNG in this example
        )
        if file_path:  # Check if a file path was selected
            secret.save(file_path)  # Save the modified image with the hidden data to the selected location
        else:
            print("No file path selected.")
    else:
        print("No modified image to save.")



logo = PhotoImage(file=resource_path("assets/output-onlinepngtools.png"))
Label(root, image=logo, bg="#34495e").place(x=10, y=10)

Label(root, text="BTP_21it3016", bg="#34495e", fg="white", font="arial 30 bold").place(x=90, y=15)

f = Frame(root, bd=3, bg="#2c3e50", width=450, height=450, relief=GROOVE)
f.place(x=10, y=80)

lbl = Label(f, bg="#2c3e50")
lbl.place(x=10, y=5)

frame2 = Frame(root, bd=3, width=450, height=450, relief=GROOVE, bg="#34495e")
frame2.place(x=480, y=80)

text1 = Text(frame2, font="Roboto 14", bg="white", fg="black", relief=GROOVE, wrap=WORD)
text1.place(x=0, y=0, width=450, height=450)

scrollbar1 = Scrollbar(frame2)
scrollbar1.place(x=430, y=0, height=445)

scrollbar1.configure(command=text1.yview)
text1.configure(yscrollcommand=scrollbar1.set)

frame3 = Frame(root, bd=3, bg="#2f4155", width=450, height=150, relief=GROOVE)
frame3.place(x=10, y=550)

Button(frame3, text="Open Image", width=10, height=2, font="arial 14 bold", command=show_image).place(x=20, y=30)
Button(frame3, text="Save Image", width=10, height=2, font="arial 14 bold", command=save).place(x=230, y=30)

frame4 = Frame(root, bd=3, bg="#2f4155", width=450, height=150, relief=GROOVE)
frame4.place(x=480, y=550)

Button(frame4, text="Hide Data", width=10, height=2, font="arial 14 bold", command=hide_data).place(x=20, y=30)
Button(frame4, text="Show Data", width=10, height=2, font="arial 14 bold", command=show_data).place(x=230, y=30)

root.mainloop()
