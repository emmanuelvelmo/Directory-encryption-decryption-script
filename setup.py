from cx_Freeze import setup, Executable

setup(name="Directory encryption decryption", executables=[Executable("Directory encryption decryption script.py")], options={"build_exe": {"excludes": ["tkinter"]}})
