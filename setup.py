from cx_Freeze import setup, Executable

setup(
    name="Directory encryption decryption",
    version="1.0",
    description="Directory encryption script",
    executables=[Executable("Directory encryption decryption script.py")]
)