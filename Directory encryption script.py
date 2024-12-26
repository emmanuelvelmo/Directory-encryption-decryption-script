import os
import base64
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Variables para opción, contraseña y directorio
op_val = 0
dir_val = ""
passw_val = ""
nuevo_dir = ""

while True:
    # Opciones en pantalla
    op_val = int(input("1 for encryption | 2 for decryption: "))

    match op_val:
        case 1:
            # Solicitar directorio
            dir_val = input("Enter directory: ")

            # Mensaje de advertencia, while se ejecuta nuevamente
            if not os.path.exists(dir_val):
                print("Error, wrong directory\n")
                continue
            
            # Solicitar contraseña y codificar a bytes
            passw_val = input("Enter password: ").encode()

            # Derivar la clave a partir de la contraseña
            kdf_val = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, salt=b'salt')
            clave_val = kdf_val.derive(passw_val)

            # Copiar nuevo directorio conservando el nombre + "(encrypted)"
            nuevo_dir = dir_val + " (encrypted)"
            os.mkdir(nuevo_dir)

            # Iterar recursivamente nuevo directorio encriptando cada archivo usando la contraseña
            for dir_act, subdirs_iter, archs_iter in os.walk(dir_val):
                for arch_it in archs_iter:
                    arch_dir = os.path.join(dir_act, arch_it)
                    
                    with open(arch_dir, "rb") as arch_rd:
                        arch_tmp = arch_rd.read()
                    
                    # Encriptar el archivo
                    iv_val = os.urandom(16)
                    cipher_val = Cipher(algorithms.AES(clave_val), modes.CBC(iv_val))
                    encryptor_val = cipher_val.encryptor()
                    padder = padding.PKCS7(128).padder()
                    padded_data = padder.update(arch_tmp) + padder.finalize()
                    encrypted_data = encryptor_val.update(padded_data) + encryptor_val.finalize()
                    nuevo_arch = os.path.join(nuevo_dir, os.path.relpath(arch_dir, dir_val))
                    
                    # Crear directorios si no existen
                    os.makedirs(os.path.dirname(nuevo_arch), exist_ok=True)
                    
                    # Escribir archivo encriptado
                    with open(nuevo_arch, "wb") as arch_rd:
                        arch_rd.write(iv_val + encrypted_data)
            
            # Salto de línea
            print()

        case 2:
            # Solicitar directorio
            dir_val = input("Enter directory: ")

            # Mensaje de advertencia, while se ejecuta nuevamente
            if not os.path.exists(dir_val):
                print("Error, wrong directory\n")
                continue
            
            # Solicitar contraseña y codificar a bytes
            passw_val = input("Enter password: ").encode()

            # Derivar la clave a partir de la contraseña
            kdf_val = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, salt=b'salt')
            clave_val = kdf_val.derive(passw_val)

            # Copiar nuevo directorio conservando el nombre + "(decrypted)"
            nuevo_dir = dir_val + " (decrypted)"
            os.mkdir(nuevo_dir)

            # Iterar recursivamente nuevo directorio desencriptando cada archivo usando la contraseña
            for dir_act, subdirs_iter, archs_iter in os.walk(dir_val):
                for arch_it in archs_iter:
                    arch_dir = os.path.join(dir_act, arch_it)
                    
                    with open(arch_dir, "rb") as arch_rd:
                        encrypted_data = arch_rd.read()
                    
                    # Desencriptar el archivo
                    iv_val = encrypted_data[:16]
                    encrypted_data = encrypted_data[16:]
                    cipher = Cipher(algorithms.AES(clave_val), modes.CBC(iv_val))
                    decryptor = cipher.decryptor()
                    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
                    unpadder = padding.PKCS7(128).unpadder()
                    arch_tmp = unpadder.update(decrypted_padded_data) + unpadder.finalize()
                    nuevo_arch = os.path.join(nuevo_dir, os.path.relpath(arch_dir, dir_val))
                    
                    # Crear directorios si no existen
                    os.makedirs(os.path.dirname(nuevo_arch), exist_ok=True)
                    
                    # Escribir archivo desencriptado
                    with open(nuevo_arch, "wb") as arch_rd:
                        arch_rd.write(arch_tmp)
            
            # Salto de línea
            print()

        case _:
            print("Error, wrong format\n")