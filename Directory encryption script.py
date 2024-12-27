import os
import base64
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Variables para opción, contraseña y directorio
op_val = 0
dir_val = ""
passw_val = ""
dir_val = ""

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
            kdf_val = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, iterations = 100000, salt = b'XXXXXXXXXXXXXXXX')
            clave_val = kdf_val.derive(passw_val)
            
            # Copiar nuevo directorio conservando el nombre + "(encrypted)"
            os.mkdir(dir_val + " (encrypted)")

            # Iterar recursivamente nuevo directorio encriptando cada archivo usando la contraseña
            for dir_act, subdirs_iter, archs_iter in os.walk(dir_val):
                for arch_it in archs_iter:
                    # Directorio del archivo
                    arch_dir = os.path.join(dir_act, arch_it)
                    
                    # Lectura de archivo
                    with open(arch_dir, "rb") as arch_rd:
                        arch_tmp = arch_rd.read()
                    
                    # Encriptar el archivo
                    # Generar un vector de inicialización (IV) aleatorio
                    iv_val = os.urandom(16)
                    # Se crea un objeto Cipher utilizando el algoritmo AES
                    cipher_val = Cipher(algorithms.AES(clave_val), modes.CBC(iv_val))
                    # Se crea un objeto Encryptor a partir del objeto Cipher
                    encryptor_val = cipher_val.encryptor()
                    
                    # Se crea un objeto Padder para agregar relleno a los datos utilizando el algoritmo PKCS#7
                    padder_val = padding.PKCS7(128).padder()
                    # Se agrega relleno a los datos del archivo utilizando el objeto Padder
                    padded_data = padder_val.update(arch_tmp) + padder_val.finalize()
                    
                    # Se encriptan los datos con relleno utilizando el objeto Encryptor
                    encrypted_data = encryptor_val.update(padded_data) + encryptor_val.finalize()
                    
                    # Crear la ruta del archivo encriptado
                    nuevo_arch = os.path.join(dir_val + " (encrypted)", os.path.relpath(arch_dir, dir_val))
                    # Crear el directorio si no existe
                    os.makedirs(os.path.dirname(nuevo_arch), exist_ok = True)
                    
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
            kdf_val = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, iterations = 100000, salt = b'salt')
            clave_val = kdf_val.derive(passw_val)

            # Copiar nuevo directorio conservando el nombre + "(decrypted)"
            os.mkdir(dir_val + " (decrypted)")

            # Iterar recursivamente nuevo directorio desencriptando cada archivo usando la contraseña
            for dir_act, subdirs_iter, archs_iter in os.walk(dir_val):
                for arch_it in archs_iter:
                    # Directorio del archivo
                    arch_dir = os.path.join(dir_act, arch_it)
                    
                    # Lectura del archivo
                    with open(arch_dir, "rb") as arch_rd:
                        encrypted_data = arch_rd.read()
                    
                    # Desencriptar el archivo
                    #  Se extraen los primeros 16 bytes del archivo encriptado, que corresponden al vector de inicialización (IV)
                    iv_val = encrypted_data[:16]
                    # Se extraen los datos encriptados restantes
                    encrypted_data = encrypted_data[16:]
                    # Se crea un objeto Cipher utilizando el algoritmo AES, el modo CBC (Cipher Block Chaining) y el IV extraído
                    cipher_val = Cipher(algorithms.AES(clave_val), modes.CBC(iv_val))
                    # Se crea un objeto Decryptor a partir del objeto Cipher
                    decryptor_val = cipher_val.decryptor()
                    # Se desencriptan los datos utilizando el objeto Decryptor. El método update() desencripta los datos proporcionados, y el método finalize() se utiliza para procesar cualquier bloque restante
                    decrypted_padded_data = decryptor_val.update(encrypted_data) + decryptor_val.finalize()
                    
                    # Se crea un objeto Unpadder para eliminar el relleno (padding) utilizado durante la encriptación
                    unpadder_val = padding.PKCS7(128).unpadder()
                    # Se elimina el relleno de los datos desencriptados utilizando el objeto Unpadder
                    arch_tmp = unpadder_val.update(decrypted_padded_data) + unpadder_val.finalize()
                    
                    # Crear la ruta del archivo encriptado
                    nuevo_arch = os.path.join(dir_val + " (decrypted)", os.path.relpath(arch_dir, dir_val))
                    # Crear el directorio si no existe
                    os.makedirs(os.path.dirname(nuevo_arch), exist_ok = True)
                    
                    # Escribir archivo desencriptado
                    with open(nuevo_arch, "wb") as arch_rd:
                        arch_rd.write(arch_tmp)
            
            # Salto de línea
            print()

        case _:
            print("Error, wrong format\n")
