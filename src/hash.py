import hashlib

def calcular_hash_sha256(ruta_archivo):
    sha256_hash = hashlib.sha256()
    try:
        with open(ruta_archivo, "rb") as f:
            for bloque in iter(lambda: f.read(4096), b""):
                sha256_hash.update(bloque)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"El archivo {ruta_archivo} no se encontró.")
        return None
    except IOError:
        print(f"Error al leer el archivo {ruta_archivo}.")
        return None

ruta_archivo = input("Introduce la ruta del archivo: ")
hash_resultado = calcular_hash_sha256(ruta_archivo)

if hash_resultado:
    print(f"Hash SHA-256 del archivo: {hash_resultado}")
    # Escribir el hash en un archivo llamado hash.txt
    try:
        with open("hash.txt", "w") as archivo_salida:
            archivo_salida.write(f"Hash SHA-256 del archivo {ruta_archivo}:\n{hash_resultado}\n")
        print("El hash ha sido guardado en hash.txt")
    except IOError:
        print("Error al escribir en el archivo hash.txt.")
