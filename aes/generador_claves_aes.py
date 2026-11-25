import os


def generar_clave_aes(key_size: int = 256) -> bytes:
    """
    Genera una clave de sesión AES criptográficamente segura.
    Para sobres digitales se utiliza 256 bits (32 bytes) por defecto.
    """
    if key_size not in (128, 192, 256):
        raise ValueError("El tamaño de la clave AES debe ser 128, 192 o 256 bits.")
    return os.urandom(key_size // 8)


def guardar_clave_aes(clave: bytes, ruta_archivo: str) -> None:
    """Almacena una clave AES en formato binario."""
    directorio = os.path.dirname(ruta_archivo)
    if directorio:
        os.makedirs(directorio, exist_ok=True)
    try:
        with open(ruta_archivo, "wb") as f:
            f.write(clave)
    except OSError as e:
        raise IOError(f"Error al guardar la clave AES en '{ruta_archivo}': {e}") from e


def cargar_clave_aes(ruta_archivo: str) -> bytes:
    """Carga una clave AES desde un archivo binario."""
    if not os.path.exists(ruta_archivo):
        raise FileNotFoundError(f"No se encontró el archivo de clave AES: '{ruta_archivo}'.")
    try:
        with open(ruta_archivo, "rb") as f:
            clave = f.read()
        if len(clave) not in (16, 24, 32):
            raise ValueError(f"Longitud de clave AES inválida ({len(clave)} bytes).")
        return clave
    except OSError as e:
        raise IOError(f"Error al leer la clave AES de '{ruta_archivo}': {e}") from e