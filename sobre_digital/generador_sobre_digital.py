import os
import json
import base64
from aes.generador_claves_aes import generar_clave_aes
from aes.cifrado_aes import AESCipher
from rsa.cifrado_rsa import cifrar_clave_aes_con_rsa


def guardar_sobre(sobre: dict, ruta_sobre: str) -> str:
    """Guarda la estructura del sobre digital en un archivo JSON."""
    directorio = os.path.dirname(ruta_sobre)
    if directorio:
        os.makedirs(directorio, exist_ok=True)
    try:
        with open(ruta_sobre, "w", encoding="utf-8") as f:
            json.dump(sobre, f, indent=4, ensure_ascii=False)
        return ruta_sobre
    except OSError as e:
        raise IOError(f"Error al guardar el sobre digital en '{ruta_sobre}': {e}") from e


def crear_sobre_archivo(
    ruta_archivo: str,
    clave_publica,
    ruta_sobre: str,
    clave_aes: bytes | None = None,
) -> dict:
    """
    Crea y guarda un sobre digital a partir de cualquier archivo binario:
    1. Genera (o usa) una clave de sesión AES-256.
    2. Cifra el archivo en modo binario con AES-256-CBC + PKCS#7 e IV aleatorio de 16 bytes.
    3. Cifra la clave de sesión AES con la clave pública RSA (RSA-OAEP + SHA-256).
    4. Empaqueta y guarda el sobre digital.
    """
    if not os.path.isfile(ruta_archivo):
        raise FileNotFoundError(f"El archivo a proteger no existe: '{ruta_archivo}'.")

    clave_sesion = clave_aes if clave_aes is not None else generar_clave_aes(256)
    aes = AESCipher(key_size=256)

    datos_cifrados, iv = aes.encrypt_file_to_bytes(ruta_archivo, clave_sesion)
    clave_aes_cifrada = cifrar_clave_aes_con_rsa(clave_sesion, clave_publica)

    sobre = {
        "tipo": "archivo",
        "nombre_original": os.path.basename(ruta_archivo),
        "algoritmo_simetrico": "AES-256-CBC",
        "padding_simetrico": "PKCS#7",
        "algoritmo_asimetrico": "RSA-OAEP-SHA256",
        "clave_aes_cifrada_b64": base64.b64encode(clave_aes_cifrada).decode("utf-8"),
        "iv_b64": base64.b64encode(iv).decode("utf-8"),
        "contenido_cifrado_b64": base64.b64encode(datos_cifrados).decode("utf-8"),
    }

    guardar_sobre(sobre, ruta_sobre)
    return {
        "ruta_sobre": ruta_sobre,
        "clave_aes_hex": clave_sesion.hex(),
        "iv_hex": iv.hex(),
        "tamano_clave_cifrada_bytes": len(clave_aes_cifrada),
        "tamano_contenido_cifrado_bytes": len(datos_cifrados),
    }


def crear_sobre_texto(
    mensaje: str,
    clave_publica,
    ruta_sobre: str,
    clave_aes: bytes | None = None,
) -> dict:
    """
    Crea y guarda un sobre digital a partir de un mensaje de texto UTF-8.
    """
    if not mensaje:
        raise ValueError("El mensaje de texto no puede estar vacío.")

    clave_sesion = clave_aes if clave_aes is not None else generar_clave_aes(256)
    aes = AESCipher(key_size=256)

    datos_cifrados, iv = aes.encrypt_bytes(mensaje.encode("utf-8"), clave_sesion)
    clave_aes_cifrada = cifrar_clave_aes_con_rsa(clave_sesion, clave_publica)

    sobre = {
        "tipo": "texto",
        "nombre_original": None,
        "algoritmo_simetrico": "AES-256-CBC",
        "padding_simetrico": "PKCS#7",
        "algoritmo_asimetrico": "RSA-OAEP-SHA256",
        "clave_aes_cifrada_b64": base64.b64encode(clave_aes_cifrada).decode("utf-8"),
        "iv_b64": base64.b64encode(iv).decode("utf-8"),
        "contenido_cifrado_b64": base64.b64encode(datos_cifrados).decode("utf-8"),
    }

    guardar_sobre(sobre, ruta_sobre)
    return {
        "ruta_sobre": ruta_sobre,
        "clave_aes_hex": clave_sesion.hex(),
        "iv_hex": iv.hex(),
        "tamano_clave_cifrada_bytes": len(clave_aes_cifrada),
        "tamano_contenido_cifrado_bytes": len(datos_cifrados),
    }