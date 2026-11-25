import os
import json
import base64
import filecmp
from aes.cifrado_aes import AESCipher
from rsa.cifrado_rsa import descifrar_clave_aes_con_rsa


CAMPOS_REQUERIDOS = {
    "tipo",
    "clave_aes_cifrada_b64",
    "iv_b64",
    "contenido_cifrado_b64",
}


def cargar_sobre(ruta_sobre: str) -> dict:
    """Carga y valida la estructura de un sobre digital existente."""
    if not os.path.isfile(ruta_sobre):
        raise FileNotFoundError(f"No se encontró el sobre digital: '{ruta_sobre}'.")

    try:
        with open(ruta_sobre, "r", encoding="utf-8") as f:
            sobre = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"El archivo '{ruta_sobre}' no es un JSON válido.") from e

    faltantes = CAMPOS_REQUERIDOS - set(sobre.keys())
    if faltantes:
        raise ValueError(f"El sobre digital está incompleto. Faltan campos: {faltantes}")

    return sobre


def abrir_sobre(
    ruta_sobre: str,
    clave_privada,
    directorio_salida: str = "salida",
) -> dict:
    """
    Abre un sobre digital existente:
    1. Recupera la clave de sesión AES-256 con la clave privada RSA (RSA-OAEP + SHA-256).
    2. Descifra el contenido con AES-256-CBC y retira el padding PKCS#7.
    3. Recupera el archivo binario (en 'salida/') o el mensaje de texto UTF-8.
    """
    sobre = cargar_sobre(ruta_sobre)

    try:
        clave_aes_cifrada = base64.b64decode(sobre["clave_aes_cifrada_b64"])
        iv = base64.b64decode(sobre["iv_b64"])
        contenido_cifrado = base64.b64decode(sobre["contenido_cifrado_b64"])
    except Exception as e:
        raise ValueError("Error al decodificar los campos Base64 del sobre digital.") from e

    # Paso 1: Recuperar la clave de sesión AES con la clave privada RSA
    clave_aes_recuperada = descifrar_clave_aes_con_rsa(clave_aes_cifrada, clave_privada)

    # Paso 2: Descifrar el contenido con AES-256-CBC
    aes = AESCipher(key_size=256)
    tipo = sobre["tipo"]

    if tipo == "archivo":
        nombre_original = sobre.get("nombre_original") or "archivo_recuperado.bin"
        os.makedirs(directorio_salida, exist_ok=True)
        ruta_recuperada = os.path.join(directorio_salida, f"recuperado_{nombre_original}")
        aes.decrypt_bytes_to_file(contenido_cifrado, iv, clave_aes_recuperada, ruta_recuperada)
        return {
            "tipo": "archivo",
            "ruta_recuperada": ruta_recuperada,
            "clave_aes_recuperada_hex": clave_aes_recuperada.hex(),
        }

    if tipo == "texto":
        datos_planos = aes.decrypt_bytes(contenido_cifrado, iv, clave_aes_recuperada)
        mensaje_recuperado = datos_planos.decode("utf-8")
        return {
            "tipo": "texto",
            "mensaje_recuperado": mensaje_recuperado,
            "clave_aes_recuperada_hex": clave_aes_recuperada.hex(),
        }

    raise ValueError(f"Tipo de sobre digital no soportado: '{tipo}'.")


def verificar_integridad_archivo(ruta_original: str, ruta_recuperada: str) -> bool:
    """Compara dos archivos estrictamente byte a byte."""
    if not os.path.isfile(ruta_original) or not os.path.isfile(ruta_recuperada):
        raise FileNotFoundError("Ambos archivos deben existir para realizar la comparación.")
    return filecmp.cmp(ruta_original, ruta_recuperada, shallow=False)