import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generar_par_claves_rsa(key_size: int = 2048):
    """
    Genera un par de claves RSA (privada y pública).
    Exige un tamaño mínimo de 2048 bits según los requisitos de seguridad.
    """
    if key_size < 2048:
        raise ValueError("El tamaño de clave RSA debe ser de al menos 2048 bits.")

    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica


def guardar_claves_rsa(
    clave_privada,
    clave_publica,
    ruta_privada: str = os.path.join("claves", "clave_privada.pem"),
    ruta_publica: str = os.path.join("claves", "clave_publica.pem"),
) -> tuple[str, str]:
    """Almacena la clave privada (PKCS#8) y la clave pública (SubjectPublicKeyInfo) en archivos PEM separados."""
    for ruta in (ruta_privada, ruta_publica):
        directorio = os.path.dirname(ruta)
        if directorio:
            os.makedirs(directorio, exist_ok=True)

    pem_privada = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_publica = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    try:
        with open(ruta_privada, "wb") as f_priv:
            f_priv.write(pem_privada)
        with open(ruta_publica, "wb") as f_pub:
            f_pub.write(pem_publica)
        return ruta_privada, ruta_publica
    except OSError as e:
        raise IOError(f"Error al almacenar las claves RSA: {e}") from e


def cargar_clave_privada(ruta_privada: str):
    """Carga una clave privada RSA desde un archivo PEM."""
    if not os.path.isfile(ruta_privada):
        raise FileNotFoundError(f"No se encontró la clave privada RSA: '{ruta_privada}'.")
    try:
        with open(ruta_privada, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except (ValueError, TypeError) as e:
        raise ValueError(f"El archivo '{ruta_privada}' no contiene una clave privada PEM válida.") from e


def cargar_clave_publica(ruta_publica: str):
    """Carga una clave pública RSA desde un archivo PEM."""
    if not os.path.isfile(ruta_publica):
        raise FileNotFoundError(f"No se encontró la clave pública RSA: '{ruta_publica}'.")
    try:
        with open(ruta_publica, "rb") as f:
            return serialization.load_pem_public_key(f.read())
    except (ValueError, TypeError) as e:
        raise ValueError(f"El archivo '{ruta_publica}' no contiene una clave pública PEM válida.") from e