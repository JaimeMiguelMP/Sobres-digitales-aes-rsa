from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes


def cifrar_clave_aes_con_rsa(clave_aes: bytes, clave_publica) -> bytes:
    """
    Protege una clave de sesión AES utilizando RSA-OAEP con SHA-256
    y la clave pública del destinatario.
    """
    if not isinstance(clave_aes, bytes) or len(clave_aes) == 0:
        raise ValueError("La clave AES a cifrar debe ser una secuencia de bytes no vacía.")

    try:
        return clave_publica.encrypt(
            clave_aes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise RuntimeError(f"Error al cifrar la clave AES con RSA-OAEP: {e}") from e


def descifrar_clave_aes_con_rsa(clave_aes_cifrada: bytes, clave_privada) -> bytes:
    """
    Recupera la clave de sesión AES utilizando RSA-OAEP con SHA-256
    y la clave privada del destinatario.
    """
    try:
        return clave_privada.decrypt(
            clave_aes_cifrada,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as e:
        raise ValueError(
            "No se pudo descifrar la clave AES con RSA-OAEP: la clave privada no corresponde "
            "al destinatario o la clave cifrada fue alterada."
        ) from e