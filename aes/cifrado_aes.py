import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class AESCipher:
    """
    Implementación de AES en modo CBC con padding PKCS#7.
    Configurada por defecto para AES-256 (32 bytes) para sobres digitales.
    """

    def __init__(self, key_size: int = 256):
        if key_size not in (128, 192, 256):
            raise ValueError("El tamaño de la clave debe ser 128, 192 o 256 bits.")
        self.key_size_bytes = key_size // 8
        self.backend = default_backend()

    def _validar_clave(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != self.key_size_bytes:
            raise ValueError(
                f"Clave AES inválida: se esperaban {self.key_size_bytes} bytes "
                f"({self.key_size_bytes * 8} bits)."
            )

    def encrypt_bytes(self, data: bytes, key: bytes) -> tuple[bytes, bytes]:
        """Cifra datos binarios arbitrarios con AES-CBC y PKCS#7. Retorna (cifrado, iv)."""
        self._validar_clave(key)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    def decrypt_bytes(self, ciphertext: bytes, iv: bytes, key: bytes) -> bytes:
        """Descifra datos binarios con AES-CBC y retira padding PKCS#7."""
        self._validar_clave(key)
        if len(iv) != 16:
            raise ValueError("El vector de inicialización (IV) debe medir exactamente 16 bytes.")

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        try:
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
        except ValueError as e:
            raise ValueError(
                "Error al descifrar con AES-CBC: padding PKCS#7 inválido, clave o IV incorrectos."
            ) from e

    def encrypt_text(self, plaintext: str, key: bytes) -> tuple[str, str]:
        """Cifra una cadena UTF-8 y retorna (texto_cifrado_b64, iv_b64)."""
        ciphertext, iv = self.encrypt_bytes(plaintext.encode("utf-8"), key)
        return base64.b64encode(ciphertext).decode("utf-8"), base64.b64encode(iv).decode("utf-8")

    def decrypt_text(self, ciphertext_b64: str, iv_b64: str, key: bytes) -> str:
        """Descifra un texto en Base64 y retorna el string UTF-8 original."""
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        plaintext_bytes = self.decrypt_bytes(ciphertext, iv, key)
        return plaintext_bytes.decode("utf-8")

    def encrypt_file_to_bytes(self, input_filepath: str, key: bytes) -> tuple[bytes, bytes]:
        """
        Lee un archivo en modo binario por bloques de 4096 bytes, aplica PKCS#7
        y lo cifra con AES-CBC. Retorna (datos_cifrados, iv).
        """
        self._validar_clave(key)
        if not os.path.isfile(input_filepath):
            raise FileNotFoundError(f"El archivo de entrada no existe: '{input_filepath}'.")

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        bloques_cifrados = []
        try:
            with open(input_filepath, "rb") as f_in:
                for chunk in iter(lambda: f_in.read(4096), b""):
                    padded_chunk = padder.update(chunk)
                    bloques_cifrados.append(encryptor.update(padded_chunk))
                bloques_cifrados.append(encryptor.update(padder.finalize()) + encryptor.finalize())
            return b"".join(bloques_cifrados), iv
        except OSError as e:
            raise IOError(f"Error al leer el archivo '{input_filepath}': {e}") from e

    def decrypt_bytes_to_file(
        self, ciphertext: bytes, iv: bytes, key: bytes, output_filepath: str
    ) -> None:
        """
        Descifra bloques binarios con AES-CBC, retira padding PKCS#7 y guarda
        el archivo recuperado sin sobrescribir el original.
        """
        self._validar_clave(key)
        if len(iv) != 16:
            raise ValueError("El IV debe medir exactamente 16 bytes.")

        directorio = os.path.dirname(output_filepath)
        if directorio:
            os.makedirs(directorio, exist_ok=True)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()

        try:
            with open(output_filepath, "wb") as f_out:
                for i in range(0, len(ciphertext), 4096):
                    chunk = ciphertext[i : i + 4096]
                    decrypted_chunk = decryptor.update(chunk)
                    f_out.write(unpadder.update(decrypted_chunk))
                f_out.write(unpadder.update(decryptor.finalize()) + unpadder.finalize())
        except ValueError as e:
            if os.path.exists(output_filepath):
                os.remove(output_filepath)
            raise ValueError(
                "Error de padding PKCS#7 al descifrar archivo: datos corruptos o clave/IV incorrectos."
            ) from e
        except OSError as e:
            raise IOError(f"Error al escribir el archivo '{output_filepath}': {e}") from e