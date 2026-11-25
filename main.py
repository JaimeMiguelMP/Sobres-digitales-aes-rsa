"""
Archivo principal del proyecto de sobres digitales utilizando AES-256-CBC y RSA-OAEP.

Autor: Martínez Pérez Jaime Miguel
Fecha: 23/noviembre/2026
Materia: Criptografía

"""

import os
from rsa.generador_claves_rsa import (
    generar_par_claves_rsa,
    guardar_claves_rsa,
    cargar_clave_privada,
    cargar_clave_publica,
)
from rsa.cifrado_rsa import cifrar_clave_aes_con_rsa, descifrar_clave_aes_con_rsa
from aes.generador_claves_aes import generar_clave_aes
from sobre_digital.generador_sobre_digital import crear_sobre_archivo, crear_sobre_texto
from sobre_digital.lector_sobre_digital import abrir_sobre, verificar_integridad_archivo


RUTA_PRIVADA_DEF = os.path.join("claves", "clave_privada.pem")
RUTA_PUBLICA_DEF = os.path.join("claves", "clave_publica.pem")


def limpiar_ruta(ruta: str) -> str:
    """Elimina espacios y comillas al arrastrar archivos a la consola."""
    return ruta.strip().lstrip("& ").strip("'\"")


def flujo_completo_automatico() -> None:
    """
    Ejecuta automáticamente el flujo integral del proyecto (pasos 1 a 9):
    generación y carga de RSA -> generación de clave AES-256 -> prueba RSA-OAEP ->
    creación/guardado del sobre -> apertura/recuperación -> validación de integridad.
    """
    print("\n" + "=" * 65)
    print(" FLUJO COMPLETO AUTOMÁTICO DE SOBRE DIGITAL (AES-256 + RSA-OAEP)")
    print("=" * 65)

    modo = input("¿Qué deseas proteger? [1] Archivo  [2] Mensaje de texto: ").strip()
    if modo not in ("1", "2"):
        print("[ERROR] Opción inválida. Selecciona 1 o 2.")
        return

    entrada_archivo = None
    entrada_texto = None

    if modo == "1":
        entrada_archivo = limpiar_ruta(input("Ruta del archivo a cifrar (puedes arrastrarlo aquí): "))
        if not os.path.isfile(entrada_archivo):
            print(f"[ERROR] El archivo '{entrada_archivo}' no existe.")
            return
    else:
        entrada_texto = input("Escribe el mensaje de texto a proteger: ")
        if not entrada_texto:
            print("[ERROR] El mensaje no puede estar vacío.")
            return

    try:
        # 1. Generar par de claves RSA y almacenarlas en archivos separados
        print("\n[Paso 1] Generando par de claves RSA (2048 bits)...")
        priv_gen, pub_gen = generar_par_claves_rsa(2048)
        guardar_claves_rsa(priv_gen, pub_gen, RUTA_PRIVADA_DEF, RUTA_PUBLICA_DEF)
        print(f"  [OK] Clave privada guardada en: {RUTA_PRIVADA_DEF}")
        print(f"  [OK] Clave pública guardada en: {RUTA_PUBLICA_DEF}")

        # 2. Cargar las claves RSA previamente almacenadas
        print("\n[Paso 2] Cargando claves RSA desde disco...")
        clave_privada = cargar_clave_privada(RUTA_PRIVADA_DEF)
        clave_publica = cargar_clave_publica(RUTA_PUBLICA_DEF)
        print("  [OK] Par de claves RSA cargado correctamente.")

        # 3. Generar clave de sesión AES de 256 bits
        print("\n[Paso 3] Generando clave de sesión AES-256 (32 bytes)...")
        clave_aes = generar_clave_aes(256)
        print(f"  [OK] Clave AES-256 generada (hex): {clave_aes.hex()}")

        # 7. Verificación explícita de cifrado/descifrado de clave AES con RSA-OAEP + SHA-256
        print("\n[Paso 4] Probando protección de clave AES mediante RSA-OAEP (SHA-256)...")
        clave_aes_cifrada = cifrar_clave_aes_con_rsa(clave_aes, clave_publica)
        clave_aes_verif = descifrar_clave_aes_con_rsa(clave_aes_cifrada, clave_privada)
        if clave_aes != clave_aes_verif:
            raise RuntimeError("La clave AES recuperada con RSA no coincide con la original.")
        print(f"  [OK] Clave AES cifrada ({len(clave_aes_cifrada)} bytes) y recuperada con éxito.")

        # 4 y 5. Crear y guardar el sobre digital
        print("\n[Paso 5] Creando y guardando sobre digital...")
        if modo == "1":
            nombre_base = os.path.basename(entrada_archivo)
            ruta_sobre = os.path.join("sobres", f"{nombre_base}.sobre.json")
            info_creacion = crear_sobre_archivo(
                entrada_archivo, clave_publica, ruta_sobre, clave_aes=clave_aes
            )
        else:
            ruta_sobre = os.path.join("sobres", "mensaje_texto.sobre.json")
            info_creacion = crear_sobre_texto(
                entrada_texto, clave_publica, ruta_sobre, clave_aes=clave_aes
            )
        print(f"  [OK] Sobre digital guardado en: {info_creacion['ruta_sobre']}")
        print(f"  [OK] IV aleatorio generado (hex): {info_creacion['iv_hex']}")

        # 6 y 8. Abrir el sobre digital existente y recuperar contenido
        print("\n[Paso 6] Abriendo sobre digital existente y recuperando contenido...")
        resultado = abrir_sobre(ruta_sobre, clave_privada, directorio_salida="salida")
        print(f"  [OK] Clave AES recuperada (hex): {resultado['clave_aes_recuperada_hex']}")

        # Validación de integridad
        print("\n[Paso 7] Validando integridad del contenido recuperado...")
        if resultado["tipo"] == "archivo":
            ruta_rec = resultado["ruta_recuperada"]
            iguales = verificar_integridad_archivo(entrada_archivo, ruta_rec)
            print(f"  [OK] Archivo recuperado en: {ruta_rec}")
            print(f"  [VERIFICACIÓN] ¿Coinciden byte a byte?: {'SÍ (100% idénticos)' if iguales else 'NO'}")
        else:
            msg_rec = resultado["mensaje_recuperado"]
            iguales = entrada_texto == msg_rec
            print(f"  [OK] Mensaje original:   {entrada_texto}")
            print(f"  [OK] Mensaje recuperado: {msg_rec}")
            print(f"  [VERIFICACIÓN] ¿Coinciden exactamente?: {'SÍ' if iguales else 'NO'}")

        print("\n[ÉXITO] Flujo completo finalizado sin errores.")

    except Exception as e:
        print(f"\n[ERROR] Fallo durante el flujo completo: {e}")


def opcion_generar_rsa() -> None:
    try:
        tam_str = input("Tamaño de clave RSA en bits [2048/4096, Enter=2048]: ").strip()
        tam = int(tam_str) if tam_str else 2048
        priv, pub = generar_par_claves_rsa(tam)
        r_priv, r_pub = guardar_claves_rsa(priv, pub, RUTA_PRIVADA_DEF, RUTA_PUBLICA_DEF)
        print(f"[OK] Claves RSA de {tam} bits generadas:")
        print(f"     Privada: {r_priv}")
        print(f"     Pública: {r_pub}")
    except Exception as e:
        print(f"[ERROR] {e}")


def opcion_crear_sobre() -> None:
    try:
        ruta_pub = limpiar_ruta(
            input(f"Ruta de la clave pública PEM [Enter={RUTA_PUBLICA_DEF}]: ")
        ) or RUTA_PUBLICA_DEF
        clave_publica = cargar_clave_publica(ruta_pub)

        modo = input("Tipo de entrada: [1] Archivo  [2] Mensaje de texto: ").strip()
        if modo == "1":
            ruta_archivo = limpiar_ruta(input("Ruta del archivo a proteger: "))
            nombre_base = os.path.basename(ruta_archivo)
            ruta_sobre = os.path.join("sobres", f"{nombre_base}.sobre.json")
            info = crear_sobre_archivo(ruta_archivo, clave_publica, ruta_sobre)
        elif modo == "2":
            mensaje = input("Escribe el mensaje a proteger: ")
            nombre = input("Nombre identificador para el sobre [Enter=texto]: ").strip() or "texto"
            ruta_sobre = os.path.join("sobres", f"{nombre}.sobre.json")
            info = crear_sobre_texto(mensaje, clave_publica, ruta_sobre)
        else:
            print("[ERROR] Tipo de entrada no válido.")
            return

        print(f"[OK] Sobre digital creado en: {info['ruta_sobre']}")
        print(f"     Clave AES-256 (hex): {info['clave_aes_hex']}")
        print(f"     IV aleatorio (hex):  {info['iv_hex']}")
    except Exception as e:
        print(f"[ERROR] {e}")


def opcion_abrir_sobre() -> None:
    try:
        ruta_sobre = limpiar_ruta(input("Ruta del sobre digital (.sobre.json): "))
        ruta_priv = limpiar_ruta(
            input(f"Ruta de la clave privada PEM [Enter={RUTA_PRIVADA_DEF}]: ")
        ) or RUTA_PRIVADA_DEF
        clave_privada = cargar_clave_privada(ruta_priv)

        resultado = abrir_sobre(ruta_sobre, clave_privada, directorio_salida="salida")
        print(f"[OK] Sobre digital abierto correctamente.")
        print(f"     Clave AES recuperada (hex): {resultado['clave_aes_recuperada_hex']}")

        if resultado["tipo"] == "archivo":
            print(f"     Archivo recuperado en: {resultado['ruta_recuperada']}")
            orig = limpiar_ruta(
                input("Ruta del archivo original para comparar byte a byte (Enter para omitir): ")
            )
            if orig:
                iguales = verificar_integridad_archivo(orig, resultado["ruta_recuperada"])
                print(f"     ¿Coinciden exactamente byte a byte?: {'SÍ' if iguales else 'NO'}")
        else:
            print(f"     Mensaje recuperado: {resultado['mensaje_recuperado']}")
    except Exception as e:
        print(f"[ERROR] {e}")


def opcion_prueba_rsa_aes() -> None:
    """Cifra y descifra directamente una clave AES-256 con RSA-OAEP-SHA256."""
    try:
        clave_publica = cargar_clave_publica(RUTA_PUBLICA_DEF)
        clave_privada = cargar_clave_privada(RUTA_PRIVADA_DEF)
        clave_aes = generar_clave_aes(256)

        cifrada = cifrar_clave_aes_con_rsa(clave_aes, clave_publica)
        recuperada = descifrar_clave_aes_con_rsa(cifrada, clave_privada)

        print(f"[OK] Clave AES original (hex):   {clave_aes.hex()}")
        print(f"[OK] Clave cifrada RSA (bytes):  {len(cifrada)} bytes")
        print(f"[OK] Clave AES recuperada (hex): {recuperada.hex()}")
        print(f"[VERIFICACIÓN] ¿Coinciden?: {'SÍ' if clave_aes == recuperada else 'NO'}")
    except Exception as e:
        print(f"[ERROR] {e}")


def opcion_prueba_clave_incorrecta() -> None:
    """Demuestra que un sobre digital NO puede abrirse con una clave privada distinta."""
    try:
        ruta_sobre = limpiar_ruta(input("Ruta de un sobre digital existente (.sobre.json): "))
        print("Generando un par RSA diferente (simulando un atacante o destinatario incorrecto)...")
        priv_ajena, _ = generar_par_claves_rsa(2048)
        abrir_sobre(ruta_sobre, priv_ajena, directorio_salida="salida")
        print("[ADVERTENCIA] No debería haber abierto el sobre.")
    except ValueError as e:
        print(f"[OK - SEGURIDAD VERIFICADA] El sistema bloqueó el acceso correctamente:\n  -> {e}")
    except Exception as e:
        print(f"[ERROR] {e}")


def menu() -> None:
    while True:
        print("\n" + "-" * 55)
        print(" SISTEMA DE SOBRES DIGITALES (AES-256-CBC + RSA-OAEP)")
        print("-" * 55)
        print("1. Ejecutar flujo completo automático (Pasos 1 a 9)")
        print("2. Generar y almacenar par de claves RSA (PEM)")
        print("3. Crear y guardar sobre digital (Archivo o Texto)")
        print("4. Abrir sobre digital existente")
        print("5. Probar cifrado/descifrado de clave AES con RSA-OAEP")
        print("6. Prueba de seguridad (intentar abrir con clave privada ajena)")
        print("0. Salir")

        opcion = input("\nSelecciona una opción: ").strip()
        if opcion == "1":
            flujo_completo_automatico()
        elif opcion == "2":
            opcion_generar_rsa()
        elif opcion == "3":
            opcion_crear_sobre()
        elif opcion == "4":
            opcion_abrir_sobre()
        elif opcion == "5":
            opcion_prueba_rsa_aes()
        elif opcion == "6":
            opcion_prueba_clave_incorrecta()
        elif opcion == "0":
            print("Saliendo del sistema.")
            break
        else:
            print("[ERROR] Opción no reconocida. Intenta de nuevo.")


if __name__ == "__main__":
    menu()