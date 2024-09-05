from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64

# Clave pública en formato Base64
clave_publica_base64 = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL6HxqQd+2d12Zb88X7vSPowa+O2vt5d8N/A74CN8Pmqdodja0LJIYUWH0/pZzAIapGG/lY+nIZeDth2aRmJgksCAwEAAQ=="

# Decodificar la clave pública desde Base64
clave_publica_bytes = base64.b64decode(clave_publica_base64)

# Cargar la clave pública
clave_publica = serialization.load_der_public_key(
    clave_publica_bytes,
    backend=default_backend()
)

# Datos de la transacción
valor_transaccion = 250000
id_destinatario = "c1327d3d-eb80-41f4-bd04-885c93f25ad5"
firma = "7842b570f4828ad5e6ac9cbf064c649b1ce73aeaa516d12bc36e67034899124c8c45c6ac9dace95e78ec61d4e07a6f32a05de057ebba069c7321bacf91032487"

# Mensaje para verificar la firma
mensaje = f'valor={valor_transaccion}&destinatario={id_destinatario}'.encode('utf-8')
firma_bytes = bytes.fromhex(firma)

# Verificar la firma


print(mensaje)
print(firma_bytes)
try:
    clave_publica.verify(
        firma_bytes,
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Firma válida")
except:
    print("Firma inválida")
