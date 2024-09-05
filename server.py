import json
import os
import uuid
import hashlib
from flask import Flask, jsonify, request, send_from_directory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__, static_folder='/')
usuarios_file = 'usuarios.json'
blockchain_file = 'blockchain.json'
blockchain = []

@app.route('/firmar_transaccion', methods=['POST'])
def firmar_transaccion():
    data = request.get_json()
    valor_transaccion = data.get('valor_transaccion')
    clave_privada_pem = data.get('clave_privada')
    id_destinatario = data.get('id_destinatario')
    clave_privada_pem = "-----BEGIN RSA PRIVATE KEY-----\n"+clave_privada_pem+"\n-----END RSA PRIVATE KEY-----\n"
    

    if not valor_transaccion or not clave_privada_pem or not id_destinatario:
        return jsonify(success=False, error='Faltan datos requeridos')

    try:
        clave_privada = serialization.load_pem_private_key(
            clave_privada_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
    except Exception as e:
        return jsonify(success=False, error=str(e))

    mensaje = f'valor={valor_transaccion}&destinatario={id_destinatario}'.encode('utf-8')
    firma = clave_privada.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return jsonify(success=True, firma=firma.hex())

@app.route('/calcular_saldo/<user_id>', methods=['GET'])
def calcular_saldo(user_id):

    print("calcular saldo")
    # Cargar la blockchain y las transacciones desde los archivos o base de datos
    with open('blockchain.json', 'r') as file:
        blockchain = json.load(file)
    

    saldo = 0
    for bloque in blockchain:
        for transaccion in bloque["transacciones"]:
            print(transaccion)
            if transaccion['id_destinatario'] == user_id:
                saldo += int(transaccion['valor'])  

    return jsonify(success=True, saldo=saldo)


@app.route('/agregar_transaccion', methods=['POST'])
def agregar_transaccion():
    data = request.get_json()
    valor = data.get('valor')
    firma = data.get('firma')
    id_destinatario = data.get('id_destinatario')
    id_emisor = data.get('id_emisor')

    print(id_emisor)
    if not valor or not firma or not id_destinatario:
        return jsonify(success=False, error='Faltan datos requeridos')

    # Cargar bloques existentes desde el archivo JSON
    with open('blockchain.json', 'r') as file:
        blockchain = json.load(file)

    # Obtener el último bloque de la cadena
    ultimo_bloque = blockchain[-1]

    # Verificar si el último bloque tiene menos de 16 transacciones
    if len(ultimo_bloque['transacciones']) < 16:
        # Agregar la nueva transacción al último bloque
        nueva_transaccion = {
            'numero': len(ultimo_bloque['transacciones']),
            'valor': valor,
            'firma': firma,
            'id_destinatario': id_destinatario,
            'id_emisor': id_emisor
        }
        ultimo_bloque['transacciones'].append(nueva_transaccion)
    else:

        merkle_root = calcular_merkle_root(ultimo_bloque['transacciones'])
        ultimo_bloque['merkle_root'] = merkle_root

        noncepow  = calcular_nonce(merkle_root, ultimo_bloque['transacciones'])
        nonce = noncepow[0]
        pow = noncepow[1]
        ultimo_bloque['nonce'] = nonce
        ultimo_bloque['POW'] = pow


        datos_concatenados = ultimo_bloque['hash_anterior'] + str(nonce) + pow + merkle_root 
        # Calcular el HASH Actual
        hash_actual = hashlib.sha512(datos_concatenados.encode()).hexdigest()

        ultimo_bloque['hash_actual'] = hash_actual

        # Crear un nuevo bloque con la nueva transacción
        nuevo_bloque = {
            'numero': ultimo_bloque['numero'] + 1,
            'hash_anterior': ultimo_bloque['hash_actual'],
            'nonce': '',
            'merkle_root': '',
            'transacciones': [
                {
                    'numero': 0,
                    'valor': valor,
                    'firma': firma,
                    'id_destinatario': id_destinatario,
                    'id_emisor': id_emisor
                }
            ],
            'POW': '',
            'hash_actual': ''
        }
        blockchain.append(nuevo_bloque)

    # Guardar la cadena de bloques actualizada en el archivo JSON
    with open('blockchain.json', 'w') as file:
        json.dump(blockchain, file, indent=4)

    return jsonify(success=True)


@app.route('/verificar_firma', methods=['POST'])
def verificar_firma():
    data = request.get_json()
    valor_firma = data.get('valorFirma')
    clave_publica_base64 = data.get('clavePublica')
    firma_verificar = data.get('firmaVerificar')
    id_destinatario = data.get('verificaridDestinatario')
    


    print(valor_firma)
    print(clave_publica_base64)
    print(firma_verificar)
    print(id_destinatario)

    clave_publica_bytes = base64.b64decode(clave_publica_base64)

    clave_publica = serialization.load_der_public_key(
        clave_publica_bytes,
        backend=default_backend()
    )


    mensaje = f'valor={valor_firma}&destinatario={id_destinatario}'.encode('utf-8')
    firma_bytes = bytes.fromhex(firma_verificar)
    
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
        return jsonify(success=True, mensaje='Firma válida')
    except:
        return jsonify(success=False, error='Firma inválida')


def calcular_hash(transaccion):
    transaccion_str = json.dumps(transaccion, sort_keys=True).encode()
    return hashlib.sha256(transaccion_str).hexdigest()

# Función para calcular la raíz de Merkle
def calcular_merkle_root(transacciones):
    if len(transacciones) == 0:
        return ''

    # Calcular el hash de cada transacción
    hashes = [calcular_hash(tx) for tx in transacciones]
    print("hashes transacciones")
    for h in hashes:
        print(h)
    # Continuar combinando hasta que quede un solo hash
    #ronda 1
    hashes1 = [
        hashlib.sha256((hashes[0] + hashes[1]).encode()).hexdigest(),
        hashlib.sha256((hashes[2] + hashes[3]).encode()).hexdigest(),
        hashlib.sha256((hashes[4] + hashes[5]).encode()).hexdigest(),
        hashlib.sha256((hashes[6] + hashes[7]).encode()).hexdigest(),
        hashlib.sha256((hashes[8] + hashes[9]).encode()).hexdigest(),
        hashlib.sha256((hashes[10] + hashes[11]).encode()).hexdigest(),
        hashlib.sha256((hashes[12] + hashes[13]).encode()).hexdigest(),
        hashlib.sha256((hashes[14] + hashes[15]).encode()).hexdigest()
    ]

    print("ronda 1:")
    for h in hashes1:
        print(h)

    # Round 2
    hashes2 = [
        hashlib.sha256((hashes1[0] + hashes1[1]).encode()).hexdigest(),
        hashlib.sha256((hashes1[2] + hashes1[3]).encode()).hexdigest(),
        hashlib.sha256((hashes1[4] + hashes1[5]).encode()).hexdigest(),
        hashlib.sha256((hashes1[6] + hashes1[7]).encode()).hexdigest()
    ]

    print("ronda 2:")
    for h in hashes2:
        print(h)

    # Round 3
    hashes3 = [
        hashlib.sha256((hashes2[0] + hashes2[1]).encode()).hexdigest(),
        hashlib.sha256((hashes2[2] + hashes2[3]).encode()).hexdigest()
    ]

    print("ronda 2:")
    for h in hashes3:
        print(h)

    # Final round
    hashFinal = hashlib.sha256((hashes3[0] + hashes3[1]).encode()).hexdigest()

    print("Merkle root\n", hashFinal)
    return hashFinal


    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            # Si el número de hashes es impar, duplicar el último hash
            hashes.append(hashes[-1])

        # Combinar hashes pares
        hashes = [hashlib.sha256((hashes[i] + hashes[i + 1]).encode()).hexdigest()
                  for i in range(0, len(hashes), 2)]

    return hashes[0]


def calcular_hash_con_dificultad(data, dificultad):
    prefijo = '0' * dificultad
    nonce = 0
    while True:
        hash_actual = hashlib.sha256(f'{data}{nonce}'.encode()).hexdigest()
        if hash_actual.startswith(prefijo):
            return hash_actual, nonce
        nonce += 1


def calcular_nonce(merkle_root, transacciones):
    nonce = 0
    while True:
        # Crear una representación de las transacciones
        transacciones_str = json.dumps(transacciones, sort_keys=True)
        
        # Concatenar nonce, merkle_root y la representación de las transacciones
        data = f"{nonce}{merkle_root}{transacciones_str}"
        
        # Calcular el hash MD5
        hash_result = hashlib.md5(data.encode('utf-8')).hexdigest()
        
        # Verificar si el hash comienza con tres ceros
        if hash_result.startswith('000'):
            return nonce, hash_result
        nonce += 1


def cargar_usuarios():
    if os.path.exists(usuarios_file):
        with open(usuarios_file, 'r') as file:
            return json.load(file)
    return []

def guardar_usuarios(usuarios):
    with open(usuarios_file, 'w') as file:
        json.dump(usuarios, file, indent=4)

def limpiar_clave(clave_pem):
    lines = clave_pem.splitlines()
    return ''.join(lines[1:-1])  # Remueve la primera y última línea (cabecera y pie)

@app.route('/crear_usuario', methods=['POST'])
def crear_usuario():
    data = request.get_json()
    nombre = data.get('nombre', 'Usuario ' + str(uuid.uuid4())[:8])
    id = str(uuid.uuid4())

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=512,
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')


    private_key_pem = limpiar_clave(private_key_pem)

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    public_key_pem = limpiar_clave(public_key_pem)

    usuario = {
        'nombre': nombre,
        'id': id,
        'clave_publica': public_key_pem,
        'clave_privada': private_key_pem
    }

    usuarios = cargar_usuarios()
    usuarios.append(usuario)
    guardar_usuarios(usuarios)

    return jsonify(success=True)


@app.route('/eliminar_usuario/<user_id>', methods=['DELETE'])
def eliminar_usuario(user_id):
    usuarios = cargar_usuarios()
    usuarios = [usuario for usuario in usuarios if usuario['id'] != user_id]
    guardar_usuarios(usuarios)
    return jsonify(success=True)

@app.route('/usuarios.json')
def obtener_usuarios():
    return jsonify(cargar_usuarios())




@app.route('/')
def root():
    return send_from_directory(app.static_folder, 'index.html')


if __name__ == '__main__':
    if os.path.exists(blockchain_file):
        with open(blockchain_file, 'r') as file:
            try:
                blockchain = json.load(file)
                if not blockchain:  # Si el archivo está vacío, crear el bloque inicial
                    raise ValueError("El archivo está vacío.")
            except (json.JSONDecodeError, ValueError):
                # Crear el primer bloque de la cadena de bloques
                primer_bloque = {
                    'numero': 0,
                    'hash_anterior': '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                    'nonce': 'nonce_inicial',
                    'merkle_root': 'merkle_root_inicial',
                    'transacciones': [],
                    'POW': 'POW_inicial',
                    'hash_actual': 'hash_actual_inicial'
                }
                blockchain.append(primer_bloque)

                with open(blockchain_file, 'w') as file:
                    json.dump(blockchain, file, indent=4)
    else:
        # Crear el primer bloque de la cadena de bloques
        primer_bloque = {
            'numero': 0,
            'hash_anterior': '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
            'nonce': 'nonce_inicial',
            'merkle_root': 'merkle_root_inicial',
            'transacciones': [],
            'POW': 'POW_inicial',
            'hash_actual': 'hash_actual_inicial'
        }
        blockchain.append(primer_bloque)

        with open(blockchain_file, 'w') as file:
            json.dump(blockchain, file, indent=4)

    app.run(debug=True)
