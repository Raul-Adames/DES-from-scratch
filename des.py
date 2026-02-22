from S_box import Sbox
from key_tables import Ktables
from permutation_tables import Ptables


class DES:

    def to_binary(self, value: str, base: int):
        try:
            # Check if is text, base 0 is text
            if base == 0:
                binary_text = ''.join(format(ord(char), '08b') for char in value)
                return binary_text
            # Check if binary
            elif base == 2:
                if all(num in "01" for num in value):
                    return value
            # Check if byte
            elif base == 8:
                return ''.join(f"{byte:08b}" for byte in value)
            # Check if decimal
            elif base == 10:
                if value.isdigit():
                    return str(bin(int(value))[2:])
            # Check if hex
            elif base == 16:
                # Calcular el numero correcto de bits basado en la longitud del hexadecimal
                num_bits = len(value) * 4  # Cada digito hexadecimal = 4 bits
                return str(bin(int(value, 16))[2:].zfill(num_bits))
        except ValueError:
            raise ValueError("Error desconocido")

    def valid_length(self, value: str):
        return len(value) == 64

    def rotate(self, value: str, round: int):
        shift_nums = Ktables.left_shift[round]
        while shift_nums > 0:
            value = value[1:] + value[0]
            shift_nums -= 1
        return value

    def pc2(self, key: str):
        pc2_table = Ktables.permuted_choice_two
        subkey = ""
        for i in pc2_table:
            subkey += key[i - 1]
        return subkey

    def pc1(self, key: str):
        pc1_table = Ktables.permuted_choice_one
        temp = ""
        for i in pc1_table:
            temp += key[i - 1]  # Restar 1 porque los índices en la tabla son 1-based, y Python usa 0-based
        return temp

    def initial_permutation(self, text: str):
        result = ""
        IP = Ptables.matriz_initialPermutation
        for i in IP:
            result += text[i - 1]  # Restar 1 porque los índices en la tabla son 1-based, y Python usa 0-based
        return result

    def expand(self, R: str):
        expansion_table = Ptables.matriz_expansionPermutation
        result = ""
        for i in expansion_table:
            result += R[i - 1]  # Restar 1 porque los índices en la tabla son 1-based, y Python usa 0-based
        return result

    def xor(self, first: str, second: str):
        if len(first) != len(second):
            raise ValueError(f"El largo de los inputs es diferente. Input1: {len(first)}, Input2: {len(second)}")
        result = ""
        for i in range(len(first)):
            temp = int(first[i]) + int(second[i])
            if temp == 2:
                result += "0"
            else:
                result += str(temp)
        return result

    def s_box(self, R):
        six_bits_groups = list()  # Lista para almacenar los grupos de 6 bits
        six_bit = ""  # String temporal para almacenar cada grupo de 6 bits
        for i in range(len(R)):
            six_bit += R[i]
            # Cada vez que tengamos 6 bits, agregamos el grupo a la lista y reiniciamos `six_bit`
            if (i + 1) % 6 == 0:
                six_bits_groups.append(six_bit)
                six_bit = ""  # Reiniciamos el string para el siguiente grupo

        if len(six_bits_groups) != 8:  # Solo para estar seguros
            raise ValueError(f"No hay 8 grupos de 6 bits. Cantidad: {len(six_bits_groups)}")

        master_sbox = Sbox.S_box
        result = ""

        for i in range(len(six_bits_groups)):
            # Sub-string (grupo de bits) | Obtener los 6 bits del grupo correspondiente
            grupo = six_bits_groups[i]
            # Determinar la fila usando el primer y último bit (bits 1 y 6)
            row_selection = grupo[0] + grupo[-1]
            row_selection = int(row_selection, 2)
            # Determinar la columna usando los 4 bits del medio (bits 2-5)
            column_selection = grupo[1:-1]
            column_selection = int(column_selection, 2)

            # master_sbox[s_box_deseada][row][column]
            # Obtener el nuevo valor de la S-Box correspondiente
            new_num = master_sbox[i][row_selection][column_selection]
            # Convertir el nuevo valor a binario de 4 bits
            new_num_bin = f"{new_num:04b}"  # Asegurarse de que siempre sea un string de 4 bits

            result += new_num_bin
        return result

    def permute(self, R):
        permutation_table = Ptables.matriz_permutation_function
        result = ""
        for i in permutation_table:
            result += R[i - 1]
        return result

    def final_permutation(self, block: str):
        final_permutation_table = Ptables.matriz_inversePermutation
        result = ""
        for i in final_permutation_table:
            result += block[i - 1]  # Restar 1 porque la tabla es 1-based
        return result

    def encriptar_helper(self, text: str, key: str, total_rounds: int, key_base: int, text_base: int):

        text = self.to_binary(text, text_base)
        if not self.valid_length(text):
            raise ValueError("El texto de entrada debe tener exactamente 64 bits.")

        key = self.to_binary(key, key_base)

        if not self.valid_length(key):
            raise ValueError(f"El key debe ser de 64 bits. Longitud actual: {len(key)}")

        # Setup
        subkeys = self.generate_subkeys(key, total_rounds)
        text = self.initial_permutation(text)  # IP permutation

        # Dividir texto en dos mitades
        L = text[:len(text) // 2]
        R = text[len(text) // 2:]

        for round in range(total_rounds):

            subkey = subkeys[round]

            # Expande R de 32 bits a 48
            R_expanded = self.expand(R)

            # Xor con el subkey y el R_expandido
            R_xor = self.xor(R_expanded, subkey)

            # Aplica las S-boxes
            R_sbox = self.s_box(R_xor)

            # Aplica la permutacion P
            R_permuted = self.permute(R_sbox)

            # Xor con el L y el R_permutated
            new_R = self.xor(L, R_permuted)

            # Actualizar L y R
            L = R  # L va a ser el antiguo R
            R = new_R  # R va a ser resultado del xor

        final_block = R + L  # Se invierte el left y el right
        result = self.final_permutation(final_block)
        #  Convierte el string de bin a su forma hex
        result = str(hex(int(result, 2)))[2:].zfill(16)
        return result

    def encriptar(self, text: str, key: str, total_rounds: int, key_base: int, text_base: int):
        # text --> Texto normal
        # key --> key
        # total_rounds --> total de rondas a completar
        # key_base --> base en el que esta ecrito el key
        # text_base --> base en el que el texto esta escrito

        if len(text) == 0:
            return text

        text_inBytes = text.encode("utf-8")

        # Agrupar el texto en bloques de 64 bits (8 bytes)
        textBlocks = []  # Para guardar el texto en bloques de 64 bits
        block = b""  # Bloque de 64-bits, 8-bytes, 8 letras ... -> 1 letra = 1 byte
        for byte in text_inBytes:
            block += bytes([byte])  # Anadir el byte al bloque
            if len(block) == 8:  # Si el bloque tiene 8 bytes
                textBlocks.append(block)
                block = b""  # Reiniciar el bloque

        # Si queda algo en el bloque despues del bucle
        # Solo se entra si no se pudo completar el bloque con los 64 bits y quedo algo
        if block:  # No hay 64-bits (8 bytes o 8 letras)
            # rellenar()
            relleno_necesario = 8 - (len(block) % 8)
            relleno = bytes([relleno_necesario] * relleno_necesario)
            block += relleno
            textBlocks.append(block)

        hex_string = ""
        for block in textBlocks:
            block = self.to_binary(block, 8)
            hex_string += self.encriptar_helper(block, key, total_rounds, key_base, 2)

        return hex_string


    def generate_subkeys(self, key: str, total_rounds: int):
        # PC-1: aplicar permutación para reducir la clave de 64 bits a 56 bits
        subkey_56bits = self.pc1(key)

        # Dividir la clave de 56 bits en dos partes de 28 bits
        C = subkey_56bits[:28]
        D = subkey_56bits[28:]

        # Generar las 16 subclaves
        subkeys = []
        for round_num in range(total_rounds):
            # Rotar C y D según el número de la ronda
            C = self.rotate(C, round_num)  # Actualiza C con el valor rotado
            D = self.rotate(D, round_num)  # Actualiza D con el valor rotado

            # Concatenar C y D y aplicar PC-2 para obtener la subclave de 48 bits
            concatenated = C + D  # 56 bits
            subkey = self.pc2(concatenated)  # Aplicar PC-2 para obtener 48 bits
            subkeys.append(subkey)  # Guardar la subclave generada para la ronda actual

        return subkeys  # Devolver la lista de 16 subclaves

    def desencriptar_helper(self, text: str, key: str, total_rounds: int, key_base: int):
        # El texto esta en binario
        # 64-bits cipher
        # number of rounds
        # base of the key

        # Cambiar a binario
        text = self.to_binary(text, 2)
        if not self.valid_length(text):
            raise ValueError("El texto cifrado no es de 64 bits")

        key = self.to_binary(key, key_base)
        if not self.valid_length(key):
            raise ValueError(f"El key debe ser de 64 bits. Longitud actual: {len(key)}")

        # Setup
        subkeys = self.generate_subkeys(key, total_rounds)  # Obtener todos los subkeys para las rondas
        subkeys.reverse()

        text = self.initial_permutation(text)  # IP permutation

        # Dividir texto en dos mitades
        L = text[:len(text) // 2]
        R = text[len(text) // 2:]

        for round in range(total_rounds):

            subkey = subkeys[round]

            # Expande R de 32 bits a 48
            R_expanded = self.expand(R)

            # Xor con el subkey y el R_expandido
            R_xor = self.xor(R_expanded, subkey)

            # Aplica las S-boxes
            R_sbox = self.s_box(R_xor)

            # Aplica la permutacion P
            R_permuted = self.permute(R_sbox)

            # Xor con el L y el R_permutated
            new_R = self.xor(L, R_permuted)

            # Actualizar L y R
            L = R  # L va a ser el antiguo R
            R = new_R  # R va a ser resultado del xor

        final_block = R + L  # Se invierte el left y el right
        result = self.final_permutation(final_block)

        # Convierte en un string hexadecimal que siempre tiene 16 caractres (64-bits)
        # el zfill es por si tiene 0 a la izquierda, cuando le haces hex la funcion los elimina ....
        # por lo que el zfill lo que hace es que los vuelve a poner, asegurando siempre 64-bits
        # El [2:] elimina el prefijo 0x del inicio
        return str(hex(int(result, 2)))[2:].zfill(16)

    def desencriptar(self, text: str, key: str, total_rounds: int, key_base: int):
        # Asume que el texto esta en hex
        # key --> key
        # total rounds --> rounds que hay que hacer para desencriptar
        # key_base --> base en la que esta el key

        if len(text) == 0:
            return text

        # Convertir el cipher text de hex a bin
        text = self.to_binary(text, 16)

        # Agrupar el texto en bloques de 64-bits
        textBlocks = []  # 64-bits text blocks
        block = ""
        for i in range(len(text)):
            block += text[i]
            if len(block) == 64:
                textBlocks.append(block)
                block = ""

        # Obtener texto original (en hex) (y con relleno **de tener**)
        hex_string = ""
        for block in textBlocks:
            hex_string += self.desencriptar_helper(block, key, total_rounds, key_base)

        # Tomar el ultimo byte
        # Esto se hace pq para rellenar se utiliza el ultimo byte para indicar cuantos bytes se rellenaron
        # Ejemplo: af\a2\01\c1\04\04\04\04 --> el ultimo byte es 04 haciendo referencia de que los ultimos 4 bytes son los que se rellenaron
        # Entonces el ultimo y los proximos 3 tienen el mismo valor. Asi que en total hay 4 bytes que se tuvieron que rellenar
        last_byte = hex_string[-2:]  # -2 porque cada valor (en hex) son 4 bits y un byte son 8 bits

        if 0 < int(last_byte, 16) <= 8:  # Evita errores donde el plaintext es una cadena que se repite. El relleno solo puede ser de 0 a 8, si el valor de last_byte es otro entonces no tiene relleno
                                         # Ejemplo: "A" * 80, no da el resultado correcto sino tiene este if pq es una sequencia que se repite
                                         # Entonces ps chequea y como todos los bytes son iguales ps asume que hay relleno y lo elimina cuando no se supone que lo haga
                                         # hex_strring cuando el plaintext es "A" * 80 --> 414141414141414141414141414141 ...
                                         # Como el ultimo byte es igual a los anteriores ps quita parte del mensaje aunque no se supone que lo haga

            # Temp --> una lista de bytes, ej: [02, af, b5, 01] ... cada letra o num son 4 bits (pq es hex) y un byte son 8 bits (osea dos numeros o letras)
            temp = []
            c = ""
            for i in range(len(hex_string)):
                c += hex_string[i]
                if len(c) == 2:
                    temp.append(c)
                    c = ""

            # Identifica si hay relleno o no
            count = 0  # Cuenta la cantidad de veces que se repite el last_byte
            for i in reversed(temp):
                # byte in hex --> 06 | 0 --> 4 bits | 6 --> 4 bits | 4 + 4 = 8
                if i == last_byte:
                    count += 1
                if count == (int(last_byte, 16)):
                    break  # Hay relleno
                elif count < (int(last_byte, 16)) and i != last_byte:  # Todos los bytes tienen que ser iguales (uno detras del otro), si hay uno diferente se termina
                                                                   # Ej: [af, 84, 44, 08, 02, 02] --> los ultimos dos tienen que ser iguales
                                                                   # Si es asi --> [af, 44, 44, 08, 02] --> se asume que no hay relleno
                    break  # No hay relleno

            # Chequea (el resultado) de si hay relleno o no
            if count == int(last_byte, 16):
                # Quita el relleno
                while count > 0:
                    temp.pop()  # Elimina el item al final de la lista.
                    count -= 1

            hex_string = ""
            for i in temp:
                hex_string += i

        # Convertir el string hex a bytes
        bytes_object = bytes.fromhex(hex_string)

        # Convertir los bytes a un string legible (UTF-8)
        legible_text = bytes_object.decode("utf-8")

        return legible_text
