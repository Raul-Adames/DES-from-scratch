import string

from key_tables import Ktables
from permutation_tables import Ptables
from S_box import Sbox
from des import DES
import random


#_____________________________________#
# maquina1 = DES()
# plain_text = "02468aceeca86420"
# key = "0f1571c947d9e859"
#
# encriptado = maquina1.encriptar(plain_text, key, 16, 16, 16)
# encriptado_esperado = "da02ce3a89ecac3b"
#
# print("Prueba 1: Encriptacion de mensaje")
# print("\tEsperado: {}".format(encriptado_esperado))
# print("\tObtenido: {}".format(encriptado))
# print("\tComparacion: {}".format(encriptado == encriptado_esperado))
#
# print()
#
# descencriptado = maquina1.desencriptar(encriptado, key, 16, 16)
# print("Prueba 2: Descencriptacion de mensaje")
# print("\tEsperado: {}".format(plain_text))
# print("\tObtenido: {}".format(descencriptado))
# print("\tComparacion: {}".format(plain_text == descencriptado))

#________________________________________#
def main():
    maquina1 = DES()
    plaintext = "5465787457697468466f726d617473"
    key = "0f1571c947d9e859"

    encriptado = maquina1.encriptar(plaintext, key, 16, 16, 0)

    print("Prueba 1: Encriptacion de mensaje")
    print("\tObtenido: {}".format(encriptado))

    print()

    descencriptado = maquina1.desencriptar(encriptado, key, 16, 16)
    print("Prueba 2: Descencriptacion de mensaje")
    print("\tEsperado: {}".format(plaintext))
    print("\tObtenido: {}".format(descencriptado))
    print("\tComparacion: {}".format(plaintext == descencriptado))


# def main():
#     maquina = DES()
#     key = "0f1571c947d9e859"
#     failed = []
#     for i in range(0, 2000, 5):
#         text = "A" * i
#         cipher = maquina.encriptar(text, key, 16, 16, 0)
#         decript = maquina.desencriptar(cipher, key, 16, 16)
#         if decript != text:
#             failed.append(i)
#     print(failed)


if __name__ == '__main__':
    main()
