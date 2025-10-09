import numpy as np
from pprint import pprint

# import collections
from contextlib import contextmanager

am = set([1, 2, 3, 4, 5, 6, 7, 89, 1])
am2 = set([30, 50, 60, 80, 2, 1])
am3 = set([1, 2, 3, 4])


print(np.arange(1, 2, 3))

pprint(am)
pprint(am2)
pprint(am > am3)


def dd():
    for i in range(3):
        yield i
    return None


def deld():
    arr = []
    print(f"be arr{arr}")
    yield arr
    print(f"la arr{arr}")


class ASMA:
    def __len__(self):
        return 100


class Duck:
    def __init__(self, input_name):
        self.hidden_name = input_name

    @property
    def name2(self):
        print("inside the getter")
        return self.hidden_name

    @name2.setter
    def name2(self, input_name):
        print("inside the setter")
        self.hidden_name = input_name


def pagga(func):
    print(func)
    return func


@pagga
def test():
    pprint("test func")


fowl = Duck("Howard")
fowl.name2

a2 = ASMA()

pprint(len(a2))


s = "321CRdtRDt"

print(s.strip())

# test()


d = {"1": 2, "2": 3, "5": 21}

pprint(d.setdefault("71", 100))
print(d.items())

dt = dd()

for x in dt:
    print("one", x)
    if x == 4:
        break
print("========")
for x in dt:
    print("two", x)
    if x == 4:
        break


@contextmanager
def my_context_manager():
    print("Вход в контекстный менеджер")  # Аналог __enter__
    try:

        yield "Возвращаемое значение (опционально)"  # То,что будетдоступн в as
    finally:
        print("Выход из контекстного менеджера")  # Аналог __exit__


# Использование:
with my_context_manager() as value:
    print("Внутри блока with")
    print("Получено значение:", value)


def rg(**krgs):
    print(krgs["d"])


rg(b=8, d=8, ff=898097)
