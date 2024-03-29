from config import MAX_LIST_SIZE
from types_d import Bool, Decimal, BytesM, String, Address, Bytes, FixedList, DynArray, Int
from utils import get_nearest_multiple


def _has_field(instance, field):
    try:
        return instance.HasField(field)
    except ValueError:
        return False


def extract_type(instance):
    if instance.HasField("b"):
        current_type = Bool()
    elif instance.HasField("d"):
        current_type = Decimal()
    elif instance.HasField("bM"):
        m = instance.bM.m % 32 + 1
        current_type = BytesM(m)
    elif _has_field(instance, "s"):
        max_len = 1 if instance.s.max_len == 0 else instance.s.max_len
        current_type = String(max_len)
    elif instance.HasField("adr"):
        current_type = Address()
    elif _has_field(instance, "barr"):
        max_len = 1 if instance.barr.max_len == 0 else instance.barr.max_len
        current_type = Bytes(max_len)
    elif _has_field(instance, "list"):
        # TODO: handle size in class?
        list_len = 1 if instance.list.n == 0 else instance.list.n
        list_len = list_len if instance.list.n < MAX_LIST_SIZE else MAX_LIST_SIZE

        current_type = extract_type(instance.list)
        current_type = FixedList(list_len, current_type)
    elif _has_field(instance, "dyn"):
        list_len = 1 if instance.dyn.n == 0 else instance.dyn.n
        list_len = list_len if instance.dyn.n < MAX_LIST_SIZE else MAX_LIST_SIZE
        current_type = extract_type(instance.dyn)
        current_type = DynArray(list_len, current_type)
    else:
        n = instance.i.n % 256 + 1
        n = get_nearest_multiple(n, 8)
        current_type = Int(n, instance.i.sign)

    return current_type
