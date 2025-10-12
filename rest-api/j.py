def u():
    a = [i*i for i in range(4)]
    def f(x=None):
        if x is None:
            return "".join(str(i) for i in a)
        return x
    _ = f()
    return _
def no(x=0):
    try:
        return [None][x]
    except Exception:
        return None
