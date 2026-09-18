"""Code and label naming.  Inside IDA the Namer is fed IDA's own names."""


class Namer:
    def __init__(self, code_names=None):
        self.code_names = dict(code_names or {})

    def code(self, ea):
        if ea is None:
            return "?"
        return self.code_names.get(ea) or ("sub_%X" % ea)

    def label(self, ea):
        return self.code_names.get(ea) or ("loc_%X" % ea)
