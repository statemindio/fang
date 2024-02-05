class BaseType:
    def __eq__(self, other):
        return isinstance(other, self.__class__)

    def __str__(self):
        return self.vyper_type

    def __hash__(self):
        return hash(self.vyper_type)

    @property
    def vyper_type(self):
        raise NotImplementedError()

    def generate(self):
        raise NotImplementedError()

    def generate_literal(self, value):
        raise NotImplementedError()

    @property
    def name(self):
        return self.__class__.__name__.upper()
