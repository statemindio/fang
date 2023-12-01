class BaseType:
    def __eq__(self, other):
        return isinstance(other, self.__class__)

    def __str__(self):
        return self.vyper_type

    @property
    def vyper_type(self):
        raise NotImplementedError()
