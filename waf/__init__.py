"""WAF factory; importing policy helpers must not build another application."""


def create_app(settings=None):
    from .app import create_app as factory
    return factory(settings)


__all__ = ['create_app']
