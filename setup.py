from setuptools import setup


setup(
    name='frasco-users-ldap',
    version='0.1.8',
    url='http://github.com/frascoweb/frasco-users-ldap',
    license='MIT',
    author='Maxime Bouroumeau-Fuseau',
    author_email='maxime.bouroumeau@gmail.com',
    description="LDAP support for Frasco-Users",
    py_modules=['frasco_users_ldap'],
    zip_safe=False,
    platforms='any',
    install_requires=[
        'frasco',
        'frasco-users',
        'python-ldap'
    ]
)
