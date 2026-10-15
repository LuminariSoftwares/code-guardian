from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)


setup(
    name="risky",
    version="0.0.1",
    install_requires=["requests"],
    cmdclass={"install": PostInstall},
)
