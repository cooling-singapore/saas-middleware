# Simulation-as-a-Service (SaaS) Middleware

The SaaS Middleware provides the necessary infrastructure to faciliate deployment and operations of a loosely-coupled federation of models.

## Install Dependencies
```
pip3 install flask flask_cors requests jsonschema canonicaljson cryptography docker
```


## Build and Install Package
Install `build`:
```
pip3 install --upgrade build
```

From the root directory of the repository, initiate the build:
```
python3 -m build
```

Important: for now, we are only creating local builds that are *not* uploaded to PyPi. The package can be installed from its local source as follows:
```
pip3 install /path/to/saas-middleware/dist/saas-middleware_cooling-singapore-0.0.1.tar.gz
```
