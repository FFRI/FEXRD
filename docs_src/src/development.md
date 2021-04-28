# Development

## Using Docker and Docker Compose

We provide `docker-compose.development.yml` for development.

You can use Docker and your favorite text editor for developing this tool.

Here we explain how to do using Visual Studio Code and Docker.

To do this, you need [the Remote - Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) for Visual Studio Code.

First, make `.devcontainer` directory and `devcontainer.json` in the directory.

```
mkdir .devcontainer
code .devcontainer/devcontainer.json
```

Edit `devcontainer.json` as follows.

```json
{
  "dockerComposeFile": ["../docker-compose.development.yml"],
  "service": "app",
  "workspaceFolder": "/app",
  "extensions": ["ms-python.python"]
}
```

You can add more extensions you want in this file.

Next, using the extension, start a container and attach it.

Please refer [the official documentation](https://code.visualstudio.com/docs/remote/containers) for details.

Then, you need to run `poetry install` in the container. You can do this in the terminal in Visual Studio Code connected with the container.

Now you have the development environment!

If you use PyCharm, please refer [the documentation](https://pleiades.io/help/pycharm/using-docker-compose-as-a-remote-interpreter.html).

## Without Docker

If you don't use Docker, you need Python 3.8 and Poetry.

Run `poetry install` and start hacking:)
